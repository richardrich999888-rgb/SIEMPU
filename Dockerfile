# Manifest-list digest resolved from the official Docker registry. Update with review and image scans.
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS build
WORKDIR /build
COPY . .
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && npm run check \
 && npm run lint \
 && npm run typecheck \
 && npm run security \
 && npm run build

FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df
LABEL org.opencontainers.image.title="SYNTRIASS SIEPMU synthetic-data demonstrator" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/richardrich999888-rgb/SIEMPU"
WORKDIR /app
COPY --from=build --chown=1000:1000 /build/dist/ ./
COPY --chown=1000:1000 deployment/ ./deployment/
RUN mkdir -p /var/lib/siepmu/control /var/lib/siepmu/relay /var/lib/siepmu/relay-auth \
 && chown -R 1000:1000 /var/lib/siepmu \
 && chmod 700 /var/lib/siepmu/control /var/lib/siepmu/relay /var/lib/siepmu/relay-auth
USER 1000:1000
ENV NODE_ENV=production SIEPMU_DATA_DIR=/var/lib/siepmu/control
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["node", "deployment/healthcheck.mjs"]
CMD ["node", "services/web/server.mjs"]
