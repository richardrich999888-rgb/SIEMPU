# Manifest-list digest resolved from the official Docker registry. Update with review and image scans.
FROM node:26.11.1-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567 AS build
ARG SIEPMU_BUILD_REVISION=unknown
ARG SIEPMU_BUILD_TIMESTAMP=unknown
WORKDIR /build
COPY . .
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && npm run check \
 && npm run lint \
 && npm run typecheck \
 && npm run security \
 && npm run build

# The dependency-free runtime needs Node only. Keep build tooling out of the
# shipped image and pin the independently resolved official Alpine manifest.
FROM node:26.11.1-alpine3.24@sha256:143494b1da2945f061539253adc65e4f1569ddf07da2d384c022c791a9d90a4a
ARG SIEPMU_BUILD_REVISION=unknown
ARG SIEPMU_BUILD_TIMESTAMP=unknown
LABEL org.opencontainers.image.revision=$SIEPMU_BUILD_REVISION \
      org.opencontainers.image.created=$SIEPMU_BUILD_TIMESTAMP \
      org.opencontainers.image.title="SYNTRIASS SIEPMU synthetic-data demonstrator" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/richardrich999888-rgb/SIEMPU"
WORKDIR /app
COPY --from=build --chown=1000:1000 /build/dist/ ./
COPY --chown=1000:1000 deployment/ ./deployment/
# Upgrade the actual shared libraries: the pinned base predates the fix for
# CVE-2026-14456. Versions verified against the official Alpine v3.24 index.
RUN apk add --no-cache --upgrade libcrypto3=3.5.9-r0 libssl3=3.5.9-r0 \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /opt/yarn* /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && mkdir -p /var/lib/siepmu/control /var/lib/siepmu/relay /var/lib/siepmu/relay-auth \
 && chown -R 1000:1000 /var/lib/siepmu \
 && chmod 700 /var/lib/siepmu/control /var/lib/siepmu/relay /var/lib/siepmu/relay-auth
USER 1000:1000
ENV NODE_ENV=production SIEPMU_DATA_DIR=/var/lib/siepmu/control \
    SIEPMU_BUILD_REVISION=$SIEPMU_BUILD_REVISION \
    SIEPMU_BUILD_TIMESTAMP=$SIEPMU_BUILD_TIMESTAMP
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["node", "deployment/healthcheck.mjs"]
CMD ["node", "services/web/server.mjs"]
