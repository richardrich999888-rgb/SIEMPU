# Official Docker image manifest index verified against docker-library/repo-info; see security/README.md.
FROM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
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

FROM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
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
# The runtime has no npm dependencies; remove bundled package managers and their attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
 && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/corepack \
 && node --input-type=module -e "import { DatabaseSync } from 'node:sqlite'; import { randomBytes } from 'node:crypto'; if (process.config.variables.node_use_quic !== false) throw new Error('QUIC must remain disabled'); const db = new DatabaseSync(':memory:'); db.exec('CREATE TABLE smoke (id INTEGER)'); db.close(); if (randomBytes(32).length !== 32) process.exit(1);" \
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
