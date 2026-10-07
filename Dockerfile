# The self-hosted Miblo relay (Node runtime). Reproducible: the base image is pinned by digest,
# dependencies come from package-lock.json (npm ci), and the build writes dist/HASHES.txt (the
# SHA-256 of every file served and of the server bundle) so you can compare yours with a release's.
#
#   docker build -t miblo-relay .
#   docker run -p 8787:8787 -v miblo-relay:/data -e PUBLIC_ORIGIN=https://relay.example.com -e TRUSTED_PROXY=1 miblo-relay
#
# Put it behind a TLS reverse proxy (deploy/docker/docker-compose.yml runs Caddy in front of it).

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json vitest.config.mts ./
COPY app ./app
COPY server ./server
COPY scripts ./scripts
COPY migrations ./migrations
RUN npm run build && node scripts/hashes.mjs > dist/HASHES.txt

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
ENV NODE_ENV=production \
    MIBLO_RELAY_DATA=/data \
    PORT=8787 \
    HOST=0.0.0.0
WORKDIR /app
COPY --from=build /src/dist ./dist
COPY --from=build /src/migrations ./migrations
COPY LICENSE ./
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8787/.well-known/miblo-relay.json >/dev/null || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "dist/server.mjs"]
