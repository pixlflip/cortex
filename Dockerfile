# Cortex — dynamic memory layer over MCP.
#
# The image bundles the same `cortex` CLI used on bare metal, so there is one
# code path everywhere. Provide a vault and a config at runtime via mounts:
#
#   docker build -t cortex .
#   docker run --rm -it \
#     -v "$PWD/vault:/data/vault" \
#     -v "$PWD/cortex.yaml:/data/cortex.yaml:ro" \
#     -e CORTEX_CONFIG=/data/cortex.yaml \
#     cortex check
#
# For stdio MCP clients, run with `-i` and `cortex serve`. For HTTP transport
# (a later build step), expose the port and run `cortex serve`.

FROM node:22-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN CORTEX_WEB_OUT_DIR=/web/dist npm run build

FROM python:3.11-slim AS base

# git is required for the audit layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY --from=web /web/dist /app/src/cortex/web_dist
RUN pip install --no-cache-dir .

# Optional provider extras: build with --build-arg EXTRAS=openai etc.
ARG EXTRAS=""
RUN if [ -n "$EXTRAS" ]; then pip install --no-cache-dir ".[$EXTRAS]"; fi

# Non-root runtime user owning the data dir.
RUN useradd --system --create-home --home-dir /data cortex \
    && mkdir -p /data/vault /data/data/vaults /data/data/indexes /data/data/archive \
    && chown -R cortex:cortex /data
USER cortex
WORKDIR /data

ENV CORTEX_CONFIG=/data/cortex.yaml \
    CORTEX_WEB_DIST=/app/src/cortex/web_dist \
    GIT_AUTHOR_NAME=cortex \
    GIT_COMMITTER_NAME=cortex

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3)" || exit 1

ENTRYPOINT ["cortex"]
CMD ["serve"]
