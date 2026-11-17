# Cortex — dynamic memory layer over MCP.
#
# The image bundles the same `cortex` CLI used on bare metal, so there is one
# code path everywhere. Provide a config and data directory at runtime:
#
#   docker build -t cortex .
#   docker run --rm -it \
#     -v "$PWD/data:/data/data" \
#     -v "$PWD/cortex.yaml:/data/cortex.yaml:ro" \
#     cortex check
#
# The default command serves whatever transport cortex.yaml selects. For the
# usual headless HTTP deployment, publish 8765 behind a TLS-terminating proxy
# (docs/http-exposure.md). For a local stdio MCP client, run with `-i` and no
# TTY (see the `stdio` profile in docker-compose.yml).

# Pinned by digest for reproducible builds; Dependabot proposes updates.
FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git is required for the audit layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install hash-locked runtime dependencies first so this layer caches across
# source-only changes. Regenerate the lock with scripts/lock.sh (see
# requirements/README.md).
COPY requirements/runtime.txt ./requirements/runtime.txt
RUN pip install --no-cache-dir --require-hashes -r requirements/runtime.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

# Optional provider extras: build with --build-arg EXTRAS=openai etc. These are
# resolved at build time and are not covered by the runtime lock.
ARG EXTRAS=""
RUN if [ -n "$EXTRAS" ]; then pip install --no-cache-dir ".[$EXTRAS]"; fi

# Non-root runtime user owning the data dir.
RUN useradd --system --create-home --home-dir /data cortex \
    && mkdir -p /data/data/vaults /data/data/indexes /data/data/archive \
    && chown -R cortex:cortex /data
USER cortex
WORKDIR /data

ENV CORTEX_CONFIG=/data/cortex.yaml \
    GIT_AUTHOR_NAME=cortex \
    GIT_COMMITTER_NAME=cortex

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3)" || exit 1

LABEL org.opencontainers.image.title="Cortex" \
      org.opencontainers.image.description="A governed Obsidian-vault memory layer for AI agents, served over MCP." \
      org.opencontainers.image.source="https://github.com/pixlflip/cortex" \
      org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["cortex"]
CMD ["serve"]
