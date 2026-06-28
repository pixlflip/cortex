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

FROM python:3.11-slim AS base

# git is required for the audit layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Optional provider extras: build with --build-arg EXTRAS=openai etc.
ARG EXTRAS=""
RUN if [ -n "$EXTRAS" ]; then pip install --no-cache-dir ".[$EXTRAS]"; fi

# Non-root runtime user owning the data dir.
RUN useradd --system --create-home --home-dir /data cortex \
    && mkdir -p /data/vault \
    && chown -R cortex:cortex /data
USER cortex
WORKDIR /data

ENV CORTEX_CONFIG=/data/cortex.yaml \
    GIT_AUTHOR_NAME=cortex \
    GIT_COMMITTER_NAME=cortex

ENTRYPOINT ["cortex"]
CMD ["serve"]
