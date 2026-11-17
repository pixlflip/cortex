#!/usr/bin/env bash
# Regenerate the dependency locks from pyproject.toml.
#
#   requirements/runtime.txt  hash-locked runtime deps; installed by the Docker
#                             image with --require-hashes and audited in CI.
#   requirements/dev.txt      runtime + dev tools; used as a pip constraints
#                             file in CI so test runs are reproducible.
#
# Requires uv (https://docs.astral.sh/uv/). Pass --upgrade to move every pin to
# the newest version pyproject.toml allows.
set -euo pipefail
cd "$(dirname "$0")/.."

common=(--universal --python-version 3.11 --quiet "$@")
uv pip compile pyproject.toml "${common[@]}" --generate-hashes \
  -o requirements/runtime.txt
uv pip compile pyproject.toml "${common[@]}" --extra dev \
  -o requirements/dev.txt
echo "updated requirements/runtime.txt and requirements/dev.txt"
