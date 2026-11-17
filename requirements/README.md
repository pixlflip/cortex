# Dependency locks

`pyproject.toml` declares Cortex's supported dependency *ranges*. The files in
this directory pin exact versions so CI runs and container builds are
reproducible:

| File | Contents | Used by |
| --- | --- | --- |
| `runtime.txt` | Runtime dependencies, with hashes | `Dockerfile` (`pip install --require-hashes`), CI `pip-audit` |
| `dev.txt` | Runtime plus test, lint and type-check tools | CI, as a pip constraints file |

Both are generated; do not edit them by hand. After changing dependencies in
`pyproject.toml`, or to pick up new releases, run:

```bash
scripts/lock.sh            # re-resolve, keeping existing pins where possible
scripts/lock.sh --upgrade  # move every pin to the newest allowed version
```

Dependabot also proposes lock updates weekly. Optional provider extras
(`anthropic`, `openai`, `ldap`) are not part of the lock; Docker builds that
set `EXTRAS` resolve them at build time.

A plain `pip install .` (as in the bare-metal guide) ignores these files and
resolves within the `pyproject.toml` ranges. To install exactly what CI tests:

```bash
pip install -c requirements/dev.txt -e '.[dev]'
```
