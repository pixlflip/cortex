# v2 release checklist

- [ ] Set matching versions in `pyproject.toml`, `src/cortex/__init__.py`, and
  `web/package.json`; update `CHANGELOG.md`.
- [ ] Run `python -m pytest -q` on Python 3.11–3.13.
- [ ] Run `npm ci`, lint, production build, and `npm audit --audit-level=high`.
- [ ] Build the wheel and verify `cortex/web_dist/index.html` is included.
- [ ] Build the Docker image and run `scripts/smoke-v2.sh cortex:<tag>`.
- [ ] Test a v1 snapshot with `cortex migrate` twice and verify the second run
  is a no-op; confirm the legacy main vault and client tokens still work.
- [ ] Test fresh Compose setup, admin login, local user creation, private vault,
  group shared scope, token issuance, and authenticated MCP discovery.
- [ ] Test LDAP dry-run/apply against the supported directory fixture.
- [ ] Test upstream MCP allow/deny/outage paths and inspect audit rows for
  argument values or secrets.
- [ ] Take/restore a backup containing DB plus all vault `.git` directories.
- [ ] Review [`security-review-v2.md`](security-review-v2.md), publish image and
  Python artifacts, tag the commit, and monitor migration/support reports.

