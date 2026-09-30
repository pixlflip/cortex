# v2 release checklist

- [ ] Set matching versions in `pyproject.toml` and `src/cortex/__init__.py`;
  update `CHANGELOG.md`.
- [ ] Run `python -m pytest -q` on Python 3.11–3.13.
- [ ] Build the wheel and verify no web assets are included.
- [ ] Verify `/` and old UI/static/admin routes return 404; health, API, MCP,
  and optional OAuth authorization remain functional.
- [ ] Build the Docker image and run `scripts/smoke-v2.sh cortex:<tag>`.
- [ ] Test a v1 snapshot with `cortex migrate` twice and verify the second run
  is a no-op; confirm the legacy main vault and client tokens still work.
- [ ] Test fresh Compose setup, CLI local user creation, private vault,
  group shared scope, token issuance, and authenticated MCP discovery.
- [ ] Test LDAP dry-run/apply against the supported directory fixture.
- [ ] Test upstream MCP allow/deny/outage paths and inspect audit rows for
  argument values or secrets.
- [ ] Take/restore a backup containing DB plus all vault `.git` directories.
- [ ] Review [`security-review-v2.md`](security-review-v2.md), publish image and
  Python artifacts, tag the commit, and monitor migration/support reports.

