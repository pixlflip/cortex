# v2 release checklist

- [ ] Set matching versions in `pyproject.toml` and `src/cortex/__init__.py`;
  update `CHANGELOG.md`.
- [ ] Run `python -m pytest -q` on Python 3.11–3.13.
- [ ] Build the wheel and verify no web assets or gateway/proxy module are included.
- [ ] Verify `/` and old UI/static/admin routes return 404; health, API, MCP,
  and optional OAuth authorization remain functional.
- [ ] Build the Docker image and run `scripts/smoke-v2.sh cortex:<tag>`.
- [ ] Test an existing DB snapshot upgrade; verify accounts, existing tokens,
  audit and inert upstream records survive. No destructive migration.
- [ ] Test fresh Compose setup, CLI local user creation, private vault,
  group memory policy, token issuance, and authenticated memory-only MCP discovery.
- [ ] Test LDAP dry-run/apply against the supported directory fixture.
- [ ] Test old broker calls fail and REST routes return 404 without outbound
  activity. Test deny-wins memory calls for old gateway.enabled true AND false;
  inspect audit rows for argument values or secrets.
- [ ] Parent/operator: verify direct consumer coverage before cutover, take
  runtime backups, publish/deploy, run real MCP tests, and verify external
  Nextcloud sync. See [retirement requirements](memory-policy.md).
- [ ] Take/restore a backup containing DB plus all vault `.git` directories.
- [ ] Review [`security-review-v2.md`](security-review-v2.md), publish image and
  Python artifacts, tag the commit, and monitor migration/support reports.

