# Release checklist

CI already runs lint, mypy, the dependency audit, the test matrix with
coverage floors, the end-to-end MCP tests and the image smoke test on every
push. This list covers what CI cannot.

## Before tagging

- [ ] CI is green on the release commit.
- [ ] `version` in `pyproject.toml` and `__version__` in
  `src/cortex/__init__.py` match the tag (the release workflow rejects a
  mismatch).
- [ ] `CHANGELOG.md`: move "Unreleased" under the new version heading and date
  it. Call out breaking changes and link [upgrading](upgrading.md).
- [ ] [`upgrading.md`](upgrading.md) covers every breaking change, with steps
  and rollback.
- [ ] `scripts/lock.sh` produces no diff, and `pip-audit` is clean (CI's
  `audit` job).
- [ ] Upgrade test: start the previous release on a copy of a real (or
  representative) database and vaults, upgrade, run `cortex migrate`, and
  confirm accounts, tokens, grants and audit rows survive and existing tokens
  still work. Confirm the documented rollback path.
- [ ] Fresh install test with Docker Compose: `check`, `init`, `user add`,
  `token mint`, then connect a real MCP client over HTTP and over the `stdio`
  profile.
- [ ] If LDAP changed: run a dry-run and an apply sync against a test directory.
- [ ] If semantic search changed: run `cortex check` and
  `cortex index --embeddings` against a real local embedding model.
- [ ] Take and restore a backup containing the database plus every vault
  including `.git`.

## Tag and publish

- [ ] Tag `vX.Y.Z` on the release commit and push the tag. The
  [release workflow](../.github/workflows/release.yml) smoke-tests and pushes
  `ghcr.io/<owner>/cortex:X.Y.Z`, `:X.Y` and `:latest` with provenance and an
  SBOM.
- [ ] Create a GitHub release from the changelog section.
- [ ] Pull the published image and run `scripts/smoke-v2.sh ghcr.io/<owner>/cortex:X.Y.Z`.

## After

- [ ] Watch issues for upgrade reports for a week.
- [ ] Merge any Dependabot base-image or dependency PRs that queued up.
