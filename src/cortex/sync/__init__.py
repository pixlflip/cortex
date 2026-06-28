"""Sync adapters (build step 11, opt-in).

The default is ``none`` (local-only). Opt-in adapters propagate the vault to/from
a source of truth: git (a remote that is both sync and audit), nextcloud/WebDAV,
or s3. Git internals (.git/) are never propagated to a file-sync backend.
"""
