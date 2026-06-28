"""Janitor — asynchronous maintenance mind (build step 12, dark by default).

Heartbeat-driven, low-power worker that tidies/validates the vault and watches
for drift. Bounded: it can never edit scopes, principals, credentials, or its
own ruleset. Ships disabled; dry-run/report-only before any write mode.
"""
