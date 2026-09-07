# Report-only memory lifecycle janitor

The janitor scans eligible Markdown notes and writes only a structured report to
Cortex's database. It never edits, rewrites, normalizes, or deletes vault files.
A caller can verify this by snapshotting bytes, including line endings.

For valid YAML frontmatter it reports:

- missing `memory_state` as an explicit unreviewed review item; it never infers a
  state from project status or file timestamps;
- values outside `unreviewed`, `draft`, `current`, `superseded`, and `disputed`;
- `superseded` notes without a scalar, same-vault, existing
  `memory_superseded_by` note;
- self references, replacement cycles, and a missing/inconsistent replacement
  backlink. A replacement may point back with `memory_supersedes` or
  `memory_superseded_from`;
- `disputed` notes as review-needed.

Malformed YAML is reported as frontmatter trouble and is not interpreted as
lifecycle metadata. Malformed or unhashable state values do not crash a scan.
Findings retain the existing `JanitorFinding(path, kind, detail)` contract.

The optional `cortex.janitor.suggestions.review_lifecycle(provider, notes, *,
max_notes=32, max_bytes=120000, max_tokens=800)` helper accepts only an explicit
mapping of note paths to text and an existing `LLMProvider`. It returns
`LifecycleReview(suggestions, error)`, where suggestions are
`LifecycleSuggestion(path, state, reason)`. It has no scheduler or filesystem
access, enforces the supplied bounds, requires strict JSON, allows only selected
paths and lifecycle states, and treats model output as untrusted. It never
applies suggestions or includes note body text in report persistence.
