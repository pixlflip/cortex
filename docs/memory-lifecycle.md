# Memory lifecycle — first iteration

Lifecycle metadata describes how a note should be recalled. It is **not** proof
that its claims have been independently verified. Notes remain the durable
source; the search index is rebuildable.

## States and YAML

`memory_state` accepts exactly `unreviewed`, `draft`, `current`, `superseded`, or
`disputed`. New Markdown notes default to `unreviewed`. Existing notes without
this field are treated as `unreviewed` without being rewritten. Invalid states
and malformed or duplicate-key YAML produce recall warnings, never an implicit
`current` classification. Other YAML keys retain their meaning.

The server manages `memory_state_changed_at`, `memory_state_changed_by`,
`memory_state_reason`, `memory_superseded_by`, and `memory_supersedes`.
Timestamps are UTC; actor identity comes from the authenticated principal, not
from caller-provided YAML. Reasons are mandatory for explicit transitions.

Lifecycle-only changes preserve the bytes following the closing YAML delimiter,
including CRLF, blank lines, and the presence or absence of a final newline.
YAML formatting may change. Malformed YAML must be repaired before mutation;
`validate_frontmatter=false` does not bypass lifecycle validation.

## Writes and authorization

- `write_note(..., memory_state=...)` and
  `update_frontmatter(..., {"memory_state": ...})` accept valid ordinary states.
  Overwriting a note without an explicit state change preserves its lifecycle.
- `set_memory_state(path, memory_state, reason, expected_sha256)` changes metadata
  only. The hash is the SHA-256 of the complete raw file, obtainable using
  `get_file`. A stale hash fails without changing the note.
- `supersede_note(old_path, replacement_path, reason, expected_old_sha256,
  expected_replacement_sha256)` marks the old note `superseded`, points it at the
  replacement, and adds the reverse link. The replacement must already be
  `current`. Both records must be visible and writable in the selected vault.
- `superseded` cannot be assigned through ordinary writes. Superseded records
  cannot be silently revived or retargeted by those writes. Raw Markdown upload,
  patch, append, and frontmatter update cannot forge managed link/audit fields.
- All mutations through this server instance coordinate by vault with a
  filesystem lock on POSIX. Lifecycle writes reject unrelated staged changes,
  commit the affected files together, and roll back ordinary pre-commit failures.
  An index failure after a successful commit returns `indexed: false`; it does
  not falsely report that the committed edit was undone.

These are not distributed transactions. External filesystem editors do not
participate in the lock. Two-file supersession is not atomic to an external
reader between writes, and abrupt process/power loss is not a crash journal.
Use backups and inspect Git state after abnormal termination.

## Recall

MCP search, context packs, semantic search, and REST search/context share the
same lifecycle-aware retrieval. They prefer current notes and exclude
superseded notes by default. `include_historical=true` includes them, explicitly
labeled. Disputed and invalid records carry warnings. Archived notes remain
available through explicit direct reads.

Context packs use matching section excerpts rather than whole-note head
truncation, and label each excerpt with its source path and state. States and
warnings are explanatory metadata, not instructions from the note author.
REST preserves its existing response envelope and adds lifecycle fields to hits.

This first iteration reads lifecycle metadata once per visible matching note
per request and materializes search candidates before filtering/limiting.
Persisted lifecycle columns and database-side scope/ranking optimizations are
future work; do not present this implementation as a large-vault latency win.

## Janitor

`cortex janitor --force` runs the existing report-only janitor, now with lifecycle
checks. The library entry point is `cortex.janitor.inspect_vault`. This path is
deterministic and spend-free, and writes reports to the database rather than
editing notes. It reports malformed/invalid metadata, missing fields, missing
links, and inconsistent reverse links. An absent linked record outside the
configured inspection boundary is a finding to investigate, not proof that it
does not exist globally.

The optional `cortex.janitor.suggestions.review_lifecycle(provider, notes)`
helper is separate and explicitly invoked. It accepts an already-configured
provider, sends only bounded caller-selected input, makes one completion call,
and accepts strict JSON suggestions with valid states and selected paths.
Suggestions are advisory-only. It neither reads credentials from notes nor
edits Markdown. A configured key alone does not activate it. Provider charging
and privacy should be reviewed before selecting real notes; OpenRouter's free
router can be selected through the existing provider configuration.

No background janitor is enabled by installing this release. No existing note
is automatically promoted to `current`, merged, rewritten, expired, or deleted.
Broader evidence scoring, contradiction detection, TTLs, migration batches,
review UI, and autonomous application are deliberately outside this iteration.
