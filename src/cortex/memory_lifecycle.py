"""Validated YAML lifecycle metadata; note bodies remain opaque bytes."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import inspect
from pathlib import Path
import re
import threading
from typing import Any, Literal

import yaml

MemoryState = Literal['unreviewed', 'draft', 'current', 'superseded', 'disputed']
STATES = ('unreviewed', 'draft', 'current', 'superseded', 'disputed')
MANAGED = frozenset({'memory_state', 'memory_state_changed_at', 'memory_state_changed_by',
                     'memory_state_reason', 'memory_superseded_by', 'memory_supersedes'})
_OPENING = re.compile(rb'\A---[ \t]*(?:\r\n|\n|\r)')
_CLOSE = re.compile(rb'(?m)^---[ \t]*(?:\r\n|\n|\r|\Z)')
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            if key in result:
                raise ValueError('duplicate frontmatter key')
            result[key] = loader.construct_object(value_node, deep=deep)
        except TypeError as exc:
            raise ValueError('invalid frontmatter key') from exc
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _parse(raw: bytes) -> tuple[dict, bytes, bytes | None, bytes]:
    opening = _OPENING.match(raw)
    if not opening:
        if raw == b'---':
            raise ValueError('unclosed leading frontmatter')
        return {}, raw, None, b''
    # splitlines(keepends=True) preserves CRLF, whitespace, and empty bodies.
    pos = opening.end()
    end = pos
    for line in raw[pos:].splitlines(keepends=True):
        if re.fullmatch(rb'---[ \t]*(?:\r\n|\n|\r)?', line):
            try:
                data = yaml.load(raw[pos:end].decode('utf-8'), Loader=_UniqueLoader)
            except (UnicodeDecodeError, yaml.YAMLError) as exc:
                raise ValueError('malformed leading frontmatter') from exc
            if data is None:
                data = {}
            if not isinstance(data, dict):
                raise ValueError('leading frontmatter must be a mapping')
            boundary = end + len(line)
            nl = b'\r\n' if opening.group().endswith(b'\r\n') else b'\n'
            return data, raw[boundary:], nl, raw[:boundary]
        end += len(line)
    raise ValueError('malformed or unclosed leading frontmatter')


def inspect_memory(frontmatter: dict) -> dict:
    if not isinstance(frontmatter, dict):
        return {'state': 'unreviewed', 'warnings': ['frontmatter is not a mapping']}
    if 'memory_state' not in frontmatter:
        return {'state': 'unreviewed', 'warnings': []}
    value = frontmatter['memory_state']
    if not isinstance(value, str) or value not in STATES:
        return {'state': 'unreviewed', 'warnings': ['invalid memory_state']}
    return {'state': value, 'warnings': []}


def inspect_memory_bytes(raw: bytes) -> dict:
    try:
        fm, _ = parse_memory_bytes(raw)
        return inspect_memory(fm)
    except ValueError:
        return {'state': 'unreviewed', 'warnings': ['invalid frontmatter']}


def validate_memory_state(value: Any) -> str:
    if not isinstance(value, str) or value not in STATES:
        raise ValueError('invalid memory_state; expected one of ' + ', '.join(STATES))
    return value


def update_metadata_bytes(raw: bytes, patch: dict) -> bytes:
    if not isinstance(patch, dict):
        raise ValueError('metadata patch must be a mapping')
    data, body, nl, _ = _parse(raw)
    data.update(patch)
    if 'memory_state' in data:
        validate_memory_state(data['memory_state'])
    nl = nl or b'\n'
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True).rstrip('\n').encode('utf-8')
    if nl != b'\n':
        text = text.replace(b'\n', nl)
    return b'---' + nl + text + nl + b'---' + nl + body


def memory_patch(state: str, *, actor: str, reason: str) -> dict:
    validate_memory_state(state)
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError('reason must contain 1-2000 characters')
    return {'memory_state': state,
            'memory_state_changed_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'memory_state_changed_by': actor, 'memory_state_reason': reason}


def parse_memory_bytes(raw: bytes) -> tuple[dict, bytes]:
    data, body, _nl, _fm = _parse(raw)
    return data, body


@contextmanager
def vault_write_lock(root: Path):
    """Coordinate Cortex writers in this process and, on Unix, other processes.

    External editors/sync do not participate; revision hashes detect prior edits.
    This is coordination, not a filesystem transaction or crash-recovery journal.
    """
    key = str(root.resolve())
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(key, threading.RLock())
    with lock:
        # Vault parents need not be writable; do not dirty the Git worktree.
        lock_dir = root / '.git' if (root / '.git').is_dir() else root
        lockpath = lock_dir / '.cortex-write.lock'
        with lockpath.open('a+b') as handle:
            try:
                import fcntl
            except ImportError:
                fcntl = None
            if fcntl:
                fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl:
                    fcntl.flock(handle, fcntl.LOCK_UN)


def serialized_write(method):
    signature = inspect.signature(method)
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        bound = signature.bind(self, *args, **kwargs)
        bundle = bound.arguments.get('bundle')
        store = bundle.store if bundle is not None else self.vault
        with vault_write_lock(store.root):
            return method(self, *args, **kwargs)
    return wrapped
