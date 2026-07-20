"""Focused conversion of Cortex values into JSON-compatible structures."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from typing import Any


def normalize_json(value: Any) -> Any:
    """Return a JSON-safe copy of nested date-bearing data.

    Only the types Cortex expects YAML to produce are converted. Unsupported
    objects remain unsupported so the JSON encoder still reports them rather
    than silently stringifying programming errors.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {key: normalize_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_json(item) for item in value]
    return value
