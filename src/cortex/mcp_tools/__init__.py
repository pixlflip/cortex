"""MCP tool registration for :class:`cortex.server.CortexServer`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .read_tools import register_read_tools
from .write_tools import register_write_tools

if TYPE_CHECKING:
    from ..server import CortexServer

__all__ = ["register_tools", "register_read_tools", "register_write_tools"]


def register_tools(server: CortexServer) -> None:
    register_read_tools(server)
    register_write_tools(server)
