#!/usr/bin/env python3
"""Deterministic harmless stdio MCP used only by gateway lifecycle tests."""

import atexit
import os
import sys
import time
from mcp.server.fastmcp import FastMCP

marker = os.environ.get("FIXTURE_MARKER")
if marker:
    with open(marker, "a", encoding="utf-8") as stream:
        stream.write(f"start:{os.getpid()}\n")
    atexit.register(
        lambda: open(marker, "a", encoding="utf-8").write(f"stop:{os.getpid()}\n")
    )

mcp = FastMCP("cortex-stdio-fixture")


@mcp.tool()
def echo(value: str) -> str:
    return value


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


@mcp.tool()
def fail() -> str:
    raise RuntimeError("fixture failure")


@mcp.tool()
def sleep(seconds: float) -> str:
    time.sleep(seconds)
    return "awake"


@mcp.tool()
def environment(name: str) -> str:
    return os.environ.get(name, "<unset>")


@mcp.tool()
def startup_args() -> list[str]:
    return sys.argv[1:]


if __name__ == "__main__":
    mcp.run(transport="stdio")
