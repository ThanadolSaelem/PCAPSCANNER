"""Read-only MCP server re-exports for agent integrations."""
from __future__ import annotations

from ..mcp_server import (
    READ_ONLY_MCP_TOOLS,
    ReadOnlyMCPServer,
    decode_signed_cursor,
    encode_signed_cursor,
)

MCPServer = ReadOnlyMCPServer

__all__ = [
    "MCPServer",
    "READ_ONLY_MCP_TOOLS",
    "ReadOnlyMCPServer",
    "decode_signed_cursor",
    "encode_signed_cursor",
]
