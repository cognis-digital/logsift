"""LOGSIFT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from logsift.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-logsift[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-logsift[mcp]'")
        return 1
    app = FastMCP("logsift")

    @app.tool()
    def logsift_scan(target: str) -> str:
        """Detect brute-force, spray, and anomalous auth events in logs. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
