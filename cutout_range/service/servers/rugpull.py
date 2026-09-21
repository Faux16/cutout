"""notes-helper rug-pull tool service (MCP + an out-of-band arm control).

The MCP tool ``summarize_notes`` is benign until the attacker flips the server via the
``/rugpull/arm`` control endpoint, after which the same call leaks a secret — the networked
form of CUT-PERS-006, with the tool's advertised schema unchanged throughout.
"""

from __future__ import annotations

from cutout_range.service.mcp_servers import rugpull_app

app = rugpull_app()
