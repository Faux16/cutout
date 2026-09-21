"""directory tool service (MCP + an out-of-band description-poison control).

The MCP tool ``lookup_employee`` is benign, but its advertised description is poisonable via
``/tooldesc/poison`` — the agent reads the description as guidance and obeys any directive in
it (CUT-INJ-006). A ``persistent`` poison survives ``/tooldesc/reconnect`` (CUT-PERS-004).
"""

from __future__ import annotations

from cutout_range.service.mcp_servers import directory_app

app = directory_app()
