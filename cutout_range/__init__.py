"""cutout-range — a deliberately-vulnerable, in-process multi-agent stack.

This is the bundled target the framework attacks (the ``/range`` from PROJECT_PLAN.md,
named ``cutout_range`` so it doesn't shadow Python's builtin ``range``). It runs fully
in-process against the deterministic mock brain — no docker, no network, no accounts —
so the whole attack chain is demonstrable at a kiosk in minutes.

The stack is INTENTIONALLY insecure. Its vulnerabilities each map to a technique ID:

* No trust boundary between retrieved data and instructions  -> CUT-INJ-002 / CUT-EXEC-001
* Unauthenticated writes to the RAG corpus                    -> CUT-INJ-002 / CUT-PERS-001
* An implant craftable to be retrieved by any future query    -> CUT-PERS-001
* The agent's delegated token used on the attacker's behalf    -> CUT-EXEC-001 (confused deputy)

See ETHICS.md. Do not deploy any part of this package.
"""

from __future__ import annotations

from .agent import Orchestrator, OrchestratorResult
from .chat_target import ChatReply, ChatTarget, MockChatAgent
from .corpus import Document, RagCorpus
from .guardrail import (
    Guardrail,
    GuardrailVerdict,
    default_guardrail,
    normalize,
    to_base64_marker,
    to_homoglyph,
    to_zero_width,
)
from .hosts import HostInfo
from .mcp_target import McpTarget
from .range import Range, connect_range, get_range, reset_ranges
from .tool_servers import ToolResult, ToolServer, ToolSpec

__all__ = [
    "ChatReply",
    "ChatTarget",
    "Document",
    "Guardrail",
    "GuardrailVerdict",
    "HostInfo",
    "McpTarget",
    "MockChatAgent",
    "Orchestrator",
    "OrchestratorResult",
    "RagCorpus",
    "Range",
    "ToolResult",
    "ToolServer",
    "ToolSpec",
    "connect_range",
    "default_guardrail",
    "get_range",
    "normalize",
    "reset_ranges",
    "to_base64_marker",
    "to_homoglyph",
    "to_zero_width",
]
