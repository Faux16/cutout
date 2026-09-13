"""orchestrator agent service (retrieves from corpus, calls tool servers over HTTP)."""

from __future__ import annotations

from cutout_range.service.apps import orchestrator_app
from cutout_range.service.config import settings

app = orchestrator_app(settings)
