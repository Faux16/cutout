"""rag-corpus service (poisonable, unauthenticated writes)."""

from __future__ import annotations

from cutout_range.service.apps import corpus_app
from cutout_range.service.config import settings

app = corpus_app(settings.state_dir)
