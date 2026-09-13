"""Service configuration from environment, with localhost defaults.

Two URL sets:

* *internal* — how the orchestrator reaches its peers (service DNS under docker).
* *advertised* — what ``/topology`` hands a client (must be reachable from where the
  attacker runs; under docker these are the host-published ``127.0.0.1`` ports). Each
  advertised URL defaults to its internal counterpart, so local uvicorn needs no extra env.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cutout_range.range import BILLING_TOKEN, DELEGATED_TOKEN


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    token: str = field(default_factory=lambda: _env("CUTOUT_RANGE_TOKEN", DELEGATED_TOKEN))
    billing_token: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_BILLING_TOKEN", BILLING_TOKEN)
    )

    # Internal (orchestrator -> peers).
    customer_data_url: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_CUSTOMER_DATA_URL", "http://127.0.0.1:8611")
    )
    fs_tools_url: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_FS_TOOLS_URL", "http://127.0.0.1:8612")
    )
    external_fetch_url: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_EXTERNAL_FETCH_URL", "http://127.0.0.1:8613")
    )
    rag_corpus_url: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_RAG_CORPUS_URL", "http://127.0.0.1:8614")
    )
    payments_url: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_PAYMENTS_URL", "http://127.0.0.1:8615")
    )
    billing_agent_url: str = field(
        default_factory=lambda: _env("CUTOUT_RANGE_BILLING_AGENT_URL", "http://127.0.0.1:8616")
    )
    state_dir: str | None = field(
        default_factory=lambda: os.environ.get("CUTOUT_RANGE_STATE_DIR") or None
    )

    @property
    def servers(self) -> dict[str, str]:
        """Internal tool-server id -> base URL (the corpus is a separate service)."""
        return {
            "customer-data": self.customer_data_url,
            "fs-tools": self.fs_tools_url,
            "external-fetch": self.external_fetch_url,
        }

    # Advertised (what /topology hands a client); default to internal.
    @property
    def advertised_servers(self) -> dict[str, str]:
        return {
            "customer-data": _env(
                "CUTOUT_RANGE_ADVERTISE_CUSTOMER_DATA_URL", self.customer_data_url
            ),
            "fs-tools": _env("CUTOUT_RANGE_ADVERTISE_FS_TOOLS_URL", self.fs_tools_url),
            "external-fetch": _env(
                "CUTOUT_RANGE_ADVERTISE_EXTERNAL_FETCH_URL", self.external_fetch_url
            ),
        }

    @property
    def advertised_corpus_url(self) -> str:
        return _env("CUTOUT_RANGE_ADVERTISE_RAG_CORPUS_URL", self.rag_corpus_url)

    @property
    def advertised_agents(self) -> dict[str, str]:
        """A2A peer agents a client can reach (host ports under docker)."""
        return {
            "billing-agent": _env(
                "CUTOUT_RANGE_ADVERTISE_BILLING_AGENT_URL", self.billing_agent_url
            )
        }


settings = Settings()
