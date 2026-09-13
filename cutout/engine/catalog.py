"""Read the repo's technique catalog and cross-reference it with the registry.

The catalog is a lightweight YAML index of technique IDs the framework intends to
cover. ``cutout catalog`` reads it and shows which entries have a registered module and
which are still planned. (The canonical, richer taxonomy lives in
``taxonomy/matrix.yaml``; this catalog is the engine-facing coverage index.)
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .registry import get_registry


class CatalogEntry(BaseModel):
    """One planned technique and whether a module implements it."""

    id: str
    name: str = ""
    tactic: str = ""
    targets: list[str] = Field(default_factory=list)
    implemented: bool = False


def _default_catalog_path() -> Path:
    # Repo root is two levels up from this file: cutout/engine/catalog.py -> repo/.
    return Path(__file__).resolve().parents[2] / "catalog.yaml"


def load_catalog(path: str | Path | None = None) -> list[CatalogEntry]:
    """Load catalog entries and flag each as implemented per the live registry."""

    catalog_path = Path(path) if path is not None else _default_catalog_path()
    raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    entries = raw.get("techniques", [])
    registered = set(get_registry())

    result: list[CatalogEntry] = []
    for item in entries:
        result.append(
            CatalogEntry(
                id=item["id"],
                name=item.get("name", ""),
                tactic=item.get("tactic", ""),
                targets=list(item.get("targets", [])),
                implemented=item["id"] in registered,
            )
        )
    return result
