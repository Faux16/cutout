"""Cutout engine: session, evidence, module contract, registry, and run loop."""

from __future__ import annotations

from .catalog import CatalogEntry, load_catalog
from .engine import Engine
from .errors import (
    CheckMutationError,
    CutoutError,
    DuplicateModuleError,
    ModuleNotRegisteredError,
    OptionError,
)
from .evidence import EvidenceEvent, EvidenceWriter, Phase, read_events
from .module import BaseModule, Module, ModuleSpec, Option
from .provider import MockProvider, Provider
from .registry import (
    get_module,
    get_registry,
    register,
    unregister,
    validate_options,
)
from .session import (
    CheckResult,
    ModuleResult,
    RunResult,
    Session,
    TargetDescriptor,
)

__all__ = [
    "BaseModule",
    "CatalogEntry",
    "CheckMutationError",
    "CheckResult",
    "CutoutError",
    "DuplicateModuleError",
    "Engine",
    "EvidenceEvent",
    "EvidenceWriter",
    "MockProvider",
    "Module",
    "ModuleNotRegisteredError",
    "ModuleResult",
    "ModuleSpec",
    "Option",
    "OptionError",
    "Phase",
    "Provider",
    "RunResult",
    "Session",
    "TargetDescriptor",
    "get_module",
    "get_registry",
    "load_catalog",
    "read_events",
    "register",
    "unregister",
    "validate_options",
]
