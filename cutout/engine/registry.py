"""Module discovery, registration, and option validation.

Modules register two ways:

* the :func:`register` decorator, applied to a :class:`BaseModule` subclass; and
* Python entry points in the ``cutout.modules`` group (the out-of-tree path).

In-tree modules under ``cutout.modules`` are found by walking the package. Both paths
funnel through :func:`register`, which is idempotent per technique ID.
"""

from __future__ import annotations

import importlib
import pkgutil
from importlib import metadata
from typing import Any, TypeVar

from .errors import DuplicateModuleError, ModuleNotRegisteredError, OptionError
from .module import BaseModule, Option

_REGISTRY: dict[str, type[BaseModule]] = {}
_LOADED = False

T = TypeVar("T", bound=type[BaseModule])

_COERCERS: dict[str, Any] = {
    "str": str,
    "int": int,
    "float": float,
}


def register(module_cls: T) -> T:
    """Class decorator: add a module to the global registry, keyed by its ID."""

    module_id = getattr(module_cls, "id", "")
    if not module_id:
        raise OptionError(f"{module_cls.__name__} must define a non-empty 'id'")
    existing = _REGISTRY.get(module_id)
    if existing is not None and existing is not module_cls:
        raise DuplicateModuleError(
            f"technique ID '{module_id}' is already registered to {existing.__name__}"
        )
    _REGISTRY[module_id] = module_cls
    return module_cls


# Built-in module namespaces. The six layers mirror CLAUDE.md's architecture; `modules`
# holds cross-cutting/plumbing modules (e.g. the inventory reference stub).
_BUILTIN_PACKAGES = (
    "cutout.recon",
    "cutout.delivery",
    "cutout.payloads",
    "cutout.persistence",
    "cutout.lateral",
    "cutout.evidence",
    "cutout.modules",
)


def _load_builtin_modules() -> None:
    for pkg_name in _BUILTIN_PACKAGES:
        try:
            pkg = importlib.import_module(pkg_name)
        except ModuleNotFoundError:
            continue  # layer not populated yet
        pkg_path = getattr(pkg, "__path__", None)
        if pkg_path is None:
            continue
        for info in pkgutil.walk_packages(pkg_path, prefix=f"{pkg_name}."):
            importlib.import_module(info.name)


def _load_entry_point_modules() -> None:
    for ep in metadata.entry_points(group="cutout.modules"):
        obj = ep.load()
        if isinstance(obj, type) and issubclass(obj, BaseModule):
            register(obj)
        # If the entry point names a module, importing it already fired any
        # @register decorators it contains.


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _load_builtin_modules()
    _load_entry_point_modules()
    _LOADED = True


def unregister(module_id: str) -> None:
    """Testing hook: drop a single module from the registry (e.g. a temp fixture).

    Full clear-and-reload is intentionally not offered: Python caches imported
    modules, so re-running discovery would not re-execute their ``@register``
    decorators and the registry would come back empty.
    """

    _REGISTRY.pop(module_id, None)


def get_registry() -> dict[str, type[BaseModule]]:
    """Return a copy of all registered modules, keyed by technique ID."""

    _ensure_loaded()
    return dict(_REGISTRY)


def get_module(module_id: str) -> type[BaseModule]:
    _ensure_loaded()
    try:
        return _REGISTRY[module_id]
    except KeyError:
        raise ModuleNotRegisteredError(f"no module registered for '{module_id}'") from None


def _coerce(raw: str, option_type: str) -> Any:
    if option_type == "bool":
        lowered = raw.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise OptionError(f"cannot parse '{raw}' as bool")
    coercer = _COERCERS.get(option_type, str)
    try:
        return coercer(raw)
    except (TypeError, ValueError) as exc:
        raise OptionError(f"cannot parse '{raw}' as {option_type}") from exc


def validate_options(options: dict[str, Option], provided: dict[str, str]) -> dict[str, Any]:
    """Resolve user-provided string options against a module's declared options.

    Coerces to declared types, applies defaults, and enforces required options.
    Rejects unknown keys.
    """

    unknown = set(provided) - set(options)
    if unknown:
        raise OptionError(f"unknown option(s): {', '.join(sorted(unknown))}")

    resolved: dict[str, Any] = {}
    for key, spec in options.items():
        if key in provided:
            resolved[key] = _coerce(provided[key], spec.type)
        elif spec.required and spec.default is None:
            raise OptionError(f"required option '{key}' is missing")
        else:
            resolved[key] = spec.default
    return resolved
