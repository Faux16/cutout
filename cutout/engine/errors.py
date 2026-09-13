"""Engine exception hierarchy."""

from __future__ import annotations


class CutoutError(Exception):
    """Base class for all engine errors."""


class ModuleNotRegisteredError(CutoutError):
    """Raised when a requested technique ID has no registered module.

    Deliberately not named ``ModuleNotFoundError``: that is a Python builtin, and
    shadowing it breaks ``except ModuleNotFoundError`` anywhere this module is imported.
    """


class DuplicateModuleError(CutoutError):
    """Raised when two modules register the same technique ID."""


class OptionError(CutoutError):
    """Raised when a module is invoked with missing/unknown/uncoercible options."""


class CheckMutationError(CutoutError):
    """Raised when a module's check() mutates session state.

    check() is contractually read-only; the engine snapshots the session before and
    after and raises this if the two differ.
    """
