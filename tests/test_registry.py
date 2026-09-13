"""Registry discovery and option validation."""

from __future__ import annotations

import pytest
from cutout.engine import (
    ModuleNotRegisteredError,
    Option,
    OptionError,
    get_module,
    get_registry,
    validate_options,
)


def test_stub_is_discovered() -> None:
    registry = get_registry()
    assert "CUT-INV-001" in registry
    module = get_module("CUT-INV-001")
    assert module.name == "Session Inventory"
    assert module.tactic == "inventory"


def test_unknown_module_raises() -> None:
    with pytest.raises(ModuleNotRegisteredError):
        get_module("CUT-DOES-NOT-EXIST")


def test_missing_required_option_raises() -> None:
    options = {"host": Option(required=True, type="str")}
    with pytest.raises(OptionError, match="required option 'host'"):
        validate_options(options, {})


def test_unknown_option_raises() -> None:
    options = {"host": Option(type="str")}
    with pytest.raises(OptionError, match="unknown option"):
        validate_options(options, {"bogus": "1"})


def test_option_type_coercion() -> None:
    options = {
        "port": Option(type="int", default=8080),
        "ratio": Option(type="float", default=1.0),
        "verbose": Option(type="bool", default=False),
        "name": Option(type="str", default="x"),
    }
    resolved = validate_options(options, {"port": "9090", "ratio": "0.5", "verbose": "yes"})
    assert resolved == {"port": 9090, "ratio": 0.5, "verbose": True, "name": "x"}


def test_bad_int_coercion_raises() -> None:
    with pytest.raises(OptionError, match="as int"):
        validate_options({"port": Option(type="int")}, {"port": "abc"})
