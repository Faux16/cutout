"""Built-in modules. Each subpackage groups modules by tactic.

The registry discovers everything under this package by walking it at load time, so a
new module is registered simply by defining a ``@register``-decorated class in a module
placed anywhere beneath ``cutout.modules``.
"""
