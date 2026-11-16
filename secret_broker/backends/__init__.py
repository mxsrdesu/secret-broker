from __future__ import annotations

import inspect
import types
import typing

from .base import Backend


def _backend_class(name: str) -> type[Backend]:
    if name == "agefile":
        from .agefile import AgeFileBackend

        return AgeFileBackend
    if name == "bws":
        from .bws import BwsBackend

        return BwsBackend
    raise ValueError(f"unknown backend {name!r} (expected 'agefile' or 'bws')")


def check_backend(name: str, options: dict) -> None:
    """Raise ValueError naming the missing or unknown keys of [backends.NAME]; touches nothing on disk."""
    params = dict(inspect.signature(_backend_class(name).__init__).parameters)
    params.pop("self")
    unknown = sorted(set(options) - set(params))
    if unknown:
        raise ValueError(f"[backends.{name}] has unknown key(s): {', '.join(unknown)}; known: {', '.join(params)}")
    missing = [k for k, p in params.items() if p.default is inspect.Parameter.empty and k not in options]
    if missing:
        raise ValueError(f"[backends.{name}] needs {', '.join(missing)}")
    hints = typing.get_type_hints(_backend_class(name).__init__)
    for key, value in options.items():
        hint = hints.get(key)
        kinds = [t for t in (typing.get_args(hint) if isinstance(hint, types.UnionType) else (hint,)) if t in (str, int)]
        if kinds and (isinstance(value, bool) or not isinstance(value, tuple(kinds))):
            what = " or ".join({str: "a string", int: "a whole number"}[t] for t in kinds)
            raise ValueError(f"[backends.{name}] {key} must be {what}")


def make_backend(name: str, options: dict) -> Backend:
    check_backend(name, options)
    return _backend_class(name)(**options)
