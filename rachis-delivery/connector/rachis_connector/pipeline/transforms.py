"""
rachis_connector.pipeline.transforms
=====================================

The published standard transform library (thesis §9.2). A mapping may only name these
functions with declared arguments; it cannot supply arbitrary code. This is the constraint
that keeps mappings declarative, auditable by non-programmers, and reusable across every
organisation running the same source product (thesis §8.6, §9.2).

Adding a transform is a change to the *standard library*, reviewed once and available to
all — never an escape hatch in an individual mapping. If a source needs a transformation
not expressible here, the correct response is to propose it for the library, not to embed
logic in a mapping (thesis §9.2).

Each transform is a factory: it takes the declared arguments and returns a function of one
value. Unknown values pass through as None so that `on_unmapped` handling in the mapping can
decide what to do.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

TransformFn = Callable[[object], object]


def _trim() -> TransformFn:
    return lambda v: v.strip() if isinstance(v, str) else v


def _upper() -> TransformFn:
    return lambda v: v.upper() if isinstance(v, str) else v


def _lower() -> TransformFn:
    return lambda v: v.lower() if isinstance(v, str) else v


def _prefix(arg: str) -> TransformFn:
    return lambda v: f"{arg}{v}" if v is not None else None


def _suffix(arg: str) -> TransformFn:
    return lambda v: f"{v}{arg}" if v is not None else None


def _split(sep: str) -> TransformFn:
    return lambda v: [p.strip() for p in v.split(sep) if p.strip()] \
        if isinstance(v, str) else v


def _codelist(table: Dict[str, str]) -> TransformFn:
    """Map source codes to target codes. Unmapped -> None, so on_unmapped can act."""
    return lambda v: table.get(v) if v is not None else None


def _to_int() -> TransformFn:
    def fn(v):
        if v is None:
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None
    return fn


def _to_float() -> TransformFn:
    def fn(v):
        if v is None:
            return None
        try:
            return float(v)
        except (ValueError, TypeError):
            return None
    return fn


def _default(arg: str) -> TransformFn:
    return lambda v: v if v not in (None, "") else arg


# name -> (factory, {required arg keys})
_REGISTRY: Dict[str, tuple] = {
    "trim": (lambda **k: _trim(), set()),
    "upper": (lambda **k: _upper(), set()),
    "lower": (lambda **k: _lower(), set()),
    "prefix": (lambda **k: _prefix(k["arg"]), {"arg"}),
    "suffix": (lambda **k: _suffix(k["arg"]), {"arg"}),
    "split": (lambda **k: _split(k["arg"]), {"arg"}),
    "codelist": (lambda **k: _codelist(k["table"]), {"table"}),
    "to_int": (lambda **k: _to_int(), set()),
    "to_float": (lambda **k: _to_float(), set()),
    "default": (lambda **k: _default(k["arg"]), {"arg"}),
}


def build_transform(spec: dict) -> TransformFn:
    """Build one transform from a mapping spec like {"fn": "prefix", "arg": "IMO"}.

    Raises on an unknown function or missing argument — a malformed mapping fails at load,
    not at first record.
    """
    fn_name = spec.get("fn")
    if fn_name not in _REGISTRY:
        raise ValueError(f"unknown transform: {fn_name!r} (not in the standard library)")
    factory, required = _REGISTRY[fn_name]
    args = {k: v for k, v in spec.items() if k != "fn"}
    missing = required - set(args)
    if missing:
        raise ValueError(f"transform {fn_name!r} missing argument(s): {sorted(missing)}")
    return factory(**args)


def build_chain(specs: List[dict]) -> List[TransformFn]:
    return [build_transform(s) for s in specs]


def known_transforms() -> List[str]:
    return sorted(_REGISTRY)
