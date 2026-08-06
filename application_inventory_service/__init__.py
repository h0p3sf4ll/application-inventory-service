"""Compatibility API for the pre-2.0 Application Inventory Service package."""

import appsec_atlas as _implementation


__all__ = _implementation.__all__
globals().update({name: getattr(_implementation, name) for name in __all__})
