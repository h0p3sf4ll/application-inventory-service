import appsec_scan_router as _implementation


__all__ = _implementation.__all__
globals().update({name: getattr(_implementation, name) for name in __all__})


if __name__ == "__main__":
    raise SystemExit(_implementation.main())
