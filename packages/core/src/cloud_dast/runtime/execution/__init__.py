"""Public live path execution boundary."""

from importlib import import_module

__all__ = ["BoundPathRunner", "BoundPathRunnerOptions"]


def __getattr__(name: str) -> object:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(".runner", __name__), name)
