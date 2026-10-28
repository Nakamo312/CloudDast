"""Runtime-neutral candidate complexity metric."""

from cloud_dast.model import JsonValue


def request_complexity(request: tuple[tuple[str, JsonValue], ...]) -> int:
    """Return deterministic complexity used for candidate minimization."""

    return sum(_value_complexity(value) for _name, value in request)


def _value_complexity(value: JsonValue) -> int:
    if value is None or isinstance(value, bool):
        return 0 if value is None else 1
    if isinstance(value, str):
        return len(value)
    if isinstance(value, int | float):
        return abs(int(value))
    return sum(_value_complexity(item) for item in value)


__all__ = ["request_complexity"]
