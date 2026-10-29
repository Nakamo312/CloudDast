from __future__ import annotations

from cloud_dast.model import Check


class AllowAllGuardrail:
    """Explicit permissive policy for tests and controlled local sandboxes."""

    def allows(self, check: Check) -> bool:
        return True


__all__ = ["AllowAllGuardrail"]
