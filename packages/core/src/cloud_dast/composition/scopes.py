from __future__ import annotations

from dishka import BaseScope, new_scope


class CloudDastScopes(BaseScope):
    APP = new_scope("APP")
    RUN = new_scope("RUN")


AppScope = CloudDastScopes.APP
RunScope = CloudDastScopes.RUN

__all__ = ["AppScope", "CloudDastScopes", "RunScope"]
