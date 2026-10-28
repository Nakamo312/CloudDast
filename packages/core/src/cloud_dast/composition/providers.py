"""Public composition entry points grouped by DI boundary."""

from cloud_dast.composition.app_provider import AppProvider
from cloud_dast.composition.container import make_cloud_dast_container
from cloud_dast.composition.grpc_target import make_grpc_target
from cloud_dast.composition.run_provider import RunProvider

__all__ = [
    "AppProvider",
    "RunProvider",
    "make_cloud_dast_container",
    "make_grpc_target",
]
