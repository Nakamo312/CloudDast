from __future__ import annotations

from cloud_dast.composition.guardrails import (
    AllowlistEndpointPolicy,
    AllowlistGuardrail,
    GuardedTarget,
)
from cloud_dast.infrastructure.runtime import (
    GrpcTarget,
    GrpcTransport,
    PayloadCodec,
)
from cloud_dast.ports import (
    Guardrail,
    InvocationRepository,
    MethodRepository,
    Target,
    TokenProvider,
)


def make_grpc_target(
    method_repository: MethodRepository,
    invocations: InvocationRepository,
    codec: PayloadCodec,
    tokens: TokenProvider,
    transport: GrpcTransport,
    *,
    guardrail: Guardrail | None = None,
    timeout: float | None = 30.0,
) -> Target:
    """Build a graph-backed gRPC target guarded by composition policies."""

    endpoint_policy = AllowlistEndpointPolicy.from_environment()
    if guardrail is None:
        guardrail = AllowlistGuardrail.from_environment(method_repository)
    return GuardedTarget(
        GrpcTarget(
            invocations=invocations,
            codec=codec,
            tokens=tokens,
            transport=transport,
            endpoint_policy=endpoint_policy,
            timeout=timeout,
        ),
        guardrail,
    )
