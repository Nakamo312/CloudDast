"""Explicit live composition for a graph-backed runtime target."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from dishka import Container, Provider, make_container, provide

from cloud_dast.composition.app_provider import AppProvider
from cloud_dast.composition.container import GuardrailProvider
from cloud_dast.composition.guardrails import (
    AllowlistEndpointPolicy,
    AllowlistGuardrail,
    GuardedTarget,
)
from cloud_dast.composition.model import make_model_client, model_token
from cloud_dast.composition.run_provider import RunProvider
from cloud_dast.composition.scopes import AppScope, CloudDastScopes
from cloud_dast.extensions import ExtensionRegistry
from cloud_dast.infrastructure.events import JsonlEventStore
from cloud_dast.infrastructure.neo4j.common.repository import (
    Neo4jConfig,
    SessionFactory,
    make_session_factory,
)
from cloud_dast.infrastructure.runtime import (
    DescriptorRegistry,
    EnvironmentTokenProvider,
    GrpcioTransport,
    GrpcTarget,
    GrpcTransport,
    PayloadCodec,
    ProtobufPayloadCodec,
)
from cloud_dast.infrastructure.runtime.http_json import (
    HttpJsonTarget,
    HttpTransport,
    JsonPayloadCodec,
    UrllibHttpTransport,
)
from cloud_dast.infrastructure.runtime.tokens import (
    configured_token_command,
    normalize_identity_key,
)
from cloud_dast.infrastructure.secrets import secret_configured
from cloud_dast.ports import (
    EventPublisher,
    EventStore,
    Guardrail,
    InvocationRepository,
    MethodRepository,
    ModelClient,
    ReportPublisher,
    Target,
    TokenProvider,
)


@dataclass(frozen=True)
class LivePrerequisites:
    """Machine-readable preflight result for a live run."""

    missing: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.missing


TargetKind = Literal["grpc", "http-json"]
_TARGET_KINDS = frozenset(("grpc", "http-json"))


def resolve_target_kind(
    selected: str | None = None,
    *,
    environ: MutableMapping[str, str] | None = None,
) -> TargetKind:
    """Resolve the explicitly selected runtime target transport."""

    environment = os.environ if environ is None else environ
    raw = (
        selected
        if selected is not None
        else environment.get("CLOUD_DAST_TARGET", "grpc")
    )
    value = raw.strip()
    if not value:
        value = "grpc"
    if value not in _TARGET_KINDS:
        raise RuntimeError("CLOUD_DAST_TARGET must be one of: grpc, http-json")
    return "http-json" if value == "http-json" else "grpc"


def check_live_prerequisites(
    identity: str | None = None,
    *,
    require_model: bool = False,
    target_kind: str | None = None,
) -> LivePrerequisites:
    """Report target-specific configuration gaps without external calls."""

    missing: list[str] = []
    stand_source = os.environ.get("CLOUD_DAST_STAND_SOURCE", "file").strip().lower()
    if stand_source not in {"file", "neo4j"}:
        missing.append("CLOUD_DAST_STAND_SOURCE must be one of: file, neo4j")
    if _neo4j_session_required():
        names = (
            "CPA_NEO4J_URI",
            "CPA_NEO4J_USER",
            "CPA_NEO4J_PASSWORD",
        )
        missing.extend(
            name
            for name in names
            if not (
                secret_configured(name)
                if name.endswith("PASSWORD")
                else os.environ.get(name)
            )
        )
    if stand_source == "file":
        stand_file = os.environ.get("CLOUD_DAST_STAND_FILE", "stand.json")
        if not Path(stand_file).is_file():
            missing.append(f"stand file {stand_file}")
        contract_file = os.environ.get("CLOUD_DAST_CONTRACT_FILE", "contract.json")
        if not Path(contract_file).is_file():
            missing.append(f"contract file {contract_file}")
    if resolve_target_kind(target_kind) == "grpc":
        if find_spec("grpc") is None:
            missing.append("python package grpcio")
        try:
            protobuf_available = find_spec("google.protobuf") is not None
        except ModuleNotFoundError:
            protobuf_available = False
        if not protobuf_available:
            missing.append("python package protobuf")
        descriptor = os.environ.get("CLOUD_DAST_DESCRIPTOR_SET", "").strip()
        if not descriptor:
            missing.append("CLOUD_DAST_DESCRIPTOR_SET")
        elif not Path(descriptor).is_file():
            missing.append(f"descriptor file {descriptor}")
    if identity:
        token_key = "CLOUD_DAST_TOKEN_" + normalize_identity_key(identity)
        has_static_token = secret_configured(token_key)
        has_identity_token = False
    else:
        token_key = "CLOUD_DAST_IAM_TOKEN"
        has_static_token = secret_configured(token_key)
        has_identity_token = any(
            name.startswith("CLOUD_DAST_TOKEN_") for name in os.environ
        )
    has_token_command = bool(configured_token_command(identity))
    if not identity:
        has_token_command = has_token_command or any(
            name.startswith("CLOUD_DAST_TOKEN_") and name.endswith("_COMMAND")
            for name in os.environ
        )
    if not has_static_token and not has_token_command and not has_identity_token:
        missing.append(f"{token_key} or {token_key}_COMMAND")
    if require_model:
        if not os.environ.get("CLOUD_DAST_MODEL_URL"):
            missing.append("CLOUD_DAST_MODEL_URL")
        elif find_spec("langchain_openai") is None:
            missing.append("python package langchain-openai")
        elif find_spec("langchain_core") is None:
            missing.append("python package langchain-core")
        elif not model_token():
            missing.append("CLOUD_DAST_MODEL_TOKEN_FILE or CLOUD_DAST_MODEL_TOKEN")
    oob_server_url = os.environ.get("CLOUD_DAST_OOB_SERVER_URL", "").strip()
    if oob_server_url:
        parsed_oob_url = urlsplit(oob_server_url)
        if (
            parsed_oob_url.scheme != "https"
            or not parsed_oob_url.netloc
            or parsed_oob_url.username is not None
            or parsed_oob_url.password is not None
            or parsed_oob_url.query
            or parsed_oob_url.fragment
        ):
            missing.append("CLOUD_DAST_OOB_SERVER_URL must be an HTTPS origin")
        if not secret_configured("CLOUD_DAST_OOB_TOKEN"):
            missing.append("CLOUD_DAST_OOB_TOKEN for CLOUD_DAST_OOB_SERVER_URL")
        raw_interval = os.environ.get("CLOUD_DAST_OOB_POLL_INTERVAL", "").strip()
        try:
            interval = float(raw_interval or "0.5")
        except ValueError:
            missing.append("CLOUD_DAST_OOB_POLL_INTERVAL must be a number")
        else:
            if interval <= 0:
                missing.append("CLOUD_DAST_OOB_POLL_INTERVAL must be positive")
    return LivePrerequisites(tuple(missing))


def _neo4j_session_required() -> bool:
    """Report whether the selected composition needs a Neo4j session."""

    stand_source = os.environ.get("CLOUD_DAST_STAND_SOURCE", "file").strip().lower()
    formal_store = os.environ.get("CLOUD_DAST_FORMAL_STORE", "sqlite").strip().lower()
    return stand_source == "neo4j" or formal_store == "neo4j"


def _make_session_factory(config: Neo4jConfig | None) -> SessionFactory | None:
    """Create the Neo4j session factory only when the run selected Neo4j.

    The file/sqlite composition stays Neo4j-free: no driver, no credentials,
    and no eager connection settings are required.  An explicitly injected
    ``config`` remains an explicit opt-in for callers that manage their own
    graph store.
    """

    if config is not None or _neo4j_session_required():
        return make_session_factory(config)
    return None


def _build_live_target(
    method_repository: MethodRepository,
    invocations: InvocationRepository,
    codec: PayloadCodec | None,
    *,
    tokens: TokenProvider | None,
    transport: GrpcTransport | None,
    guardrail: Guardrail | None,
    timeout: float | None,
    safe_fields: tuple[str, ...],
    target_kind: str | None,
    http_transport: HttpTransport | None,
    descriptor_registry: DescriptorRegistry | None = None,
) -> Target:
    """Build one guarded target from already-injected repository ports."""

    selected_kind = resolve_target_kind(target_kind)
    if guardrail is None:
        guardrail = AllowlistGuardrail.from_environment(method_repository)
    endpoint_policy = AllowlistEndpointPolicy.from_environment()
    if selected_kind == "http-json":
        if codec is not None or transport is not None:
            raise ValueError(
                "gRPC codec and transport cannot be combined with http-json target"
            )
        return GuardedTarget(
            HttpJsonTarget(
                invocations,
                JsonPayloadCodec(safe_fields=safe_fields),
                tokens or EnvironmentTokenProvider(),
                http_transport or UrllibHttpTransport(),
                endpoint_policy=endpoint_policy,
                timeout=timeout,
            ),
            guardrail,
        )

    if codec is None:
        codec = ProtobufPayloadCodec(
            descriptor_registry or DescriptorRegistry.from_environment(),
            safe_fields=safe_fields,
        )
    insecure = os.environ.get("CLOUD_DAST_GRPC_INSECURE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    return GuardedTarget(
        GrpcTarget(
            invocations,
            codec,
            tokens or EnvironmentTokenProvider(),
            transport or GrpcioTransport(insecure=insecure),
            endpoint_policy=endpoint_policy,
            timeout=timeout,
        ),
        guardrail,
    )


class LiveTargetProvider(Provider):
    """Assemble the live target inside the Dishka container."""

    def __init__(
        self,
        codec: PayloadCodec | None = None,
        *,
        tokens: TokenProvider | None = None,
        transport: GrpcTransport | None = None,
        timeout: float | None = 30.0,
        safe_fields: tuple[str, ...] = (),
        target_kind: str | None = None,
        http_transport: HttpTransport | None = None,
        descriptor_registry: DescriptorRegistry | None = None,
    ) -> None:
        super().__init__()
        self._codec = codec
        self._tokens = tokens
        self._transport = transport
        self._timeout = timeout
        self._safe_fields = safe_fields
        self._target_kind = target_kind
        self._http_transport = http_transport
        self._descriptor_registry = descriptor_registry

    @provide(scope=AppScope, provides=Target)
    def target(
        self,
        method_repository: MethodRepository,
        invocations: InvocationRepository,
        guardrail: Guardrail,
    ) -> Target:
        return _build_live_target(
            method_repository,
            invocations,
            self._codec,
            tokens=self._tokens,
            transport=self._transport,
            guardrail=guardrail,
            timeout=self._timeout,
            safe_fields=self._safe_fields,
            target_kind=self._target_kind,
            http_transport=self._http_transport,
            descriptor_registry=self._descriptor_registry,
        )


def make_live_target(
    method_repository: MethodRepository,
    invocations: InvocationRepository,
    codec: PayloadCodec | None = None,
    *,
    tokens: TokenProvider | None = None,
    transport: GrpcTransport | None = None,
    guardrail: Guardrail | None = None,
    timeout: float | None = 30.0,
    safe_fields: tuple[str, ...] = (),
    target_kind: str | None = None,
    http_transport: HttpTransport | None = None,
    descriptor_registry: DescriptorRegistry | None = None,
) -> Target:
    """Build the graph-backed target used by a live run.

    The default ``grpc`` target builds a descriptor-backed protobuf codec from
    ``CLOUD_DAST_DESCRIPTOR_SET`` when ``codec`` is omitted.  Selecting
    ``http-json`` builds the JSON codec and HTTP transport instead; gRPC
    dependencies are then neither required nor accepted.  The returned target
    is always guarded by the campaign guardrail and destination allowlist.
    """

    return _build_live_target(
        method_repository,
        invocations,
        codec,
        tokens=tokens,
        transport=transport,
        guardrail=guardrail,
        timeout=timeout,
        safe_fields=safe_fields,
        target_kind=target_kind,
        http_transport=http_transport,
        descriptor_registry=descriptor_registry,
    )


def make_live_container(
    codec: PayloadCodec | None = None,
    *,
    event_store: EventStore | None = None,
    event_path: str | None = None,
    config: Neo4jConfig | None = None,
    tokens: TokenProvider | None = None,
    transport: GrpcTransport | None = None,
    timeout: float | None = 30.0,
    endpoint_environment: str | None = None,
    safe_fields: tuple[str, ...] = (),
    model_client: ModelClient | None = None,
    require_model: bool = False,
    guardrail: Guardrail | None = None,
    target_kind: str | None = None,
    http_transport: HttpTransport | None = None,
    method_prefix_aliases: Mapping[str, str] | None = None,
    extension_registry: ExtensionRegistry | None = None,
    report_publisher_factory: Callable[[EventPublisher], ReportPublisher] | None = None,
) -> Container:
    """Compose a live runtime without hiding network or credential failures.

    The default file/sqlite composition creates no Neo4j session factory at
    all; the graph store is selected only through ``CLOUD_DAST_STAND_SOURCE``
    or ``CLOUD_DAST_FORMAL_STORE`` set to ``neo4j``.
    """

    session_factory = _make_session_factory(config)
    if event_store is None:
        path = event_path or os.environ.get("CLOUD_DAST_EVENT_LOG")
        if not path:
            raise RuntimeError(
                "event_store or event_path is required for a live run; "
                "set CLOUD_DAST_EVENT_LOG explicitly"
            )
        event_store = JsonlEventStore(path)
    if model_client is None:
        model_client = make_model_client(required=require_model)
    descriptor_registry = None
    if (
        resolve_target_kind(target_kind) == "grpc"
        and codec is None
        and os.environ.get("CLOUD_DAST_DESCRIPTOR_SET", "").strip()
    ):
        descriptor_registry = DescriptorRegistry.from_environment()
    return make_container(
        AppProvider(
            endpoint_environment=endpoint_environment,
            method_prefix_aliases=method_prefix_aliases,
            schema_resolver=descriptor_registry,
        ),
        RunProvider(
            model_client=model_client,
            extension_registry=extension_registry,
            report_publisher_factory=report_publisher_factory,
        ),
        GuardrailProvider(guardrail),
        LiveTargetProvider(
            codec,
            tokens=tokens,
            transport=transport,
            timeout=timeout,
            safe_fields=safe_fields,
            target_kind=target_kind,
            http_transport=http_transport,
            descriptor_registry=descriptor_registry,
        ),
        scopes=CloudDastScopes,
        context={
            SessionFactory: session_factory,
            EventStore: event_store,
        },
    )
