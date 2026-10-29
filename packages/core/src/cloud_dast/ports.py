"""Public core ports implemented by composition and infrastructure adapters."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ContextManager, Literal, Protocol, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cloud_dast.contracts.proposals import (
    MAX_MODEL_FACTS,
    MAX_MODEL_RULES,
    MAX_MODEL_STRING_LENGTH,
    MAX_MODEL_UNCERTAINTIES,
)
from cloud_dast.model import (
    AddressingMode,
    BindingLevel,
    Check,
    IdentityClass,
    JsonValue,
    MethodSpec,
    Observation,
    RequestSchema,
    ResourceState,
    ResponseSchema,
    ScenarioPosition,
    ScopeRelation,
)
from cloud_dast.model.events import ApprovalAuditRecord, DomainEvent, EventScope
from cloud_dast.proposals import ProposalPromotionRequest, ProposalPromotionResult
from cloud_dast.qdl.graph import QdlGraph

MAX_MODEL_CHECKS = 16
MAX_MODEL_PROMPT_BYTES = 1024 * 1024
_MAX_MODEL_LOG_CHARS = 2000
E = TypeVar("E", bound=DomainEvent)
T = TypeVar("T")

# Transport-neutral target and adapter capabilities belong to core.  Concrete
# HTTP/gRPC/local implementations remain in infrastructure.
Target = Callable[[Check], Observation]
type EvidenceChannelKind = Literal["response", "oob", "ebpf", "app-log"]


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    """Raw normalized channel event ingested by infrastructure adapters."""

    correlation_id: str
    channel: EvidenceChannelKind
    event_id: str = field(default_factory=lambda: uuid4().hex)
    event_type: str = ""
    source: str = ""
    observed_at: float = 0.0
    attributes: tuple[tuple[str, JsonValue], ...] = ()


def _bound_model_log_value(value: object) -> str:
    """Return a bounded diagnostic representation of a model value."""

    text = value if isinstance(value, str) else str(value)
    return text[:_MAX_MODEL_LOG_CHARS]


class ModelRequest(BaseModel):
    """Bounded request sent through the core model-call port."""

    model_config = ConfigDict(frozen=True)

    task: str = Field(min_length=1)
    instruction: str = ""
    context: Mapping[str, Any] = Field(default_factory=dict)
    budget: ModelBudget | None = None
    request_id: str = Field(default_factory=lambda: uuid4().hex)


class ModelBudget(BaseModel):
    """Explicit token budget for one model call."""

    model_config = ConfigDict(frozen=True)

    max_input_tokens: int = Field(default=32768, gt=0)
    max_output_tokens: int = Field(default=8192, gt=0)


ModelBudget.model_rebuild()


class ModelResponse(BaseModel):
    """Decoded provider response returned by a model adapter."""

    model_config = ConfigDict(frozen=True)

    structured: Any = None
    content: str = ""
    model_id: str = "unknown"
    request_id: str | None = None
    finish_reason: str | None = None
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0


class ModelClient(Protocol):
    """External model capability used by optional extensions."""

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type: type[BaseModel] | None = None,
    ) -> ModelResponse: ...


class AxisGroundingDispatcher(Protocol):
    """Dispatch one bounded formal-grounding request through an LLM adapter."""

    def cache_key(self, axis: str, namespace: str, slice_hash: str) -> str: ...

    def dispatch(self, axis: str, context: Mapping[str, Any]) -> ModelResponse: ...


class Guardrail(Protocol):
    """Policy deciding whether a generated check may be executed."""

    def allows(self, check: Check) -> bool: ...


class FindingExampleStore(Protocol):
    """Persist and replay minimal examples for previously found norms."""

    def save(self, key: bytes, value: bytes) -> None: ...

    def fetch(self, key: bytes) -> Iterable[bytes]: ...


class EventStore(Protocol):
    """Append-only journal port for domain events."""

    def append(self, event: DomainEvent) -> None: ...

    def read(self) -> Iterator[DomainEvent]: ...

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]: ...


# Target architecture name; EventStore remains the compatibility spelling used
# by existing adapters and composition code.
Journal = EventStore


class EventPublisher(Protocol):
    """Publish domain events without binding core to an event bus."""

    def publish(self, event: DomainEvent) -> None: ...


class EventSubscriber(Protocol):
    """Subscribe to domain events without exposing an infrastructure bus."""

    def subscribe(self, event_type: type[E], handler: Callable[[E], None]) -> None: ...


class ReportPublisher(Protocol):
    """Publish render-ready projections without coupling runtime to reporting."""

    def publish_plan(
        self,
        execution: Any,
        *,
        max_checks: int | None,
        scope: EventScope,
    ) -> None: ...

    def publish_coverage(self, coverage: Any, *, scope: EventScope) -> None: ...


class EvidenceChannel(Protocol):
    """Transport-neutral join point for asynchronous runtime evidence."""

    def record(self, event: EvidenceEvent) -> None: ...

    def wait_for(
        self,
        correlation_id: str,
        timeout: float,
        *,
        channel: Literal["response", "oob", "ebpf", "app-log"] | None = None,
    ) -> EvidenceEvent | None: ...

    def ready(self) -> bool: ...

    def set_ready(self, ready: bool) -> None: ...

    def block(self, reason: str) -> None: ...

    def blocked_reason(self) -> str | None: ...


class GroundingCache(Protocol):
    """Durable cache boundary for validated grounding proposals."""

    def load(self, key: str) -> QdlGraph | None: ...

    def save(self, key: str, graph: QdlGraph) -> None: ...


class CampaignMetricsRecorder(Protocol):
    """Thread-safe metrics capability used by grounding workers."""

    def model_request_started(self, description: str = "") -> None: ...

    def model_request_finished(self) -> None: ...

    def record_tokens(
        self,
        input_tokens: int,
        output_tokens: int,
        cached_input_tokens: int = 0,
        *,
        phase: str = "default",
    ) -> None: ...

    def set_model_id(self, model_id: str) -> None: ...

    def record_grounding_cache_hit(self, axis: str) -> None: ...

    def record_grounding_cache_miss(self, axis: str) -> None: ...


GroundingEnrichmentStatus = Literal[
    "not_started",
    "pending",
    "committed",
    "failed",
    "discarded",
]


@dataclass(frozen=True, slots=True)
class GroundingBatch:
    """One promoted grounding batch visible to the campaign thread."""

    axis: str
    batch_key: str
    fact_count: int


class GroundingSink(Protocol):
    """Publisher available to one background grounding worker."""

    def publish(self, batch: GroundingBatch) -> None: ...

    def mark_enrichment(self, status: GroundingEnrichmentStatus) -> None: ...

    def finish(self, error: BaseException | None = None) -> None: ...


class GroundingHandle(Protocol):
    """Completion stream consumed by the campaign thread."""

    def wait_batch(self, timeout: float | None = None) -> GroundingBatch | None: ...

    @property
    def done(self) -> bool: ...

    @property
    def promoted_facts(self) -> int: ...

    @property
    def error(self) -> BaseException | None: ...

    @property
    def enrichment_status(self) -> GroundingEnrichmentStatus: ...

    def mark_enrichment(self, status: GroundingEnrichmentStatus) -> None: ...


class GroundingTaskHandle(Protocol[T]):
    """Handle for one independently running grounding task."""

    def result(self, timeout: float | None = None) -> T: ...


class GroundingRunner(Protocol):
    """Own threads and executors used by model grounding."""

    @property
    def lifecycle_revision(self) -> int: ...

    def commit(self, lifecycle_revision: int) -> ContextManager[bool]: ...

    def close(self) -> None: ...

    def start(self, work: Callable[[GroundingSink], None]) -> GroundingHandle: ...

    def start_task(self, task: Callable[[], T]) -> GroundingTaskHandle[T]: ...

    def run_tasks(
        self,
        tasks: Sequence[Callable[[], T]],
        *,
        max_workers: int,
        timeout: float | None,
    ) -> Iterator[tuple[int, T]]: ...


class FormalGrounder(Protocol):
    """Prepare untrusted model output, then admit it through the campaign owner."""

    def prepare(self, service: str) -> ProposalPromotionRequest | None: ...

    def commit(
        self, service: str, request: ProposalPromotionRequest
    ) -> ProposalPromotionResult: ...


class ApprovalAuditLog(Protocol):
    """Append an approval after its formal projection is durable."""

    def append(self, record: ApprovalAuditRecord) -> None: ...


class TokenProvider(Protocol):
    """Resolve transport-neutral credential metadata for one identity."""

    def metadata(self, identity: str) -> tuple[tuple[str, str], ...]: ...


class EndpointPolicy(Protocol):
    """Decide whether a runtime destination may receive credentials."""

    def allows(self, endpoint: str) -> bool: ...


class OobUrlFactory(Protocol):
    """Build an out-of-band callback URL for a bounded marker."""

    def url_for(self, marker: str) -> str: ...


class GraphNode(BaseModel):
    """One raw node from an external contract graph."""

    model_config = ConfigDict(frozen=True)

    node_id: str
    labels: tuple[str, ...] = ()
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """One raw edge from an external contract graph."""

    model_config = ConfigDict(frozen=True)

    edge_id: str
    source_id: str
    target_id: str
    kind: str
    properties: dict[str, Any] = Field(default_factory=dict)


class ServiceGraphSlice(BaseModel):
    """A bounded raw contract-graph slice returned by a repository port."""

    model_config = ConfigDict(frozen=True)

    service: str
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()

    @classmethod
    def from_methods(
        cls,
        service: str,
        methods: tuple[MethodSpec, ...],
    ) -> "ServiceGraphSlice":
        """Build a method-only ingestion slice with input-field metadata."""

        nodes: list[GraphNode] = [
            GraphNode(
                node_id=f"service:{service}",
                labels=("Service",),
                properties={"canonical_id": service},
            )
        ]
        edges: list[GraphEdge] = []
        for method in methods:
            method_node = GraphNode(
                node_id=f"method:{method.method_id}",
                labels=("Method",),
                properties={
                    "method_id": method.method_id,
                    "input_fields": tuple(
                        field.model_dump(mode="json")
                        for field in method.request_schema.fields
                    ),
                },
            )
            nodes.append(method_node)
            edges.append(
                GraphEdge(
                    edge_id=f"service:{service}:method:{method.method_id}",
                    source_id=f"service:{service}",
                    target_id=method_node.node_id,
                    kind="EXPOSES_METHOD",
                )
            )
        return cls(service=service, nodes=tuple(nodes), edges=tuple(edges))


class MethodRepository(Protocol):
    def get_method(self, method_id: str) -> MethodSpec | None: ...

    def list_methods(self, service: str) -> tuple[MethodSpec, ...]: ...


class MessageSchemaResolver(Protocol):
    """Resolve transport-declared message types into canonical schemas."""

    def request_schema(self, name: str) -> RequestSchema: ...

    def response_schema(self, name: str) -> ResponseSchema: ...


@dataclass(frozen=True)
class Invocation:
    """Resolved invocation metadata for one transport."""

    method_id: str
    endpoint: str
    transport: Literal["grpc", "http-json", "local-process", "socket"] = "grpc"
    input_type: str | None = None
    rpc_path: str | None = None
    output_type: str | None = None
    command_template: tuple[str, ...] = ()
    stdin_fields: tuple[str, ...] = ()
    http_method: str | None = None
    path_template: str | None = None
    query_fields: tuple[str, ...] = ()
    header_fields: tuple[str, ...] = ()
    cookie_fields: tuple[str, ...] = ()
    body_fields: tuple[str, ...] | None = None


class InvocationRepository(Protocol):
    def get_invocation(self, method_id: str) -> Invocation | None: ...


class ContractGraphRepository(Protocol):
    def load_slice(self, service: str) -> ServiceGraphSlice: ...


class FormalRepository(Protocol):
    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: Mapping[str, Any],
        adapter_version: str,
        mapping_report: Mapping[str, Any],
    ) -> None: ...

    def load(self, source_id: str) -> QdlGraph: ...

    def load_merged(self, source_prefix: str) -> QdlGraph: ...


class StandSource(Protocol):
    def project(self, service: str) -> QdlGraph: ...


class ScenarioRepository(Protocol):
    def get_scenario(
        self,
        principal_id: str,
        resource_id: str,
        method: MethodSpec | None = None,
        *,
        method_id: str | None = None,
        scope_relation: ScopeRelation | None = None,
        binding_level: BindingLevel | None = None,
        resource_state: ResourceState = "existing",
        identity_class: IdentityClass = "attacker",
        addressing_mode: AddressingMode = "direct",
    ) -> ScenarioPosition | None: ...


__all__ = [
    "EndpointPolicy",
    "EventPublisher",
    "EventSubscriber",
    "EvidenceChannel",
    "EvidenceChannelKind",
    "EvidenceEvent",
    "GroundingCache",
    "CampaignMetricsRecorder",
    "ApprovalAuditLog",
    "FormalGrounder",
    "GroundingBatch",
    "GroundingEnrichmentStatus",
    "GroundingHandle",
    "GroundingRunner",
    "ReportPublisher",
    "GroundingSink",
    "GroundingTaskHandle",
    "EventStore",
    "GraphEdge",
    "GraphNode",
    "FindingExampleStore",
    "Guardrail",
    "MAX_MODEL_CHECKS",
    "MAX_MODEL_FACTS",
    "MAX_MODEL_PROMPT_BYTES",
    "MAX_MODEL_RULES",
    "MAX_MODEL_STRING_LENGTH",
    "MAX_MODEL_UNCERTAINTIES",
    "ModelBudget",
    "ModelClient",
    "ModelRequest",
    "ModelResponse",
    "Journal",
    "ContractGraphRepository",
    "FormalRepository",
    "IdentityClass",
    "Invocation",
    "InvocationRepository",
    "MethodRepository",
    "OobUrlFactory",
    "Target",
    "TokenProvider",
    "ScenarioRepository",
    "ServiceGraphSlice",
    "StandSource",
    "_bound_model_log_value",
]
