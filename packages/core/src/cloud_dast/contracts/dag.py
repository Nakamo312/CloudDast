"""Immutable domain models for the runtime Campaign DAG read model."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cloud_dast.model import AccessOutcome, JsonValue, VerdictStatus
from cloud_dast.qdl.graph import Context, canonical_json, hash_content

CAMPAIGN_DAG_SCHEMA_VERSION = "1"


class CampaignNodeKind(StrEnum):
    """Node roles represented by the Campaign DAG projection."""

    PATH = "path"
    STEP = "step"
    OBSERVATION = "observation"
    CLUE = "clue"
    DEFICIT = "deficit"
    HYPOTHESIS = "hypothesis"
    REFLECTION = "reflection"
    RESOURCE_STATE = "resource_state"
    VERDICT = "verdict"
    HANDOFF = "handoff"


class CampaignEdgeKind(StrEnum):
    """Typed relationships between Campaign DAG nodes."""

    DEPENDS_ON = "depends_on"
    PRODUCES = "produces"
    OBSERVED_BY = "observed_by"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    NEXT_STEP = "next_step"
    SHARES_RESOURCE = "shares_resource"


class CampaignNodeRef(BaseModel):
    """A typed, context-preserving reference to one Campaign DAG node."""

    model_config = ConfigDict(frozen=True)

    node_id: str
    kind: CampaignNodeKind
    context: Context


class PathNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["path"] = "path"
    node_id: str
    context: Context
    path_id: str
    outcome: Literal["completed", "blocked"] | None = None
    attempted_steps: int | None = Field(default=None, ge=0)
    step_count: int | None = Field(default=None, ge=1)
    probe_count: int | None = Field(default=None, ge=0)
    reason: str = ""


class StepNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["step"] = "step"
    node_id: str
    context: Context
    step_id: str
    path_id: str | None = None
    step_index: int | None = Field(default=None, ge=0)
    phase: str | None = None
    verdict: VerdictStatus | None = None
    reason: str = ""
    completed_steps: tuple[str, ...] = ()


class ObservationNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["observation"] = "observation"
    node_id: str
    context: Context
    observation_id: str
    check_id: str | None = None
    scenario_id: str | None = None
    observed_outcome: AccessOutcome | None = None
    response_summary: str = ""
    method_id: str | None = None
    probe_marker: str | None = None
    response_digest: str | None = None


class ClueNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["clue"] = "clue"
    node_id: str
    context: Context
    clue_id: str
    action_id: str | None = None
    mode: str | None = None
    control_observation_id: str | None = None
    treatment_observation_id: str | None = None
    dimensions: tuple[str, ...] = ()
    reason: str = ""


class DeficitNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["deficit"] = "deficit"
    node_id: str
    context: Context
    deficit_id: str
    deficit_kind: str = ""
    action: str = ""
    axis: str | None = None
    details: tuple[tuple[str, str], ...] = ()
    reason: str = ""


class HypothesisNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["hypothesis"] = "hypothesis"
    node_id: str
    context: Context
    hypothesis_id: str
    prerequisites: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    statement: str = ""


class ReflectionNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["reflection"] = "reflection"
    node_id: str
    context: Context
    reflection_id: str
    step_id: str | None = None
    path_id: str | None = None
    verdict: VerdictStatus | None = None
    reason: str = ""


class ResourceStateNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["resource_state"] = "resource_state"
    node_id: str
    context: Context
    resource_state_id: str
    observation_id: str | None = None
    step_id: str | None = None
    method_id: str | None = None
    scenario_id: str | None = None
    phase: Literal["before", "after"] | None = None
    attributes: tuple[tuple[str, JsonValue], ...] = ()


class VerdictNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["verdict"] = "verdict"
    node_id: str
    context: Context
    verdict_id: str
    status: VerdictStatus | None = None
    path_id: str | None = None
    step_id: str | None = None
    observation_id: str | None = None
    reason: str = ""
    deterministic: bool | None = None
    grounded: bool | None = None


class HandoffNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["handoff"] = "handoff"
    node_id: str
    context: Context
    handoff_id: str
    handoff_kind: str = ""
    budget: int | None = Field(default=None, ge=0)
    requester: str | None = None
    responder: str | None = None
    reason: str = ""


CampaignNode = Annotated[
    PathNode
    | StepNode
    | ObservationNode
    | ClueNode
    | DeficitNode
    | HypothesisNode
    | ReflectionNode
    | ResourceStateNode
    | VerdictNode
    | HandoffNode,
    Field(discriminator="kind"),
]


class CampaignEdge(BaseModel):
    """One typed Campaign DAG relationship."""

    model_config = ConfigDict(frozen=True)

    edge_id: str
    kind: CampaignEdgeKind
    source: CampaignNodeRef
    target: CampaignNodeRef
    payload: tuple[tuple[str, JsonValue], ...] = ()


class CampaignDag(BaseModel):
    """Canonical, immutable Campaign DAG projection."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1"] = "1"
    source_digest: str
    nodes: tuple[CampaignNode, ...]
    edges: tuple[CampaignEdge, ...]

    @field_validator("nodes")
    @classmethod
    def sort_nodes(cls, nodes: tuple[CampaignNode, ...]) -> tuple[CampaignNode, ...]:
        return tuple(sorted(nodes, key=canonical_json))

    @field_validator("edges")
    @classmethod
    def sort_edges(cls, edges: tuple[CampaignEdge, ...]) -> tuple[CampaignEdge, ...]:
        return tuple(sorted(edges, key=canonical_json))

    @model_validator(mode="after")
    def validate_graph(self) -> CampaignDag:
        node_by_id = {node.node_id: node for node in self.nodes}
        if len(node_by_id) != len(self.nodes):
            raise ValueError("campaign nodes must have unique node_id")
        if len({edge.edge_id for edge in self.edges}) != len(self.edges):
            raise ValueError("campaign edges must have unique edge_id")
        for edge in self.edges:
            for endpoint in (edge.source, edge.target):
                node = node_by_id.get(endpoint.node_id)
                if node is None:
                    raise ValueError(
                        f"campaign edge references missing node {endpoint.node_id}"
                    )
                if _node_ref(node) != endpoint:
                    raise ValueError(
                        f"campaign edge endpoint mismatch for {endpoint.node_id}"
                    )
        return self

    @property
    def canonical_hash(self) -> str:
        return hash_content(self)


def _node_ref(node: CampaignNode) -> CampaignNodeRef:
    return CampaignNodeRef(
        node_id=node.node_id,
        kind=CampaignNodeKind(node.kind),
        context=node.context,
    )


__all__ = [
    "CAMPAIGN_DAG_SCHEMA_VERSION",
    "CampaignDag",
    "CampaignEdge",
    "CampaignEdgeKind",
    "CampaignNode",
    "CampaignNodeKind",
    "CampaignNodeRef",
    "ClueNode",
    "DeficitNode",
    "HandoffNode",
    "HypothesisNode",
    "ObservationNode",
    "PathNode",
    "ReflectionNode",
    "ResourceStateNode",
    "StepNode",
    "VerdictNode",
]
