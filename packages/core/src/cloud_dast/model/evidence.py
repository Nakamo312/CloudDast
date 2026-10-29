from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cloud_dast.qdl.graph import Fact as QdlFact

type JsonValue = (
    str
    | int
    | Annotated[float, Field(allow_inf_nan=False)]
    | bool
    | None
    | tuple[JsonValue, ...]
)


class AccessOutcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    ERROR = "error"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_SCORE: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_score(severity: Severity) -> int:
    """Return the canonical ordered severity score shared by the engine.

    The score preserves the ``LOW < MEDIUM < HIGH < CRITICAL`` order and is
    used by threat synthesis and search rewards instead of per-module scales.
    """

    return _SEVERITY_SCORE[severity]


class VerdictStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    AMBIGUOUS = "ambiguous"
    ERROR = "error"
    SKIPPED = "skipped"
    UNSCOREABLE = "unscoreable"


class IdentityRelation(StrEnum):
    """Whether two compared executions ran as the same identity."""

    SAME = "same"
    DIFFERENT = "different"


def identity_relation(
    left: tuple[str, ...],
    right: tuple[str, ...],
) -> IdentityRelation:
    """Classify whether two compared executions share their identity.

    Read-back legs and payload pairs must compare the same identity, while
    differential factor pairs may deliberately vary it; callers use this
    classification instead of re-deriving tuple equality at every boundary.
    """

    return (
        IdentityRelation.SAME
        if tuple(left) == tuple(right)
        else IdentityRelation.DIFFERENT
    )


class ResponseData(BaseModel):
    """Safe structured response fields retained for workflow forwarding."""

    model_config = ConfigDict(frozen=True)

    fields: tuple[tuple[str, JsonValue], ...] = ()
    field_names: tuple[str, ...] = Field(
        default=(),
        description=(
            "shape-only names of every response field, including nested dotted "
            "paths; values are never retained here"
        ),
    )

    @model_validator(mode="after")
    def validate_field_names(self) -> ResponseData:
        names = tuple(name for name, _ in self.fields)
        if len(names) != len(set(names)):
            raise ValueError("response field names must be unique")
        return self


class HttpStatus(BaseModel):
    """HTTP response status.

    The 100-599 range is an HTTP hierarchy: it is validated on this
    transport-typed status instead of being imposed on every transport.
    """

    model_config = ConfigDict(frozen=True)

    transport: Literal["http"] = "http"
    code: int = Field(ge=100, le=599)

    @property
    def token(self) -> str:
        """Canonical evidence token, for example ``http:403``."""

        return f"http:{self.code}"

    def is_error(self) -> bool:
        return self.code >= 400

    def is_transport_failure(self) -> bool:
        """Whether the transport itself failed, not the application.

        Gateway and network-layer statuses mean the request never reached a
        functioning application; 4xx responses are application answers.
        """

        return self.code in {502, 503, 504}

    def is_not_found(self) -> bool:
        return self.code == 404

    def is_auth_failure(self) -> bool:
        return self.code == 401

    def is_timeout(self) -> bool:
        return self.code == 504


class GrpcStatus(BaseModel):
    """gRPC response status.

    ``code`` is the canonical gRPC status name, for example
    ``PERMISSION_DENIED``.  The domain never translates one transport's
    hierarchy into another transport's numbering; adapters own the mapping
    from their status hierarchy to ``AccessOutcome``.
    """

    model_config = ConfigDict(frozen=True)

    transport: Literal["grpc"] = "grpc"
    code: str = Field(min_length=1)

    @field_validator("code", mode="before")
    @classmethod
    def reject_blank_code(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            raise ValueError("grpc status code must not be blank")
        return value

    @property
    def token(self) -> str:
        """Canonical evidence token, for example ``grpc:PERMISSION_DENIED``."""

        return f"grpc:{self.code}"

    def is_error(self) -> bool:
        return self._normalized() not in {"OK", "SUCCESS"}

    def is_transport_failure(self) -> bool:
        """Whether the RPC failed at the wire level.

        UNAVAILABLE covers connect/TLS failures; UNKNOWN covers handshake
        protocol errors.  Application statuses (NOT_FOUND, PERMISSION_DENIED)
        are answers, not transport failures.
        """

        return self._normalized() in {"UNAVAILABLE", "UNKNOWN"}

    def is_not_found(self) -> bool:
        return self._normalized() == "NOT_FOUND"

    def is_auth_failure(self) -> bool:
        return self._normalized() == "UNAUTHENTICATED"

    def is_timeout(self) -> bool:
        return self._normalized() == "DEADLINE_EXCEEDED"

    def _normalized(self) -> str:
        return self.code.strip().upper()


type TransportStatus = Annotated[
    HttpStatus | GrpcStatus, Field(discriminator="transport")
]


class TraceStep(BaseModel):
    """Safe, structured evidence for one executed API step.

    Request values are intentionally not retained here.  ``request_fields``
    describes the shape of the request, while response values must already be
    projected by the infrastructure codec into ``ResponseData``.
    """

    model_config = ConfigDict(frozen=True)

    observation_id: str
    step_id: str
    method_id: str
    scenario_id: str
    status: AccessOutcome
    request_fields: tuple[str, ...] = ()
    response: ResponseData | None = None
    resource_state_before: tuple[tuple[str, JsonValue], ...] = ()
    resource_state_after: tuple[tuple[str, JsonValue], ...] = ()
    permissions_checked: tuple[str, ...] = ()
    gates_passed: tuple[str, ...] = ()
    sinks_reached: tuple[str, ...] = ()


class ExecutionTrace(BaseModel):
    """Structured evidence consumed by policy and structural oracles."""

    model_config = ConfigDict(frozen=True)

    steps: tuple[TraceStep, ...] = ()

    @property
    def observation_ids(self) -> tuple[str, ...]:
        return tuple(step.observation_id for step in self.steps)


class Observation(BaseModel):
    model_config = ConfigDict(frozen=True)

    observation_id: str = Field(default_factory=lambda: uuid4().hex)
    check_id: str
    scenario_id: str
    observed_outcome: AccessOutcome
    response_summary: str
    transport_status: TransportStatus | None = None
    auth_failed: bool = False
    output: ResponseData | None = None
    trace: ExecutionTrace | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    probe_marker: str | None = Field(
        default=None,
        description="runtime canary expected in marker or OOB evidence",
    )
    error_reason: str | None = Field(
        default=None,
        description=(
            "redacted transport error text, length-capped evidence, "
            "never workflow-forwarded"
        ),
    )
    response_tree: tuple[tuple[str, JsonValue], ...] = Field(
        default=(),
        description=(
            "full-fidelity decoded response on isolated stands; flat "
            "dotted-path to scalar-leaf mapping for deterministic diffing "
            "and marker search"
        ),
    )
    response_digest: str | None = Field(
        default=None,
        description=(
            "sha256 hex of the canonical JSON of the sorted response tree; "
            "cheap equality across observations, including cross-run"
        ),
    )


def response_tree_digest(tree: tuple[tuple[str, JsonValue], ...]) -> str:
    """Return the stable sha256 hex digest of a full-fidelity response tree.

    The tree is canonicalized as a JSON array of ``[path, value]`` leaves
    sorted by path, so digest equality is independent of leaf collection
    order and any single leaf change produces a different digest.
    """
    canonical = json.dumps(
        [[path, value] for path, value in sorted(tree, key=lambda leaf: leaf[0])],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


type OracleDeficitKind = Literal[
    "candidate_witness",
    "echo_witness",
    "incomplete_negative_scope",
    "partial_sequence",
    "principal_scope",
    "ungrounded_expectation",
]


class OracleDeficit(BaseModel):
    """A typed reason why an oracle could not establish a witness scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: OracleDeficitKind
    action_id: str | None = None
    context: tuple[tuple[str, str], ...] = ()
    rationale: str


class PolicyVerdict(BaseModel):
    """A deterministic or grounded verdict produced by an oracle.

    A ``PASS`` is a universal negative witness.  It must name the complete
    observation channels that made the negative scope local-closed-world; an
    absent marker or another unknown value must remain ``UNSCOREABLE``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: VerdictStatus
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    model_id: str
    negative_scope: tuple[str, ...] = Field(
        default=(),
        description="complete channels proving the universal negative witness",
    )
    deficits: tuple[OracleDeficit, ...] = ()
    sink_ids: tuple[str, ...] = Field(
        default=(),
        description="formal sink identifiers named by the violated norm",
    )
    probe_fields: tuple[str, ...] = Field(
        default=(),
        description="grounded input fields carried by the finding witness",
    )
    deterministic: bool = False
    grounded: bool = False
    oracle_called: bool = True

    @model_validator(mode="after")
    def enforce_pass_semantics(self) -> PolicyVerdict:
        if self.status is VerdictStatus.PASS:
            if not self.negative_scope:
                raise ValueError("PASS requires a complete negative witness scope")
            if not self.grounded:
                raise ValueError("PASS requires grounded negative witness evidence")
            if self.deficits:
                raise ValueError("PASS must not carry oracle deficits")
        return self


class FindingFingerprint(BaseModel):
    """Value-free identity of one confirmed finding root cause."""

    model_config = ConfigDict(frozen=True)

    invariant_id: str
    scenario_id: str
    sink_ids: tuple[str, ...] = ()
    probe_fields: tuple[str, ...] = ()
    witness_kind: str = ""

    @field_validator("sink_ids", "probe_fields")
    @classmethod
    def canonicalize_identifiers(cls, identifiers: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(dict.fromkeys(identifiers)))

    @property
    def key(self) -> tuple[str, str, tuple[str, ...], tuple[str, ...], str]:
        """Return the canonical merge key used by finding evaluation."""

        return (
            self.invariant_id,
            self.scenario_id,
            self.sink_ids,
            self.probe_fields,
            self.witness_kind,
        )


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(default_factory=lambda: uuid4().hex)
    observation_id: str
    invariant_id: str
    method_id: str
    scenario_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    goal_id: str | None = None
    path_id: str | None = None
    step_id: str | None = None
    rationale: str = ""
    fingerprint: FindingFingerprint | None = Field(
        default=None,
        description="value-free root-cause identity used to merge witnesses",
    )
    minimal_poc: tuple[tuple[str, JsonValue], ...] | None = Field(
        default=None,
        description="minimal request payload that reproduced the deterministic witness",
    )
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_refs: tuple[str, ...] = ()
    vulnerability_class: str = Field(
        default="classification_deficit",
        min_length=1,
        description="catalog class, or classification_deficit when QDL facts are incomplete",
    )
    classification_deficits: tuple[str, ...] = Field(
        default=("missing_classification_facts",),
        description="reasons why no catalog class could be selected",
    )
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    stride: tuple[str, ...] = ()
    norm_fact: QdlFact | None = Field(
        default=None,
        description="formal QDL prevents-fact carried from the violated invariant",
    )
