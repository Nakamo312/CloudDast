# Domain model

## Status

This document fixes the canonical domain vocabulary and the ownership boundary
between `model`, `qdl`, `runtime`, `verification`, and `infrastructure`. The
boundary is enforced by the architecture tests; migration work must preserve
these ownership rules rather than reintroduce a mixed public model namespace.

## What counts as a domain entity

A type belongs to the domain model when it describes a durable security or
service concept, has identity or domain invariants, and can be understood
without knowing how a campaign is scheduled, which transport is used, or
which model generated a proposal.

Pure value objects and enums may live beside entities when they define those
entities. A derived execution plan, queue item, adapter DTO, or model response
does not become a domain entity merely because it is represented by a
Pydantic model.

## Canonical entities and value objects

| Concept | Canonical owner | Role | Explicitly not included |
|---|---|---|---|
| `MethodSpec` | `core.model` | Transport-neutral callable contract: method identity, service, permissions, resource types, request and response schemas | HTTP/gRPC client details, auth tokens, retry policy |
| `FieldSpec`, `RequestSchema`, `ResponseSchema` | `core.model` | Immutable contract schema and field value objects | Codec objects, generated transport classes |
| `PrincipalRef`, `ResourceRef`, `BindingRef` | `core.model` | Typed references used by scenarios and security reasoning | Credentials and adapter-specific resource handles |
| `ScenarioProfile` | `core.model` | Semantic dimensions of one security scenario | Queue state, retry counters, campaign phase |
| `StandState` | `core.model` | Immutable snapshot of resources, principals, bindings, and effective permissions used to bind a scenario | Provisioning commands and live repository state |
| `ScenarioPosition` | `core.model` | The canonical bound-scenario value: identity together with its profile and immutable stand snapshot | Campaign accumulator and mutable run state; there is no second `BoundScenario` model |
| `Check` | `core.model` | One concrete auditable action candidate: method, scenario, identities, and request values | Generator implementation, scheduler state, transport invocation |
| `Observation` | `core.model` | Normalized result of executing a check; the durable evidence anchor for later verification | Raw HTTP/gRPC response objects and secrets |
| `ExecutionTrace`, `TraceStep`, `ResponseData` | `core.model` | Transport-neutral structured evidence consumed by verification oracles | Packet captures, client sessions, adapter logs |
| `Finding` | `core.model` | Stable security result exposed to API/reporting, with evidence references and fingerprint | Oracle algorithm, report format, ticket representation |
| `FindingFingerprint` | `core.model` | Value-free identity used to merge equivalent witnesses | Deduplication storage implementation |
| `AccessOutcome`, `Severity`, `VerdictStatus` | `core.model` | Shared domain vocabulary for observations and security decisions | Per-adapter status enums |
| `DomainEvent` and event records | `core.model.events` | Append-only facts about domain transitions and durable replay links | Event bus, JSONL/SQLite/Neo4j persistence |

The execution chain is therefore:

```text
MethodSpec + StandState + ScenarioProfile
                    ↓ binding
              ScenarioPosition
                    ↓ candidate generation
                  Check
                    ↓ execution
                Observation
                    ↓ verification/oracles
             Verdict / Finding
```

QDL is the declarative source of truth alongside this chain. It is not copied
into a second set of model entities:

```text
QDL graph (facts, rules, norms, learned automata)
       ↓ projections and binding
ScenarioPosition (bound scenario) / Check
       ↓ runtime evidence
Observation → runtime QDL facts → verification → Finding
```

## Types that must not be canonical domain model

### QDL-owned types

`Atom`, `Variable`, `Struct`, `Fact`, `Rule`, `QdlGraph`, contexts, admission,
canonicalization, and QDL validation belong to `core.qdl`. An
`InvariantProjection` that combines a norm identity with a `QdlFact` is a
verification view, not a second source of truth. Its owner is
`verification/invariant_projection.py`; the authoritative
declarative data remains the QDL norm.

### Runtime and verification projections

`VerificationPlan` is a derived binding of a QDL obligation to a method and a
scenario. Its canonical contract belongs to `core/contracts/plan.py`. Runtime
and extensions import it directly from that owner. It is not a canonical domain
entity.

`InvestigationIntent` is not part of the public model facade. It is the payload
of the `InvestigationActionExecuted` event and is owned by `model.events`; the
runtime owns its guarded execution.

`CoverageMatrix`, `NormCoverageRow`, `ObservationEvaluation`, oracle-specific
evidence, classification leads, and promotion results are verification
outputs or policies. They may consume domain entities but must not be added to
`model`.

### Runtime state

`RuntimeState`, `CampaignRoundState`, `SchedulerState`, `Deficit`, work
items, queue entries, execution views, replay state, budgets, and consultation
outcomes are run-local state. They belong to `runtime` even when they contain
references to `Check` or `Observation`.

### Extension and wire contracts

`Payload*`, `Grammar*`, `FormalModelOutput`, `FormalModelWireOutput`, and
seed-enrichment outputs are neutral extension/proposal contracts under
`core.contracts`; `ExecutionFeedback` belongs to runtime feedback. Their
algorithms and model clients remain in fuzzing/LLM packages. They are not
domain entities merely because they are validated with Pydantic.

`EvidenceEvent` is an adapter-ingestion record from response/OOB/eBPF/log
channels. Its neutral boundary contract is owned by `core.ports`; concrete
channel stores remain infrastructure. The domain receives its normalized
result as `Observation` or a normalized evidence value; raw channel records
are not domain entities.

`replay.py`, `graph.py`, `candidate_fields.py`, `candidate_metrics.py`, and
`couplings.py` are
technical helpers or runtime/application contracts and must not be exported as
part of the canonical domain model.

## Initial ownership of the existing files

The first migration keeps the number of domain files small and moves concepts
by responsibility rather than creating a file per class.

```text
core/model/
├── schemas.py       # FieldSpec, MessageSchema, RequestSchema, ResponseSchema
├── checks.py        # MethodSpec, refs, ScenarioProfile, StandState,
│                    # ScenarioPosition, Check and their domain enums
├── evidence.py      # normalized evidence, Observation, Finding and shared
│                    # verdict/severity vocabulary
├── events.py        # event envelope and append-only event contracts
└── __init__.py      # deliberate public exports only
```

The following are removed from the public `model` export surface during the
migration, then moved to their owning package without compatibility aliases:

```text
VerificationPlan       → contracts/plan.py
InvariantProjection    → verification view over a QDL norm
InvestigationIntent    → model/events event payload; runtime executes it
Payload*, Grammar*     → core/contracts extension boundary
FormalModel*           → core/contracts proposal boundary
ExecutionFeedback      → runtime/feedback.py
replay/graph/helpers   → runtime/infrastructure as appropriate
EvidenceEvent          → infrastructure/integration evidence ingestion
```

No code is moved until consumers of each type are classified. During the
migration we preserve one owner and update imports directly; duplicate
classes, wrapper aliases, and parallel “legacy” domain models are forbidden.

## Acceptance checks for the catalog

Before changing the package tree:

1. every public type under `core.model` appears in one of the two tables above;
2. `ScenarioProfile`, `StandState`, and `ScenarioPosition` have one owner in
   `model/checks.py`; no parallel `BoundScenario` type exists;
3. no canonical domain type imports `runtime`,
   `infrastructure`, `presentation`, or an extension package;
4. no QDL fact/rule/norm is duplicated as an independent model entity;
5. a `Check → Observation → Finding` path can be constructed without an
   adapter, event store, queue, or LLM client;
6. adapters and plugins depend on these contracts, while the contracts do not
   depend on adapters or plugins.

