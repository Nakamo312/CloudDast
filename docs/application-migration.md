# Application migration map

## Purpose

`cloud_dast.application` has been removed. The target architecture has no
application layer. This document records the final ownership decisions for the
former modules and the invariants that keep the namespace from returning.

The migration rule is semantic ownership, not directory symmetry: a module is
moved only after its lifecycle, dependencies, and public consumers are known.

## Confirmed first migrations

| Former module | Current owner | Evidence/invariant |
|---|---|---|
| `application/verification/scenarios/capability.py` | `verification/scenarios/capability.py` | Pure capability calculation over `MethodSpec` and a permission snapshot; no runtime or I/O dependency |
| `application/verification/scenarios/matching.py` | `verification/scenarios/matching.py` | Pure resource matching over `ScenarioPosition` and `MethodSpec` |
| `application/shared/indexing.py` | removed | One runtime call site; a local dictionary comprehension is the complete operation |

These moves remove the application namespace from the scenario capability
path. The old application files are deleted; no compatibility module remains.

## Canonical scenario model

The former scenario concepts are deliberately not merged into a generic
mutable object:

| Concept | Canonical owner | Meaning |
|---|---|---|
| `ScenarioProfile` | `core/model/checks.py` | immutable semantic classification |
| `StandState` | `core/model/checks.py` | immutable resources/principals/permissions snapshot |
| `ScenarioPosition` | `core/model/checks.py` | the single bound-scenario value combining identity, profile, and stand |

`BoundScenario` is the architectural concept, not a second Python model. This
keeps scenario identity separate from mutable campaign state and prevents
duplicate profile/stand wrappers from reappearing in runtime or reporting.

## Proposed ownership map

### Reporting

| Module | Target | Status |
|---|---|---|
| `application/reporting/service.py` | `packages/reporting` read-model service | migrated |
| `application/reporting/metrics.py` | `core/runtime/metrics_models.py` | migrated |
| `application/reporting/events.py` | `packages/reporting` report events | migrated |
| `application/reporting/ablation.py` | `packages/reporting` benchmark/report artifact | migrated |
| `application/reporting/__init__.py` | removed | migrated |

Reporting may consume domain events and verification outputs, but must not
participate in planning or execution.

### Runtime and campaign execution

| Module | Target | Status |
|---|---|---|
| `application/verification/campaign.py` | `core/runtime/campaign/replay.py` | migrated |
| `application/verification/campaign_dag.py` | `core/runtime/campaign_dag.py` | migrated |
| `application/verification/execution_results.py` | `core/runtime/execution_results.py` | migrated |
| `application/verification/plan.py` | `core/contracts/plan.py` | migrated |
| `application/verification/reference_projection.py` | `core/runtime/reference_projection.py` | migrated |
| `application/verification/resource_projection.py` | `core/runtime/resource_projection.py` | migrated |
| `application/verification/planning.py` | `core/runtime/planning.py` | migrated |

The runtime owns mutable campaign state, queueing, budgets, replay, and
execution coordination. It may consume QDL plans, but it must not own QDL
ontology or duplicate QDL facts.

### Verification and security decisions

| Module | Target | Status |
|---|---|---|
| `application/verification/finding_evaluator.py` | `core/verification/finding_evaluator.py` | migrated; kept separate from pure ObservationEvaluator |
| `application/verification/invariant_projection.py` | `core/verification/invariant_projection.py` | migrated |
| `formal/observation_projection.py` | `core/verification/projection.py` | migrated |
| `formal/contract_projection.py` | `core/verification/contract_projection.py` | migrated |
| `formal/spec_projection.py` | `core/verification/spec_projection.py` | migrated |
| `formal/secret_shapes.py` | `core/verification/secret_shapes.py` | migrated |
| `formal/threat_compiler.py` | `core/qdl/threat_compiler.py` | migrated |

Verification owns deterministic interpretation of evidence, finding admission,
coverage, taxonomy, and oracle decisions. It must not own transport calls,
campaign lifecycle, or model-client dispatch.

### QDL and declarative compilation

| Module | Target | Status |
|---|---|---|
| `application/campaign_intents.py` | `core/qdl/intents.py` | migrated |
| `formal/semantic_norm_compiler.py` | `core/qdl/semantic_norm_compiler.py` | migrated |
| `formal/state_machine.py` | `core/qdl/state_machine.py` | migrated |
| `formal/state_machine_spec.py` | `core/qdl/state_machine_spec.py` | migrated |
| `formal/policy_projection.py` | `core/qdl/policy_projection.py` | migrated |
| `formal/graph_slice.py` | `core/qdl/graph_slice.py` | migrated |
| `formal/payload_hints.py` | `core/runtime/payload_hints.py` | migrated |
| `formal/grammar_facts.py` | `core/runtime/grammar_facts.py` | migrated |
| `formal/asp.py` | removed facade; use `core/qdl.asp` | migrated |
| `formal/binding.py` | removed facade; use `core/binding.py` | migrated |
| `formal/clingo_engine.py` | removed facade; use `core/qdl.engine` | migrated |
| `formal/couplings.py` | removed facade; use `core/couplings.py` | migrated |

QDL remains the single source of truth for declarative intent. A QDL module may
compile or project the graph, but cannot own runtime state or external I/O.

## Complete former-source inventory

The last pre-migration source inventory contained the following modules. Every
one has a final owner or an explicit removal decision:

| Former module | Final owner | Decision |
|---|---|---|
| `application/shared/indexing.py` | — | removed; one local lookup was sufficient |
| `application/__init__.py`, `verification/__init__.py`, `formal/__init__.py` | — | removed compatibility facades |
| `application/verification/campaign.py` | `runtime/campaign/replay.py` | moved |
| `application/verification/campaign_dag.py` | `runtime/campaign_dag.py` | moved |
| `application/verification/execution_results.py` | `runtime/execution_results.py` | moved |
| `application/verification/finding_evaluator.py` | `verification/finding_evaluator.py` | moved |
| `application/verification/invariant_projection.py` | `verification/invariant_projection.py` | moved |
| `application/verification/planning.py` | `runtime/planning.py` | moved |
| `application/verification/reference_projection.py` | `runtime/reference_projection.py` | moved |
| `application/verification/resource_projection.py` | `runtime/resource_projection.py` | moved |
| `application/verification/scenarios/capability.py` | `verification/scenarios/capability.py` | moved |
| `application/verification/scenarios/matching.py` | `verification/scenarios/matching.py` | moved |
| `application/verification/formal/asp.py` | `qdl/asp.py` | moved |
| `application/verification/formal/axis_grounding.py` | `runtime/axis_grounding.py` | moved |
| `application/verification/formal/campaign_graphs.py` | `runtime/campaign/graph.py` | moved and renamed |
| `application/verification/formal/clingo_engine.py` | `qdl/engine.py` | moved |
| `application/verification/formal/contract_projection.py` | `verification/contract_projection.py` | moved |
| `application/verification/formal/grammar.py` | `contracts/grammar.py` | moved |
| `application/verification/formal/grammar_facts.py` | `runtime/grammar_facts.py` | moved |
| `application/verification/formal/graph_slice.py` | `qdl/graph_slice.py` | moved |
| `application/verification/formal/grounding.py` | `runtime/grounding.py` | moved |
| `application/verification/formal/ingestion.py` | `composition/formal_ingestion.py` | moved and renamed |
| `application/verification/formal/observation_projection.py` | `verification/projection.py` | moved |
| `application/verification/formal/payload_hints.py` | `runtime/payload_hints.py` | moved |
| `application/verification/formal/policy_projection.py` | `qdl/policy_projection.py` | moved |
| `application/verification/formal/projection.py` | `qdl/projection.py` | moved |
| `application/verification/formal/qdl_projection.py` | — | removed facade; canonical projection is `qdl/projection.py` |
| `application/verification/formal/secret_shapes.py` | `verification/secret_shapes.py` | moved |
| `application/verification/formal/semantic_norm_compiler.py` | `qdl/semantic_norm_compiler.py` | moved |
| `application/verification/formal/spec_projection.py` | `verification/spec_projection.py` | moved |
| `application/verification/formal/state_machine.py` | `qdl/state_machine.py` | moved |
| `application/verification/formal/threat_compiler.py` | `qdl/threat_compiler.py` | moved |
| `application/reporting/service.py` | `packages/reporting` | extracted |
| `application/reporting/metrics.py` | `runtime/metrics_models.py` | moved |
| `application/reporting/events.py` | `packages/reporting` | extracted |
| `application/reporting/ablation.py` | `packages/reporting` | extracted |

The inventory is intentionally about semantic responsibility, not one-file
replacement. Several former files were facades or duplicate ownership points;
those are recorded as removed rather than recreated under a new path.

## Completion criteria

1. `packages/core/src/cloud_dast/application` contains no Python modules.
2. Production packages contain no `cloud_dast.application` imports.
3. Tests import the canonical owner directly; no compatibility facade is kept.
4. Reporting is an optional package connected through `ReportPublisher` at
   composition time, so core runtime does not import reporting.

Each step must preserve probe markers, evidence provenance, replay, budgets,
identity binding, and deterministic finding semantics. A green unit test alone
does not prove those boundaries; each migration needs an import check and a
characterization test at its existing public seam.

## Validation status

The transitional namespace is removed. The migration-specific architecture
checks and import-linter pass after extracting runtime-neutral contracts into
`core/contracts` (`plan.py`, `feedback.py`, `execution.py`, and
`candidate_metrics.py`).

Three live-workflow characterization tests still execute one extra
content-versioned path each in the current branch (5/5/3 observations instead
of 4/3/2). This is recorded as a separate behavioral follow-up; it is not
hidden by the structural migration and does not reintroduce an application
layer.
