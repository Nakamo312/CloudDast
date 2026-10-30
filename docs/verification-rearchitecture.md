# Verification rearchitecture

Status: active. Base `6594554`; isolated branch `codex/verification-rearchitecture-20261030`.

## Goal and acceptance

Review every module semantically and follow its real consumers. Establish one owner for each rule and domain concept; remove proven duplication and misplaced lifecycle/I/O without adding parallel models, facades or gratuitous files. Preserve QDL trust contexts, evidence, provenance, verdicts/findings, coverage, error order, budgets and DI lifetimes.

Runtime review branch remains untouched. Local code and tests may change; paid models, live targets and publishing are outside this task. A local slice, import contract or test count never completes this goal. Completion requires all module rows assessed, necessary changes implemented and independently reviewed, and every remaining failure/violation explained.

## Model data policy

The user explicitly permits full data disclosure to internal models. Model
contexts therefore retain full captured values subject to technical byte,
leaf, string and token limits; mandatory field-role masking is removed.
This policy concerns model context serialization. QDL admission and security
findings still require their existing deterministic evidence and provenance.
Splitty is installed at `/usr/sbin/splitty` and identifies itself as a DNS Split
manager; no active routing or model call was tested during this refactor.

## Baseline

47 Python modules, 16,491 physical lines, 563 functions/methods, 79 classes. Structural linter: 89 findings. Counts include package initializers; resource YAML is reviewed with its owner. Production deltas count all owners and both sides of moves; tests separately. Docstrings count as nonblank code; no formatter or exclusion changes to manufacture reductions.

## Module ledger

`pending` means not yet semantically accepted. These rows will be updated with findings, actions and evidence.

| Module | Track | Status | Decision / evidence |
|---|---|---|---|
| `__init__.py` | parent | reviewed_validation_pending | Keep: Only package docstring, no API/state/facade. |
| `action_runtime.py` | parent | reviewed_validation_pending | Changes pending: Derived event read ledger, not mutable campaign state. Wrapper/complexity and naming remain open. |
| `contract_projection.py` | parent | independently_reviewed_final_validation_pending | Keep source-schema adapter in verification, no I/O. Four scalar calls use one ordered loop; numeric min/max duplicate emission now shares existing _emit_scalar with Atom-preserving canonicalization. -31 physical LOC, no new entity. 729 complete graph/report old-new comparisons equal; 43 broader tests and16 projector tests pass. Canary suppressing minimum caught by2 tests. Independent review: 152 malformed public inputs and729 raw pre-sort emission-order comparisons unchanged; bodies outside emitters/signatures/provenance unchanged. |
| `coverage.py` | coverage-norms | reviewed_changes_pending | C1/C2/C3. Keep field/resource aspects, effect/state separation and request-executed vs oracle-witness distinction. _build_field_cells=176 lines, _build_effect_cells=111, _runtime_evidence=104; repeated ten-parameter forwarding and private imports from coverage_models. _atom_text/_term_key bodies identical; _declarations has no static caller, neither is a substantive saving. Naming migration: CoverageMatrixBuilder→Builder and build_coverage_matrix→build_matrix, three production/five test consumers, no aliases; exact AST rename equality,170 tests before/after and cold imports passed. Naming delta0 production LOC. Removed forwarding-only build_graph (no found separate callers/overrides/docs/registries): -29 physical lines, one method/signature removed. 71 consumer tests pass before/after;512 complete argument-forwarding combinations and4 error cases equal. build type guard/build_plan hash guard retained. Independent wrapper review confirms no direct/dynamic callers, subclasses, overrides or registrations; exact two AST changes, other guards/arguments unchanged. |
| `coverage_models.py` | coverage-norms | reviewed_validation_pending | Keep evaluator: required=False first, then semantic/setup/channel/primitive/runtime. Name is misleading mixed ownership; no rename-only batch. Do not remove evidence_target schema merely for lacking a production factory call. _reference clone does not justify universal helper; role/reference schema boundaries remain distinct. |
| `differential/__init__.py` | coverage-norms | reviewed_validation_pending | Keep existing exports pending consumer migration; do not add a new facade. No substantive reduction by import moves. |
| `differential/comparator.py` | coverage-norms | reviewed_validation_pending | Keep timing/concurrency distinct. Exact incomplete-response clone belongs to Kepler shared witness kernel; comparator becomes consumer only after parent agrees kernel. Preserve mixed tree/legacy comparisons; shape uses authoritative tree but value union includes legacy. |
| `differential/contracts.py` | coverage-norms | reviewed_validation_pending | Keep experiment-specific models in verification; do not move wholesale to model or public contracts. _payload_fields_from_baseline is live and behavior-sensitive: deleting its string-field fallback changes readback mutation. Stateless stand policy checks marker only, not isolation guarantee. _profile_factors duplicates ordered factor names with value tuple; bounded getattr comparison could remove ~12-20 LOC, secondary only. |
| `differential/modes.py` | coverage-norms | reviewed_validation_pending | Keep. Equal TIMING_REPEATS/MIN_SAMPLES and CONCURRENCY_PROBES/MAX_WORKERS values represent different policy dimensions, not duplication. Avoid file explosion to separate constants. |
| `differential/projection.py` | coverage-norms | reviewed_validation_pending | Keep. Preserve action/observation prefixes, paired fact even for zero dimensions, first-occurrence dimension dedup and runtime context. Small atom helpers encode identifier namespaces; generic abstraction adds little. |
| `differential/report.py` | coverage-norms | reviewed_validation_pending | Keep verification ownership (architecture test pins it). Do not move to packages/reporting or merge with Observation/PolicyVerdict. dimensions may explicitly override derived flags, retain duplicates/order in signature; fields signature uses treatment-only fields today. Changing these is a dedup behavior change, not cleanup. |
| `evaluation.py` | oracle-evidence | reviewed_changes_pending | Consumes read-only evidence view; no own mutable campaign store. Any step/request types obscure existing QdlExecutionStep/LiveRequest contracts; narrow to existing types. Repeated norm compilation and linear readback search need measured shared seam, not new DTOs. |
| `evidence.py` | oracle-evidence | implemented_independent_review_pending | User-authorized full bounded model context: mandatory masks/role-release params/metadata/logger removed; one representation and detached JSON dump with rendered digest. Keep min1024, UTF8/leaf/string/latest-attempt caps, original digest and explicit malformed budget errors. Worker: retention pin old1fail/new1pass;348focused/2597broad pass;135 boundary cases. Batch-252 production physical/-228 nonblank, tests-100physical. QDL roles and admission/findings unchanged; two benchmark modules unavailable (missing benchmarks.nsfy_bench). |
| `evidence_facts.py` | oracle-evidence | reviewed_changes_pending | Constructors do not persist or verify by themselves. supports_dataflows is a pure declared-intent gate, not evidence proof; name/document at consumer rather than invent repository. Keep runtime context filter for verified IDs. |
| `finding_evaluator.py` | oracle-evidence | moved_pending_final_validation | Stateful publication/replay owner moved to runtime/campaign/evaluation.py using the shared EventProjection; pure decision/merge functions belong to verification/findings.py. F1 gate requires accepted deterministic norm and explicit recorded observation reference. |
| `findings.py` | oracle-evidence | reviewed_changes_pending | Fingerprint is root-cause identity, not observation/probe identity. Factory enforces explicit FAIL and check/scenario but not deterministic+grounded+norm+refs; central boundary hardening is semantic and changes tests. |
| `invariant_projection.py` | parent | reviewed_validation_pending | Keep semantics: Norm identity/severity/action/effect indexes are verification semantics; do not merge into runtime path binding. Naming/boundaries validation pending. |
| `norm_coverage.py` | coverage-norms | reviewed_validation_pending | Keep separate from graph coverage: factors have different witnesses. Proposed followup: index paths/checks/provenance once instead of scanning them for each norm/observation; savings unproven, do not claim LOC reduction. _effect/_effect_id/_requirement_term repeat decoding but have different malformed-term fallbacks; preserve before sharing. build_norm_coverage=115 lines, _blocked_reason has 11 parameters; protocol Any hides the execution contract. |
| `norm_view.py` | coverage-norms | merged_pending_final_validation | NormView merged into existing norms.py; distinct validation entrypoints preserved, no re-export shim. 18 production lines and one file removed; focused metadata/error-order and import checks passed. |
| `norms.py` | coverage-norms | reviewed_validation_pending | Keep NormCompilation/NormCompiler for this batch. SemanticNormCompiler creates accepted candidates from grounded semantics; this compiler interprets one accepted fact, so they are not duplicate compilers. QdlInvariant overlaps output but has string norm vs Atom and accepted-path lifecycle; unification needs outside-scope consumer migration. changed maps to marker here but NormView routes changed to differential: intentional tested distinction. |
| `oracles/__init__.py` | oracle-evidence | reviewed_changes_pending | Keep current used exports; description “business services” is stale; eager import fanout is real but no new lazy facade justified. |
| `oracles/action_alignment.py` | oracle-evidence | changed_final_validation_pending | Shared action alignment retained; action_alignment_rationale renamed explain_mismatch in owner and eight actual oracle consumers. No body/signature change or alias. All181 oracle tests pass before/after, Ruff clean; naming-only delta0 LOC. |
| `oracles/classification_lead.py` | oracle-evidence | reviewed_changes_pending | Proposal lead is not an accepted norm or finding. Keep graph context/prefix validation and operator-visible UNSCOREABLE rationale. |
| `oracles/differential.py` | oracle-evidence | reviewed_changes_pending | Reuse canonical completeness helper; preserve channel precedence, partial positive vs complete negative evidence, unique aligned probes and minimum two successes. No transport execution here. |
| `oracles/field_exposure.py` | oracle-evidence | reviewed_changes_pending | Replace exact completeness clone. Preserve schema-index stripping and case-sensitive path matching, principal scope before PASS, full tree needed for absence. |
| `oracles/grounded.py` | oracle-evidence | reviewed_changes_pending | Keep IAM grounding and unknown/missing permissions branches; replace missing_capabilities(method, scenario.stand.effective_permissions) with method.permissions - scenario.stand.effective_permissions; remove import. Parent/Erdos reports all other scenarios helpers test-only. Remove package at its owning scope; no replacement helpers. Reexpress significant tests through GroundedOutcomeOracle behavior. |
| `oracles/latency.py` | oracle-evidence | reviewed_changes_pending | One registry owns method calibration. Separate availability meaning from paired latency; repeated raw norm parser is migration candidate, not mechanically equivalent to NormView. Keep finite paired samples and delivered-error semantics. |
| `oracles/marker.py` | oracle-evidence | reviewed_changes_pending | Import shared witness helpers; remove completeness/echo/response/value clones. Keep action+observation+scenario binding before projection and adversarial-target rule. |
| `oracles/oob.py` | oracle-evidence | changed_pending_final_validation | Pure Oracle owns scoring. Runtime Coordinator owns pending state/deadlines; existing RunScope provider now finalizes collaborator via yield/finally. 71 focused tests plus 11 real-container/docs checks passed; actual poller termination and deregistration tested with fake external transport, no network. Cleanup does not admit final-poll callbacks into a previously returned result. |
| `oracles/primitive_router.py` | oracle-evidence | reviewed_changes_pending | Router is real execution boundary. Extracts all signals even for outcome/sequence/field and witness facade re-parses norm; simplify only after pinning diagnostics and injected witness implementations. |
| `oracles/roles.py` | oracle-evidence | reviewed_changes_pending | Keep candidate semantics, policy validation and default loader. Error/not-found selector methods currently have no production callers; remove only together with reviewed policy schema/data/test consumers. |
| `oracles/sequence.py` | oracle-evidence | independently_reviewed_final_validation_pending | Shared existing transition-verdict assembly between paired and aggregated evidence; selection/order remain distinct. 29 production lines removed, no new entities. 29 tests and 19 full old/new verdict comparisons passed; deliberate FAIL-to-PASS mutation caught by four tests. Independent reviewer compared 1874 complete verdicts old/new, zero differences. |
| `oracles/trace.py` | oracle-evidence | reviewed_changes_pending | Nine-line alias is reused by all primitive signatures. Inlining increases repetition and adds no architectural improvement. |
| `oracles/witness.py` | oracle-evidence | reviewed_changes_pending | Large block duplicates verification.witness; reuse canonical helpers and PathWitness, delete uncalled old helper subgraph. Explicit pair/known-content APIs are test-only today: do not mistake them for live grammar execution. |
| `projection.py` | parent | reviewed_validation_pending | Changes pending: Correct evidence interpretation owner, typed/scoped references and effect proofs distinct; complexity/structure findings open. |
| `promotion.py` | parent | changed_pending_review | Predicate-shape match preserves prior policy gates: preview equality in 4368 synthetic cases and all 229 traced tests; checker120lines/CC48 ->78lines/CC33. Prior admission slice did not finish module. |
| `scenarios/__init__.py` | parent | removed_pending_review | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. |
| `scenarios/capability.py` | parent | removed_pending_review | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. |
| `scenarios/matching.py` | parent | removed_pending_review | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. |
| `secret_shapes.py` | oracle-evidence | reviewed_changes_pending | Not duplicate of accepted semantic roles. Preserve single-action restriction and proposal context. Fix misleading “shape proves a secret” docstring; recursive leaves walker resembles evidence_response_fields but value/path contracts differ. |
| `slices.py` | parent | changed_pending_review | Consolidated duplicate runtime model-slice hash into canonical fingerprint, 24 golden values identical; 135 focused tests passed |
| `spec_projection.py` | parent | reviewed_validation_pending | Keep public feature: Documented recursive input specification is distinct from flat FieldSpec, reused ContractProjector; no artificial wiring/removal. |
| `state_machine_ingestion.py` | parent | moved_pending_review | Existing state and contract ingestion moved into runtime/ingestion.py, body/summary AST equivalent, 311 focused tests and 27 contracts passed; no summary or source_id policy merge. |
| `taxonomy/__init__.py` | oracle-evidence | reviewed_changes_pending | Used by finding construction, runtime deficits and metrics. No independent state. |
| `taxonomy/catalog.py` | oracle-evidence | reviewed_changes_pending | Consolidate repeated norm/candidate selection; constant -len(_constraint_count(entry)) is a correctness issue, not safe cleanup. Keep residual algebra shared between matching and diagnostics; runtime consumes catalog candidate vocabulary. Import-time package YAML is configuration I/O, not persistence. |
| `threat_model.py` | parent | changed_pending_review | Test-only StrideView/Category moved to existing tests/support/threat_model.py; no production consumers or dynamic registrations found; no production runtime behavior added or removed. |
| `witness.py` | oracle-evidence | reviewed_changes_pending | Own shared completeness, echo, response-values and witness-path helpers here. Keep extraction separate from verdict and from transport. Signature claims value-free but includes marker/delta; adjust documentation or explicit consumers after review. |

## Batches

Partial batches in progress: STRIDE test fixture removal; canonical slice fingerprint; runtime ingestion owner; coverage materialization/private-unit removal; witness helper consolidation; predicate-shape admission checker; explicit final finding gate; unused scenario package removal; shared class-catalog selection; removal of mandatory model-context redaction. These are independently scoped changes, not completion of verification.

The final finding gate is a separate requirements repair: FAIL/deterministic/grounded plus a NormCompiler-accepted deterministic norm and an explicit reference to an observation recorded in ExecutionResult. Full oracle evidence is retained, including paired controls and OOB events. A previous worst-latency measurement may be the witness; requiring the latest observation ID was refuted and is not enforced.

No overall completion claim: stateful finding event projection, OOB pending lifecycle, norm layout/metadata, byte-budget verification and the remaining structural/naming findings still need resolution. Repository history remains the rollback boundary.

## Validation and remaining work

Baseline verification/formal + tests/verification + architecture: 1250 passed, 1 skipped. Updated checks and independent review are still in progress. Prior checkout limitations (missing benchmark/profile fixtures and incompatible Hypothesis internals) must be rechecked before treating failures as inherited. Global structural findings are not silently waived.

### OOB resource ownership

The collaborator was already RunScope, but its provider returned an unmanaged
instance. A generator provider now calls `stop()` in `finally`: four additional
production lines, without a new type or port. Before the repair, both normal
and exceptional exit tests failed because stop was absent. Afterward, 71 focused
OOB/provider tests passed. Eleven container/docs checks additionally cover lazy
construction, separate runs, and actual poller termination/final poll/transport
deregistration using a fake transport without network calls.

Independent review accepts cleanup-only semantics. The campaign finalizer
calculates findings before RunScope closes; callbacks received by the shutdown
poll cannot retroactively enter an already returned result. This batch does not
claim a new shutdown-drain or arbitrary concurrent-sweep guarantee.

### Transition verdict assembly

Paired and aggregate state evidence keep separate collection paths and share
the existing verdict constructor. This removes 29 production lines without a
new entity. All 29 focused tests pass; 19 complete verdicts match the previous
implementation on identical inputs. A deliberate FAIL-to-PASS mutation breaks
four existing tests. Independent review additionally compared 1,874 complete
old/new verdicts with zero differences. Final integrated validation remains.

### Contextual names

The alignment helper is now `action_alignment.explain_mismatch` in its owner
and eight oracle consumers. Body, signature and diagnostics are unchanged;
there is no compatibility alias. All 181 oracle tests passed before and after,
and import sorting/lint/format passed. This naming-only batch removes zero
lines and is not counted as simplification of responsibilities or complexity.

The coverage owner now exposes `coverage.Builder` and `build_matrix` through
three production and five test consumers, with no aliases. Exact AST comparison
after normalizing the two renamed symbols is equal. All 170 focused tests passed
before and after; production LOC is unchanged and tests lose two formatting
lines. Canonical coverage models, hash guards and method signatures remain.

### Contract scalar emission

Field type/required/repeated/oneof emission uses one ordered loop. Numeric
minimum/maximum keep their original position after enum emission and now use
the same existing `_emit_scalar`; Atom values are canonically serialized without
wrapping them in a second Atom. The batch removes 31 production lines without
new helpers, types or files. All 729 combinations of absent/single/conflicting
values yield identical full graphs and reports. Forty-three broader tests and
16 projector tests passed; suppressing minimum emission deliberately breaks
two tests. Independent review also compared 152 malformed public inputs and
729 raw emission sequences before report sorting, without differences.

### Coverage forwarding

Removed the forwarding-only `build_graph`: `build` now invokes `_build_qdl`
directly. No separate consumer, override, registration or documentation was
found for the intermediate method. The source type guard in `build` and the
plan/graph hash guard in `build_plan` remain. This removes 29 production lines
and one oversized signature. All 71 focused consumer tests passed before and
after; 512 combinations of optional forwarding arguments and four type-error
cases match the old implementation. Independent review remains pending.


### Evidence budget requirements repair (E2)

Before correction, valid Unicode observations produced 5,120 serialized bytes
under a 4,096-byte cap; caps smaller than the metadata envelope were accepted.
EvidenceBudget now requires at least 1 KiB (the existing reserve), preserving
validation order for nonpositive limits. The default remains 128 KiB.
The fallback keeps its previous prefix whenever it fits; otherwise binary
search shrinks that prefix using actual JSON/UTF-8 bytes. It never grows the
preview. Unrepresentable metadata fails explicitly instead of escaping the cap.
The 23 new boundary cases cover minimum caps, Unicode and JSON escaping;
pre-fix 5 failed / 18 passed, post-fix focused suite 102 passed. This is an
explicit behavior repair. Mandatory role-based redaction is superseded by the
user's internal-model disclosure policy above; byte-budget guarantees remain.

### Current integration snapshot

Relative to `6594554`, all production owners together change by -923 physical
lines and -778 nonblank/noncomment lines, with 33 fewer functions and three
fewer classes. Tests change separately by +964 physical / +887 nonblank lines.
These counts include new runtime files and both sides of moves. They describe
this intermediate snapshot, not a final reduction or completion claim.

Ruff across packages/tests and all 27 import contracts pass. Structural checks
still report 74 findings after removing the coverage forwarding signature;
long functions, signatures and semantic ownership review remain active work.

The integrated current-snapshot suite finished with 2,647 passed, one skipped
and two failures. Both failure node IDs and the `many.more` AttributeError
match the recorded inherited Hypothesis incompatibility. This is not a claim
that the whole repository suite is green. The evidence worker separately ran
2,597 tests successfully; its two changed benchmark modules could not run
because `benchmarks.nsfy_bench` is absent from this checkout.
