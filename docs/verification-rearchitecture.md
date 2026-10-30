# Verification rearchitecture

Status: **active**. Baseline: `6594554`. Branch:
`codex/verification-rearchitecture-20261030`. Runtime review branch is unchanged.

## Acceptance boundary

Review all 47 original production modules and their real consumers. Give each
concept one owner, remove proven duplicates and forwarding, and keep campaign
state and transport lifecycle outside verification. Preserve QDL contexts,
provenance, verdict/findings gates, coverage meanings, diagnostics, budgets and
DI scopes. Short names must express the local role without compatibility aliases.

Completion requires a disposition for every module and finding, independent
review, and classification of every test failure and residual structural issue.
A local cut or green import check is not completion. The remaining work below
is part of the active goal. No live target, paid model call or publication ran.

## Owners and current behavior

| Responsibility | Owner |
|---|---|
| Formal facts and contexts | Existing QDL model, compiler and admission contracts |
| Norm interpretation and view | `verification/norms.py`: NormCompilation, NormCompiler, NormView |
| Deterministic evidence/coverage decisions | Verification; graph, runtime and per-norm views retain different witnesses |
| Finding admission, fingerprint and merge | Pure `verification/findings.py` |
| Event cursor, recovery and publication | `runtime/campaign/evaluation.py`, sharing the existing EventProjection |
| Callback wait, deadlines and pending state | `runtime/oob.py` Coordinator |
| Callback security verdict | Pure `verification/oracles/oob.py` Oracle |
| Callback transport creation/closing | Existing RunScope generator provider, `yield/finally` |
| Contract and state-machine ingestion | `runtime/ingestion.py`; assembly owns external connections |
| Shared completeness, echo and path helpers | `verification/witness.py`; consumers retain their distinct matching rules |
| Model context | One bounded EvidenceView representation over captured data |

Finding emission requires FAIL, deterministic and grounded verdicts, a
NormCompiler-accepted deterministic norm, and an explicit reference resolving to
an observation in ExecutionResult. Evidence is not synthesized. A recorded prior
worst-latency observation may be the witness; paired/control/OOB refs remain.

The user permits full data disclosure to internal models. Mandatory model-context
field-role masking and its configuration are removed. Byte, leaf, string and token
limits remain: minimum envelope 1 KiB, default cap 128 KiB. Dumps are detached JSON
copies, rendered digests cover those copies, reconstruction is idempotent and
unrepresentable metadata raises ValueError. QDL truth and finding gates remain.
Manual EvidenceView without budget metadata retains prior uncapped behavior;
its Mapping is readonly by contract, not deeply immutable. No production mutation
was found. Splitty is installed; active routing and model calls were not tested.

## API consolidation

Promotion accepts the existing ProposalPromotionRequest and separate campaign
caps. Runtime no longer unpacks the request into eleven scalar arguments.
Action-ID normalization precedes cap/graph checks, preserving the production
call order. Ordered trust/evidence passes, context.with_evidence_refs, parking,
lock coverage and budget accounting remain. Normally constructed requests retain
cap error order. Unsupported old raw threshold/action shapes are an explicit API
migration limitation; their constructor/error behavior is not claimed equivalent.
No compatibility path or new request type was added.

Coverage uses the existing Builder directly. Forwarding `build_graph` and
`build_matrix` are removed. The source type guard and build_plan graph-hash guard
remain. The invariant mapping is a binding snapshot: replacing it with a fresh
graph-derived index changes coverage by losing an event key. Remaining arguments
are not hidden in a new options DTO. QDL exposure constants come from their
canonical owner; four query variables belong to their sole builder consumer.

Norm coverage consumes existing ExecutionResult and QdlExecutionView, replacing
three redundant Protocols. Two scheduler Protocols remain to avoid a runtime
back-dependency. Attribution uses provenance values; historical paths use its
keys. Direct canonical lookup replaces a redundant index of singleton lists.
The existing attribution helper owns its sole-use index. Fallback, duplicate
observations, whole-path actions, deferred hashing and malformed-value errors
remain. The build function is still 129 lines; this residual issue is recorded.

The private duration decoder remains distinct from NormView. Real Fact and
InvariantProjection inputs demonstrate different behavior for Variable norm
identifiers; direct primitive diagnostics cannot be replaced by router checks.
Its private names are now _Duration and _parse_duration, with unchanged bodies.

## Measurements

Counts compare the union of baseline and current files, including committed
deletions, new runtime files and both sides of moves. No formatting/exclusion
changes manufacture the reduction. Nonblank counts exclude comments, not docstrings.

| Scope | Baseline | Current | Delta |
|---|---:|---:|---:|
| All production, physical LOC | 85,620 | 84,559 | −1,061 |
| All production, nonblank/noncomment LOC | 74,144 | 73,248 | −896 |
| All production functions | 3,345 | 3,306 | −39 |
| All production classes | 733 | 727 | −6 |
| Tests, physical LOC | 105,280 | 106,526 | +1,246 |
| Tests, nonblank/noncomment LOC | 90,285 | 91,430 | +1,145 |
| Verification modules | 47 | 40 | −7 |
| Verification physical LOC | 16,491 | 15,078 | −1,413 |
| Verification functions | 563 | 506 | −57 |
| Verification classes | 79 | 67 | −12 |
| Verification structural findings | 89 | 69 | −20 |

All-production cyclomatic-complexity sum decreases by 152; maximum decreases
from 48 to 38. These are intermediate measurements, not completion criteria.

## Verification evidence

The current integrated suite covers verification formal/oracle/catalog cases,
verification, architecture, execution workflow and review C3/L1 tests:
**2,658 passed, one skipped, two inherited failures** in 81.29 seconds. Both failed
nodes are in test_path_runner_fuzzing.py: grammar-generator feedback and finding
shrink/replay. Both raise the previously recorded Hypothesis `many.more`
AttributeError. This does not claim the whole repository suite is green.
Two changed benchmark modules remain unrun because benchmarks.nsfy_bench is absent.

Ruff across packages/tests passes. All 27 import contracts pass. Changed sources
pass formatting and diff checks; an unrelated baseline automata format issue is
not silently attributed to this batch.

| Boundary | Behavioral evidence |
|---|---|
| Promotion request | 144 tests; 130 pure and 780 actual Policy comparisons of full results, issues, logs and accounting; independent AST/freeze/lock review |
| Coverage forwarding | 331 tests before/after; 512 argument combinations and source/hash errors; Builder AST unchanged; independent acceptance |
| Norm coverage | 21 before/after pins, 26 consumer/finalization tests, 2,592 row comparisons, nine errors and 12 finding cases; key/value conflation canary; 45 independent comparisons |
| Shared witness helpers | 446 focused tests, 1,026 original comparisons; independent 132 consumer comparisons; negative echo/completeness canaries |
| Finding gate | 24-case policy matrix, prior-latency witness regression, actual collector/primitive paths |
| Model evidence | 348 focused and 2,597 broader tests; 135 boundary cases, independent 72 adversarial cases and 216 reconstructions; malformed metadata checks |
| Transition verdict | 29 tests, 19 original and 1,874 independent full verdict comparisons; FAIL-to-PASS canary breaks four tests |
| Contract projection | 729 full graph/report and raw-order cases, 152 malformed inputs, 32,448 edge cases, 600 annotation cases; direction and bound-emission canaries |
| Action ledger | 62 tests and 2,058 comparisons; bound/planned/recovery and tie behavior retained |
| Ingestion | 311 tests, body/summary equivalence, actual CLI/DI consumers and cold imports |
| OOB resource cleanup | 71 focused tests plus real-container lifecycle checks using fake transport, including actual poller termination and deregistration |

## Module ledger

Rows track the original modules, including removals and moves. A reviewed local
change can still have remaining module work. Only explicit accepted states close
a module; global acceptance remains incomplete.

| Original module | State | Decision and remaining work |
|---|---|---|
| `__init__.py` | accepted_unchanged | Keep: Only package docstring, no API/state/facade. |
| `action_runtime.py` | changed_independent_review_pending | Pure event-derived ledger stays verification; explicit bound/planned/recovery semantics retained. Shared _step_actions removes two copies; removed _term_key wrapper, stable min selects deficit, nullable Check fallback simplified.163→154LOC, buildCC20→17,62tests+2058old/newcomparisons pass, no new tests/types. declared_actions and three production consumers retained. |
| `contract_projection.py` | independently_reviewed_further_disposition_pending | Keep source-schema adapter in verification, no I/O. Four scalar calls use one ordered loop; numeric min/max duplicate emission now shares existing _emit_scalar with Atom-preserving canonicalization. -31 physical LOC, no new entity. 729 complete graph/report old-new comparisons equal; 43 broader tests and16 projector tests pass. Canary suppressing minimum caught by2 tests. Independent review: 152 malformed public inputs and729 raw pre-sort emission-order comparisons unchanged; bodies outside emitters/signatures/provenance unchanged. After5614d10: one edge-spec table owns labels/predicate/direction, special term construction preserved;32448 raw returns/errors equal,CC20→12,-19LOC. Unknown-label report folding preserves600raw facts/issues sequences with positive/empty/dualunknown coverage; emit_annotation105→96lines/CC13→12,-9LOC.46consumer tests pass; inversion canarygoldenfails; independentreview pending. Independent15symbolic predicate/direction references and guard checks agree; all15specs verified; source-selection/parser ASTunchanged, edge/annotation diagnostic order preserved. |
| `coverage.py` | independently_reviewed_remaining_work | One Builder owns graph/plan coverage; removed forwarding build_graph and module build_matrix, callers directly Builder.build. Preserve typeguard/hashguard/profiles and allbinding snapshotinputs. Newwrappercut-29productionLOC;331before/aftertests,512forward/errorcomparisons and independentreview accepted. Prior sharedfield/effectmaterialization-95LOC,constant-ownercleanup-10LOC; imports57 stillover40. Longmethods/signatures and structure remain; derivinginvariantsfromgraph losesboundeventkey, so kwargs not replaced by a bag. |
| `coverage_models.py` | changed_final_module_disposition_pending | Keep evaluator: required=False first, then semantic/setup/channel/primitive/runtime. Name is misleading mixed ownership; no rename-only batch. Do not remove evidence_target schema merely for lacking a production factory call. _reference clone does not justify universal helper; role/reference schema boundaries remain distinct. Removed compatibility exposure-constant alias/import; four builder-only query variables movedtoactualconsumer. Coveragealgebra, typed deficit priority, schema/factfactory and publicexports unchanged. Two-filecleanup -10productionLOC,62before/aftertests, canonicalexposureconstantobjectidentity and4queryvariablevalues preserved. |
| `differential/__init__.py` | reviewed_validation_pending | Keep existing exports pending consumer migration; do not add a new facade. No substantive reduction by import moves. |
| `differential/comparator.py` | reviewed_validation_pending | Keep timing/concurrency distinct. Exact incomplete-response clone belongs to Kepler shared witness kernel; comparator becomes consumer only after parent agrees kernel. Preserve mixed tree/legacy comparisons; shape uses authoritative tree but value union includes legacy. |
| `differential/contracts.py` | reviewed_validation_pending | Keep experiment-specific models in verification; do not move wholesale to model or public contracts. _payload_fields_from_baseline is live and behavior-sensitive: deleting its string-field fallback changes readback mutation. Stateless stand policy checks marker only, not isolation guarantee. _profile_factors duplicates ordered factor names with value tuple; bounded getattr comparison could remove ~12-20 LOC, secondary only. |
| `differential/modes.py` | changed_final_review_pending | Keep distinct timing repeat/minsample and concurrency probe/worker policies despite equal values. Runtime DIFF_MODES now derives from canonical DiffMode Literal via typing.get_args, removing duplicated closed vocabulary: -2physicalLOC. Existing configuration parser pin passes before/after;61projector+differentialtests pass; no new abstraction. |
| `differential/projection.py` | accepted_unchanged | Accepted unchanged: pure projection of measured dimensions into runtime QDL; pairing, treatment evidence and normalized IDs covered by targeted tests. No I/O/state or structural findings. |
| `differential/report.py` | accepted_unchanged | Accepted unchanged: paired/aggregate measurement contract, distinct from Observation and presentation reporting. Comparator/timing/concurrency and current evidence consumer tested. Signature remains a coarse identity: different control-only fields may collide; persisted-revision uniqueness is not established here. |
| `evaluation.py` | reviewed_changes_pending | Consumes read-only evidence view; no own mutable campaign store. Any step/request types obscure existing QdlExecutionStep/LiveRequest contracts; narrow to existing types. Repeated norm compilation and linear readback search need measured shared seam, not new DTOs. |
| `evidence.py` | independently_reviewed_final_module_acceptance_pending | User-authorized full bounded model context: mandatory masks/role-release params/metadata/logger removed; one representation and detached JSON dump with rendered digest. Keep min1024, UTF8/leaf/string/latest-attempt caps, original digest and explicit malformed budget errors. Worker: retention pin old1fail/new1pass;348focused/2597broad pass;135 boundary cases. Batch-252 production physical/-228 nonblank, tests-100physical. QDL roles and admission/findings unchanged; two benchmark modules unavailable (missing benchmarks.nsfy_bench). Independent review accepts:72adversarial cases strictUTF8 caps,216idempotent reconstructions,10malformed metadata cases rejected, nestedcopies/digests correct,25helper ASTunchanged. Manual views without budget keep prior uncapped behavior; Mapping is readonly by contract, no production mutation found. |
| `evidence_facts.py` | reviewed_changes_pending | Constructors do not persist or verify by themselves. supports_dataflows is a pure declared-intent gate, not evidence proof; name/document at consumer rather than invent repository. Keep runtime context filter for verified IDs. |
| `finding_evaluator.py` | moved_pending_final_validation | Stateful publication/replay owner moved to runtime/campaign/evaluation.py using the shared EventProjection; pure decision/merge functions belong to verification/findings.py. F1 gate requires accepted deterministic norm and explicit recorded observation reference. |
| `findings.py` | reviewed_changes_pending | Fingerprint is root-cause identity, not observation/probe identity. Factory enforces explicit FAIL and check/scenario but not deterministic+grounded+norm+refs; central boundary hardening is semantic and changes tests. |
| `invariant_projection.py` | accepted_unchanged | Accepted unchanged: owner of binding identity and norm indexes. Mutable index and frozen planned_ids have distinct roles; dedup, action binding and exclusion of proposal transitions verified. No structural findings. |
| `norm_coverage.py` | independently_reviewed_structural_disposition_pending | Corrected canonical-type/index batch443→397(-46physical,-30code excludingdocstrings),-3Protocols,-5helpers. ExecutionResult/QdlExecutionView canonical;2schedulerprotocols retained. Canonicalprovenance lookup directly, attribution-index ownedsolelybyexistinghelper.21pins/26consumercases/2592rows/9errors/12findingcases+canary/coldimports pass. Independent45comparisons(39returns6errors) accepted; key/value distinction, malformedNone/emptyhistory/wholepathactions/fallback/deferredhash preserved. build115→129 andhelper25→30: remaininglongfunction/sig review notwaived. |
| `norm_view.py` | merged_pending_final_validation | NormView merged into existing norms.py; distinct validation entrypoints preserved, no re-export shim. 18 production lines and one file removed; focused metadata/error-order and import checks passed. |
| `norms.py` | reviewed_validation_pending | Keep NormCompilation/NormCompiler for this batch. SemanticNormCompiler creates accepted candidates from grounded semantics; this compiler interprets one accepted fact, so they are not duplicate compilers. QdlInvariant overlaps output but has string norm vs Atom and accepted-path lifecycle; unification needs outside-scope consumer migration. changed maps to marker here but NormView routes changed to differential: intentional tested distinction. |
| `oracles/__init__.py` | reviewed_changes_pending | Keep current used exports; description “business services” is stale; eager import fanout is real but no new lazy facade justified. |
| `oracles/action_alignment.py` | changed_final_validation_pending | Shared action alignment retained; action_alignment_rationale renamed explain_mismatch in owner and eight actual oracle consumers. No body/signature change or alias. All181 oracle tests pass before/after, Ruff clean; naming-only delta0 LOC. |
| `oracles/classification_lead.py` | reviewed_changes_pending | Proposal lead is not an accepted norm or finding. Keep graph context/prefix validation and operator-visible UNSCOREABLE rationale. |
| `oracles/differential.py` | reviewed_changes_pending | Reuse canonical completeness helper; preserve channel precedence, partial positive vs complete negative evidence, unique aligned probes and minimum two successes. No transport execution here. |
| `oracles/field_exposure.py` | reviewed_changes_pending | Replace exact completeness clone. Preserve schema-index stripping and case-sensitive path matching, principal scope before PASS, full tree needed for absence. |
| `oracles/grounded.py` | reviewed_changes_pending | Keep IAM grounding and unknown/missing permissions branches; replace missing_capabilities(method, scenario.stand.effective_permissions) with method.permissions - scenario.stand.effective_permissions; remove import. Parent/Erdos reports all other scenarios helpers test-only. Remove package at its owning scope; no replacement helpers. Reexpress significant tests through GroundedOutcomeOracle behavior. |
| `oracles/latency.py` | reviewed_changes_pending | One registry owns method calibration. Separate availability meaning from paired latency; repeated raw norm parser is migration candidate, not mechanically equivalent to NormView. Keep finite paired samples and delivered-error semantics. N1disposition: retain private decoder/DTO as a distinct direct-API boundary adapter; actualPydantic Variable-ID norm parses locally but NormView rejects. No artificial NormCompilation/tuple replacement. Public APIdiagnostic ordering maintained. Long evaluate_policy/naming remain open. Private semanticnames corrected: _LatencyNorm→_Duration and_parse_latency_norm→_parse_duration, onefile/zeroLOC/normalizedASTequal/191tests beforeandafter. PublicprimitiveAPIs unchanged. |
| `oracles/marker.py` | reviewed_changes_pending | Import shared witness helpers; remove completeness/echo/response/value clones. Keep action+observation+scenario binding before projection and adversarial-target rule. |
| `oracles/oob.py` | changed_pending_final_validation | Pure Oracle owns scoring. Runtime Coordinator owns pending state/deadlines; existing RunScope provider now finalizes collaborator via yield/finally. 71 focused tests plus 11 real-container/docs checks passed; actual poller termination and deregistration tested with fake external transport, no network. Cleanup does not admit final-poll callbacks into a previously returned result. |
| `oracles/primitive_router.py` | reviewed_changes_pending | Router is real execution boundary. Extracts all signals even for outcome/sequence/field and witness facade re-parses norm; simplify only after pinning diagnostics and injected witness implementations. |
| `oracles/roles.py` | reviewed_changes_pending | Keep candidate semantics, policy validation and default loader. Error/not-found selector methods currently have no production callers; remove only together with reviewed policy schema/data/test consumers. |
| `oracles/sequence.py` | independently_reviewed_final_validation_pending | Shared existing transition-verdict assembly between paired and aggregated evidence; selection/order remain distinct. 29 production lines removed, no new entities. 29 tests and 19 full old/new verdict comparisons passed; deliberate FAIL-to-PASS mutation caught by four tests. Independent reviewer compared 1874 complete verdicts old/new, zero differences. |
| `oracles/trace.py` | accepted_unchanged | Nine-line alias is reused by all primitive signatures. Inlining increases repetition and adds no architectural improvement. |
| `oracles/witness.py` | reviewed_changes_pending | Large block duplicates verification.witness; reuse canonical helpers and PathWitness, delete uncalled old helper subgraph. Explicit pair/known-content APIs are test-only today: do not mistake them for live grammar execution. |
| `projection.py` | reviewed_validation_pending | Changes pending: Correct evidence interpretation owner, typed/scoped references and effect proofs distinct; complexity/structure findings open. |
| `promotion.py` | independently_reviewed_remaining_work | Canonical ProposalPromotionRequest replaces11raw promotion arguments at soleproductionPolicycaller; -14productionLOC, no newDTO/alias.144before/aftertests;130pure+780Policy fullresult/issues/log/budget comparisons equal. Independent AST and freeze/lock/order review accepted. Actionnormalization first,then caps/declarations; all54otherpurefunctions unchanged. Oldunsupportedrawshapes explicitly outside migratedcontract. Long semantic/response/norm-admission functions remain. |
| `scenarios/__init__.py` | removed_pending_review | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. |
| `scenarios/capability.py` | removed_pending_review | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. |
| `scenarios/matching.py` | removed_pending_review | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. |
| `secret_shapes.py` | reviewed_changes_pending | Keep proposal-only heuristic sensor. Corrected docstring: shapes produce proposal leads, never prove a secret/classification. Schema/value leaf walker differs from model evidence path extraction; no forced merge. |
| `slices.py` | changed_pending_review | Consolidated duplicate runtime model-slice hash into canonical fingerprint, 24 golden values identical; 135 focused tests passed |
| `spec_projection.py` | accepted_unchanged | Accepted unchanged: README-documented recursive specification adapter. Recursive SpecField differs from flat FieldSpec; nested projection and shared contract report verified. No I/O/campaign state or structural findings. |
| `state_machine_ingestion.py` | moved_pending_review | Existing state and contract ingestion moved into runtime/ingestion.py, body/summary AST equivalent, 311 focused tests and 27 contracts passed; no summary or source_id policy merge. |
| `taxonomy/__init__.py` | reviewed_changes_pending | Used by finding construction, runtime deficits and metrics. No independent state. |
| `taxonomy/catalog.py` | reviewed_changes_pending | Consolidate repeated norm/candidate selection; constant -len(_constraint_count(entry)) is a correctness issue, not safe cleanup. Keep residual algebra shared between matching and diagnostics; runtime consumes catalog candidate vocabulary. Import-time package YAML is configuration I/O, not persistence. |
| `threat_model.py` | changed_pending_review | Test-only StrideView/Category moved to existing tests/support/threat_model.py; no production consumers or dynamic registrations found; no production runtime behavior added or removed. |
| `witness.py` | reviewed_changes_pending | Own shared completeness, echo, response-values and witness-path helpers here. Keep extraction separate from verdict and from transport. Signature claims value-free but includes marker/delta; adjust documentation or explicit consumers after review. Corrected signature docstring: keys include timingdelta/marker, not value-free. Executable bodies still identical tobase; only this docstring differs. |

## Remaining work and limits

Structural checks still report 26 complexity, 17 namespace, 16 length, nine
signature and one import-block findings. Assess them against responsibility and
canonical contracts; do not add DTOs, aliases or helper files merely to silence
rules. Large promotion, coverage, projection, slices and taxonomy routines remain
part of this goal. Four unchanged projection modules are accepted after 75 targeted tests and
13 contract probes: differential projection/report, invariant projection and
spec projection. The full per-module disposition and final broad review remain.

Characterized limitations are not silently repaired under cleanup:

- OOB shutdown polls after the campaign result cutoff; those callbacks cannot
  retroactively enter returned findings. A stuck poller can still prevent clean
  deregistration. Cleanup does not claim a shutdown-drain guarantee.
- Direct Coordinator API retains same-marker/two-norm last-registration behavior.
  Shipping paths classify each observation only under its step invariant; readback
  reevaluation is limited to changed/transition, and reuse excludes normed steps.
  No shipping reachability of the collision was proved. Arbitrary injected
  targets/generators are not guaranteed unique by a hard runtime assertion.
- Explicit pair API has a baseline mixed echo/non-echo correctness candidate;
  a live finding path was not established.
- Finalization omits recovery paths in one coverage call. A pure-seam difference
  is characterized, but reachability with an incomplete shipping event stream
  remains unproved.
- DiffReport.signature can merge distinct control-only fields. It is a coarse
  identity, not a proved content hash for persisted revisions.
- Existing duration decoders treat float budgets as incomplete and accept
  negative integer budgets. This requires a separate policy decision, not an
  unannounced dedup change.

No publication is part of this checkpoint. The runtime review branch remains
at 1c563c2db8571c54650cd0d3b4d9671b2ce37af9 and is unchanged.
