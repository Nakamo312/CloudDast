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
| Model context | One bounded evidence.View representation over captured data |

Finding emission requires FAIL, deterministic and grounded verdicts, a
NormCompiler-accepted deterministic norm, and an explicit reference resolving to
an observation in ExecutionResult. Evidence is not synthesized. A recorded prior
worst-latency observation may be the witness; paired/control/OOB refs remain.

The user permits full data disclosure to internal models. Mandatory model-context
field-role masking and its configuration are removed. Byte, leaf, string and token
limits remain: minimum envelope 1 KiB, default cap 128 KiB. Dumps are detached JSON
copies, rendered digests cover those copies, reconstruction is idempotent and
unrepresentable metadata raises ValueError. QDL truth and finding gates remain.
Manual View without budget metadata retains prior uncapped behavior;
its Mapping is readonly by contract, not deeply immutable. No production mutation
was found. Splitty is installed; active routing and model calls were not tested.
The authorization covers captured data passed to the configured internal models.
It does not change what counts as evidence of a target vulnerability: QDL field
roles and target response-redaction semantics still participate in verification.

## API consolidation

PrimitiveOracleRouter consumes the existing WitnessSignalOracle as one
component. RunScope owns its latency, marker and OOB wiring; the router no
longer retains duplicate latency/marker attributes just for construction.
The constructor has five parameters instead of nine. This removes four
production lines across router and provider, while preserving standalone
construction. Scalar constructor keywords were migrated at internal consumers,
without compatibility aliases. Actual container tests show that updated
calibration affects the current router verdict and does not leak to the next
run; detached latency and OOB dependency canaries fail verdict assertions.

Evidence types use local names `Budget` and `View`; response field extraction
is `response_fields`. The rename changes no model, configuration, JSON, digest,
budget policy or executable algorithm. All 420 affected tests passed before
and after, with 19 normalized module ASTs equal and 21 cold imports passing.

The six differential profile axes have one source, the ProfileFactor Literal.
The ordered value projection reads that vocabulary; control and treatment
remain eagerly projected in their original order. This removes 14 production
lines and two repeated lists. All 64 profile combinations retain constructor
results/errors; 80 differential execution tests pass.

Optional packages consume verification capabilities through `cloud_dast.api`.
Exports reference canonical objects; they add no wrappers or duplicate models.
Signal and SignalKind belong to the runtime-neutral feedback contract, while
signal extraction remains in verification. The import contracts cover all five
optional packages and reject direct imports of verification internals. Six
explicit pure entry points are allowed into the API, with a separate transitive
ban on runtime, infrastructure and composition, without exceptions. Importing
the API currently loads 27 verification modules through existing barrels and
reads the local taxonomy YAML; this import cost remains a limitation.

Parked classification leads use `oracles/leads.py`: Lead and evaluate.
The stateless ClassificationLeadOracle and unused substitution hook are removed;
PolicyVerdict is constructed at the actual evaluation loop. Proposal context,
prefix and NormView validation still precede scoring. Lead fields/properties,
UNSCOREABLE diagnostics, sorting and report data are unchanged. No old exports
or aliases remain. The production reduction across owner, barrel and campaign
consumer is 31 lines.

Coverage also removes an uncalled private declaration helper and an exact
term-key helper clone. Sixteen references use the existing canonical helper;
this removes 15 production lines. The import block is unchanged and 92 graph,
plan, hash and type-boundary tests passed before and after.

Finding construction belongs to `collect`. Its former 16-argument factory had
one production caller and has been removed. Tests exercise the collector,
canonical Finding and ClassCatalog directly. The minimal-PoC read still precedes
association errors, and finding admission and merge ordering are preserved.
This removes 46 production lines; collect grows from 68 to 90 lines and its
complexity from 16 to 18, an explicit tradeoff for removing the redundant API.

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
| All production, physical LOC | 85,620 | 84,451 | −1,169 |
| All production, nonblank/noncomment LOC | 74,144 | 73,150 | −994 |
| All production functions | 3,345 | 3,302 | −43 |
| All production classes | 733 | 726 | −7 |
| Tests, physical LOC | 105,280 | 106,554 | +1,274 |
| Tests, nonblank/noncomment LOC | 90,285 | 91,466 | +1,181 |
| Verification modules | 47 | 40 | −7 |
| Verification physical LOC | 16,491 | 14,900 | −1,591 |
| Verification functions | 563 | 499 | −64 |
| Verification classes | 79 | 65 | −14 |
| Verification structural findings | 89 | 57 | −32 |

All-production cyclomatic-complexity sum decreases by 188; maximum decreases
from 48 to 38. These are intermediate measurements, not completion criteria.

## Verification evidence

The current integrated suite covers verification formal/oracle/catalog cases,
verification, architecture, execution workflow and review C3/L1 tests:
**2,765 passed, one skipped, three failures** in 81.83 seconds. The new DI
provider required one documentation-projection update; after that correction all
six documentation-projection tests pass. The remaining two inherited failed
nodes are in test_path_runner_fuzzing.py: grammar-generator feedback and finding
shrink/replay. Both raise the previously recorded Hypothesis `many.more`
AttributeError. This does not claim the whole repository suite is green.
Two changed benchmark modules remain unrun because benchmarks.nsfy_bench is absent.

Ruff across packages/tests passes. All 29 import contracts pass. All 146 changed Python sources
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
| `__init__.py` | accepted_unchanged | Keep: Only package docstring, no API/state/facade. None for this module; full goal and shared-contract integration still active. |
| `action_runtime.py` | accepted_changed | Pure event-derived ledger stays verification; explicit bound/planned/recovery semantics retained. Shared _step_actions removes two copies; removed _term_key wrapper, stable min selects deficit, nullable Check fallback simplified.163→154LOC, buildCC20→17,62tests+2058old/newcomparisons pass, no new tests/types. declared_actions and three production consumers retained. No required module change identified. Full goal remains active. |
| `contract_projection.py` | independently_reviewed_further_disposition_pending | Keep source-schema adapter in verification, no I/O. Four scalar calls use one ordered loop; numeric min/max duplicate emission now shares existing _emit_scalar with Atom-preserving canonicalization. -31 physical LOC, no new entity. 729 complete graph/report old-new comparisons equal; 43 broader tests and16 projector tests pass. Canary suppressing minimum caught by2 tests. Independent review: 152 malformed public inputs and729 raw pre-sort emission-order comparisons unchanged; bodies outside emitters/signatures/provenance unchanged. After5614d10: one edge-spec table owns labels/predicate/direction, special term construction preserved;32448 raw returns/errors equal,CC20→12,-19LOC. Unknown-label report folding preserves600raw facts/issues sequences with positive/empty/dualunknown coverage; emit_annotation105→96lines/CC13→12,-9LOC.46consumer tests pass; inversion canarygoldenfails; independentreview pending. Independent15symbolic predicate/direction references and guard checks agree; all15specs verified; source-selection/parser ASTunchanged, edge/annotation diagnostic order preserved. Final naming/structure disposition and independent review |
| `coverage.py` | accepted_changed | One Builder owns graph/plan coverage; removed forwarding build_graph and module build_matrix, callers directly Builder.build. Preserve typeguard/hashguard/profiles and allbinding snapshotinputs. Newwrappercut-29productionLOC;331before/aftertests,512forward/errorcomparisons and independentreview accepted. Prior sharedfield/effectmaterialization-95LOC,constant-ownercleanup-10LOC; imports57 stillover40. Longmethods/signatures and structure remain; derivinginvariantsfromgraph losesboundeventkey, so kwargs not replaced by a bag. No required module change remains in this disposition. Full goal and other module work remain active. |
| `coverage_models.py` | accepted_renamed | Renamed to term_coverage.py: evaluator/algebra plus exact-term evidence schema/factory belong to verification, canonical assessment models remain contracts.assessment. Net LOC0; no facade. None for this module; whole verification remains active. |
| `differential/__init__.py` | reviewed_validation_pending | Keep existing exports pending consumer migration; do not add a new facade. No substantive reduction by import moves. Implementation where necessary, naming/structure findings resolution, final validation and independent review |
| `differential/comparator.py` | reviewed_validation_pending | Keep timing/concurrency distinct. Exact incomplete-response clone belongs to Kepler shared witness kernel; comparator becomes consumer only after parent agrees kernel. Preserve mixed tree/legacy comparisons; shape uses authoritative tree but value union includes legacy. Implementation where necessary, naming/structure findings resolution, final validation and independent review |
| `differential/contracts.py` | reviewed_validation_pending | Keep experiment-specific models in verification; do not move wholesale to model or public contracts. _payload_fields_from_baseline is live and behavior-sensitive: deleting its string-field fallback changes readback mutation. Stateless stand policy checks marker only, not isolation guarantee. _profile_factors duplicates ordered factor names with value tuple; bounded getattr comparison could remove ~12-20 LOC, secondary only. Single ProfileFactor Literal now owns6orderedcomparisonaxes; derive name tuple and read values fromit, removing2duplicatelists (-14productionLOC). Implementation where necessary, naming/structure findings resolution, final validation and independent review |
| `differential/modes.py` | changed_final_review_pending | Keep distinct timing repeat/minsample and concurrency probe/worker policies despite equal values. Runtime DIFF_MODES now derives from canonical DiffMode Literal via typing.get_args, removing duplicated closed vocabulary: -2physicalLOC. Existing configuration parser pin passes before/after;61projector+differentialtests pass; no new abstraction. Implementation where necessary, naming/structure findings resolution, final validation and independent review |
| `differential/projection.py` | accepted_unchanged | Accepted unchanged: pure projection of measured dimensions into runtime QDL; pairing, treatment evidence and normalized IDs covered by targeted tests. No I/O/state or structural findings. None for this module in current scope. |
| `differential/report.py` | accepted_unchanged | Accepted unchanged: paired/aggregate measurement contract, distinct from Observation and presentation reporting. Comparator/timing/concurrency and current evidence consumer tested. Signature remains a coarse identity: different control-only fields may collide; persisted-revision uniqueness is not established here. None for this module in current scope. |
| `evaluation.py` | reviewed_changes_pending | Consumes read-only evidence view; no own mutable campaign store. Any step/request types obscure existing QdlExecutionStep/LiveRequest contracts; narrow to existing types. Repeated norm compilation and linear readback search need measured shared seam, not new DTOs. Resolve module findings/structural and naming rules; independent final review |
| `evidence.py` | accepted_changed | User-authorized full bounded model context: mandatory masks/role-release params/metadata/logger removed; one representation and detached JSON dump with rendered digest. Keep min1024, UTF8/leaf/string/latest-attempt caps, original digest and explicit malformed budget errors. Worker: retention pin old1fail/new1pass;348focused/2597broad pass;135 boundary cases. Batch-252 production physical/-228 nonblank, tests-100physical. QDL roles and admission/findings unchanged; two benchmark modules unavailable (missing benchmarks.nsfy_bench). Independent review accepts:72adversarial cases strictUTF8 caps,216idempotent reconstructions,10malformed metadata cases rejected, nestedcopies/digests correct,25helper ASTunchanged. Manual views without budget keep prior uncapped behavior; Mapping is readonly by contract, no production mutation found. No required module change remains in this disposition. Full goal and other module work remain active. |
| `evidence_facts.py` | accepted_unchanged | Constructors do not persist or verify by themselves. supports_dataflows is a pure declared-intent gate, not evidence proof; name/document at consumer rather than invent repository. Keep runtime context filter for verified IDs. None for this module; full goal remains active. |
| `finding_evaluator.py` | accepted_moved | Stateful publication/replay owner moved to runtime/campaign/evaluation.py using the shared EventProjection; pure decision/merge functions belong to verification/findings.py. F1 gate requires accepted deterministic norm and explicit recorded observation reference. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `findings.py` | accepted_changed | Removed internal 16-argument factory and inlined sole production use in collect, -46 production LOC. Keep canonical Finding/ClassCatalog types; tests retarget actual collect, canonical model and catalog instead of preserving test-only factory. No confirmed remaining module ownership or naming issue. Full goal remains active. |
| `invariant_projection.py` | accepted_unchanged | Accepted unchanged: owner of binding identity and norm indexes. Mutable index and frozen planned_ids have distinct roles; dedup, action binding and exclusion of proposal transitions verified. No structural findings. None for this module in current scope. |
| `norm_coverage.py` | accepted_changed | Corrected canonical-type/index batch443→397(-46physical,-30code excludingdocstrings),-3Protocols,-5helpers. ExecutionResult/QdlExecutionView canonical;2schedulerprotocols retained. Canonicalprovenance lookup directly, attribution-index ownedsolelybyexistinghelper.21pins/26consumercases/2592rows/9errors/12findingcases+canary/coldimports pass. Independent45comparisons(39returns6errors) accepted; key/value distinction, malformedNone/emptyhistory/wholepathactions/fallback/deferredhash preserved. build115→129 andhelper25→30: remaininglongfunction/sig review notwaived. No required semantic change found. Retain justified129line join and11parameter diagnostic helper; full goal remains active. |
| `norm_view.py` | accepted_merged | NormView merged into existing norms.py; distinct validation entrypoints preserved, no re-export shim. 18 production lines and one file removed; focused metadata/error-order and import checks passed. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `norms.py` | accepted_changed | Keep NormCompilation/NormCompiler for this batch. SemanticNormCompiler creates accepted candidates from grounded semantics; this compiler interprets one accepted fact, so they are not duplicate compilers. QdlInvariant overlaps output but has string norm vs Atom and accepted-path lifecycle; unification needs outside-scope consumer migration. changed maps to marker here but NormView routes changed to differential: intentional tested distinction. No required module change identified. Full goal remains active. |
| `oracles/__init__.py` | reviewed_changes_pending | Keep current used exports; description “business services” is stale; eager import fanout is real but no new lazy facade justified. Resolve module findings/structural and naming rules; independent final review |
| `oracles/action_alignment.py` | accepted_changed | Shared action alignment retained; action_alignment_rationale renamed explain_mismatch in owner and eight actual oracle consumers. No body/signature change or alias. All181 oracle tests pass before/after, Ruff clean; naming-only delta0 LOC. No required module change found. |
| `oracles/classification_lead.py` | accepted_renamed_and_simplified | Owner oracles/leads.py exposes Lead and evaluate; statelessOracle and unused override hook deleted; canonicalPolicyVerdict built at actualloop. Shortread_role/render_term helpers, oldaliases absent. Netproduction-31LOC. No remaining module work identified. |
| `oracles/differential.py` | semantic_reviewed_naming_or_cleanup_pending | Reuse canonical completeness helper; preserve channel precedence, partial positive vs complete negative evidence, unique aligned probes and minimum two successes. No transport execution here. Coherent qualified Oracle naming migration; small duplicate/plumbing findings from final7module review must be dispositioned. |
| `oracles/field_exposure.py` | semantic_reviewed_naming_or_cleanup_pending | Replace exact completeness clone. Preserve schema-index stripping and case-sensitive path matching, principal scope before PASS, full tree needed for absence. Coherent qualified Oracle naming migration; small duplicate/plumbing findings from final7module review must be dispositioned. |
| `oracles/grounded.py` | semantic_reviewed_naming_or_cleanup_pending | Keep IAM grounding and unknown/missing permissions branches; replace missing_capabilities(method, scenario.stand.effective_permissions) with method.permissions - scenario.stand.effective_permissions; remove import. Parent/Erdos reports all other scenarios helpers test-only. Remove package at its owning scope; no replacement helpers. Reexpress significant tests through GroundedOutcomeOracle behavior. Coherent qualified Oracle naming migration; small duplicate/plumbing findings from final7module review must be dispositioned. |
| `oracles/latency.py` | reviewed_baseline_correctness_and_naming_pending | One registry owns method calibration. Separate availability meaning from paired latency; repeated raw norm parser is migration candidate, not mechanically equivalent to NormView. Keep finite paired samples and delivered-error semantics. N1disposition: retain private decoder/DTO as a distinct direct-API boundary adapter; actualPydantic Variable-ID norm parses locally but NormView rejects. No artificial NormCompilation/tuple replacement. Public APIdiagnostic ordering maintained. Long evaluate_policy/naming remain open. Private semanticnames corrected: _LatencyNorm→_Duration and_parse_latency_norm→_parse_duration, onefile/zeroLOC/normalizedASTequal/191tests beforeandafter. PublicprimitiveAPIs unchanged. Confirmed inherited nonfinitebaseline issue L2, separate hardening disposition; qualifiedOracle/Baseline naming pending. Ordinary/paired/availability semantics remain distinct. |
| `oracles/marker.py` | semantic_reviewed_naming_or_cleanup_pending | Import shared witness helpers; remove completeness/echo/response/value clones. Keep action+observation+scenario binding before projection and adversarial-target rule. Coherent qualified Oracle naming migration; small duplicate/plumbing findings from final7module review must be dispositioned. |
| `oracles/oob.py` | changed_pending_final_validation | Pure Oracle owns scoring. Runtime Coordinator owns pending state/deadlines; existing RunScope provider now finalizes collaborator via yield/finally. 71 focused tests plus 11 real-container/docs checks passed; actual poller termination and deregistration tested with fake external transport, no network. Cleanup does not admit final-poll callbacks into a previously returned result. Resolve module findings/structural and naming rules; independent final review |
| `oracles/primitive_router.py` | accepted_changed | Inject existing WitnessSignalOracle through RunScope; router no longer stores/constructs duplicate latency/marker/OOB assembly. Constructor9->5params, productionnet-4 acrossrouter/provider. Standalone defaults remain. Oldkeywords intentionallymigrated withoutaliases. No required module change remains in this disposition. Full goal and other module work remain active. |
| `oracles/roles.py` | accepted_unchanged | Keep candidate semantics, policy validation and default loader. Error/not-found selector methods currently have no production callers; remove only together with reviewed policy schema/data/test consumers. None for this module; full goal remains active. |
| `oracles/sequence.py` | semantic_reviewed_naming_or_cleanup_pending | Shared existing transition-verdict assembly between paired and aggregated evidence; selection/order remain distinct. 29 production lines removed, no new entities. 29 tests and 19 full old/new verdict comparisons passed; deliberate FAIL-to-PASS mutation caught by four tests. Independent reviewer compared 1874 complete verdicts old/new, zero differences. Coherent qualified Oracle naming migration; small duplicate/plumbing findings from final7module review must be dispositioned. |
| `oracles/trace.py` | accepted_unchanged | Nine-line alias is reused by all primitive signatures. Inlining increases repetition and adds no architectural improvement. None for this module; full goal and shared-contract integration still active. |
| `oracles/witness.py` | reviewed_changes_pending | Large block duplicates verification.witness; reuse canonical helpers and PathWitness, delete uncalled old helper subgraph. Explicit pair/known-content APIs are test-only today: do not mistake them for live grammar execution. Resolve module findings/structural and naming rules; independent final review |
| `projection.py` | reviewed_validation_pending | Changes pending: Correct evidence interpretation owner, typed/scoped references and effect proofs distinct; complexity/structure findings open. Final naming/structure disposition and independent review |
| `promotion.py` | independently_reviewed_remaining_work | Canonical ProposalPromotionRequest replaces11raw promotion arguments at soleproductionPolicycaller; -14productionLOC, no newDTO/alias.144before/aftertests;130pure+780Policy fullresult/issues/log/budget comparisons equal. Independent AST and freeze/lock/order review accepted. Actionnormalization first,then caps/declarations; all54otherpurefunctions unchanged. Oldunsupportedrawshapes explicitly outside migratedcontract. Long semantic/response/norm-admission functions remain. Two privatehandlersnowconsumeSAMEcanonicalRequest:10→6/9→6params,-10physical. Derivednormalizedrefs/context/source_actions/declarations/compiler/effects/cap remainexplicit.144tests/130pure+780Policy/identitypin+reverseASTpass. Parentreview source confirmedfieldsubstitution only; independentpeerreviewpending. Independent156publicresult/phasetracecases+4errors confirmprivateRequestpropagation;observed56response-filtercalls andsameRequestidentity. Raw->derivedContext inputs preserved;whole reverseASTequal. Classification/budget/response pipeline complexity and full semantic/review coverage remain open; no completion claim |
| `scenarios/__init__.py` | accepted_removed | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `scenarios/capability.py` | accepted_removed | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `scenarios/matching.py` | accepted_removed | No shipping consumers except plain permission set difference; inlined at sole grounded oracle; obsolete helper-only tests removed, real oracle has four added permission behavior cases. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `secret_shapes.py` | accepted_changed | Keep proposal-only heuristic sensor. Corrected docstring: shapes produce proposal leads, never prove a secret/classification. Schema/value leaf walker differs from model evidence path extraction; no forced merge. No required module change identified. Full goal remains active. |
| `slices.py` | accepted_changed | Consolidated duplicate runtime model-slice hash into canonical fingerprint, 24 golden values identical; 135 focused tests passed No required module change identified. Full goal remains active. |
| `spec_projection.py` | accepted_unchanged | Accepted unchanged: README-documented recursive specification adapter. Recursive SpecField differs from flat FieldSpec; nested projection and shared contract report verified. No I/O/campaign state or structural findings. None for this module in current scope. |
| `state_machine_ingestion.py` | accepted_moved | Existing state and contract ingestion moved into runtime/ingestion.py, body/summary AST equivalent, 311 focused tests and 27 contracts passed; no summary or source_id policy merge. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `taxonomy/__init__.py` | accepted_unchanged | Used by finding construction, runtime deficits and metrics. No independent state. No required module change identified. Full goal remains active. |
| `taxonomy/catalog.py` | independently_reviewed_remaining_validator_work | Consolidate repeated norm/candidate selection; constant -len(_constraint_count(entry)) is a correctness issue, not safe cleanup. Keep residual algebra shared between matching and diagnostics; runtime consumes catalog candidate vocabulary. Import-time package YAML is configuration I/O, not persistence. Currentfrom_graph fold:one structural field parse/triplewrite; input/output actionaliases distinctfromrawresourceIDs. Net-4LOC,CC26→13,53tests before/after,120validGraphcases equal (2760constructionfailures excluded). Independentreviewpending. Existingconstraint-activation/residualpolicy duplication underread-onlyproposal; no newregistry yet. Independent141extracted-body comparisons acceptroleprojection fold. Negativecanary misrouteswitnessroles→input andbreaksexistingclassify test. Constraintpreview has1974fullclassification/querytrace comparisons incl204exceptions and37tests; dataactivationownerconsolidation -5LOC approved, implementation underway. No behavioralprioritychange ornewDTO. Constraintactivation nowownedone map,selectorexistingtuplereturn,noDTO; -5LOC/residualCC17→11/selector6→2.53tests and1974result/querytracecomparisons incl204exceptions pass,canarycatchesdisablechangedconstraints. Parent377actualcatalog/effect cases confirmboolactivation,tupleidentity andfailurecodes. Combinedroleprojection+policybatch-9LOC;ClassEntryvalidatorCC16 andfinalnaming/data-policy decisions remain. Resolve module findings/structural and naming rules; independent final review |
| `threat_model.py` | accepted_moved_to_tests | Test-only StrideView/Category moved to existing tests/support/threat_model.py; no production consumers or dynamic registrations found; no production runtime behavior added or removed. No remaining required move/deletion work. Downstream external imports unverified; historical architecture snapshot marked superseded. |
| `witness.py` | signal_rename_reviewed_public_boundary_proposal_pending | Own shared completeness, echo, response-values and witness-path helpers here. Keep extraction separate from verdict and from transport. Signature claims value-free but includes marker/delta; adjust documentation or explicit consumers after review. Corrected signature docstring: keys include timingdelta/marker, not value-free. Executable bodies still identical tobase; only this docstring differs. Signal/SignalKind rename5production2tests/0LOC/127before-aftertests/JSONhistory+digest+normalizedAST equal. No oldalias. Oldpickleunsupported,no shippingpicklefound. Newfinding: optionalFuzzing consumesSignal+extractorfromprivateverification; canonicaltypefeedbackcontracts/publicAPIboundarypreviewactive, includingother7optionalverificationimports. Resolve module findings/structural and naming rules; independent final review |

## Remaining work and limits

Structural checks still report 24 complexity, 11 namespace, 16 length, five
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

Confirmed inherited correctness issue L2: three positive-infinity latency
samples produce a NaN baseline threshold. Both runtime calibration and an
environment JSON configuration containing 1e309 reproduce a grounded PASS for a
1,000,000 ms probe ("within threshold nan"). The canonical baseline constructor
is AST-identical to 6594554. Deployment occurrence is unverified. Finite-input
validation needs a separate hardening change; this refactor has not silently
changed its input/error policy.
