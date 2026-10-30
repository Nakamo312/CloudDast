# Verification rearchitecture

Final architecture/refactor disposition; baseline `6594554`, isolated branch
`codex/verification-rearchitecture-20261030`. All 47 original modules have a
semantic decision below. The runtime review worktree/branch is unchanged.
No live target or model call was needed for this refactor.

## Acceptance and observable behavior

Verification owns interpretation, taxonomy, coverage and finding admission.
Runtime owns campaign state, event replay/publication, ingestion, OOB waiting
and lifecycle. Adapters own storage/transport. Immediate reads of captured
callbacks through EvidenceChannel remain allowed: the projector has no waiting
policy, retries, deadlines or lifecycle. It is not strictly pure when that port
is injected. A regression pin verifies invalid duration fails before the port
read; moving the read into caller kwargs would change the error phase.

Finding emission requires a deterministic, grounded FAIL, an accepted norm
compiled to a deterministic primitive, and an explicit reference to a recorded
observation. No evidence reference is synthesized. A recorded prior worst-latency
observation may supply the witness. Publication and replay use one shared
RunScope EventProjection; refresh is serialized by its actual owner, not claimed
universally thread-safe. OOB transport closes at run exit, including exceptions
and lazy construction; cleanup does not guarantee admission of callbacks arriving
after the result cutoff.

Full captured data is authorized for configured internal models. Mandatory
model-context masking was removed; byte/leaf/string/token limits remain. The
minimum envelope is 1 KiB, default cap 128 KiB. Dumps are detached, digests cover
the rendered copy and reconstruction is idempotent. Manual View without budget
metadata retains the prior uncapped behavior; Mapping is readonly by contract,
not deeply immutable. Splitty is installed; live routing was not tested. QDL
field roles and target redaction semantics still participate in verification.

Readback now carries the resolver's exact mutable-field selection through the
existing ReadBackSpec to PayloadPairSpec.from_baseline. The keyword is required;
string/resource-ID mutation heuristics are removed. Actual target pins retain
unknown and credential guard fields, mutate only the declared payload field,
preserve identities/resource binding and charge exactly three calls. This fixes
a demonstrated loss of QDL metadata; it is an intentional behavioral correction.

## Public names and owners

Oracle implementations use qualified `module.Oracle`, with latency.Baseline.
Signal/SignalKind belong to contracts.feedback; evidence uses Budget/View.
Differential contracts expose Spec/EvidenceView at their owner. Composite contract
mapping returns contract_projection.Result: fields/JSON/hash are unchanged;
Pydantic schema title, $defs/$ref names and class identity follow the new name.
Old import/pickle names have no aliases. External downstream imports were not
verified. Canonical domain entities such as Check/Observation/Finding are unchanged.

Promotion consumes the existing ProposalPromotionRequest with separate caps.
Action normalization still precedes cap checks. Unsupported old raw argument
shapes are not claimed constructor/error equivalent. Coverage uses Builder
rather than forwarding build_graph/build_matrix APIs. Source/hash guards and
binding snapshots remain; provenance values and historical keys are not merged.

Optional packages consume verification through cloud_dast.api. Exports are the
canonical objects; six approved pure entry points have an independent transitive
ban on runtime/infrastructure/composition. All five optional packages reject
direct verification imports. API cold import loads 19 verification modules,
including local taxonomy YAML, and no outer layers. QDL/model/contracts purity
is retained. Built-in candidate/session algorithms were not replaced.

## Measurements

Physical and nonblank/noncomment LOC use the union of baseline and current paths,
including committed deletions and both sides of moves. Docstrings count as code;
tests are separate. No structural-lint threshold/exclusion or formatter policy was changed.

| Scope | Baseline | Final | Delta |
|---|---:|---:|---:|
| All production physical LOC | 85,620 | 84,317 | -1,303 |
| All production nonblank/noncomment LOC | 74,144 | 73,036 | -1,108 |
| All production functions | 3,345 | 3,293 | -52 |
| All production classes | 733 | 726 | -7 |
| All production complexity sum | 12,107 | 11,897 | -210 |
| All production max complexity | 48 | 38 | -10 |
| Tests physical LOC | 105,280 | 106,613 | +1,333 |
| Tests nonblank/noncomment LOC | 90,285 | 91,509 | +1,224 |
| Verification modules | 47 | 40 | -7 |
| Verification physical LOC | 16,491 | 14,755 | -1,736 |
| Verification functions | 563 | 489 | -74 |
| Verification classes | 79 | 65 | -14 |
| Verification structural findings | 89 | 46 | -43 |

## Validation

Expanded suite: **2,996 passed, one skipped, 46 failed** in 93.74 seconds.
Every failed node reproduces in an isolated, clean 6594554 checkout: the same
46 nodes fail with Hypothesis/hypothesis_jsonschema `many.more` AttributeError
in 7.58 seconds. This is failure classification, not a claim the whole repository
suite is green. V2 has two separately reproduced baseline failures from the same
library; V2R and benchmark modules cannot collect without benchmarks.nsfy_bench.

Ruff passes packages/tests; 168 changed Python files pass formatting. All 29
import contracts pass. The final unused Term import removal changes no function
or class AST; the 70 coverage/action/smoke consumers were rerun afterward.
Exact executable-AST clone audit (docstrings stripped, at least 12 nodes) finds
zero groups. This is not a claim of universally absent semantic duplication;
the per-module semantic review supplies the complementary evidence.

Negative checks cover finding evidence/association gates, context/provenance,
coverage key/value distinction, declaration direction, channel completeness,
paired/control selection, callback ownership and detached DI dependencies.
Readback's three new pins fail on the original source and pass on current code.
Shared kernel tests cover state selection/errors and full projection/sequence
results; runtime-fact JSON/hash/error results and canonical function identity;
term-label payloads and body equality. Existing large comparison matrices were
reused, not counted as new independent audits of each rename.

## Original 47-module ledger

Each row is accepted for the architecture/refactor scope. Latency explicitly
retains the separately owned L2 functional defect below. A moved/merged owner
is not a second source of truth, and deleted modules have no compatibility facade.

| Original module | Current owner/path | Decision |
|---|---|---|
| `__init__.py` | `__init__.py` | Package documentation only. |
| `action_runtime.py` | `action_runtime.py` | Action/event ledger; shared term_label. Planned, bound and executed evidence remain distinct. |
| `contract_projection.py` | `contract_projection.py` | Source-schema mapping; Result carries graph plus external mapping diagnostics. |
| `coverage.py` | `coverage.py` | One Builder; canonical factor algebra; forwarding APIs and duplicate helpers removed. |
| `coverage_models.py` | `term_coverage.py` | Exact-term factor algebra and evidence schema, not duplicate domain models. |
| `differential/__init__.py` | `differential/__init__.py` | Used canonical exports; obsolete Spec export removed, no aliases. |
| `differential/comparator.py` | `differential/comparator.py` | Paired/timing/concurrency measurements; canonical completeness helper. |
| `differential/contracts.py` | `differential/contracts.py` | Spec/EvidenceView; required QDL mutable fields; heuristic mutation fallback deleted. |
| `differential/modes.py` | `differential/modes.py` | One Literal vocabulary; independent sample/worker policies preserved. |
| `differential/projection.py` | `differential/projection.py` | Difference facts use canonical runtime_fact; correlation preserved. |
| `differential/report.py` | `differential/report.py` | Measured read contract; signature is a dedup discriminator, not a complete content hash. |
| `evaluation.py` | `evaluation.py` | Canonical annotations; candidate ownership, security verdict and causal progress remain separate. |
| `evidence.py` | `evidence.py` | Budget/View; full bounded internal-model data; detached dumps, digests and cap enforcement. |
| `evidence_facts.py` | `evidence_facts.py` | Canonical runtime_fact and metadata readers/factories; declarations are not proof of effects. |
| `finding_evaluator.py` | `runtime/campaign/evaluation.py` | Moved campaign state/publication/replay; shares the runner EventProjection and cursor. |
| `findings.py` | `findings.py` | Single collect boundary enforces finding admission, fingerprint, merge and PoC selection. |
| `invariant_projection.py` | `invariant_projection.py` | Binding identities/indexes; snapshot cannot be reconstructed from raw graph alone. |
| `norm_coverage.py` | `norm_coverage.py` | Execution/scheduler/event join; shared factor algebra, independent historical attribution. |
| `norm_view.py` | `norms.py` | Merged into existing interpretation owner; no re-export shim. |
| `norms.py` | `norms.py` | Accepted/lead norm compiler and view; distinct from semantic candidate synthesis. |
| `oracles/__init__.py` | `oracles/__init__.py` | Nine class exports removed; six used helper/type exports remain. |
| `oracles/action_alignment.py` | `oracles/action_alignment.py` | One action mismatch helper, reused by primitive scorers. |
| `oracles/classification_lead.py` | `oracles/leads.py` | Lead/evaluate; stateless Oracle and unused override removed; proposal-only UNSCOREABLE. |
| `oracles/differential.py` | `oracles/differential.py` | Oracle; state/response selection preserves precedence and distinct error phases. |
| `oracles/field_exposure.py` | `oracles/field_exposure.py` | Oracle; principal scope and complete-tree negative evidence preserved. |
| `oracles/grounded.py` | `oracles/grounded.py` | Oracle; IAM grounding; duplicate permission helper and constant wrapper removed. |
| `oracles/latency.py` | `oracles/latency.py` | Oracle/Baseline; ordinary/paired/availability policies distinct. L2 deferred explicitly below. |
| `oracles/marker.py` | `oracles/marker.py` | Oracle; binding before projection; reflection-only evidence cannot prove a sink. |
| `oracles/oob.py` | `oracles/oob.py` | Pure scoring/preflight; waits, pending state and lifecycle belong to runtime. |
| `oracles/primitive_router.py` | `oracles/primitive_router.py` | Oracle dispatch; existing witness component injected through RunScope. |
| `oracles/roles.py` | `oracles/roles.py` | Witness-channel policy/YAML, distinct from QDL field roles; supported policy fields retained. |
| `oracles/sequence.py` | `oracles/sequence.py` | Oracle; shared verdict assembly/read_state; unused projector plumbing removed. |
| `oracles/trace.py` | `oracles/trace.py` | Used ObservationTrace alias; no independent implementation. |
| `oracles/witness.py` | `oracles/witness.py` | Oracle delegates channel scoring; canonical _norm and common witness kernel reused. |
| `projection.py` | `projection.py` | Trusted observation interpretation; common runtime_fact/read_state; captured-query port phase retained. |
| `promotion.py` | `promotion.py` | One ProposalPromotionRequest; ordered trust/closure/budget passes; import tuple facade removed. |
| `scenarios/__init__.py` | `removed` | Deleted; no shipping package consumer remains. |
| `scenarios/capability.py` | `removed` | Deleted; sole permission difference lives at the grounded oracle consumer. |
| `scenarios/matching.py` | `removed` | Deleted test-only helpers; actual binding remains the runtime binder responsibility. |
| `secret_shapes.py` | `secret_shapes.py` | Heuristic proposal leads only; never accepted classifications or findings. |
| `slices.py` | `slices.py` | Bounded graph/evidence view; canonical fingerprint; selection and reference closure retained. |
| `spec_projection.py` | `spec_projection.py` | Recursive external specification adapter; reuses contract projector and Result. |
| `state_machine_ingestion.py` | `runtime/ingestion.py` | Moved with contract ingestion; distinct source-ID policies retained. |
| `taxonomy/__init__.py` | `taxonomy/__init__.py` | Existing canonical exports, no second catalog. |
| `taxonomy/catalog.py` | `taxonomy/catalog.py` | Shared candidates/constraint policy; test-only classify duplicate removed. |
| `threat_model.py` | `tests/support/threat_model.py` | STRIDE fixture moved to test support; no shipping parallel threat model. |
| `witness.py` | `witness.py` | One path/value/completeness/state kernel; Signal belongs to contracts.feedback. |

## Residual structural findings

There are zero namespace/name-length warnings. The 46 remaining findings are
24 complexity, 16 length, five signature and one import-block warning. These
remain visible to the unchanged linter; no exemptions were added. They are
accepted with the semantic dispositions below, rather than hidden in DTOs,
extra forwarding functions or mechanically split files.

| Module | Exact residuals | Decision |
|---|---|---|
| `action_runtime.py` | SL103 build_action_runtime_ledger has cyclomatic complexity 17 (max 15) | Independent planned/bound/recovery/transport/deficit axes; a blocked path is not an executed request. |
| `contract_projection.py` | SL103 _classification_sources has cyclomatic complexity 21 (max 15) | Ordered source eligibility checks; status and usability are independent fields with distinct diagnostics. |
| `coverage.py` | SL102 top-level import block has 57 imported names (max 40; ends at line 82); SL101 Builder.build has 10 parameters (max 8); SL101 Builder.build_plan has 11 parameters (max 8); SL101 Builder._build_qdl has 11 parameters (max 8); SL100 Builder._build_field_cells spans 140 lines (max 100); SL103 Builder._build_field_cells has cyclomatic complexity 20 (max 15); SL100 Builder._runtime_evidence spans 104 lines (max 100); SL103 Builder._runtime_evidence has cyclomatic complexity 24 (max 15); SL103 Builder._transition_norms has cyclomatic complexity 19 (max 15); SL103 _field_units has cyclomatic complexity 21 (max 15) | Independent graph/binding/event/scope inputs and field/effect/state matrix joins. A fresh graph index loses binding event keys; an options DTO would hide dependencies. |
| `evaluation.py` | SL101 ObservationEvaluator.classify has 9 parameters (max 8) | Invariant, candidate, method/scenario, evidence key and channel inputs are independently meaningful; replacing them by a step shifts error phase. |
| `findings.py` | SL103 collect has cyclomatic complexity 18 (max 15) | Ordered norm/evidence/association guards plus classification and merge; removing the redundant factory concentrates this actual boundary. |
| `norm_coverage.py` | SL100 build_norm_coverage spans 129 lines (max 100); SL101 _blocked_reason has 11 parameters (max 8); SL103 _blocked_reason has cyclomatic complexity 16 (max 15) | Execution/event/scheduler joins and diagnostic priority. Scheduled, selected, executed, oracle-called and baseline-waiting are different states. |
| `oracles/differential.py` | SL103 Oracle.evaluate_policy has cyclomatic complexity 20 (max 15); SL100 Oracle.evaluate_concurrency_policy spans 132 lines (max 100); SL103 Oracle.evaluate_concurrency_policy has cyclomatic complexity 20 (max 15) | Readback and concurrency have distinct diagnostics. Eager generic channel collection and state-only selection differ on malformed lower-priority channels; a merge preview was refuted. |
| `oracles/field_exposure.py` | SL100 Oracle.evaluate_policy spans 101 lines (max 100) | Principal scope precedes projection; negative evidence requires a complete tree and case-sensitive path semantics. |
| `oracles/grounded.py` | SL103 Oracle.evaluate_outcome has cyclomatic complexity 16 (max 15) | Known, unknown and contradictory IAM evidence require different outcomes and grounding flags. |
| `oracles/latency.py` | SL100 Oracle.evaluate_policy spans 117 lines (max 100); SL103 Oracle.evaluate_policy has cyclomatic complexity 21 (max 15) | Ordinary, paired and availability evidence are separate contracts; combining them would hide diagnostics. Nonfinite calibration is separately tracked L2. |
| `oracles/marker.py` | SL100 Oracle.evaluate_policy spans 123 lines (max 100); SL103 Oracle.evaluate_policy has cyclomatic complexity 28 (max 15) | Action/candidate binding, adversarial target policy, sink evidence and reflection-only leads differ. |
| `oracles/sequence.py` | SL103 Oracle._evaluate_transition has cyclomatic complexity 17 (max 15) | Paired and aggregate evidence selection differ; verdict construction is already shared. |
| `projection.py` | SL100 ObservationProjector.project spans 113 lines (max 100); SL103 ObservationProjector.project has cyclomatic complexity 16 (max 15); SL100 _consume_inputs spans 172 lines (max 100); SL103 _consume_inputs has cyclomatic complexity 28 (max 15); SL100 _effect_evidence spans 105 lines (max 100); SL103 _effect_evidence has cyclomatic complexity 30 (max 15); SL100 _query_observations spans 165 lines (max 100) | Scoped identity/reference/expiry joins use the canonical Clingo engine. Long query literals belong to the same evidence policy; moving them merely to shorten functions adds no owner. |
| `promotion.py` | SL100 _filter_response_semantics spans 130 lines (max 100); SL100 promote_proposal spans 198 lines (max 100); SL103 promote_proposal has cyclomatic complexity 20 (max 15); SL100 promote_payload_corpus_proposal spans 122 lines (max 100); SL103 promote_payload_corpus_proposal has cyclomatic complexity 27 (max 15); SL103 _source_sink_grammar has cyclomatic complexity 19 (max 15); SL100 _promote_semantic_facts spans 211 lines (max 100); SL103 _promote_semantic_facts has cyclomatic complexity 38 (max 15); SL103 _semantic_fact_is_promotable has cyclomatic complexity 32 (max 15) | Ordered admission phases: action/anchor, provenance, admissibility, declaration closure, budget and response filtering; corpus branches retain distinct diagnostics. |
| `slices.py` | SL100 build_sibling_action_slice spans 141 lines (max 100); SL103 build_sibling_action_slice has cyclomatic complexity 25 (max 15) | Selection, justification, cap and reference closure form one graph-view operation; scans have different identifier semantics. |
| `taxonomy/catalog.py` | SL103 ClassEntry.validate_entry has cyclomatic complexity 16 (max 15) | Ordered configuration boundary validation has distinct diagnostics; constraint-selection policy is already shared. |

## Explicit functional follow-up: L2

**Deferred, confirmed inherited defect.** Owner: verification/oracles/latency.py,
Baseline construction and Oracle runtime calibration. Three positive-infinity
samples produce a NaN threshold; a 1,000,000 ms probe then receives grounded
PASS ("within threshold nan"). Both runtime calibration and environment JSON
containing 1e309 reproduce this; deployment occurrence is unverified.

The preservation refactor does not silently choose a new reject-versus-ignore
policy for invalid samples. A separate finite-calibration hardening batch must
cover sample eligibility, finite computed statistics, live calibration failure
and configuration diagnostics, while pinning existing finite-input behavior.
This deferral was explicitly reviewed against the original goal. It prevents a
claim of full functional correctness or safe PASS handling for nonfinite inputs;
it does not reopen architecture ownership or imply a new refactor regression.

Reproduce the constructor symptom with the project interpreter:

```python
from math import inf, isnan
from cloud_dast.verification.oracles.latency import Baseline
assert isnan(Baseline.from_durations("a", (inf, inf, inf)).threshold_ms)
```

The current qualified-API full verdict reproducer and JSON are preserved in
~/tmp/verification-l2-reproducer-20261030.py and
~/tmp/verification-l2-current-reproduction-20261030.json. The complete machine
ledger, failure-node comparison, fixed-baseline metrics, source hashes and
independent reviews are preserved under ~/tmp with verification-* names.
