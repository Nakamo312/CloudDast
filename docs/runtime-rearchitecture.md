# Runtime rearchitecture

## Scope

`runtime/` owns execution lifecycle and reactive campaign state. It must not
become a second declarative store: QDL remains the source of truth for facts,
rules, obligations, and promoted knowledge.

Runtime-neutral reporting snapshots and activity projections belong to
`contracts/metrics.py`; mutable collection remains in `runtime/metrics.py`.

Candidate ownership is split by responsibility: the deterministic core
generator and pure candidate transforms live in `cloud_dast/candidates.py`;
optional fuzzing and symbolic packages consume only core contracts; per-step
session selection and adaptive feedback live in `runtime/candidates/`. Request-field
algebra and finding-example encoding are runtime-neutral contracts, while graph
algorithms shared with extensions live in `cloud_dast/graphs.py`.

The inventory records current responsibilities; the later sections describe
completed contractions, validated boundaries and remaining architectural debt.

## Complete semantic inventory

The revised 2026-10-28 snapshot covers **122 of 122 runtime Python files**
and **24,155 physical lines**, including package initializers (initial inventory:
25,725). Four
independent source-reading passes recorded responsibility, hidden decisions,
state/lifetime, side effects, actual entry relationships and remaining debt.
Every source SHA-256 and line count was checked against the current checkout;
there are no missing, duplicate, stale or inferred file records in this snapshot.
This proves inventory coverage, not completion of the architecture migration.

Source-set fingerprint: `ddbb31363c7e8adb25e89c763183b004051f923a505a821b482a1645980e63ff`.
The combined manifest records the fingerprint algorithm; its executable-input, queue-owner
and scheduler-owner records were re-read after their contractions. Canonical-contract
import migrations were checked by executable AST equality; the remaining live
prefilter contract was re-read separately. Original group JSON files retain the
initial inventory snapshot.
Full records, evidence locations and ranked remaining cuts are retained at
`~/tmp/runtime-semantic-inventory-20261028/manifest.json`.

| Module | Responsibility and hidden decision | State and effects |
|---|---|---|
| `runtime/__init__.py` | Mark the campaign runtime package without importing execution services. No exports or initialization beyond the module docstring. | none Effects: none |
| `runtime/binding.py` | Load service methods and canonical QDL, plan actions, and bind executable scenarios with explicit deficits. Explicit requested method wins; otherwise first resolvable planned action, then repository order; all declared actions and invariant actions receive scenario attempts. | Injected repositories, planner, graph assembler and optional compiler for binder lifetime; per-bind deficit/scenario indexes. Effects: MethodRepository.list_methods; ScenarioRepository.get_scenario; Assembler.load/run_formal_grounding (repository/proposal capability) |
| `runtime/budget.py` | Account for every live check, setup call and differential leg under campaign and round spending policies. Ordinary calls protect a differential reserve; differential cap compares total campaign spend, while ordinary round limit compares round spend; spend occurs after transport. | Campaign counters, round counters/caps and protected reserve; mutable single-campaign object. Effects: Mutates live-call, setup, differential and round counters; rejects overspend. |
| `runtime/campaign/__init__.py` | Lazily exposes campaign lifecycle APIs and selected foreign execution, verification and result symbols. Explicit symbol-to-module export table and first-access import caching. | Module globals cache resolved exports; no business or campaign state. Effects: import_module on first attribute access; cache symbol in globals |
| `runtime/campaign/dag.py` | Projects QDL declarations and runtime events into a canonical campaign node/edge read model. Context-qualified node IDs, payload/source hashes, latest-event node replacement and derived hypothesis/evidence relations. | Fresh _Projection dictionaries and EventIndex per build; no retained campaign state. Effects: none |
| `runtime/campaign/events.py` | Indexes typed events into latest path/step/observation records and append-only evidence lists for DAG projection. Last occurrence wins for keyed records; ordered accumulation for findings, diffs, intents and facts. | Mutable index dictionaries/lists scoped to one from_events call. Effects: none |
| `runtime/campaign/finalization.py` | Closes grounding, incorporates late OOB/readback evidence, evaluates findings and builds the public campaign result. Ordering of advisory shutdown, late verdict replacement by model ID, contract-only final rebind and scoped coverage projection. | Holds injected capabilities; mutates campaign accumulator during finish; no independent campaign store. Effects: GroundingHandle.mark_enrichment; GroundingRunner.close; runner OOB/readback reevaluation; binder.bind; evaluator.evaluate; publish phase events and metrics; logging |
| `runtime/campaign/graph.py` | Loads formal-source batches and optionally proposes, promotes and persists graph additions before producing a planner view. Repository key families, planner visibility, once-per-instance proposal cache and content-addressed accepted-batch persistence. | _proposal_done and _proposal persist for Assembler instance, not keyed by service; repository is durable state owner. Effects: FormalRepository.load/load_merged/save; ThreatModelProposer.propose capability may invoke a model; PromotionPolicy.promote; logging |
| `runtime/campaign/initialization.py` | Starts asynchronous grounding, creates the initial contract-only binding and constructs campaign scheduler, budget and coordination state. No-model first bind, run-scope baseline, reactive retry allowance, differential reserve and initial sweep sequencing. | Injected capabilities live with Bootstrap; constructed RuntimeState and scheduler/queues live for one execute call. Effects: grounding.start_grounded; binder.bind; report publish_plan/publish_coverage; event/metrics publication; differential.run_initial may execute target probes; logging |
| `runtime/campaign/replay.py` | Replays scoped evidence/intents into QDL and restores path outcomes and evidence signatures for a scheduler round. Latest surviving scoped evaluation supplies outcome/signature, including explicit None. Consumed scheduler invalidations remove historical entries. Only surviving signatures overwrite scheduler memory; invalidated or untouched history retains the existing scheduler fallback. | Round-local verified IDs and historical outcomes. Signature values are restored through a scheduler capability after scoped event reduction; no retained signature-value map. Effects: Restore surviving historical evidence signatures through the supplied capability; no I/O or dependency on the scheduler implementation. |
| `runtime/campaign/round.py` | Sequence one budgeted round and own intent initialization/execution metrics plus stored regression-example eligibility. | Runner retains capability callbacks, metrics and example store; caller/per-invocation round state remains separate. No callbacks to parent runner for these policies. Effects: Checker reset, scoped replay, scheduler/path execution, metrics transitions and terminal repair. |
| `runtime/campaign/runtime.py` | Runs the campaign fixed point across execution rounds, differential discovery, grounding batches and branch rebinding. Campaign loop order, first-sweep reserve, one-wave yield, startup waiting and finalization are preserved. Runtime receives an assembled dependency graph; active IDs come from campaign state and path selection from the canonical execution view. | LiveWorkflow holds seven explicitly injected collaborators plus runtime policy/ports read from existing options. No collaborator construction, latency alias, differential-mode environment parsing or duplicate mode set. Effects: Reads CLOUD_DAST_DIFF_MODES; constructs runtime services; runner execution/reconsideration; differential probes; reactive consultation capability; grounding-handle waits; finalization; phase metrics/events; logging |
| `runtime/campaign/state.py` | Groups campaign-wide execution, differential and grounding state into explicit mutable dataclass slices. Campaign-wide state owns active_path_ids derived freshly from current view selection plus every branch backlog ID; scheduler membership does not replace this projection. | RuntimeState and three mutable slices live for execute; scheduler, accumulator, budget, deficits, recovery and handle are referenced owners. Effects: none |
| `runtime/candidates/__init__.py` | Mark the candidate runtime package without creating candidate sessions. No exported aliases or eager imports. | none Effects: none |
| `runtime/candidates/feedback.py` | Compute deterministic delivery, witness-channel and violation proximity for candidate and recovery feedback. FAIL scores 1; delivered response scores 1/3; available primitive channel scores 2/3; earlier delivered observations contribute to multi-step score. | none Effects: none |
| `runtime/candidates/session.py` | Select and execute one QDL step candidate, apply symbolic filtering, and feed classification back to its fuzz session. Preview and execution share session construction; prefiltered paths execute stored solved checks; feedback precedes deferred observation finalization; non-final steps advance only on evidence or no causal requirement. | Per-call _StepRun selection/telemetry state, optional mutable injected fuzz session; runner retains callbacks/metrics. Effects: Injected budgeted step/check transport calls; SymbolicPrefilter.prefilter; FuzzSession.preview/next/record; Event publication and CampaignMetrics.record_generator_outcome |
| `runtime/consultation/__init__.py` | Marks the consultation package without re-exporting orchestration symbols. Empty public export surface. | No business state. Effects: none |
| `runtime/consultation/calls.py` | Prepare worker proposals from immutable PlannedItem inputs. | Injected BatchFlow, DifferentialFlow and publisher; no aggregate grounding service. Workers prepare only; owner-thread admission stays separate. |
| `runtime/consultation/commit.py` | Apply evidence gates, lifecycle lease and source revision checks before ordered admission. | Actual BatchFlow, DifferentialFlow and shared Loader are separate inputs alongside gate, outcome policy, publisher and metrics. No aggregate or source proxy. |
| `runtime/consultation/context.py` | Carry owner outcome metadata and pinned wave results/revisions for admission. Worker inputs are frozen records; WaveContext identifies mutable owner resources and untyped proposal slots. | Frozen owner-side OutcomeMeta, WaveExecution and WaveContext; no general capability callback bag. Effects: none |
| `runtime/consultation/evidence.py` | Selects the latest applicable observation/check and derives evidence-signed consultation identities. Exact observation beats path fallback; paired deficits require both legs; field-filtered candidates use accumulator order; service scopes AttemptKey. | No owned mutable state; reads campaign accumulator. Effects: none |
| `runtime/consultation/outcomes.py` | Stores the first terminal consultation outcome for each service/work-item/evidence key. Fixed precedence conflict > contract error > infrastructure error > missing evidence > promoted > parked > rejected; only a new key permits dispatch. | OutcomePolicy._states dictionary lives with Coordinator; states property is a read-only live view. Effects: OutcomePolicy.record mutates in-memory outcome dictionary |
| `runtime/consultation/wave.py` | Pin source/evidence and dispatch one independent wave; compare fresh source revisions before commit. | Explicit Loader shared with committer; frozen worker inputs and lifecycle revision retained. Effects: model tasks through GroundingRunner, no-source failure recording and ordered commit. |
| `runtime/coupling/__init__.py` | Declare the field-coupling package without exporting symbols or constructing services. Package namespace only; resolution and solving remain in explicit submodules. | None; no business state. Effects: none |
| `runtime/coupling/constraints.py` | Solve occurrence-consistent, schema-valid request field bindings and reject absent or ambiguous solutions. Finite typed value IDs, one shared occurrence variable per action, exact Python-type comparisons, equality-only filling of null fields, and exactly one resulting binding. | None retained; request copy, value domains, ASP program and solution set live for one solve. Effects: Invoke ClingoEngine.solve with query-local value/relation facts. |
| `runtime/coupling/resolve.py` | Bind candidate values from compatible occurrences and admit requests only when all concrete causal prerequisites have evidence. Live attempts override retained/durable fallback, identities and scenario scope select witnesses, fields from one action join by actual occurrence, and value acquisition never establishes causal proof. | Binder retains no state; frozen Context references Checker-owned mutable method/scenario/output maps for one resolution. Effects: Query derived requirements and verification live/durable output/effect projections.; Invoke solve_coupled_request for the selected constraint component. |
| `runtime/deficits/__init__.py` | Lazily re-exports deficit constructors, queue records, semantic closure helpers and work-item contracts. String export table selects one owner module per public name and memoizes resolved imports. | Import-time export registry and module-global symbol memoization; no campaign business state. Effects: import_module loads owner modules on first attribute access |
| `runtime/deficits/classification.py` | Turns taxonomy classification gaps on grounded failed observations into bounded classification deficits. Catalog pre-image limits allowable input/witness roles and sink types; only deterministic grounded FAIL observations qualify. | No owned mutable state. Effects: none |
| `runtime/deficits/closure.py` | Determines whether promoted QDL facts close a deficit or make it stale. Classification allowed values, complete response-path grounding, variance-field/effect relevance, signal/sink/norm conjunction and context-local supersession filtering. | No owned mutable state. Effects: none |
| `runtime/deficits/collection.py` | Collects binding, blocked-path, observation, classification and coverage deficits for replanning and records recovery clues. Use canonical execution-view selection without importing the physical executor; discovery/closure/recovery semantics are unchanged. | ClassificationState carries mutable path set and observation cursor; collector retains grounding capability only. Effects: DeficitQueue.add; Mutates ClassificationState path/cursor state; Recovery Coordinator.record_round; Logging |
| `runtime/deficits/coverage.py` | Projects missing input roles, executable action paths, response witnesses and typed references from a scenario binding. Optional resource references do not block execution; declared actions can be deferred; exposure requirements follow invariant witness and source target relations. | No owned mutable state. Effects: none |
| `runtime/deficits/detection.py` | Constructs typed deficits from blocked execution, missing witnesses, timing baselines, variance reports and ungrounded responses. Reason-to-subgoal translation preserves exact causal obligations; signals remain questions; successful response leaf gaps group by action; missing evidence withdraws the consultation axis. | No owned mutable state. Effects: Logging through routing.build_deficit when an axis is unavailable |
| `runtime/deficits/dispatch.py` | Selects fair work groups using information gain within least-served predicate classes. Deterministic repairs have a separate limit; model wave allocation can reserve one selection per pending class; priority combines interest, fan-out, arrival and stable id. | No retained state; select_wave_groups mutates supplied DispatchState simulation. Effects: Updates supplied DispatchState counters during wave planning; Calls InterestPrioritizer.score |
| `runtime/deficits/lifecycle.py` | Own canonical deficit entry, closure/staleness and evidence-revision lifecycle state. Dedup/fan-out, trusted semantic settlement, quarantine, per-work-item attempts and saturation, new-evidence reopening of revision-closed keys; semantic confirmation preserves dispatch/stale state. | QueueState owns the sole entry, closed/stale and work-item registries plus arrival order for one queue lifetime. Effects: Mutates owned QueueEntry/WorkItemState records and registries.; Deterministic grounding-closure evaluation and queue logging. |
| `runtime/deficits/model.py` | Defines immutable missing-QDL-obligation records and their canonical versus consultation grouping keys. Deficit.key ignores path provenance but distinguishes variance diffs and response field sets; work_item_key additionally groups by axis/action and classification/effect coordinates. | Frozen Deficit values; no owned mutable state. Effects: none |
| `runtime/deficits/propagation.py` | Re-evaluate pending deficits after one promoted item or a merged consultation wave using one classification loop. Closure precedes staleness; pending eligibility remains lazy; each transition commits before evaluating the next deficit so partial mutation and exception identity survive. | Local counters and graph/observation projections; no lifecycle registry or queue object. Effects: Invokes supplied semantic-confirmation and staleness capabilities.; Deterministic closure queries and telemetry. |
| `runtime/deficits/queue.py` | Coordinate fair deficit selection, immutable work projections and dispatch budget accounting. Readiness precedes charging; selection mutates only a counter snapshot; committed dispatch charges canonical DispatchState and asks QueueState to mark entries in flight. | One QueueState lifecycle owner, canonical DispatchState counters, immutable limits and retained prioritizer; no duplicate entry or closed/stale registries. Effects: Calls explicit lifecycle transitions.; Selects independent waves; records deterministic and model dispatch budgets; emits telemetry. |
| `runtime/deficits/queue_state.py` | Stores mutable deficit/work-item/dispatch records and a grouped view used by queue scheduling. Group id/representative/fan-out/order and deterministic-versus-model resource accounting. | QueueEntry and WorkItemState live in campaign queue; DispatchState is a per-selection simulation; WorkGroup is a frozen view of mutable entries. Effects: DispatchState.apply mutates its dispatch counters |
| `runtime/deficits/routing.py` | Maps unprovable QDL subgoals to consultation axes and bounded requests using the shared routing algebra. Missing axis becomes an undispatchable engineering deficit; context projection and stable work-item dedup preserve semantic grouping. | Module-level existential Variable constants only. Effects: Logs missing consultation producers |
| `runtime/deficits/wave.py` | Select independent work-item groups from explicit projections, budget snapshots and prioritization. Read readiness-filtered work before first-wave selection; obtain dispatch counters after readiness callbacks; simulate fair selection without committing live state. | Only local planned work graph and groups; no mutable queue reference retained or imported. Effects: Injected readiness and projection/read capabilities.; Cold-score telemetry. |
| `runtime/deficits/work_items.py` | Projects coalesced deficits into dependency/conflict waves and deterministic commit order. Hardcoded needs/produces signatures approximate consultation capabilities; pairwise intersections determine dependency, conflict and evidence serialization; graph library computes waves. | Immutable work-item/outcome records; WorkItemGraph holds a run-local planning snapshot without retained campaign mutation. Effects: none |
| `runtime/differential/__init__.py` | Expose differential symbols through lazy package attribute loading. A name-to-module registry defers imports until access and caches each resolved symbol in module globals. | Import/export cache only; no campaign or business state. Effects: import_module on first attribute access; updates module globals. |
| `runtime/differential/campaign.py` | Schedule initial and subsequent differential sweeps, protect their budget, and update/release latency paths. Deduplicate positions by method/scenario; reserve at most a policy share of campaign calls; scheduler eligibility is explicitly reopened after reserve and baseline availability. | Owns configured mode set, latency oracle, ProbeRunner and OutcomeRecorder; mutates campaign-owned swept flag, budget and scheduler through RuntimeState. Effects: Runs ProbeRunner live measurements; Mutates scheduler blocked/outcome state and latency baselines; Logging |
| `runtime/differential/concurrency.py` | Resolve a concurrent probe batch and optional reads, retain completed evidence, and route comparison outcomes. Batch cost is CONCURRENCY_PROBES plus two only when a read method exists; missing readback role is recorded but does not block the probe batch; partial evidence survives errors. | No constructor or standalone state; accesses ProbeRunner-owned _specs, _executor, _outcomes and _measurement_key through inheritance. Effects: ProbeExecutor.execute_concurrency_step/record_concurrency_evidence; CampaignAccumulator.add_partial; OutcomeRecorder.record_concurrency; DeficitQueue mutation and logging |
| `runtime/differential/context.py` | Carry bound-step inputs and campaign mutation handles to differential mode handlers. Frozen envelope fixes references but deliberately shares mutable accumulator, deficit queue, variance map, paired set, budget and evidence store. | Envelope per step; referred campaign-owned objects remain mutable. Effects: none; construction only |
| `runtime/differential/evidence.py` | Retain readback and concurrency measurements in campaign-local key-addressed dictionaries. Independent namespaces use last-write-wins replacement and sorted snapshot iterators; MeasurementKey encodes method, scenario, resource and invariant. | Two mutable dictionaries per Store campaign lifetime; values are external immutable result contracts. Effects: In-memory put/clear only |
| `runtime/differential/executor.py` | Generate and execute differential factor/payload pairs, readback triples and concurrent batches through the shared checker. One execute_step_pair handles factor scenario preparation or payload baseline/canary preparation, followed by one Checker.execute_pair with common admission, scoped events, finally billing and incomplete-pair handling. Factor identity logging and exact mode-specific errors remain. | Injected checker and event publisher; per-call prepared steps/checks and billing boundary. No new result type or duplicate payload executor method. Effects: Checker.generate_pair_checks/execute_pair/execute_readback/execute_parallel_batch; Scoped event-context binding; CallLimits spending through spend_calls; Store writes; UUID generation; logging |
| `runtime/differential/outcomes.py` | Compare completed differential measurements and route events, runtime facts and unexplained-variance deficits. Only measured variance persists QDL runtime facts and queues work; unchanged comparisons still publish telemetry; differential measurements alone never create findings. | Retains repository/event/metrics capabilities; mutates caller-owned accumulator, variance map and deficit queue. Effects: DiffPairComputed publication; FormalRepository.save via project_diff; DeficitQueue.add and variance record insertion; Campaign accumulator/counter mutation and logging |
| `runtime/differential/probes.py` | Dispatch enabled differential modes and execute factor, payload and readback measurements once per resolved prerequisite revision. One _evaluate_pair owns resolved-mode prerequisites, successful-measurement dedup, partial/ValueError handling, accumulation and outcome recording. Factor/payload preparation and keys remain distinct; canary is generated after dedup inside execution catch. Factor correlation uses observation ID, payload correlation uses check ID. | Existing executor/outcome/spec/baseline capabilities; no second pair lifecycle. Readback, timing and concurrency remain distinct algorithms. Effects: ProbeExecutor live calls; Partial and completed accumulation; SpecResolver role deficits; OutcomeRecorder comparison/persistence delegation; Logging |
| `runtime/differential/results.py` | Represent measured variance and completed legs retained after differential execution failure. Frozen records distinguish pair/readback/concurrency partial evidence; PartialExecutionError transports a structured result through error handling. | Immutable records and exception-local partial_result; no campaign state. Effects: none |
| `runtime/differential/specs.py` | Resolve explicit owner, mutable-payload and readback prerequisites for differential experiments. Only contract/accepted owners may be controls; ambiguous owners produce deficits; only declared input roles may be mutated; contracts.Spec enforces one-factor variation. | Optional ScenarioRepository capability; no owned campaign state. Effects: ScenarioRepository.get_scenario; DeficitQueue.add and logging |
| `runtime/differential/timing.py` | Repeat factor pairs for timing comparison and register a control latency baseline. Stop on local pair failure; preserve completed/partial evidence; mark measured key before statistical comparison; only usable comparisons update baseline and route reports. | No independent initialized state; depends on ProbeRunner-owned executor/resolver/outcomes/oracle and measurement-key method. Effects: Repeated ProbeExecutor.execute_step_pair; Accumulator mutation; compare_timing_measurements and latency oracle baseline update; OutcomeRecorder report routing and logging |
| `runtime/evidence_gate.py` | Park observation-backed consultation work lacking evidence and attach a deterministic sibling-action slice. Close each original work-item deficit without a model attempt and replace it with a non-consultable evidence deficit; dataflows may admit declared sink/reaches evidence. | Gate-owned evidence-deficit registry keyed by service and parked deficit key; injected repository/publisher persist for Gate lifetime. Effects: FormalRepository.load/load_merged; DeficitQueue.close_key/add; Injected record_outcome callback; ComponentInvoked publication and logging |
| `runtime/evidence_projection.py` | Build the evidence graph visible to a path and persist normalized observation projections. Prefer repository observation snapshots when present; otherwise replay matching CheckCompleted events with executed check identities, scenario scope and event timestamp. | Retains read callbacks and repository/projector capabilities; no owned mutable evidence cache. Effects: FormalRepository.load_merged("observation:")/save; ObservationProjector.project |
| `runtime/evidence_reuse.py` | Resume already executed ordinary occurrences and discharge causal steps from scoped evidence without another live call. A no-effect/no-norm step resumes only matching path/step/method/scenario events; causal reuse requires concrete resolved typed bindings, identity-scoped proofs and downstream outputs. | No owned campaign state; mutates injected checker coupling context when reconstructable. Effects: Refreshes event projection; Checker.generate_pair_checks/resolve_check/set_coupling_context callbacks; Publishes a verified step event for reused causal evidence |
| `runtime/execution/__init__.py` | Lazily expose BoundPathRunner and its options through the execution package. Only two allow-listed names trigger runner import; unknown attributes raise AttributeError. | None; no business state or service instance. Effects: import_module loads runner and its dependency graph when an exported attribute is requested. |
| `runtime/execution/binding.py` | Bind planned attack, forbidden-state and invariant paths to methods, scenarios and verification steps. Stable edge-invariant choice, exact unique forbidden transitions, synthesized non-norm prerequisite invariants, and norm-sequence deduplication keys. | None retained; emits new plans/steps/paths. Effects: Invoke optional record_deficit callback for missing contracts or invalid forbidden transitions. |
| `runtime/execution/calls.py` | Execute bound steps and materialized checks through one explicit event-context and live-call accounting boundary. Step bindings keep their generator, observation limit and retained history. | No owned mutable state; explicit Checker, publisher and budget. Effects: execute the check, restore nested event context, then charge actual attempts in finally, including failure and cancellation. |
| `runtime/execution/checks.py` | Invoke the target, validate observation correlation, enrich traces and publish execution/coverage events for single or parallel checks. Observation IDs must match check and scenario, probe marker comes from the executed check, absent traces receive one synthetic step, and parallel results preserve input order and first error. | Module-wide ContextVar plus lock-protected (event-bus identity, check-id) context registry; bindings restore previous values on exit. Probe futures/results live for one batch. Effects: Call injected target.; Publish CheckCompleted and CoverageUpdated.; Create ThreadPoolExecutor and wait for submitted probes.; Temporarily mutate global/context-local event-attribution bindings. |
| `runtime/execution/contracts.py` | Carry prefiltered whole-path seeds/checks and live optional fuzz sessions. Immutable bound steps, paths and views belong to contracts.plan. | Frozen PrefilterResult envelope retains live per-attempt FuzzSession capabilities; no initialization or I/O. |
| `runtime/execution/evidence.py` | Fingerprint usable path-specific reference/effect evidence so terminal paths can be reconsidered after evidence changes. Group references by observation before hashing, preserve joint bindings, filter effects to path requirements/norms, and return no signature when identities or projections cannot be resolved. | PathSignature keeps a per-(scope, identities) query cache keyed by graph content hash for its runner lifetime. Effects: Call injected observed_graph capability and verification reference/effect queries. |
| `runtime/execution/metadata.py` | Compile graph-scoped executable field metadata, attach it to bound steps and derive stable path versions. Schema-filter roles/probes, preserve per-map alias precedence, explicit irreversibility and marker/OOB carrier policy; hash only action-specific trusted requirements. | Local compiled maps and step updater; a per-versioning-call requirement cache keyed by retained graph identity. No cross-call cache or lifecycle state. Effects: deterministic QDL queries. |
| `runtime/execution/paths.py` | Execute one bound path: check witnesses, prefilter, reuse evidence, execute candidates, shrink findings and delegate outcomes to the terminal owner. `scope_step` provides pure per-path forwarding scope. | Frozen Executor retains eight explicitly injected run-scoped services; attempt and round state are caller/local owned. No inherited runner fields. Effects: target-capable candidate calls, evidence projection, coupling context, deficits and terminal events through supplied services. |
| `runtime/execution/prefilter.py` | Preview and symbolically solve cross-action candidate sequences before spending live calls. Only cross-action couplings activate whole-path solving; unsat prevents downstream consumption, while non-unsat checks/sessions and audit summaries are returned. | Retains injected symbolic solver, preview, generation and publication callbacks; candidate data lives per run. Effects: Call preview/generator and SymbolicPrefilter.prefilter_sequence.; Publish ComponentInvoked, ComponentOutput and DownstreamDecision. |
| `runtime/execution/projection.py` | Assemble and deduplicate executable attack, forbidden, invariant and non-scoring smoke paths while collecting binding deficits. Bind scored paths first, suppress standalone ordinary dependency prefixes, reuse the shortest suitable prefix for uncovered contract actions, and preserve more specific deficit reasons. | Mutates caller-owned path lists/keys, binding-deficit list and invariant index when forbidden steps synthesize invariants; no retained module state. Effects: Append BindingDeficit records to optional caller sink.; Update InvariantIndex.invariants with synthesized forbidden-path invariants. |
| `runtime/execution/runner.py` | BoundPathRunner executes assembled plan/round capabilities and exposes late OOB reevaluation. EventProjection owns scoped publication and append-only cursor reads. | Runner has seven explicit dependencies, no assembly inheritance or options. EventProjection owns cursor/history. Path definitions are shared privately by projection and round through composition-local closures. |
| `runtime/execution/scenarios.py` | Generate and execute guarded checks with output forwarding, isolated differential legs and partial-failure evidence. Guard after resolving concrete bindings, register attempted checks before target invocation, restore snapshots between isolated legs, rebind read-after resource IDs, and prepare concurrent probes before dispatch. | Checker-lifetime dependencies and attempted-check list; path-scoped output occurrences, methods/scenarios, couplings and evidence graph reset independently; temporary snapshots isolate legs. Effects: Call generator/strategy selection, Guardrail.allows, Binder.resolve_check and target execution through run_check/run_probes.; Validate readback stand policy and launch concurrent probe batches.; Raise typed PartialExecutionError preserving attempted checks, completed observations and failures; allocate fresh read-after check ID. |
| `runtime/execution/state.py` | Hold shared per-round execution evidence and accumulate completed/partial results across rounds. Round evidence separates observations, provenance/verdicts, historical skip outcomes. Signature values have one persistent owner in scheduler State. Campaign accumulation still merges ordered and keyed result collections. | CampaignRoundState is mutable for one scheduler round; CampaignAccumulator is mutable across rounds and copies collections when exposing ExecutionResult. Effects: Mutate in-memory round/accumulator collections; no external I/O. |
| `runtime/execution/terminal.py` | Translate path progress, replay and changed evidence into scheduler outcomes, intent states and terminal events. Verified effects complete paths; proximity can make failures retryable; changed evidence reopens terminal paths; repair passes close scheduler-only or budget-interrupted paths with scoped events. | PathAttempt owns attempt observations/proximity/prefilter session. Terminalizer commits evidence signatures only to scheduler State; round replay retains historical skip outcomes. Invalidation reopens before publication/metrics and clears evidence only after those succeed. Effects: Publish QdlPathEvaluated and DownstreamDecision.; Refresh event-store projection through callback, query evidence signature and update scheduler/metrics. |
| `runtime/execution/view.py` | Bind a QDL plan to methods/scenarios and construct the executable view. Index aliases, retain invariant projections, attach evidence snapshots, invoke metadata.decorate and sort paths. | Local indexes and caller-owned binding-deficit list; no retained state. Effects: QDL probe compilation and deterministic metadata decoration; append probe/reference deficits. |
| `runtime/finding_shrinking.py` | Minimize deterministic finding seeds by budgeted replay and persist the smallest reproducing check. Only deterministic grounded FAIL reproduces; rejected transport candidates are discarded; original observation/invariant key retains updated minimal candidate. | Injected shrink factory/example store and execution/classification callbacks; mutates round minimal_checks, local shrink session. Effects: Budgeted live check callback; Observation classification callback; FindingShrinkerFactory/next/discard/record; save_finding_example store write |
| `runtime/grammar_facts.py` | Compile formats, scalar constraints, reachable sinks and dialects for a batch of requested methods. Preserve asymmetric aliases, executable rules, ordered constraints and request-ordered errors. | Local indexes shared across the batch; no retained state. Effects: one Clingo reachability query per nonempty batch. |
| `runtime/grounding/__init__.py` | Lazily exposes automatic grounding, promotion, approval, lifecycle and result contracts. Export table maps public names to owner modules and caches imports. | Module import registry/memoized exports only; no campaign business state. Effects: import_module loads owner modules lazily |
| `runtime/grounding/axes/__init__.py` | Marks the axes implementation package for cache, scheduling, filtering and slicing modules. No explicit exports or eager wiring. | No business state. Effects: none |
| `runtime/grounding/axes/cache.py` | Loads and stores axis proposals keyed by namespace and bounded source slice. Cache hits are re-filtered by axis/evidence policy; key generation is injected; empty/missing graphs count as misses. | Cache/metric/key-provider references persist with Grounder; cache contents live in injected store. Effects: GroundingCache.load/save; Metric cache-hit/miss recording; Logging |
| `runtime/grounding/axes/filtering.py` | Filters axis proposals to permitted predicates, alternatives grammar and observed response-field bindings. Semantic-role and declaration closure; alternatives effects/fields must be declared; response facts bind requested actions, target owners and evidence paths. | Module predicate sets only; no campaign state. Effects: Bounded warning logging for rejected facts |
| `runtime/grounding/axes/projection.py` | Builds validated axis results and comparable batch intersections with bounded uncertainty diagnostics. Filter and response-evidence issue aggregation; only same-axis/same-batch repetitions intersect; batch identity hashes axis and action sequence. | No retained mutable state. Effects: Bounded model-output and uncertainty logging |
| `runtime/grounding/axes/scheduler.py` | Runs bounded axis-batch tasks through an injected runner or a sequential fallback. Single bounded stream primitive yields in completion order. Task exceptions and missing task completions become invalid AxisResult; phase timeout scales by worker waves. Stage composition and batch-key projection belong to startup, not the scheduler. | Grounder-lived runner/function/settings references; per-stream completed-index set. Effects: GroundingRunner.run_tasks; Calls ground_batch model preparation capability; Failure/timeout logging |
| `runtime/grounding/axes/slicing.py` | Builds bounded model slices while reserving campaign-attacker policy permissions for norms. Norms split token budget between permission and action slices if may facts would be lost; hash includes exact graph, evidence digest and actions. | No retained mutable state. Effects: none |
| `runtime/grounding/classification.py` | Lists parked protected-role facts and promotes one explicitly reviewed classification with an audit record. Only selected fact hash receives operator provenance; fresh enabled policy still checks deterministic grounding; accepted classifications are excluded from queue. | Repository, promoter and optional audit capability references; no retained approval queue cache. Effects: FormalRepository reads; Fresh PromotionPolicy.promote; ProposalPromoter.save_promoted_graph; ApprovalAuditLog.append; UTC audit timestamp and logging |
| `runtime/grounding/config.py` | Startup/reactive capability protocols and immutable adapter GrounderOptions. | Configuration only; aggregate ServiceOptions moved to composition. No service construction or I/O. |
| `runtime/grounding/consultation.py` | Executes typed consultations with evidence-ledger admission, deterministic promotion and provenance persistence. Consultation identity includes service/kind/deficit/action/depth; completed evidence sets absorb repeats; fixture typing permits scoped runtime-evidence exemptions. | Existing flow lifetime state and explicit optional ReactiveGrounding capability; no startup scheduling or cache dependency. Effects: Loader.load repository reads; Axis grounder dispatch_consultation model call; ConsultationLedger.record; ProposalPromoter.promote/save_promoted_graph; Suppression telemetry publication and logs |
| `runtime/grounding/evidence.py` | Projects deterministic request-canary echoes into runtime-only measured dataflow facts. Requires same scenario and method, a declared source action, a changed request field and canary presence in changed response/error channels; emits no security norm/sink classification. | No retained mutable state. Effects: none |
| `runtime/grounding/inputs.py` | Defines immutable input envelopes for reactive, alternatives and paired variance proposal preparation. Separate call contracts preserve branch-neighbourhood hints and paired control/treatment evidence; ReactiveCall optionally separates cache source. | Frozen envelopes referencing immutable evidence/QDL values and capability data; per-call lifetime. Effects: none |
| `runtime/grounding/lifecycle.py` | Starts startup grounding, streams promoted batches and reports optional detached formal enrichment. Skip or absent startup suppresses startup work without enabling/disabling reactive preparation. Source/cache isolation, detached formal enrichment and per-batch promotion are unchanged. | RunCoordinator retains only the StartupGrounding capability plus its existing ingestion/source/promotion/formal lifecycle capabilities. Effects: Contract ingestion callback; Stand projection callback and repository.save; GroundingRunner.start/start_task; Axis grounder streaming model work; FormalGrounder.ground; Promoter promotion/save; GroundingSink.publish/finish/mark_enrichment |
| `runtime/grounding/projection.py` | Computes accepted-fact supersession, source/action/classification identities and measured variance helpers. Supersession only replaces exclusive duration/reached or setup_value/setup_skip families and adds supporting declarations; timing bound is median plus robust spread; canaries search changed channels. | No retained mutable state. Effects: none |
| `runtime/grounding/promotion.py` | Owns PromotionPolicy campaign caps and the lock shared by norm, semantic-fact and payload admission. Normalizes untrusted proposals, delegates pure admission/parking decisions to verification, and persists promoted revisions. Every incoming fact is rewritten to proposal context; accepted saves append supersession and optionally content-address source ids; parked original facts are deduplicated for telemetry. | Owns mutable PromotionPolicy counters; retains LeadLifecycle; repository is injected durable authority. Effects: Atomic campaign budget updates after successful admission; LeadLifecycle.record_graph; FormalRepository.save/load/load_merged; Secret-shape sensor projection; Consultation telemetry publisher and logs |
| `runtime/grounding/reactive.py` | Prepares evidence-bounded reactive, alternatives and variance consultation requests and filters returned proposals. Alternatives require a pinned graph-related sibling neighbourhood; generic and paired evidence are redacted projections; classification provenance is frozen into AxisResult; model usage always finishes. | Independent Followup owns consultation dispatcher, consultation budget, slice budget and metrics only. It does not construct, retain or require startup dispatcher/cache/scheduler capabilities. Effects: ConsultationDispatcher.dispatch model capability; Metrics request/token/model-id updates; Logging |
| `runtime/grounding/results.py` | Carries a validated but unpromoted axis proposal with issues, batch identity and optional classification provenance. Distinguishes absent graph from issue count and preserves observation ids for later evidence-bound promotion. | Frozen AxisResult; per-batch/request lifetime; graph is proposal, not an accepted result. Effects: none |
| `runtime/grounding/runtime.py` | BatchFlow prepares and admits reactive/branch proposals through the shared deterministic promoter. | Three direct dependencies: reactive adapter, skip flag, promoter. No aggregate assembly, source, lifecycle, variance or ledgers. Effects: secret-shape parking, admission and accepted-batch persistence with unchanged provenance/supersession. |
| `runtime/grounding/source.py` | Loads the merged contract/stand source and optionally accepted semantic revisions for grounding. Repository failures collapse to None with a caller-selected log label; accepted merges are delegated to promoter. | Loader retains repository/promoter references; no graph cache. Effects: FormalRepository.load; Promoter.accepted_semantics repository reads; Failure logging |
| `runtime/grounding/startup.py` | Runs semantic grounding before norms and decodes dispatcher responses through validation and axis filtering. One lazy semantic-then-norms stage algorithm owns batching, completion order and graph/cache enrichment. Only norms see evidence. Batch preserves result-axis identities and invalid/cache telemetry; stream preserves task-axis identities, yields valid graphs and explicitly closes its nested stage iterator. | Independent Bootstrap owns explicitly initialized validator, batch size, slice budget, dispatcher, cache wrapper and bounded scheduler. It retains no consultation dispatcher, reactive budget or shared mixin fields. Effects: Axis scheduler/model dispatcher calls; Axis cache reads/writes; Logging |
| `runtime/grounding/state.py` | Tracks parked lead belief revisions and evidence sets absorbed by completed typed consultations. Lead identity is action/holder/role; confirmations count distinct evidence refs; stable length-prefixed evidence hash; consultation identity additionally includes service, kind, deficit and depth. | LeadLifecycle._leads and ConsultationLedger._evidence live with AutoGroundingService; no reset method in this module. Effects: In-memory lead/consultation dictionary mutation |
| `runtime/grounding/variance.py` | Prepares paired variance proposals, persists measured runtime evidence and commits promoted differential semantics. Measured echo facts persist independently from accepted norms; variance commit uses response fields, observation refs and robust duration thresholds; differential save uses a non-revision-addressed campaign key. | Existing flow lifetime state and explicit optional ReactiveGrounding capability; no startup scheduling or cache dependency. Effects: MeasuredEvidencePolicy.project; FormalRepository.save measured facts; Axis grounder ground_variance model capability; Promoter parks secrets, promotes and saves accepted facts; Logging |
| `runtime/identity_projection.py` | Derive grounded QDL subject choices and attach typed identity terms to executable steps. Declared attackers apply to every action; declared owners are added to every targeted action; may pairs require subject declaration; smoke paths retain their existing identity configuration. | Local sets and returned IdentityView; frozen view contains a Mapping supplied as a normal dict, no campaign mutation. Effects: none; returns replaced execution path/plan values. |
| `runtime/investigation.py` | Execute one guarded investigation intent and optionally publish its correlated observation. Reject before target execution; replace observation.check_id with intent_id; investigation produces neither candidate expansion nor a policy finding. | none Effects: InvestigationGuardrail callback; InvestigationTarget callback; Optional EventPublisher.publish |
| `runtime/limits.py` | Provide an observation-count batch limit and re-export shared scenario-layer checks. This helper counts returned observations, unlike CallLimits live-call accounting; semantics are local to legacy Checker.execute_bindings. | none Effects: none |
| `runtime/metrics.py` | Maintain synchronized campaign counters, intent transitions and event-derived immutable metrics snapshots. Lifecycle transitions are checked; only explicit scheduler evidence invalidation reopens terminal intent; snapshots detach mutable maps and aggregate retained phase/component events. | RLock, intent/label/generator/token maps, totals and full phase/component event lists for CampaignMetrics lifetime. Effects: In-memory synchronized counter/state/event mutation; Taxonomy classification in stride_letter |
| `runtime/observation_effects.py` | Translate an already classified observation into generator/step events, normalized storage and runtime fact events. Use classification.progress for witness/FactVerified admission; explicit effect_verified controls completed step state; deduplicate effect facts by caller-owned IDs; output fields always become evidence events. | Callbacks retained for publisher lifetime; bind closure captures service/path/step and mutable verified_fact_ids per execution. Effects: Domain event publication; Projection.observed_graph/persist_observation; Mutates verified_fact_ids |
| `runtime/observation_matching.py` | Match an observation trace to either method ID or its action-prefixed spelling. Prefer the trace step with this observation_id, otherwise the final trace method; observations without trace cannot match. | none Effects: none |
| `runtime/observation_recording.py` | Record round and attempt provenance, classify an observation, publish effects, and finalize its finding after feedback. Ordered recording and provenance precede classification; publishing precedes the returned finalize callback; only progress FAIL stores a minimal check and increments finding count. | Mutates CampaignRoundState observations/provenance/verdicts/reasons/minimal_checks and PathAttempt observations/effect_verified. Effects: Injected classify_observation and publish_effects callbacks; Metrics.record_finding |
| `runtime/payload_hints.py` | Compile marker-field hints and reachable sink classes from executable QDL facts. Hints come from transitive reaches and declared roles; sink classes are limited to already selected fields; return sorted unique per-action values. | none; local indexes per call. Effects: ClingoEngine.reaches_plus_pairs solver calls |
| `runtime/planning/__init__.py` | Expose runtime planner implementations and defaults; canonical QDL plan/path/subgoal contracts and pure queries are imported directly from qdl.reasoning. | None; imports classes/functions but creates no planner or business state. Effects: Import planning.core and its Clingo/state-machine/norm compilation dependencies. |
| `runtime/planning/attacks.py` | Decode derived effect, reveal and conjunction walks into deterministic attack-path projections. Trusted contexts share declared action universe; value/reveal edges carry no invented causal requirements; accepted paths combine trusted component effects; path identity includes ordered edge effects. | None retained; per-call edge sets and path dictionaries. Effects: none |
| `runtime/planning/core.py` | Plan bounded attack, state/resource-state, forbidden and invariant views using Clingo and the state-machine engine. Default execution contexts are contract/accepted; requested closures are validated; snapshot planner reuses unchanged grounded input and rebuilds on every fact/rule change to preserve negation. | QdlPlanner retains engine/config/compiler dependencies; IncrementalQdlPlanner additionally owns program session, grounded fact/rule sets, version and started flag for its instance. Effects: Compile/solve Clingo programs, ground/reset program sessions and invoke state-machine/norm compilers.; Log non-monotonic rebuild summaries. |
| `runtime/planning/invariants.py` | Compile accepted prevents facts into sorted QDL invariant projections. Only accepted prevents facts enter NormCompiler, whose primitive/evidence/verdict policy is copied without executing an oracle. | None retained; local list of derived QdlInvariant values. Effects: Invoke injected NormCompiler.compile. |
| `runtime/planning/rules.py` | Define query-local ASP rules for trusted-context composition, causal/value/reveal edges and bounded supported action walks. Different requirements compose as AND, alternative producers as OR; dependency order is prospective rather than observed proof; permission terms do not become achieved causal effects. | Immutable module tuples/strings, generated once from operator and struct-schema catalogs; no campaign state. Effects: none |
| `runtime/planning/states.py` | Project bounded global and per-resource state-machine witnesses into stable QDL plan paths. Preserve every bounded route, derive forbidden paths per norm, deduplicate global routes by action sequence and resource routes also by state sequence, and hash their structural identities. | None retained; local witness maps/lists per graph/context query. Effects: Invoke StateMachineEngine.solve/find_paths and solve_resources. |
| `runtime/planning/symbols.py` | Decode solver closure/walk atoms and produce content-addressed structural path IDs. Context decoding filters malformed contexts, reverse-cons walks preserve repeated action occurrences, and path hashes include kind/context/nodes/extra. | None retained; local decoded sets. Effects: none |
| `runtime/prioritization.py` | Computes validated deterministic advisory interest scores for executable work items. Multiplicative coverage/prior/reward formula, neutralization of quarantined features and seeded digest tie-breaking. | Immutable score values; prioritizer retains only configured seed. Effects: none |
| `runtime/readback_reevaluation.py` | Re-evaluate retained write measurements under newly bound changed/transition norms without new requests. Match measurement by method/scenario/resource while allowing new invariant IDs; require exact saved check/observation membership and skip already-provenanced evaluations. | Per-call evaluation maps; reads external immutable execution result and campaign evidence store. Effects: Classifier callback (owns actual oracle trace construction); Step event publication |
| `runtime/recovery.py` | Collects reusable observation clues and chooses existing QDL sibling branches or typed recovery requests after blocked steps. Action-independent effect witness key, proximity threshold, per-effect 256-clue cache, shortest-path sibling/clue ranking and recovery routing. | Campaign-local State retains bounded per-effect clue deques/dedup set, latest blocked path snapshots and drainable intents. Effects: none |
| `runtime/reference_projection.py` | Index uniquely grounded targets and project typed object/principal references from explicit input roles. Exclude ambiguous targets, principal targets from object refs and undeclared roles. | Pure local maps; typed_object_refs consumes already computed targets and role policy. Effects: none. |
| `runtime/replanning.py` | Selects one reactive deficit wave against a graph snapshot and coordinates evidence persistence and consultation dispatch. Retain one-wave yield before rebinding/execution; admission/backlog semantics are unchanged. Call the explicit public consultation.run_wave boundary and consume canonical callbacks from context. | Explicit grounding, deficit collector, evidence gate and wave coordinator references. No nested assembly, callback bag or ownership of campaign active-path projection. Effects: grounding.persist_measured_evidence; deficits.pop_wave; consultation work-item execution may invoke model/grounding capabilities; logging |
| `runtime/resource_projection.py` | Project executable target resources, resource service ownership and required states from QDL. Target/service choice requires a unique value; required states join derived requirements with explicitly declared preconditions and return sorted values. | none; per-call local indexes. Effects: May invoke runtime.planning.derive_requirements when requirement rows are absent. |
| `runtime/scheduler/__init__.py` | Export canonical scheduler identity/state types and lazily load the campaign scheduler. Importing state or ranking does not load readiness, registry or scheduler coordination. | No campaign state; only normal Python import-module caching. Effects: Lazy import of core on CoverageDrivenScheduler access. |
| `runtime/scheduler/core.py` | Compose path discovery, latency readiness, pure ranking and explicit scheduler state transitions. Commit advisory scores per candidate before choosing; derive attempted keys only after the State attempt charge; query remaining work only at original telemetry points. | One State owner, one PathRegistry and one LatencyPrewarm reader per campaign; retained prioritizer. No mixin-private context. Effects: Prioritizer and baseline capabilities; State operations; scheduler telemetry. |
| `runtime/scheduler/coverage.py` | Derives scheduler coverage cells, path-version families and latency/action indexes from execution paths. NormView-derived full effect plus action-independent witness serialization; unknown invariant fallback; :pv family parsing. | none; returns pure tuple/value projections. Effects: none |
| `runtime/scheduler/model.py` | Own canonical coverage-key values and all scheduler selection, retry, terminal, latency and reward state transitions. Attempt order and canonical budgets, distinct evidence-reopen versus baseline-release permissions, protected neighbor blocking, trusted reward quarantine and partial failure semantics. | One mutable State per scheduler. released_latency_actions relocates the prior coordinator-private set; no duplicate state registry. Effects: Mutates owned fields and counters; evaluates injected attempted-key and remaining/path capabilities at pinned stages; telemetry. |
| `runtime/scheduler/prewarm.py` | Evaluate missing latency baselines and request explicit hold/bootstrap/release transitions. Park duration-only paths, prefer other unprewarmed work, grant one bootstrap per action; release has permissions distinct from general evidence reopening. | Only State/path-source/baseline references; no separately retained mutable latency registry. Effects: Injected baseline queries; State hold/bootstrap/release operations; telemetry. |
| `runtime/scheduler/registry.py` | Own discovery-ordered path snapshots and their coverage-key index. Refresh known path values without resetting history or recomputing cached coverage keys; only unseen identities add keys. Derive content-version family replacement mapping. | Path list and canonical coverage dictionary; one cached immutable MappingProxyType view exposes the same index without data copying. Effects: Mutates only registry-owned paths/keys; discovery telemetry. |
| `runtime/scheduler/selection.py` | Compute deterministic path ordering, cold scores and pending-outcome fairness from explicit inputs. Exploration/fairness/outcome-debt/cost ordering and trusted mean reward prior; return advisory score without mutating scheduling state. | No retained state and no direct State mutation. Effects: Injected InterestPrioritizer.score; no selection/terminal commit. |

### Related canonical owners

| Module | Owns | Must not own |
|---|---|---|
| `contracts/dag.py` | Immutable node, edge, and DAG contracts for the campaign read model | Event collection, projection policy, execution or verdict semantics |
| `verification/evidence_facts.py` | Canonical evidence metadata and pure declared-context sufficiency queries | Repository I/O, work-item scheduling, campaign state or promotion |

The dependency seam is:

```text
deficits/detection ─→ QDL / runtime planning / verification projections
deficits/model ─────→ deficit detectors + work-item/queue contracts
work_items ─────→ model graph / QDL
deficits/queue ─→ deficits + work_items + scheduler
campaign ───────→ queue / execution / consultation / reporting
execution_state → execution result contracts + differential evidence + campaign replay metadata
observation_recording → execution classification + round state + generator feedback callbacks
observation_effects → event publisher + evidence projection + runtime fact contracts
readback_reevaluation → differential evidence + verification callbacks + event effects
path_prefilter → candidate preview + symbolic extension + component events
evidence_reuse → event projection + evidence graph + coupling-context callbacks
coupling/constraints → QDL graph + typed model schemas + Clingo query engine
coupling/resolve → coupling/constraints + evidence projection + context snapshot
planning/core ──→ QDL / Clingo / planning projections
planning/attacks → planning/symbols + QDL graph/reasoning
planning/states ─→ QDL state-machine engine + planning/symbols
planning/invariants → QDL graph + verification norm compiler
planning/rules ────→ QDL schemas + coupling vocabulary
planning/core ─→ QDL engines (shared projection; optional snapshot session)
path_projection ─→ planning + binding primitives
finding_shrinking ─→ execution callbacks + replay store
prioritization ─→ scheduler policy inputs
scheduler/model ─→ scheduler core, registry, prewarm, and outcome policy
scheduler/coverage ─→ scheduler core, registry, and prewarm
scheduler/registry ─→ scheduler assembly and campaign path lifecycle
scheduler/prewarm ─→ scheduler assembly and latency baseline callbacks
scheduler/selection ─→ scheduler assembly and prioritization inputs
scheduler/outcomes ─→ scheduler assembly and scheduler state
deficits/queue_state ─→ deficit/work-item value objects
differential/results ─→ differential execution + round accumulation
grounding/results ─→ grounding + consultation coordination
grounding/projection ─→ grounding service's deterministic graph projections
campaign/dag ──────→ campaign DAG model + QDL/event projection inputs
axis_filtering ─→ grounding result validation/projection
axis_result_projection → axis filtering + QDL/evidence contracts
axis_dispatch → core model port (compatibility only); production dispatch comes from `cloud_dast_llm`
axis_slicing → QDL graph + evidence slice builder
axis_scheduler → grounding runner port + axis result identity projection
axis_cache → grounding cache port + axis result/filtering projections
grounding/reactive → consultation dispatcher port + shared axis result projection
consultation/evidence → execution-state observations + work-item identity + consultation outcome contracts
consultation/context → grounding/runner ports + campaign wave contracts
consultation/wave → consultation/evidence + grounding runner + deficit queue contracts
consultation/calls → evidence gate + grounding service + execution observations
consultation/commit → grounding promotion ports + consultation outcome policy + event publisher
deficits/closure → QDL graph + deficit value objects + field-role projections
deficits/dispatch → deficit queue state + deterministic prioritization
differential/campaign ─→ differential execution contracts + scheduler + differential outcomes
differential/context ─→ differential mode handlers
differential/executor ─→ live workflow + call budget + event context
differential/probes ─→ live execution port + differential contracts + differential specs + differential outcomes
differential/timing ─→ differential executor + latency comparator + outcome recorder
differential/concurrency ─→ differential executor + evidence store + outcome recorder
differential/specs ─→ QDL field roles + differential contracts + deficit queue
differential/outcomes ─→ differential comparators + runtime fact projection + deficit records
campaign_finalization ─→ campaign state + execution reevaluation + verification projections
campaign_initialization ─→ binding + scheduler + budget + differential startup
campaign_replay ─→ event log + QDL graph projection + round terminalization
recovery ─────→ execution observations + QDL path contracts
grounding/promotion ─→ QDL promotion policy + formal repository + consultation telemetry
grounding/source ───→ formal repository + accepted-semantics promotion view
grounding/consultation → consultation dispatcher + grounding source + promotion + ledger
grounding/config ───→ model/grounding/cache/task-runner ports + slice policies
grounding/inputs ───→ model/evidence/QDL call contracts
grounding/lifecycle ─→ grounding promotion + runner/task ports + axis grounder
grounding/axis ───→ startup + reactive + prompt/cache/scheduler/dispatcher dependencies
grounding/startup ─→ axis slicing/cache/scheduler + proposal validation
grounding/reactive ─→ consultation dispatcher + evidence/slice projections
```

`runtime/campaign/state.py` is reserved for campaign-wide coordination state and now
stores it in three explicit slices: `ExecutionState` advances the
scheduler loop, `DifferentialState` owns paired measurements and its
budget reserve, and `GroundingState` owns deficits, grounding, and
branch recovery. Round state and cross-round result accumulation belong to
`execution_state.py`, while event-derived terminal outcomes and verified-fact
metadata belong to `runtime/campaign/replay.py`. `RuntimeState` no longer exposes
flat forwarding properties: new code must use the nested state owner directly.

There is intentionally no import from `deficits` back to `deficits/queue`.
Consumers import `DeficitQueue` from `runtime.deficits.queue` and work-item
types from `runtime.deficits.work_items`; the old module-level re-export is removed.

## Migration order

1. Extract queue state from deficit construction — completed in the first slice.
2. Characterize and separate live path execution from candidate binding,
   evidence projection, and differential probes.
3. Separate campaign lifecycle from reactive consultation and differential
   campaign runners.
4. Move only genuinely shared runtime contracts into small modules after a
   real consumer exists.

Every step keeps QDL graph identity, deficit keys, work-item IDs, attempt and
saturation semantics, event/log names, and replay behavior stable. A change
must pass the deficit/work-item workflow tests, Ruff, and import-linter before
the next runtime boundary is touched.

## Coupling constraint construction

`runtime/coupling/constraints.py` owns finite typed witness joins. Candidate value
collection, occurrence-bound endpoint facts, relation facts, and numeric bounds
have separate pure functions; `solve_coupled_request` assembles their result and
requires a unique binding from Clingo. Distinct values retain first-seen order
and exact Python type identity. Endpoint facts retain their original occurrence
index, so witnesses from different observations cannot be combined accidentally.

The extraction reduced `solve_coupled_request` cyclomatic complexity from 30 to
14 and `_field_accepts` from 16 to 12. It adds 30 physical lines; this slice
reduces individual responsibilities and duplicated numeric-bound logic, rather
than reducing total file length. The coupling scenario suites and architecture
suite passed together: 213 passed, 1 skipped. Broader previously observed workflow
and dependency failures remain outside this verification claim.

## Verification-plan ownership

All execution consumers import `VerificationPlan` directly from
`cloud_dast.contracts.plan`. The compatibility module `runtime/plan.py` is
removed. A fresh-process boundary check blocks imports of runtime,
infrastructure, and composition while constructing and JSON-roundtripping the
plan. It preserves the distinction between ungrounded identity (`None`) and a
grounded identity deficit (an empty tuple).

## Model-dispatch ownership

`cloud_dast_llm.axis_grounding.Dispatcher` owns startup model
invocation, response schema selection, and usage accounting. Core `ports`
contains only its capability contract; the implementation and the empty runtime
subclass have been removed. `Grounder` requires an injected dispatcher.
Assembly constructs it through the registered extension factory and does not
create model grounding when that implementation is absent.

Reactive consultation is also injected explicitly. `Grounder` accepts no model
client and requires both grounding and consultation dispatchers. The fuzzing
entropy consultant likewise accepts a consultation port directly. Core no
longer exposes a resolver that discovers extensions from working algorithms;
assembly selects both implementations and enables model-backed features only
when the corresponding factories are registered.

Startup prompts, `ModelRequest` construction, wire schema identity, and the v3
prompt-sensitive cache-key algorithm now belong to the LLM axis dispatcher.
The core port accepts an axis and bounded context and provides an opaque cache
key. Runtime owns stage ordering, slice construction, proposal validation, and
cache I/O; its cache receives the key function through dependency injection.
The original prompt expressions and key algorithm were compared against the
pre-migration source and are unchanged. A behavioral check also verifies that
the cache key matches the actual dispatched instruction and response schema.
Startup/consultation/enrichment, architecture, and DI validation: 294 passed,
one optional test skipped.

Validation of the plan-owner migration: 169 focused execution/architecture
tests passed with one skipped; all three extension-boundary tests passed.
Full collection remains incomplete: 3762 tests were collected, with 27 errors
in automata and benchmark imports in this checkout.

Startup-dispatch validation: 290 grounding, consultation, architecture, and DI
tests passed; one optional algorithm test was skipped. Characterization covers
successful usage accounting (including cache tokens), explicit dispatcher
injection, and model failure: the active-request counter is finished exactly
once without inventing response tokens or a model ID. Ruff and structural
naming checks pass for the LLM dispatcher.

## Work-item relation construction

`WorkItemGraph.build` now derives dependency edges, pair relations, conflict
supersedes, and serialization edges in the same pair traversal. The unused
co-factorable/complementary sets and the second conflict-pair traversal are
removed. Shared pair priority is computed once and dependency detection is
reused by relation classification and serialization. Conflict supersedes keep
the same sorted public order and priority ties keep stable work-item-ID order.

The module shrank from 555 to 526 physical lines. The builder shrank from 133
to 104 lines and cyclomatic complexity from 19 to 15; its function-size warning
remains above the configured 100-line limit. No helper classes or files were
added. New characterization cases cover queue-priority serialization of shared
missing facts/evidence before the first attempt and parallelization afterwards.
Ten graph/property checks and 199 deficit/architecture tests passed, with one
optional test skipped. A one-off differential comparison against the saved
pre-change implementation matched 1000 generated graphs for waves, pair
relations, dependency edges, conflict pairs, and supersedes. This validation does
not claim that all workflow scenarios or the full repository suite passed.

## Execution-view consolidation

The root `runtime/execution_view.py` module is removed. Its assembly lives in
`runtime/execution/view.py`, with `build` as the entry point. Graph-scoped
metadata compilation and decoration now belong to `execution/metadata.py`.
Callers of smoke-path and deficit-construction helpers import them directly
from `execution/projection.py`. The view calls `metadata.decorate` rather than exporting a second decoration
entry point or sequencing separate field-transfer passes.

Sink-type projection now belongs to `runtime/payload_hints.py`, sharing sink
declaration collection and the existing input-field decoder from
`runtime/reference_projection.py`. It keeps its original executable-context,
facts-only source; payload-hint compilation still retains executable rules.
Subject and role deficits share one ordered traversal, preserving duplicate
records and the subject-before-role order.

Combined production size of the old view and payload-hint module decreased
from 433 to 404 physical lines. Characterization covers every QDL context and
the selected-field boundary for sink types. Ruff and structural lint pass for
the resulting view and payload-hint modules.

Execution-view validation: 234 architecture, binding, probe, payload, causal,
smoke, fixture-selection, and observation-chain tests passed; one optional
algorithm test was skipped. This does not assert full-suite completion.

## Grounding import ownership and independent loading

`grounding/axis.py` now owns only Grounder assembly. Filtering functions,
intersection projection, and AxisResult have no compatibility re-exports there;
consumers import their canonical modules. The existing consultation/axes module
owns the axis type and startup stage constants. Startup and reactive services no
longer import the Grounder assembly module, eliminating the import cycle and
the need to define vocabulary before delayed mixin imports. The unused duplicate
startup-axis list is removed and slicing shares the canonical norms label.

Fresh-process tests load startup, reactive, and axis independently with concrete
extensions and outer adapters forbidden. Broader formal-test collection also
exposed an old prompt import, stale planning/feedback file assertions, and test
assemblies passing a null path runner. Those imports/assertions now follow the
actual owners; consultation-only campaign fixtures provide a BoundPathRunner
mock constrained to its public interface. Timeout, close, admission, source
revision, and shared-quota assertions remain intact and execute successfully.

Validation of grounding import cleanup: 1107 formal, architecture, DI,
consultation outcome, campaign lifecycle, enrichment, and work-item tests passed;
one optional algorithm test skipped. Full repository validation remains open.

## Metrics read boundary

`CampaignMetrics` retains mutable counters and lifecycle validation under its
existing lock. Aggregate readers use its immutable `CampaignMetricsSnapshot`;
the typed single-intent query remains available for execution decisions.
Compatibility getters, the runtime summary wrapper, unused intent/letter count
projections, and mutable token-derived properties are removed. Formatting and
aggregate calculations stay in the neutral snapshot contracts. The mutable
TokenUsage accumulator converts itself into the immutable token snapshot for
both campaign totals and phase totals, without duplicating the conversion.

The runtime module shrank from 512 to 378 physical lines. No files or classes
were added. The detached-snapshot characterization confirms that later token
updates cannot mutate either previously issued total or per-phase snapshots;
existing concurrent-update and frozen-snapshot tests remain in place.
Validation: 226 metric/reporting/architecture/replay tests passed with one
optional test skipped; 29 path-runner tests passed. Two path-runner cases were
excluded due to the previously observed hypothesis-jsonschema `many.more`
incompatibility. Benchmark consumers were migrated to snapshots but their
execution remains unverified because benchmark sources are absent here.

## Scheduler transition ownership

Selection now owns eligibility, ranking, selection accounting, and coverage
fairness. OutcomePolicy owns reward accumulation, the canonical exhaustion
predicate, and retry-budget neighbor blocking. PathRegistry owns prerequisite
and campaign-limit blocking, reopening, supersession, and terminal reason lookup.
The composed scheduler retains its public behavior without forwarding wrappers.
Retry eligibility reuses the same canonical exhaustion predicate that guards
selection and reopening. Neighbor blocking derives its protected set once and
preserves completed, superseded, and in-flight paths.

DeficitQueue imports the shared InterestPrioritizer directly from prioritization;
the scheduler package no longer re-exports that unrelated owner. Existing score,
seed, quarantine, and shared-budget semantics remain unchanged. Characterization
covers protected neighbor states and rejection of exhausted/in-flight reopening.
The three reorganized scheduler modules shrank from 544 to 537 physical lines;
no classes or files were added. Validation: 285 scheduler, deficit, replay,
backtracking, and architecture tests passed with one optional skip; two live
replanning scenarios passed. Structural lint passes throughout scheduler.

## Forbidden-route binding

`bind_forbidden_path` now validates route binding and diagnostics, while the
pure `_forbidden_step` projection builds a validated transition's norm and
executable step. The diagnostic callback adds the shared coverage/path prefix
once. Missing and ambiguous transition checks share the failure emission path
while retaining distinct reasons, kinds, and exact ordered context fields.

The validator shrank from 143 to 93 physical lines; the whole binding module
shrunk from 383 to 378 lines. Structural lint passes. Five characterization
cases cover missing method/scenario, missing transition, ambiguous targets, and
wrong final state. A one-off comparison of 1000 generated routes matched the
saved implementation for full results, invariants, steps, and diagnostics.
Validation: 229 binding/planning/coverage/architecture tests passed with one
optional skip; two live forbidden-state scenarios passed.

The cached Import Linter can run without adding project dependencies:
`PYTHONPATH=packages/core/src uv tool run --offline --from import-linter lint-imports`.
Current core analysis covered 298 files and 1516 dependencies: all six contracts
were kept and none broken. This verifies the configured runtime, verification,
QDL, model, infrastructure, and neutral-contract dependency directions; it does
not by itself verify all optional-package boundaries or complete the runtime
migration.

## Coupling evidence ownership

The coupling resolver types are now `Binder` and `Context`, avoiding repetition
of their containing namespace. Runtime no longer owns typed live-output evidence
interpretation. `qdl.field_roles.declared_output_refs` selects declared output
references (including rule-derived declarations); `verification.projection.
read_live_outputs` intersects live values with scoped canonical witnesses. The
canonical-observation metadata predicate belongs to verification/evidence_facts.

Declared output roles deliberately remain distinct from the currently admitted
role policy: revocation must still trigger canonical witness filtering, rather
than allowing an unverified live value through the untyped-field path. Existing
canonical metadata is never reprojected with a new timestamp; a checker-only
observation may receive only a query-local sentinel projection. Current live
attempts continue to prevent fallback to durable history.

The runtime resolver decreased from 387 to 311 physical lines primarily by
moving interpretation to its owner; total production size across affected
modules decreased by one line. No files or classes were added. The evidence-owner migration initially left two resolver complexity findings
(`_resolve_values` 20 and `_coupled_rows` 16). The applicability and occurrence-history slices below address both.
Validation: the 23 canonical/transient/revocation baseline cases passed before
and after migration; the broader coupling, output evidence, field-role, and
architecture selection passed 306 tests with one optional skip. All six Import
Linter contracts passed (298 core files, 1519 dependencies). Ruff and formatting
passed for the modified code.

## Coupling applicability and backward selection

A pure `_applicable_couplings` policy now separates constraints usable at the
current call from deferred inputs and future postconditions. Endpoint actions
and current input holders are decoded once per coupling, and a shared action
rank replaces repeated endpoint rank searches. Backward closure and joint
occurrence solving remain in `_resolve_values` with unchanged ordering.

Missing producers still defer a current input even when it already has a
concrete value. A future observer permits only concrete current inputs, and
current-output postconditions are checked when consumed rather than before the
current call. Unrelated sibling constraints remain skippable. Five explicit
characterization cases cover these decisions through Binder.resolve_check.

The coordinating method shrank from 95 to 43 lines, with complexity 20 to 6;
the pure policy has complexity 13. Total resolver size is 311 to 310 lines; no
files or classes were added. At that slice, occurrence assembly still had complexity 16; the following slice addresses it.
A one-off comparison of 2000 generated contexts matched the saved pre-change
selection, selected ordering, returned checks, and exception types/messages.
All six Import Linter core contracts remain kept.

Applicability validation: 239 coupling, observation-chain, and architecture tests
passed; one optional test skipped. Ruff and formatting passed.

## Occurrence history selection

A pure `_matching_attempts` query selects compatible history while returning
whether any live attempt suppresses durable fallback. It retains null-response
attempts until after newest-live selection, preserving their ability to block
older values. A live record with a different identity likewise suppresses
retained/durable fallback even when no compatible live record remains.

Endpoint holders are grouped by normalized action once, preserving first-seen
action order and endpoint order, instead of rescanning all endpoints per action.
`_coupled_rows` now assembles current-input, selected-attempt, and durable rows
from those explicit inputs. Its complexity decreased from 16 to 13 and span from
74 to 59 lines; the history query has complexity 5. The whole resolver increased
from 310 to 319 lines. No classes or files were added, and structural lint now
passes for the whole resolver.

Four new characterization cases compare null/foreign-identity latest records
as live versus retained data. The existing latest-failure and canonical witness
cases remain unchanged. A one-off comparison of 2000 generated histories matched
ordered action/occurrence/field rows, including scope, identity, missing responses,
live priority, and durable fallback. All six Import Linter core contracts pass.

Occurrence-history validation: 315 coupling, observation-chain, evidence,
field-role, and architecture tests passed; one optional algorithm test skipped.
Ruff and formatting pass for the modified code.

## Execution owner consolidation

`execution.scenarios.Checker` now owns both direct and path-driven check
execution. The `service.Workflow` delegation layer and its separate Dishka
provider have been removed. Path and differential executors receive the same
run-scoped checker directly. The old root `runner.py` is removed; no aliases
or compatibility modules replace it. Internal dependency names use `checker`.

The former wrapper's `reset_checks` and `generate_pair_checks` operations are
implemented by the existing checker methods, renamed in place. The binding
executor accepts the wrapper's positional budget argument as well as keyword
usage. All 23 method bodies match the saved checker after normalizing those
two method renames; call ordering, partial failures, and isolation algorithms
were not rewritten in this slice.

`execution/results.py` is removed. API, campaign, observation recording and
recovery import the original result types directly from `contracts.execution`.
No additional result types or wrappers were introduced. The provider projection
in the engine runtime documentation reflects removal of the redundant provider.

Runtime decreased from 132 files / 26441 physical lines to 130 / 26257. The
production change across affected packages removes 189 physical lines. These
counts include the relocated checker once, rather than counting its move as
a reduction. A new DI behavior test executes checks in successive run scopes:
lookups within a run see the same history, while the next run starts empty
and cannot modify the previous run's history.

The initial 62 execution/composition checks passed before and after changes.
An expanded architecture, execution and provider selection passed 240 tests
with one optional skip, and the new run-scope test passed separately. All six
Import Linter contracts are kept (296 files, 1510 dependencies). Ruff passes;
formatting passes for runtime, the provider and tests. A whole-packages format
check also reported an untouched automata/plugin.py formatting issue.

A broad run initially exposed two stale architecture/documentation references,
which were corrected. Seventeen other failures reproduce in a separate baseline
copy restored from pre-change files: seven latency fixtures and one witness
fixture pass no path runner; three C2 cases use outdated campaign callbacks;
six profile cases require files absent from this checkout. Two fuzz cases
remain excluded for the previously recorded hypothesis-jsonschema dependency
issue. This slice does not establish a fully green repository suite, finish
runtime consolidation, or resolve the remaining structural lint violations.

Final broad verification after dependency renaming: 1068 passed, one skipped,
two excluded; the same 17 baseline failures remain. No additional failures
were observed in that selection.

## Grounding dispatch consolidation

The remaining reactive adapter in `consultation/reactive.py` was constructed
only by `Grounder`. It owned no scheduling decisions, retained an unused budget,
and called back into grounding's result interpretation. It is now removed.
`grounding.reactive.Followup` dispatches through the injected consultation port
and directly applies the existing axis-result projection. The former private
`_consultation_axis_result` forwarding method is replaced by `_ground_result`,
which contains the actual shared interpretation. No replacement adapter, file,
class or public alias was introduced.

Current ownership follows the execution flow:

| Owner | Responsibility |
|---|---|
| `runtime/consultation` | Campaign work-item readiness, evidence signatures, wave scheduling, terminal outcomes and campaign updates |
| `grounding.reactive.Followup` | Bounded consultation inputs, port dispatch, usage telemetry and response-grounded proposal results |
| `grounding.consultation.DispatchFlow` | Source loading, evidence absorption, promotion and persistence of accepted batches |
| `cloud_dast_llm.consultation.ConsultationDispatcher` | Prompt/model adaptation, delegation depth, request budget and typed model decoding |

The grounding evidence ledger and campaign outcome policy are not interchangeable:
the first absorbs observation references for a service/kind/deficit/action/depth
key; the second records terminal campaign outcomes for a scoped work item and
evidence signature. Their ownership is unchanged in this slice. Promotion
remains a separate explicit boundary; dispatch itself does not accept facts.

Production size decreased by 62 physical lines, one file and one class. The
dispatch and result-interpretation method bodies match their saved predecessors
after dependency and method renames. Classification provenance merging and
`require_response_grounding=True` are preserved. Four characterization cases
passed before and after the edit, checking request/telemetry identity, token
accounting and balanced model-request metrics on success/failure, with/without
a recorder. Existing grounding, consultation, architecture, provider and live
workflow checks passed: 1127 tests, one optional skip. Ruff, formatting for
touched code, and structural lint for the changed grounding modules pass.

A seventh Import Linter contract prohibits grounding from depending on campaign
consultation orchestration. The only three exceptions import the shared axis
vocabulary. All seven contracts pass (295 core files, 1504 dependencies). An
isolated negative-control configuration removed one vocabulary exception and
correctly rejected the corresponding reactive-to-axis import. Remaining runtime
consolidation and the previously recorded broad-suite failures remain open.

## Shared plan projection and snapshot cache

The ordinary and incremental planners previously duplicated constructor policy,
complete QdlPlan assembly, attack-path delegation and closure decoding. Both
implementations now live in the existing `planning/core.py`.
`IncrementalQdlPlanner` inherits the common projection from `QdlPlanner` and
overrides only Clingo snapshot solving; its own constructor initializes the
mutable session and revision counters. One-shot planners have no session state.
The old root `incremental_planning.py` and redundant attack-path wrapper are
removed without aliases. Binding and package exports use the same class owners.

Invalidation still compares canonical fact/rule sets and rebuilds for every
change, including append-only changes that retract conclusions through default
negation or supersession. Retractions still reset the revision counter, unchanged
sets do not re-ground, and the original incremental solver failure message and
log topic remain unchanged. No query rules, evidence policy or QDL ownership
changed. The mutable cache optimizes solving rather than storing independent
executable truth.

Production size decreased by 107 physical lines and one file, with no new class
or helper. Twelve characterization cases passed before and after the change,
comparing complete cached/fresh plans across growth, reorder, retraction, empty
input and regrowth, with varying depths, context selection/order and closure
selection. The focused planner/supersession selection passed 240 tests. A fresh
process additionally imports and executes both planners while campaign, queue,
scheduler, grounding, concrete extensions and outer adapters are blocked. This
replaces the obsolete test demanding separate files for the same projection.

Final validation for this slice: 1375 planner, supersession, formal/QDL,
architecture, binding, causal/live execution and DI tests passed; one optional
test skipped. All seven Import Linter contracts remain kept (294 core files,
1490 dependencies). Ruff, formatting of runtime and touched tests, and structural
lint of planning/core.py pass. A one-off comparison against the saved original
incremental class matched 300 complete plans and revision counters through
mixed-context revisions, repeated snapshots and retractions. No full repository
suite claim is made; the previously documented baseline failures remain open.

## Run-scoped planner injection

`ScenarioBinder` no longer constructs an incremental planner as a fallback.
Its planner dependency is required. `RunProvider.planner` creates the snapshot
cache in Dishka `RunScope` and exposes it as `QdlPlanner`; the binder factory
receives and passes that dependency. All 57 direct binder constructions now
supply a planner explicitly, including test/benchmark assembly. No service
locator, factory port, fallback or compatibility layer was added. The engine's
existing session has no explicit close API; this change defines object ownership
and cache isolation, rather than inventing a new resource protocol.

The DI regression test first reproduced the missing registration as Dishka
`NoFactoryError`. After the change, a real container retains revision history
across lookups in one run and starts a separate cache in the next. Both binder
and planner resolve in each run; planning outputs still match the one-shot
projection. Provider docs include the new run-scoped registration. Production
size increases by 12 physical lines (runtime binding minus one, composition plus
13) to make lifecycle ownership explicit; no files or classes were added.

Verification: the architecture/provider/binding/planning/live selection passed
326 tests with one optional skip; another 208 changed-caller and formal/state
regressions passed. The two changed C2/witness files passed ten tests and still
fail the same four previously baselined outdated callback/missing-runner cases.
The four benchmark caller migrations were linted but not executed because this
checkout lacks their benchmark assets. All seven Import Linter contracts pass,
as do Ruff and formatting for the changed production files and tests. The full
repository suite and the remaining baseline failures are not resolved by this
lifecycle slice.

## Campaign contract checks restored

Eleven recorded runtime test failures have been resolved without changing their
assertions. The two C2 campaign collectors now accept the current RuntimeState
callback and read the same deficit queue/accumulator from it. Their fixed-point
rebind guard, delivered/no-observation cases and execution-before-next-wave
assertions are unchanged. The witness-admission test now uses the real binder,
path runner and finding evaluator already supplied by its fixture. The latency
fixture supplies a spec-constrained path-runner double for the capability not
exercised by these baseline/replanning tests.

Grounding doubles and explicit test owner handoffs now use `load_source`. This
allows removal of AutoGroundingService's `_load_grounding_source` alias and the
consultation coordinator's dynamic fallback to it. The duplicate coordinator
`_key` wrapper is removed; the fair-budget test uses the existing canonical
consultation evidence key. No new types, files, compatibility paths or evidence
policies were introduced. Production size decreases by 28 physical lines.

The exact pre-change selection reproduced 11 failures and 45 passes. After the
fixture/caller migration and compatibility removal, the same 56 tests pass. An
AST comparison confirmed every assertion in the six changed test modules is
unchanged. Ruff, touched-module formatting and structural lint pass. All seven
Import Linter contracts remain kept (294 core files, 1489 dependencies). The
historical failure reports above predate this correction; six missing-profile
checks and the separate dependency/assets limitations remain unresolved.

Expanded validation: 1843 workflow execution, formal/QDL, architecture and DI
tests passed, one optional test skipped. The two previously recorded failing
hypothesis-jsonschema fuzz cases were explicitly excluded. No failure occurred
in this selection; a complete repository run remains unverified.

## Campaign state and component result ownership

Campaign state previously defined three immutable result records used by lower
components. Those definitions now belong to existing component modules:

| Record | Canonical owner |
|---|---|
| `VarianceRecord` | `runtime/differential/results.py` |
| `WaveExecution` | `runtime/consultation/context.py` |
| `EvidenceDeficitRecord` | `runtime/evidence_gate.py` |

All record definitions match their saved originals, including fields, defaults,
frozen and slots settings. Production imports go directly to those owners. The
existing lazy campaign facade resolves to the same classes, while campaign/state
contains only the four campaign state containers. DifferentialState references
the measurement owner by module rather than re-exporting the record. No new
modules, classes, fields or duplicate result types were introduced.

The three compatibility forwarding properties on CampaignRoundState are also
removed. Existing terminal replay tests now read `state.replay` directly; their
expected evidence signatures, outcomes, scope selection and restart behavior
are unchanged. Replay continues to validate/reduce events through EventGraph;
this slice does not replace that algorithm or create a second QDL store.

Net production size decreases by 13 physical lines, primarily from removed
forwarders, not the record relocation. The initial 71 state/replay/freshness,
partial execution, wave and consultation tests passed before and after. Three
fresh-process checks import each result owner and the public facade while
campaign state/lifecycle and outer adapters are blocked. An eighth Import
Linter contract prohibits lower result/consultation/round-state components
from importing campaign state or lifecycle. All eight contracts pass (294 core
files, 1486 dependencies), as do Ruff and touched-code formatting.

Expanded result-owner validation: 1866 execution, formal/QDL, campaign replay,
architecture and DI tests passed, one optional test skipped and the two known
hypothesis-jsonschema fuzz cases excluded. The remaining repository-wide
assets/dependency limitations and unfinished runtime slices remain open.

## Shared carrier and sink projections

The evidence-gate review uncovered duplicated lower-level QDL interpretation
instead of a new consultation policy: supported probe sink types, sink indexes,
input-field decoding and reach/role hint collection existed in parallel in
QDL reasoning, runtime payload hints, runtime grammar facts and reference
projection. Five duplicate helper definitions and redundant constants are
removed. Existing QDL helpers now have one explicit owner in `qdl.reasoning`:
`index_sinks`, `read_input_field`, `collect_reach_hint`, `collect_role_hint` and
`SUPPORTED_SINK_TYPES`. Runtime projections consume these directly. The grammar
field selector retains only its action-membership decision. No new files,
classes, helper variants or compatibility re-exports were added.

`compile_probe_fields` is imported from its actual QDL owner rather than
re-exported from runtime/payload_hints. Its policy is intentionally distinct
from `compile_payload_hints`: current_has plus declared carriers and explicit
probe/oob roles remain separate from the payload compiler's existing explicit
facts and privileged-role policy. An added assertion pins the difference on
the same graph. Runtime-only sink-type projection still excludes graph rules;
the other compiler retains executable rules. Those context/closure decisions
were not generalized into a new configurable engine.

The canonical input decoder preserves the previous public runtime decoder's
all-or-nothing null result for non-text references; two negative cases pin that
contract. The old private QDL decoder could return a partial null pair, but its
three callers already reject either missing component, so query outcomes are
unchanged. A one-off set of 1200 old/shared helper comparisons matched across
malformed terms, mixed-context declarations, sink vocabularies and hint updates.

Net production size decreases by 89 physical lines. The initial focused tests
ran before the refactor; 57 current helper/probe/typed-fixture/import-boundary
tests pass after the final edits. The fresh-process boundary now executes the
shared QDL queries while all runtime and outer adapters are blocked. All eight
Import Linter contracts pass (294 core files, 1487 dependencies). Ruff and
formatting pass for the modified production code and tests.

A separate filesystem-carrier baseline and twelve grammar-compiler failures
reproduce the installed hypothesis-jsonschema/Hypothesis `many.more` error.
The twelve grammar test failures match a run that loads the saved pre-change
QDL/runtime sources. Those dependency failures were not repaired or weakened
as part of deduplication. Evidence-gate admission itself remains a separate
unfinished slice: its supported-witness subset must not be broadened to the
probe sink vocabulary merely because both operate on sink facts.

Final broad validation after all shared-decoder and naming edits: 1848 execution,
formal/QDL, architecture and DI tests passed; one optional skip and the two
previously recorded fuzz dependency exclusions. No failure occurred in that
selection. The separate grammar-generation dependency failures and unfinished
runtime slices remain open.

## Declared dataflow admission

The gate no longer interprets QDL predicate/effect structure. Runtime
`Gate.allows_dataflows` loads the same repository sources and delegates to
`verification.evidence_facts.supports_dataflows`. Verification owns the three
explicit witness routes: a reach bound to the action/input field; a supported
sink with the action's scoped identifier; or a norm joining that action to a
typed sink. Repository exceptions and missing sources still fail closed. The
old long `has_declared_sink_or_reach` method and runtime source-term parser
are removed without aliases.

The query uses existing `facts_for` context selection. It is not a solver and
does not infer rule-derived facts. Only contract/accepted declarations qualify;
an output-field reach is not an input carrier. A bare reaches fact does not
require the sink taxonomy that the norm route requires. The supported norm/sink
subset remains interpreter/filesystem/external_net, not the broader probe
vocabulary. This admission establishes usable consultation context, never
proof of an executed sink or a security violation. The action-only source
reader preserves the previous parser contract and is distinct from decoding
a complete action/field binding.

A 100-case characterization matrix passed before and after migration, crossing
five contexts, two action spellings and ten witness shapes. Existing dataflow
workflow checks bring the focused total to 103 passing tests. A one-off
comparison against the saved gate matched 1000 generated mixed-context graph
and action queries, including foreign actions and legacy prefix spellings.
The fresh-process architecture check also evaluates positive and parked
queries with all runtime and outer adapters blocked.

The original coordinating method's complexity was 23. The runtime delegate is
now 2; the pure query is 6, with effect-join and action-reader helpers at 5 and
4. Production decreases by two physical lines overall: 68 leave runtime and
66 enter verification. No files or classes were added. This is an ownership
and complexity improvement, not a claimed large LOC reduction. Structural
lint passes for both changed modules. Ruff/formatting and all eight Import
Linter contracts pass (294 core files, 1488 dependencies).

Expanded admission validation: 1948 execution, formal/QDL, architecture and
DI tests passed; one optional test skipped and the same two dependency-related
fuzz cases excluded. Repository-wide assets/dependency limitations and the
remaining runtime restructuring are still open.

## Parallel probe execution boundary

Checker's parallel method previously implemented the thread pool alongside
preparation, forwarding isolation, read-back sequencing, call registration and
partial-result accounting. Physical probe execution now belongs to the existing
`execution/checks.py` as `run_probes`, alongside `run_check` and event-context
binding. Checker directly calls it; no forwarding method, executor class,
factory port or new file was introduced. Target and publisher remain injected
capabilities. The thread pool remains a batch-local context-managed resource.

The coordinator still prepares every leg before calls, registers probe attempts
before submission, restores the same output snapshot, skips read-after after
a probe error and builds the partial-result envelope. The executor submits the
whole batch before collecting successful observations in input order. It
retains the first input-ordered probe error even when pool shutdown also fails.
An interrupted submission retains emitted events while preserving the original
partial-result and registered-attempt behavior. Optional read results now use
one quantified presence check instead of separate per-leg predicates.

Three added characterization cases passed on the original method and after
extraction. A two-worker ordering test forces the later input's failure to
complete before the first input fails, while still asserting the first input
as the returned cause and no read-after invocation. Two injected pool-failure
cases pin submission and shutdown behavior, including events, retained probes
and failed-check accounting. Existing snapshot, live-overlap, pair/read-back,
partial-budget and result tests remain unchanged.

The coordinator method shrank from 103 to 96 lines and complexity 21 to 15. The
physical executor has complexity 6. Overall production increases by 22 physical
lines; no shrink claim is made for this boundary extraction. Structural lint
passes for the complete two modules. The focused selection passed 64 tests
before and after; the expanded differential, event, budget, causal/live,
architecture and DI selection passed 448 tests with one optional skip.

A fresh-process check executes probes while campaign, Checker, consultation,
grounding, scheduler, deficits and outer adapters are blocked. A ninth Import
Linter contract enforces the corresponding physical-execution dependency
boundary. All nine contracts pass (294 core files, 1488 dependencies), as do
Ruff and touched-code formatting. Repository-wide dependency/assets limitations
and the remaining runtime restructuring remain open.

## Parallel refinement and completion audit

An independent read-only audit places the runtime objective at roughly 70–80%
completion, based on responsibility and execution paths rather than LOC. The
percentage is an expert range, not a measured fraction. Campaign state/replay,
shared planning and planner RunScope have concrete behavioral evidence; other
boundaries remain partial. The remaining priorities are: reactive/branch
promotion/persistence policy in AutoGroundingService; hidden candidate/recorder
feedback coupling through mutable attempt state; and the DAG node/edge helper
import cycle. Complete semantic inventory and repository-wide behavior parity
are not yet proven by the current ownership table or a targeted green suite.

Three parallel tracks were used: independent identity projection refinement,
response-grounding refinement and completion audit. They had disjoint write
sets; the parent retained evidence reuse and integration.

Identity parsing now has one matcher for supported is/attacker/owner/may3/may4/
targets forms and one normalization path. Declared owners are intersected once
before updating targeted actions. The worker reports all 18 characterization
cases pass on old/new implementations, 5000 graph comparisons preserve complete
IdentityView and insertion order, and 1000 relevant tests pass. Its production
change is +1 physical line, without new classes or files.

Response grounding shares one field shape/owner/evidence-whitelist check across
has, exposes and is. Resource unions are computed only for is(field(...));
existing global-owner semantics are retained. Twenty-four new binding tests
passed before/after; the worker reports 121 relevant tests and 141120 old/new
function comparisons including exception behavior. Production increases by
four physical lines; it adds no files or classes. Parent review found the
policy and fail-closed binding conditions preserved in both worker patches.

## Effect witness selection

Reuse.proved_effects now coordinates generation/resolution, graph reads and step
publication. `couplings.select_outputs` owns selection of equality-only output
witnesses relevant to downstream inputs; unsupported applicable dependencies
return None rather than permitting reuse. `verification.projection.
select_effect_witness` owns the conjunction and output join over canonical
proof rows. It requires all requested effects within one observation, intersects
that observation with each unambiguous output group and selects the newest
matching row, preserving first-row tie behavior. These are projections over
existing evidence, not new domain models or independent stores.

The original distinct identity arguments for effect and output queries remain
unchanged. Output queries are supplied lazily, so an ambiguous/missing witness
still stops evaluation before later queries. No normalized-action policy,
request binding validation, scope choice or event verdict changed.

The reuse coordinator decreased from 104 lines/complexity 20 to 93/10. Net
production across the parent slice increases by 48 physical lines to express
the two responsibility boundaries, with no new files/classes. The original
five-file baseline passed 141 tests. The expanded six-file selection passes
172 tests, including complete/incomplete observation joins, ambiguous/missing/
disjoint outputs, newest valid proofs, ties and equality/reversed coupling
selection. A separate adversarial review and integrated validation follow
before this multiagent batch is accepted. Existing namespace naming warnings
in older couplings APIs were observed and are not claimed fixed by this slice.

Integrated multiagent validation and adversarial review are complete for the
identity, response-grounding and effect-reuse refinements: 2016 tests passed,
one optional test skipped and the same two known fuzz dependency failures
excluded. Global Ruff check and formatting of the selected 134 files pass.
The independent effect-reuse review reports 163 targeted passes and 2000
original/current executions matching results, event payload, reader order,
identity arguments and lazy short circuit; no confirmed regression was found.
These are bounded proofs, not full repository equivalence.

## Proposed next contraction: recovery consultation lifecycle

The user proposed reducing the repeated recovery-consultation DTO chain around
WorkItem, a single attempt boundary and ProposalPromotionRequest/Result. This
is the next architectural candidate; its full implementation is not completed
or implied by the smaller refinements above. Confirmed starting points include
ProposalInput-to-promotion-request field copying, the OracleCompiler adapter,
DerivedSetupRequirement/QdlSubgoal and duplicate backend content codecs.

A smaller type graph must preserve three distinct outcomes: a worker produced
an untrusted proposal; admission accepted facts; queue closure proved one or
more deficits discharged. Current WorkItemGrounding and WorkItemResult belong
to different outcomes. Their separate roles need not require all the current
wrapper classes. Derived gap_closed and the unused WaveContext.revision are
concrete removal candidates.

Further audit distinctions: work-item ID derives from its grouping key, while
AttemptKey also scopes exact evidence signatures; OutcomePolicy's exact-key
outcomes differ from ConsultationLedger's union/subset absorption. WorkGroup
holds live queue entries, WorkItem pins a dispatch snapshot, and DispatchState
is a simulated fairness state committed later. CampaignAccumulator is a mutable
owner while ExecutionResult is a frozen snapshot. None of those pairs should
be merged by field similarity alone. A single recovery entrypoint may permit
removal of redundant paths and their ledgers, after public/dynamic callers are
accounted for. The proposed short chain is a lifecycle target rather than proof
that all concerns can safely fit into four universal mutable DTOs.


## Recovery contract contraction — first batch

The runtime promotion owner now accepts the canonical ProposalPromotionRequest
instead of copying ProposalInput into it. Evidence is projected into the
admission field set at the evidence-owning caller. Parking source IDs and
Activity remain runtime orchestration arguments; the pure request does not
acquire repository or telemetry concerns. Proposal contexts are still forcibly
untrusted at entry, rules are discarded as before, and evidence/action refs
are frozen before policy evaluation. The obsolete AutoGroundingService._promote
and _promote_axis_proposal forwarding methods are removed with their consumers
migrated. Empty reactive/branch proposals still stop before policy evaluation.

NormCompiler/NormCompilation are now the sole norm compilation contract.
OracleCompiler/CompiledOracle and their module are removed, including the
symbolic consumer's import. NormCompilation retains the original fact and
projects its norm/effect rather than storing copies. Accepted-only compilation
and proposal lead views with unscoreable verdict policy remain distinct.

WavePlan, its single-use packing/unpacking, WorkItemResult.gap_closed and
WaveContext.revision are removed. Queue closure uses closed_deficit_ids;
promotion alone does not close a deficit. Both source revision guards and the
lifecycle commit guard remain. WorkGroup live queue handles, immutable WorkItem
snapshots and simulated DispatchState fairness counters still have separate
owners. WorkItemGrounding documentation now describes the owner-thread
committed result rather than claiming that workers produce accepted graphs.

Validation: the same 133 promotion tests pass before and after the parent
change. Independent adversarial review found no confirmed issue and passed
133 targeted plus 138 adjacent cases. Queue worker passed 189 baseline and
197 post-change cases, including readiness/budget/snapshot/revision coverage.
The final combined selection passed 2066 tests, skipped one optional test and
excluded the same two known fuzz dependency failures. All nine Import Linter
contracts are kept; global Ruff check and formatting of all 25 surviving
touched Python files pass. The structure check still reports the same 18
pre-existing findings in verification/norm_view.py and verification/promotion.py;
none were introduced in the checked scope. This is bounded regression evidence,
not a claim that the entire repository or runtime migration is complete.

LOC reporting uses physical splitlines before/after from snapshots in ~/tmp,
separates production and tests, and treats moves as zero net deletion. The
first recovery batch removes 103 production lines; tests add 126 lines.
Per-file measurements are saved in ~/tmp/recovery-compression-loc.json.
The full recovery attempt/type graph and remaining duplicate codecs, setup
requirements and state ownership are still open slices.


## Direct consultation outcomes and acyclic campaign projection

Consultation outcome classification now consumes the existing exception and
evidence flags directly. AttemptObservation, ConsultationErrorKind and their
encode/decode step are removed. The evidence owner classifies WorkItemGrounding
with the work item's evidence requirements; OutcomePolicy records the canonical
six-state result and retains exact scope/work-item/evidence-key absorption.
Unknown statuses are rejected before the first state mutation; existing absorbed
states still ignore later input. This preserves the old internally generated
outcome alphabet at the newly explicit recording boundary.

The original 53 cases passed before and after; two new behavior cases cover
invalid/None input leaving the key ready, valid subsequent admission, and ignored
input after absorption. Independent review reproduced 112 complete input
classifications and 12544 absorbing transitions against the saved original,
without a difference for valid states. No runtime-neutral contract or execution
boundary acquired model/transport responsibilities.

Campaign DAG projection previously depended on two mixins that imported helper
functions back from the builder. Importing either mixin first failed due to the
partially initialized class. The same node/edge projection now belongs to the
existing _Projection owner; dag_nodes.py and dag_edges.py are deleted. EventIndex
and the immutable CampaignDag remain separate owners. The only projection
algorithm deduplication is the shared verified-fact VerdictNode constructor.
The original 1051 lines across three production files become 993 in one file;
this is 58 deleted lines, not a claim that all moved lines disappeared. The
projection remains sizeable and its detailed node mappings are not claimed
fully compressed by this boundary fix.

Complete serialized projections and canonical hashes match on 18 original/new
samples. Behavior pins cover richer observations surviving reference-only events,
last-event precedence, same-ID ambiguity within contexts, edge-payload identity,
semantic event order, raised-findings-only report nodes, reciprocal relations,
and campaign event scope. Cold-process tests execute projection and replay after
different public imports. Old module-location assertions were replaced; no test
requires the retired mixin names. Import Linter now enforces pure outcome policy,
projection independence from execution coordination, and acyclic campaign-module
imports. The acyclic contract fails on saved original projection source (exactly
two back-import edges) and passes on the current tree. Twelve contracts are kept.

Final combined validation: 2081 passed, one optional test skipped, the same two
known fuzz dependency failures excluded. Global Ruff and formatting of the eight
surviving touched Python files pass. Structural lint passes on the four current
production modules. Physical Python LOC for this batch: production 1688 -> 1607
(-81), tests 3440 -> 3698 (+258). Config/documentation changes are not counted as
Python code. Snapshots and per-file counts live in ~/tmp/outcome-dag-loc.json.

The execution/recording seam and its partial-result ordering were the next
confirmed ownership debt; the following slice removes the shared context. The
branch/reactive admission paths remain separate: blocked identity, sibling
promotion scope, provenance and fixture/classification policies differ and need
deliberate unification. The latency-baseline updater in consultation/evidence.py
remains a side-effect callback, not a pure evidence projection.

## Step-bound recording without candidate access to campaign state

The candidate engine no longer receives _StepContext with Any request, attempt
and round state. Its private _StepRun contains only a typed immutable path,
step index, prefilter result, session, budget, scope and invocation telemetry.
It is constructed and used exclusively inside the candidate engine. The engine
accumulates step proof from ObservationEvaluation returned by its recording
callback; it does not read or mutate PathAttempt or CampaignRoundState.

Coordinator.bind captures the existing request/path-attempt/round owners for
one synchronous step. Publisher.bind captures only service, path/step, scope
and the existing verified-fact dedup set. Neither binds another universal DTO;
no new domain entity, proxy or service class was introduced. Each returned
callback is consumed synchronously by the local run and is not stored by the
candidate engine. All new signatures stay within eight parameters. The two
pass-through path recording/shrinking methods and the prefiltered-check selector
callback are removed. PrefilterResult replaces the private shared candidate
type in execution/contracts.py, its actual cross-component owner; this is a
move, not a deletion counted as shrinkage.

Recording still preserves the exact partial-result sequence: history/provenance,
classification, publication, feedback metrics, proximity/best-proximity write,
session.record, proof OR, minimal-check write and finding metric. A session
exception retains proximity but not the subsequent proof write; a finding-metric
exception retains proof and the minimal check. The forwarded check is looked up
before feedback and again after feedback because reentrant feedback may append
a newer check or change the session to replay. Six cases were characterized
against the old API and new binding. The publisher worker additionally compared
108 old/new effect executions. Independent review found no actionable issue and
passed the six recorder cases plus the import-isolation case.

A newly explicit candidate-engine contract exposed a pre-existing coverage gap:
Import Linter omitted runtime/candidates because it had no __init__.py. Adding
its package initializer made session.py and feedback.py visible to the import
graph. An inspection of all core Python directories found no other missing
initializer. Fresh uncached analysis now keeps fourteen contracts across 294
files and 1497 dependencies. The new contracts prohibit candidate-engine access
to round/attempt/recording owners, and prohibit observation/terminal owners from
importing the candidate engine. A cold-process check proves those owners import
without loading the candidate engine, path runner or assembly.

Focused integration passes 203 cases; final broad integration passes 2088,
with one optional skip and the same two known fuzz dependency exclusions.
The full log is ~/tmp/step-boundary-integration-tests.log; test storage is under
~/tmp/pytest-step-boundary-final-ig60ssc2. Production Python LOC is 1988 -> 2026 (+38),
tests 4978 -> 5221 (+243); the package initializer is included and the moved
prefilter envelope is not counted as deletion. Snapshots/per-file measurements
are in ~/tmp/step-boundary-loc.json. Global Ruff and formatting of all eleven
surviving touched Python files pass. Existing Publisher.publish_step_event still
has eleven parameters; this slice does not claim to resolve that prior warning.

At this first boundary extraction, adaptive feedback still remained inside the
recorder. The following slice assigns that policy to candidate execution without
losing partial state on exceptions or growing signatures beyond eight arguments.
The full runtime migration and complete semantic inventory remain active.


## Candidate-owned feedback and explicit observation completion

Adaptive feedback now belongs to StepCandidateRunner: generator metrics, effect/
trace proximity, the ungrounded-FAIL reward clamp and FuzzSession.record. The
recorder no longer imports candidate policy or calls session.record. It returns
the existing evaluation, a read-only Sequence view of the path observations and
a bound completion operation. Candidate execution performs feedback, then calls
completion. That operation owns proof OR, the dynamic minimal-check lookup,
post-feedback replay exclusion and finding metrics. Failure before completion
skips it; no finally block performs a false commit.

PathAttempt.record_proximity owns the maximum-over-path update and is passed as
a narrow capability. Candidate execution still has no request/attempt/round
owner reference; the trace view supplies only existing Observation values.
A live sequence is intentional: trace_proximity snapshots it after generator
metrics, preserving additions made by reentrant metric callbacks. Both old
check lookups are preserved in their original stages. The legacy last-check
association is not claimed redesigned by this ownership move.

A generator context manager was considered but rejected because PEP479 would
change StopIteration from recording/finalization into RuntimeError. Explicit
completion preserves exception identity without a new class, DTO, protocol,
helper module or lifecycle wrapper. Every new signature stays at or below eight
parameters. Six prior partial-result pins were adapted to the real candidate
entrypoint and expanded to sixteen cases: scope/one-shot, budget, ungrounded and
normless feedback, proximity callback failure, reentrant trace timing, replay,
and StopIteration identity. Independent review found no actionable issue and
passed those sixteen cases plus cold import isolation. The candidate worker
also compared 128 feedback scenarios against the original algorithm before the
final explicit-completion refinement; the feedback algorithm itself is unchanged
by that refinement.

The independent latency slice removes update_latency_baseline from the evidence
lookup module. The existing wave coordinator now owns the baseline existence/
update decision and success/defer transition. The oracle-None branch, cached
baseline short circuit, action_matches filtering and observation order are
unchanged. Twenty-one existing/new baseline cases passed before and after;
no helper or replacement DTO was introduced. The two production files shrink
504 -> 491 (-13). The overall batch is production Python 2027 -> 2032 (+5),
tests 6482 -> 6806 (+324); moved feedback is not counted as deletion. Per-file
counts and snapshots are in ~/tmp/feedback-owner-loc.json and its referenced
backup directories.

The import boundary now excludes the entire candidate-policy family from
observation/terminal owners. A fifteenth contract excludes mutable latency
state from consultation evidence lookup. Fresh uncached Import Linter keeps all
fifteen contracts. Global Ruff and formatting of all ten touched Python files
pass; structural checks pass for the edited behavior owners. Focused feedback/
causal/architecture integration passes 213 cases with one optional skip and the
two known fuzz dependency exclusions. Final combined integration passes 2108
cases, skips one optional test and excludes the same two known dependency
failures. The log is ~/tmp/feedback-owner-integration-tests.log, and test
artifacts are under ~/tmp/pytest-feedback-owner-final-hbw4pb1w.

Remaining work still includes branch/reactive admission consolidation, explicit
scheduler/replanning state ownership, the legacy global executed-check lookups,
remaining neutral-contract typing and complete runtime semantic inventory. This
batch does not claim the entire runtime goal achieved.


## One admission path for reactive and branch proposals

AutoGroundingService.commit_batch replaces the separate reactive and branch
commit methods. It keeps the axis supplied by the owner, uses the original
blocked action for branch identity/parking/telemetry, and uses only the pinned
sibling neighbourhood as branch promotion scope. The supplied slice selects
the branch policy; a generic alternatives axis without a slice remains generic
reactive admission. Invalid branch axis/cardinality combinations fail before
any parking or policy side effect. Fixture exemptions remain exclusive to the
normal fixture axis; a branch result cannot inject classification context.

The common _save_batch retains distinct branch/reactive provenance and adapter
versions, source IDs, logs and return graphs. Reactive supersession still runs
before saving; branch supersession still runs after saving. The deterministic
promoter's own supersession application remains in the same relative position.
No persistence contract or proposal/context rule was relaxed.

Classification fallback now uses the existing canonical
ClassificationPromotionContext.from_mapping before the model callback. The
prepared result receives that frozen obligation and observation lineage only
when it has no provided classification context. This removes raw mutable
context from commit without widening its signature beyond eight parameters.
The old classification.promotion_context forwarding helper and three unused
copies of supersession constants are deleted; the projection remains their
single owner. Preparation for branch prompts and measured variance remains
separate because those flows have substantive input policies.

All repository consumers, test handoffs and fake ports now use the shared
commit. The stale source-revision test mock was also migrated so it still checks
the live admission entrypoint. There are no compatibility wrappers, aliases,
new domain types, or new production modules in this contraction.

Validation: 73 original baseline cases passed. Eight newly characterized old-
snapshot cases passed before migration; 39 current admission cases passed.
Focused combined validation passed 285 with one optional skip. Full combined
integration passed 2128, skipped one optional test and excluded the same two
known fuzz dependency failures. Fifteen Import Linter contracts, global Ruff,
formatting and structural checks of the edited production owners pass.

Independent review found no production defect and compared 896 original/current
executions with real PromotionPolicy/ProposalPromoter and in-memory repositories.
Return graphs, saved content/metadata, parked leads, quota counters and save
failure behavior matched. Backend and concurrency validation were not separately
rerun by the reviewer; the broad test log records the integration scope.
Review exposed a weak positive
classification test: trusted source facts would pass without the context.
The existing eight-case matrix was strengthened with trusted facts outside both
the bound term and alphabet. All eight cases pass; a context-dropping canary
fails the expected three bound-context cases and preserves the five controls.
Only those test assertions changed after broad integration; all production
source hashes still match the fully tested snapshot.

Physical Python LOC for the changed files: production 1022 -> 961 (-61), tests
2887 -> 3248 (+361). Moves are not counted as deletion. Per-file counts are at
~/tmp/grounding-commit-loc.json; the broad log is
~/tmp/grounding-commit-integration-tests.log. Test artifacts are retained under
~/tmp/pytest-grounding-commit-final-ax_kl8kq.

The complete semantic inventory above now covers 127/127 runtime modules and
25725 physical lines. Its four source-reading passes have been reconciled with
all current source hashes. The inventory is complete as a dated code map; the
architecture migration is not complete. Ranked remaining cuts are recorded in
the inventory manifest: explicit scheduler/queue transition ownership and replay
permissions; canonical inward request/result contracts and composition; shared
executable QDL projections; differential measurement planning/admission/cost;
and observation-to-executed-check association. Code facts such as manually
selected hash fields or repeated reserve arithmetic are recorded as audit
leads; their behavioral impact needs validation before they are called defects.

## Graph-scoped executable metadata contraction

`execution.metadata.decorate` now owns executable-input attachment. It compiles
roles and reference targets once, derives typed references from those existing
maps, and applies couplings, probes, sinks, grammar and reference fields in one
step/plan update pass. Identity decoration remains first, with its separate
smoke policy. The view binds paths and calls this operation; it no longer exports
another decorator. Seven field-transfer traversals and four graph-reparsing or
forwarding reference APIs are removed without aliases or a new DTO/module.

`grammar_facts.compile` indexes a nonempty batch once and shares one Clingo
reachability result. It preserves asymmetric plain/qualified action aliases,
interleaved constraint ordering and unknown-operator errors in sorted requested
action order. Empty batches do not solve. Grammar and payload hints may use
executable rules; sink attribution deliberately remains fact-only. These
projections have distinct semantics and are not collapsed into a shared query.

Path versioning materializes requirements once per graph object retained in the
input paths. The cache is local to one call; another invocation recomputes it.
Own trusted requirements change an instruction identity; runtime evidence and
unrelated facts do not. Two stale generator-suite test fixtures used `causes`
while expecting requirement-driven invalidation and failed before any edits.
They now declare `requires`; the production identity contract is unchanged.
The semantics of including candidate-generator choice in instruction identity
remain a separate open decision.

Independent subprocess comparison against the original runtime snapshot matched
7284 cases: 6912 decorated path results (including full plan fields, field sets,
witnesses and IDs), 72 complete view builds, 72 empty-path builds, 72 grammar
batches, 72 reference projections, 72 sink projections, 10 error cases and two
cache-output cases. A separate repeated-call check reduced requirement queries
from 36 to six for six graph snapshots, on both calls, with identical outputs.
The reproducible harness and JSON summary are retained under
`~/tmp/executable-validation-20261028/`; this is bounded equivalence evidence,
not a claim about every workflow or external target. An additional independent
boundary matrix matched 555 cases, including 108 successful planner-to-view builds.
The independent review found no actionable issue in this bounded four-file diff;
its report and reproduction commands are `executable-validation-20261028/REVIEW.md`.

The final regression passed 2136 cases, with one optional skip and the same two
known Hypothesis-related exclusions. Final path-identity/versioning checks pass
23 cases. Grammar projection checks pass 17; the 12 existing Hypothesis/schema
engine failures remain outside this refactor. Ruff, touched-file formatting and
structural checks pass. Sixteen uncached Import Linter contracts pass across
294 core files, including a new prohibition on field-projection dependencies on
campaign/execution/grounding/consultation/candidate/scheduler coordination.

Changed production Python: 982 -> 836 (-146 physical LOC). Changed tests:
4805 -> 5026 (+221). No file moves count as shrink. The baseline snapshot and
per-file counts are `~/tmp/executable-inputs-before-20261028/` and
`~/tmp/executable-inputs-loc.json`; final regression output is
`~/tmp/executable-inputs-final-tests.log`. The semantic inventory was re-read for
the four production modules and all 127 source hashes/counts reverified; the
combined manifest now covers 25579 runtime LOC. Queue transition ownership,
replay/scheduling coordination, inward contract dependencies and other ranked
cuts remain active; the runtime migration is not complete.

## Canonical deficit lifecycle state and explicit dispatch policies

The existing `deficits/lifecycle.py` now contains QueueState, the sole owner of
entry records, closed/stale membership, arrival order and per-work-item evidence
revisions. DeficitQueue coordinates selection and owns DispatchState counters;
it keeps no second entry registry. Existing queue APIs delegate real lifecycle
operations rather than supplying the whole mutable queue to free functions.
Private type aliases in queue.py are removed. No module, compatibility API or
parallel state representation was added.

Lifecycle success/failure/result paths share release and settlement, while
attempt exhaustion and absorbing outcomes share saturation. The semantics are
retained: untrusted feedback releases in-flight work and quarantines without
charging attempts; one mixed work-item result charges at most one attempt;
new evidence reopens only the revision's saturation-closed keys. True semantic
closure and stale membership survive. Historical repeated-absorption behavior
is intentionally unchanged, including replacement by an empty reopen-keyset.

Wave planning accepts groups, work projections and a counter-snapshot capability.
Readiness executes before that counter snapshot is read; the queue commits
selection afterward. Propagation shares one closure/stale loop and receives a
lazy pending-deficit iterable plus confirmation/staleness capabilities. Eligibility
is rechecked on each iteration and each transition commits before the next query,
so later failures retain prior mutations. It uses no generator context manager
around the closure operation; StopIteration identity is preserved.

Semantic confirmation is deliberately separate from manual close_key. The latter
skips stale keys and releases in-flight state; propagation historically did
neither. Parent review caught this difference, and QueueState.confirm preserves
it. Independent simulation substituting close_key causes three reentrant-stale
parity mismatches; the final confirm implementation matches the old behavior.
The added reentrant-dispatch pins also prove that semantic closure does not
cancel newly selected work or lose its later attempt charge.

Fourteen new public behavior cases passed on the saved old runtime and current
runtime: eight lifecycle/revision/quarantine cases and six reentrant/partial-error
cases. The first focused suite passed 141; the two specialized propagation files
passed 126 before the six exception/reentry additions. The final broad regression passed 2150 tests, with one optional skip and the
same two known Hypothesis-dependent exclusions. Its final-source output is
`~/tmp/queue-owner-final-tests.log`. One early exception fixture accidentally
used two equal canonical deficit keys; correcting the second effect made the
partial-closure error reachable in both versions, with no production change.

Independent paired subprocesses matched 1607 sequences and 17245 actions,
including public results, nine public properties, 19851 rendered logger records
(2199 cold scores) and 96 expected exceptions. Actual QDL results exercise normal
closure; controlled closure/stale callbacks exercise failure and reentry ordering.
No actionable issue remained within the reviewed four-file scope. Source hashes
were checked against the independent report. This is finite synchronous evidence,
not a concurrency or memory-profile claim. Reproduction is retained in
`~/tmp/queue-validation-report.md`, `queue-parity.py` and `queue-compare.py`.

Eighteen uncached Import Linter contracts pass. Two new contracts prohibit
lifecycle-state dependencies on dispatch/campaign coordination and prohibit wave/
propagation dependencies on the mutable owner. Removed architecture assertions
only named the former free functions; behavioral pins and import contracts now
cover those boundaries. Ruff and structural checks pass for the four production
modules, and changed Python files are formatted.

Changed production Python: 1065 -> 977 (-88 physical LOC). Changed tests:
5757 -> 5952 (+195). Internal relocation of state is included on both sides;
only net deletion counts as shrink. Baseline source and per-file counts are
`~/tmp/queue-owner-before-20261028/` and `~/tmp/queue-owner-loc.json`. The combined
semantic manifest was re-read for the four modules and now covers 127 files /
25491 runtime lines. The original per-group inventory files remain historical.

Consultation OutcomePolicy versus queue absorption remains a separate commit/
publication-order boundary. Direct-grounding evidence-subset identity has a
different scope/lifetime and is not merged blindly with wave attempts. Campaign
replay/scheduling, inward public contracts and the other remaining runtime cuts
are still part of the active migration.

## Inward campaign, plan and assessment contracts

Runtime no longer imports the public `api` aggregation surface. LiveRequest,
LiveResult and ScenarioBinding belong to `contracts/execution.py`; bound
QdlExecutionStep/Path/View and InvariantProjection belong to `contracts/plan.py`.
Public API exports reference those exact objects. PrefilterResult stays in
runtime: its immutable envelope holds actual live fuzz-session capabilities.
No copy, compatibility model, deferred type-resolution trick or annotation
weakening was introduced; witness_requirement remains unchanged.

Canonical coverage/action/norm read models belong to `contracts/assessment.py`.
The assessment name preserves established CoverageMatrix/CoverageSummary names
without introducing a coverage.Coverage... namespace repetition. Models keep
pure read properties and the summary helper they require. Ledger construction,
term-factor evaluation, evidence projection, norm-row computation and invariant
projection algorithms remain in verification. AST comparison proves 23 moved
class bodies unchanged, 37 verification function bodies unchanged, and the
existing VerificationPlan unchanged. Consumer migration covers 179 files;
excluding intentionally updated architecture tests, their non-import ASTs are
identical to the snapshot. Updated imports include optional algorithm packages
and reporting consumers, not just the central runtime flow.

Nineteen uncached Import Linter contracts pass. Runtime cannot import api;
public api cannot import runtime, verification, infrastructure or composition,
including indirectly through other contracts. Four independent cold processes
imported contracts/API and resolved owned-class type hints while loading zero
runtime/verification modules. Nine of nine public API exports are canonical.
Independent model comparison matched 440 records across 22 classes: signatures,
defaults, schemas, JSON round trips, validation errors, frozen/slots behavior,
64 factor combinations, 32 ledger states, coverage aggregation and bound-plan
identities. No actionable issue remained in that bounded independent review.
The existing ExecutionResult name still triggers the same pre-existing SL106
warning under contracts.execution; no linter exemption or public type rename
was added. New assessment/plan/API/prefilter modules pass structural checks.
All changed 188 Python files are formatted and global Ruff passes.

Validation is deliberately reported at both scopes. The established bounded
runtime/formal/composition/architecture/symbolic regression passed 2150, with one
optional skip and the two existing Hypothesis exclusions. The available full
repository collection contains 4092 tests: 4035 passed, 56 failed, one skipped.
Every one of those 56 failures was rerun against the complete original Python
snapshot and against current source; all 56 normalized failure messages match.
The snapshot reproduction shares the three unchanged packaged YAML resources,
preloads its own extension packages, and runs from the snapshot directory.
Its first harness attempts exposed missing static YAML and mixed import paths;
those were corrected before attributing any failure to the baseline.

The 56 failures consist of 46 Hypothesis/schema-engine failures, six missing
launch profiles, one missing .env.example, two tests calling the already absent
private _shrink_finding method, and one historical-transition review failure
(target expected paid but received shipped). The latter was investigated in the following replay/state slice and traced to
an incomplete formal test contract (see below); it was neither an import
regression nor an environment issue. Full collection
also has 27 unavailable modules requiring absent benchmark sources or optional
aalpy; they were excluded explicitly from the 4092-test run. No dependencies or
missing fixture assets were invented to make that suite appear green.

Evidence: `~/tmp/inward-contracts-full-tests.log`,
`inward-contracts-regression-tests.log`, `inward-contracts-failure-comparison.json`,
`inward-contracts-algorithm-ast.json`, `inward-contracts-consumer-ast.json` and
`inward-validation-20261028/{probe.py,audit.json,differences.json}`.
The reproducible baseline failure command is the current .venv/bin/python
running `~/tmp/inward-contracts-baseline-failures.py`; the paired current command
is `inward-contracts-current-failures.py`, followed by `compare-inward-failures.py`.

Whole-slice physical Python LOC, including every moved/new definition and all
import consumers: production 29605 -> 29563 (-42), tests 51472 -> 51402 (-70).
These are changed-file totals; code moved into assessment/plan/execution is
included on both sides. The small net decrease is import/export cleanup, not
algorithm shrink. Counts/snapshots: `~/tmp/inward-contracts-loc.json` and
`inward-contracts-before-20261028/`. The inventory reverified all 127 runtime
files / 25395 lines; 53 changed records have import-only executable AST equality,
and the remaining live prefilter contract was re-read. Campaign facade exports,
planner program assembly and other ranked runtime cuts remain active.

## Replay investigation: durable existence versus initial state

The historical-transition failure discovered by the full suite was investigated
before changing execution policy. Exact tracing showed first Create/Pay/Ship,
then reused Create/Pay and a second Ship. The original test declared only durable
create(type) for Create, required only that existence for Pay and declared only
allowed(Ship) for Ship. Its target nevertheless advanced a private state to
shipped. No second resource was created, so the failure did not demonstrate
cross-resource proof leakage. Globally disabling persistent reuse would break
explicitly supported reuse of a still-valid resource in test_causal_execution.

The corrected test now declares the initial transition new->created alongside
create(type), requires that initial transition for Pay, and declares the final
paid->shipped transition for Ship. Trace-before on Create describes the new
object's new state, not the previous object's global state. Existing algorithms
then execute two complete chains with distinct IDs and forward the second ID to
its own Ship. After each chain the test independently reads durable evidence:
create(type) remains true, both old initial/paid transitions are no longer valid,
and the declared shipped transition is present. This states the fresh-object
requirement in QDL rather than adding a hidden runner cache policy.

An independent source review confirmed the distinction. Runtime requires joint
effects from one observation; declared transitions retire prior transition
claims for the same typed instance, without erasing durable existence. Both
original and completed-contract diagnostic traces are retained in
`~/tmp/replay-diagnosis.json` and `replay-complete-state-diagnosis.json`.
No production implementation or canonical evidence query was changed.
The unchanged nineteen Import Linter contracts and architecture suite were rerun.

Validation: 57 tests passed across review_P2, causal execution, transition
projection and event replay. Two isolated negative experiments each fail the
corrected case as intended: disable input-effect retirement, or weaken joint
effect matching by dropping required transitions. These experiments patch only
subprocess globals; repository production source remains unchanged. Logs and
reproduction: `~/tmp/replay-contract-tests.log`, `replay-contract-canary.py`,
`replay-canary-invalidation.log` and `replay-canary-joint.log`.

Physical LOC: production unchanged (delta 0); tests/test_review_P2.py 500 -> 532
(+32). Original test/doc/manifest snapshot is `~/tmp/replay-contract-before-20261028/`,
counts are `~/tmp/replay-contract-loc.json`. All 127 runtime source hashes match
the prior verified inventory. This closes the investigation lead as an incomplete
formal fixture, not a fixed production replay bug. The actual scheduler/replay
state-owner consolidation remains an open architecture cut.

## Explicit scheduler transition ownership

CoverageDrivenScheduler no longer inherits four cooperating mixins. It composes
PathRegistry, LatencyPrewarm and the canonical State, and calls pure ranking
functions. Registry owns discovery-order path snapshots and the coverage-key
index; State owns selection/attempt/reward/terminal/latency writes; readiness
queries propose hold/bootstrap/release changes through State methods. The former
outcomes.py mixin is deleted. No replacement module, parallel state model or
compatibility alias was added. CoverageKey remains at its original model owner.

Public scheduler APIs and their keyword names remain intact. Public imports of
state/ranking now avoid loading core, readiness, registry, campaign or execution
coordination: the existing scheduler package loads its coordinator lazily.
Round/terminal writers use State.remember_evidence/forget_evidence at their
original positions relative to replay-map updates and event publication.
This gives scheduler fields one write authority; it does not claim that
RoundReplay's separate maps have already been consolidated.

Ordering remains part of the contract. Each advisory score is committed before
ranking the next candidate; a scorer exception retains previous scores without
selecting a path. Attempted-key projection is evaluated only after releasing
in-flight status and charging the path attempt, retaining partial mutation if
iteration or lookup raises. Registry path-source capabilities are read at their
original stages; remaining work still synchronizes latency at the old telemetry
points. The read-only key map is a cached MappingProxyType view of the existing
dictionary, not a repeated data copy. Refreshing a known path keeps its cached
coverage keys, matching the original behavior.

Evidence reopening, baseline release and prerequisite blocking retain different
permissions. Reopen rejects superseded/in-flight/exhausted paths without resetting
attempts. Baseline release can clear its bootstrap block while the canonical
budget still prevents further dispatch; neither operation clears history,
quarantine or coverage. Supersession keeps already-applied sorted replacements
when a later in-flight replacement raises. No generic reset operation merges
these decisions. Existing accepted PathOutcome strings are unchanged.

Validation before independent review: original focused suite 55 passed;
eleven additional public behavior cases pass against both the saved runtime and
current source, bringing that suite to 66. The scheduler file alone passes 39,
including a public replacement_paths keyword-call pin. Architecture checks pass
151 with one optional skip; all 21 uncached Import Linter contracts pass, with
new prohibitions on state/ranking dependencies on coordination. The final broad
runtime/formal/composition/symbolic/review_P2 regression passes 2189, with one
optional skip and the same two known Hypothesis exclusions. Pure ranking matched
1000 states / 5000 path rankings, including score outputs, pending-outcome sets,
non-mutation and missing-key errors. Independent paired sequence checking covered 999 cases / 96220 operations
and 97219 trace records. The 998 non-keyword cases matched completely, including
state, paths, cached keys, logs, callback order and partial exceptions (968
RuntimeError, 534 StopIteration, 102 ValueError). The one keyword mismatch came
from an earlier loaded candidate; a fresh run of corrected case 0 matched the old
constructor, return, complete state/paths/keys and logs. This is explicitly a
998-case paired run plus one corrected boundary rerun, not a claim that the whole
999-case matrix was rerun after the keyword correction.

Physical Python LOC for all changed production files, including deleted
outcomes.py and all three external signature/reserve callers: 1826 -> 1911 (+85). Tests:
3335 -> 3648 (+313). Explicit composition and capabilities increase the total;
the removed file is counted on both sides and is not presented as net shrink.
There are two fewer implementation classes (Chooser and OutcomePolicy), while
ranking and state ownership are independently testable. Ruff, changed-file
formatting and scheduler structural checks pass without new lint exceptions.

Artifacts: `~/tmp/scheduler-owner-before-20261028/`,
`scheduler-owner-loc.json`, `scheduler-owner-frozen-tests.log`,
`scheduler-owner-architecture-tests.log`, `scheduler-owner-imports.log` and
`scheduler-owner-keyword-tests.log`. The combined semantic inventory re-read the
eight surviving changed runtime modules, archived the retired outcome owner,
and now covers 126 runtime files / 25480 physical lines. Replay restoration versus
current outcomes/signatures remains the next scheduling ownership boundary;
other ranked runtime/grounding cuts remain active.


Final ownership audit also found the differential reserve-release writer through
its local State alias. State.release_unattempted now owns exactly that transition;
the differential coordinator retains logging and the remaining-work query. An
independent 16-configuration paired comparison (32 release calls per runtime)
matched outputs, all state, callbacks/logs and an injected readiness error after
release, including zero/missing/None attempts and protected-set overlaps. The
integration pin proves only unattempted paths reopen, without resetting retries,
quarantine, reasons or selected coverage. This adds no generic reopen permission.

Readiness receives registry.snapshot directly. A measured intermediate closure
capturing the coordinator retained it until cyclic GC; the final bound-registry
capability removes that internal cycle. A weak-reference lifecycle test with
cyclic GC disabled passes on both the original and final scheduler. The complete
scheduler test file now passes 41 against both runtimes. This is a lifecycle pin,
not a comprehensive memory profile. The final broad frozen-source run passes
2189, with one optional skip and two unchanged Hypothesis exclusions. Additional
evidence is scheduler-owner-release-result.json, scheduler-owner-keyword-recheck.log,
scheduler-lifetime-tests.log and scheduler-lifetime-baseline-tests.log under ~/tmp.

## Replay evidence ownership — 2026-10-28

Scheduler `State.evidence_signatures` is the sole retained owner of evidence
signature values. `RoundReplay` keeps historical outcomes for replay skipping
and a set of paths whose signature was captured in this round. The set has a
shorter lifetime than scheduler memory: an early prerequisite/symbolic exit in
a later round may recapture evidence even when a retry signature survived in
the scheduler. No signature-value map is retained in round state.

Restoration first reduces scoped history to the latest surviving
`QdlPathEvaluated` per path. Consumed scheduler invalidations remove historical
evaluations. Only after graph projection succeeds are surviving signatures
restored through an explicit capability, including `None`. An invalidated or
absent historical entry leaves an existing scheduler signature available as
fallback, matching the former lookup. Historical skip outcomes remain distinct
from live scheduler outcomes, attempts and coverage budgets.

Finish captures evidence before outcome processing and publication. Evidence
invalidation still reopens first, publishes second, updates metrics third, then
clears historical skip/capture membership and scheduler evidence. Publication or
metrics exceptions therefore retain the prior evidence and existing partial
transition behavior. This slice does not add transactions or change admission,
findings, scope, budgets or retry policy.

Five additional behavioral cases passed against the original source before the
production change: invalidation publication/metrics errors, historical `None`
masking retained memory, invalidated history retaining unpublished evidence,
and early-exit recapture across rounds. Final focused validation: 21 passed.
A deliberate in-process canary substituting persistent signature membership for
round capture membership fails the new recapture test. The final broader suite
passed 2198 tests, with one skip and two previously incompatible private-API
tests deselected; this is not a claim that the entire repository suite is green.
Ruff, formatting and structural checks pass. All 21 import contracts pass; the
existing campaign-projection contract now also covers replay, preventing imports
of scheduler/execution/consultation and other coordination implementations.

Independent review found no actionable defect in all five changed production
modules. Its separate 22-test run covered semantic freshness and replay outcomes;
additional checks exercised final-only restoration, invalidation, and graph
reduction/projection errors before callbacks. No concurrency stress test was run.

Snapshots and reproducible evidence are under `~/tmp/replay-owner-before-20261028/`,
`replay-owner-final-tests.log`, `replay-owner-imports.log`,
`replay-owner-canary.log`, `replay_owner_canary.py`, `replay-owner.diff` and
`replay-owner-loc.json`. Physical Python LOC for the changed production files:
1192 -> 1201 (+9); changed tests: 4232 -> 4369 (+137). The production increase
makes restoration and capture lifetimes explicit while removing duplicate
retained values; it is not reported as code shrink. No files were moved or added
to production. Remaining work includes terminal-policy consolidation across
witness/symbolic exits and repair publication, startup batch/stream duplication,
and the other open cuts in the semantic inventory.

A separate parent-run old/current differential matched **400 deterministic scenarios / 5600 operations** with zero differences in events, signature callback traces, replay skip eligibility, scheduler outcomes/attempts/coverage and exceptions. It exercised scoped histories, missing signatures, ignored/consumed invalidations, retained memory, repeated restoration, selection, finish/retry, skips and publication failures. Raw internal signature-map storage was deliberately excluded because canonicalizing that representation is the change. Both processes asserted the actual runtime source origin. This sampled parity is not an exhaustive concurrency proof. Reproduction: `~/tmp/replay-owner-paired.py old` and `new` with `PYTHONHASHSEED=0 PYTHONPATH=packages/core/src:. .venv/bin/python`; comparison and traces are `replay-owner-comparison.json`, `replay-owner-old.json`, and `replay-owner-new.json`.

## Single startup grounding algorithm — 2026-10-28

`Bootstrap._staged_results` now owns deterministic action batching, completion
order, the complete semantic barrier and graph/cache enrichment before norms.
`ground_batches` materializes those results and retains invalid/cache telemetry;
`ground_stream` exposes valid proposals incrementally. The mode flag changes
logging only. Batch continues to use result-axis identity, while stream uses the
scheduled axis; both compute batch keys from the scheduled axis/action IDs.
No new result DTO, production file or dependency was introduced.

Removed the forwarding `ground_staged_batches` / `ground_staged_stream` APIs and
migrated callers and test doubles to the canonical names. `RunCoordinator`
consumes `ground_stream` directly; its staged/legacy `getattr` probe is gone.
Removed `AxisTaskScheduler.run`, whose only production consumers were the old
batch stages. The scheduler now supplies one bounded stream primitive and has
no stage composition or batch-key policy.

Five new characterization cases passed on original code before the rewrite:
permuted semantic completion with/without a failed task in both modes, enriched
source/cache and norms-only evidence, and close before norms/completion logs.
A sixth test using `ThreadedGroundingRunner` exposed a temporary cancellation
regression: the additional generator frame could keep the pending worker live
after closing the public stream. `ground_stream` now uses `contextlib.closing`
for its nested stage iterator. The real pending-worker test then passed on both
original and final code: pending work is cancelled and its late result is
rejected. This establishes the behavior on the tested CPython runtime, not a
universal proof about every Python implementation or scheduler.

The final broader suite passed **2209 tests, 1 skipped, 2 deselected**. The two
private-API exclusions and repository-wide baseline limitations are unchanged.
All **22 import contracts** pass, including a new prohibition on the axis task
scheduler depending on stage/campaign/consultation coordinators. A cold-process
import check replaces the touched method-location test. Ruff, formatting and
structural checks pass.

A parent-run old/current differential matched **720 scenarios / 5444 recorded
calls**, including outputs, source/cache hashes, evidence, ordering, log messages,
exceptions and generator finalization. Cases include synchronous/permuted task
runners, partial missing tasks, task exceptions, invalid/cache-hit results,
empty sources, differing result/task axis labels and early stream closure.
Each process asserts its actual source origin. A negative canary discarding
semantic enrichment fails all four new stage-barrier cases as expected.
Independent source review confirmed stage/cache/evidence/identity behavior;
the parent executed all behavior and differential checks reported above.

Physical Python LOC across changed production files: **672 -> 614 (-58)**.
Changed tests: **11432 -> 11549 (+117)**. No production files were moved.
Snapshot and evidence: `~/tmp/startup-owner-before-20261028/`,
`startup-owner-baseline.log`, `startup-owner-final.log`, `startup-owner-imports.log`,
`startup-owner-paired.py`, `startup-owner-comparison.json`,
`startup-owner-old.json`, `startup-owner-new.json`, `startup-owner-canary.log`,
`startup_owner_canary.py`, `startup-owner.diff` and `startup-owner-loc.json`.

Remaining Grounder debt is explicit: `Grounder(Bootstrap, Followup)` still
shares private capabilities, and startup/reactive capability injection remains
object-typed. That is the next ownership cut; startup algorithm duplication and
legacy API probing are resolved here. The full runtime architecture goal remains
open, including campaign assembly, terminal policy and other inventory cuts.

Independent validator also executed the six bounded startup pins separately against the final runtime (6 passed, 56 deselected) and original snapshot (6 passed, 56 deselected), asserting original Bootstrap source origin. Both runs exited0; no source edits were made.

## Explicit consultation owners — 2026-10-29

The consultation coordinator no longer inherits `BatchRunner`, `Invoker` and
`Committer`. `wave.Coordinator` owns public `run_wave`, readiness, runner limits,
latency repairs and the pinned-source handoff. It explicitly constructs the two
existing, now independently initialized phase owners with injected capabilities:
`calls.Invoker` prepares proposals on workers; `commit.Committer` applies
owner-thread evidence gates, promotion, outcomes and result propagation.
These collaborators share the coordinator lifetime and create no external
resources. The coordinator creates exactly one `OutcomePolicy`, which is passed
to Committer; scheduling and commit therefore observe the same absorbing ledger.

`PlannedItem` has one canonical owner beside its worker consumer in `calls.py`.
Its class AST and fields are unchanged; owner-side wave context imports that
class rather than duplicating it. Worker imports no longer pull in queue, gate,
wave, commit, campaign or grounding promotion/lifecycle implementations. Existing
`WaveContext` remains an owner-side envelope; this slice does not collapse the
pinned execution graph into the distinct repository revision.

Deleted `consultation/runner.py`; its assembly/readiness helpers now belong to
wave or commit. Replanning imports Callbacks from context and Coordinator from
wave, and calls public `run_wave`. No compatibility module, alias or forwarding
method was introduced. Existing tests that constructed coordinators through
`__new__` and assigned sibling-mixin fields now use the real constructor. The
review-C3 fixture passes promotion policy at creation instead of replacing only
one hidden service reference after wiring.

The scheduler still issues predispatch queue commands for readiness failures,
missing sources and deterministic latency repairs on the owner thread. Committer
owns evidence-gate and worker-result queue commands. The mutable queue's actual
state owner remains unchanged; adding forwarding wrappers merely to relocate
these legitimate scheduling commands would not improve this boundary.

Preserved behavior: workers use the pinned source and evidence; revision changes
clear proposals before admission; lifecycle admission encloses the whole canonical
commit loop; each item refreshes the expected repository revision while carrying
its accumulated accepted `previous` graph. Preparation and promotion catch
`Exception`, while cancellation control signals propagate. Both worker and owner
telemetry remain bound to the original work item and scope.

Validation: 34 parent baseline tests passed before implementation; 312 focused
checks passed with one skip after implementation. Independent review executed
28 equivalent baseline/current behavior cases and two import-isolation cases.
All **22 migrated method bodies** match baseline AST after normalizing renamed
methods and explicit collaborator member access; constructors were excluded from
that comparison and verified by behavior tests and independent identity checks.
The final broader regression passed **2227 tests, 1 skipped, 2 deselected**.
The private-API exclusions and repository-wide baseline limitations remain.
All **24 import contracts**, Ruff, formatting and structure checks pass. Added
contracts prevent worker dependencies on owner state and commit dependencies on
wave/campaign coordination. A cold-process worker import replaces the touched
method-location inventory test. A deliberate canary giving Committer a different
policy fails the parked-outcome workflow case, showing that shared-ledger behavior
is covered.

Physical Python LOC across changed production files, including the deleted
runner: **1253 -> 1231 (-22)**. Tests: **9466 -> 9371 (-95)**. These counts include
moved bodies on both sides; moves alone are not counted as shrink. The current
semantic inventory covers **125 runtime source files / 25,409 physical lines**.

Evidence under `~/tmp/`: `consultation-owner-before-20261029/`,
`consultation-owner-baseline.log`, `consultation-owner-focused.log`,
`consultation-owner-broad.log`, `consultation-owner-imports.log`,
`consultation-owner-ast.py`, `consultation-owner-ast.json`,
`consultation_owner_canary.py`, `consultation-owner-canary.log`,
`consultation-owner.diff`, and `consultation-owner-loc.json`.

Remaining ownership work includes `Grounder(Bootstrap, Followup)` with shared
private capabilities, broad grounding preparation/admission types, and the other
campaign/terminal/data-flow cuts recorded in the inventory. This completed
consultation slice does not establish completion of the full runtime goal.

## Independent startup/reactive grounding — 2026-10-29

Removed `grounding/axis.py` and its `Grounder(Bootstrap, Followup)` object.
`startup.Bootstrap` and `reactive.Followup` now initialize their own capabilities.
Startup owns validator, dispatcher, cache wrapper, bounded task scheduling and
slice/batch settings. Reactive owns consultation dispatch/budget, slicing and
metrics; it neither requires nor creates startup scheduling/cache resources.
Both consume their relevant fields from the existing immutable GrounderOptions;
there is no second configuration model or combined forwarding facade.

`ServiceOptions` now has independent optional `StartupGrounding` and
`ReactiveGrounding` protocols. Lifecycle receives only startup. The grounding
service, consultation dispatch and variance preparation receive only reactive.
`reactive_capable` depends on reactive presence and the existing skip flag.
The existing RunScope provider constructs both owners once from shared options,
model clients and metrics. Its model/factory availability gate remains unchanged;
this slice adds independent core capabilities, not new CLI feature-selection
policy. Startup model usage remains recorded by its injected dispatcher; reactive
usage remains recorded by Followup. No extra metric accounting was added.

New constructors validate consumed settings only. Startup requires its dispatcher
and validates batch/worker/timeout limits; reactive requires consultation but
does not reject irrelevant startup limits. Existing request, evidence, cache key,
classification, source and promotion algorithms remain unchanged. Real combined
callers now construct the two owners from one options object; legacy test doubles
may implement both contracts as one object without being wrapped or copied.

Moved `runtime/consultation/axes.py` byte-for-byte into `contracts/axes.py` and
migrated all Python consumers. This fixed the vocabulary's ownership instead of
adding a fourth import exception. All three grounding-to-consultation exceptions
were removed; the existing no-scheduling dependency contract now has no exceptions.
No alias module was left behind. The move alone contributes zero to overall LOC
delta.

Validation: 1024 relevant baseline tests passed before edits. Ten new cases cover
startup without reactive dispatch, reactive without startup resources/validation,
and every startup/reactive presence combination with the skip flag. The final
broader suite passed **2234 tests, 1 skipped, 2 deselected**; unchanged repository
baseline limitations and private-API exclusions remain. Independent review ran
25 stage/framing/cache/metrics/cancellation checks and four import-isolation checks.
A deliberate canary restoring the combined constructor requirement and deriving
reactive readiness from startup fails three new cases, as expected.

All **26 import contracts** pass. Added contracts forbid startup dependencies on
reactive/campaign grounding and reactive dependencies on startup cache/scheduler.
Cold imports validate actual owner separation without optional extensions.
Twelve startup/reactive method ASTs are identical to the saved source; another
29 service/lifecycle/variance/dispatch method ASTs match after capability-field
renaming. Constructors and intentional capability-presence behavior are covered
separately. The neutral vocabulary move is byte-identical; independent review
also compared unchanged cache load/save ASTs. Capability and constructor type
hints resolve. Ruff and formatting pass. Structural checking adds no warnings:
one inherited `build_axis_result` signature warning and six inherited assembly
warnings remain, matched against the saved source in `grounder-owner-structure.json`.

Changed physical Python LOC, including moved vocabulary at both paths and the
updated source documentation: production **5432 -> 5475 (+43)**; tests
**20318 -> 20474 (+156)**. This is explicit capability/constructor work, not a
claim of code shrink. Runtime alone now has **123 files / 25,390 physical lines**;
its apparent reduction includes the neutral move and must not be counted as
project shrink. Updated benchmark consumers pass syntax/lint checks; missing
benchmark/optional dependency collection limits from the full-suite baseline
were not resolved here.

Evidence under `~/tmp/`: `grounder-owner-before-20261029/`,
`grounder-owner-baseline.log`, `grounder-owner-focused.log` (intermediate stale
axis test, subsequently migrated), `grounder-owner-independent.log`,
`grounder-owner-broad.log`, `grounder-owner-imports.log`,
`grounder-owner-ast.py`, `grounder-owner-ast.json`,
`grounder-owner-structure.json`, `grounder_owner_canary.py`,
`grounder-owner-canary.log`, `grounder-owner.diff`, and `grounder-owner-loc.json`.

Remaining work includes campaign collaborator assembly/replanning ownership,
terminal-policy consolidation, and consultation source/preparation/admission
capability narrowing plus intermediate-envelope contraction. Those open cuts
remain in the semantic inventory; the complete runtime goal remains active.

## Campaign graph assembly — 2026-10-29

`composition.runtime.assemble_workflow` now owns the dependency graph assembled
once by the existing RunScope provider. LiveWorkflow receives its seven prepared
collaborators plus the existing options; replanning, wave and committer similarly
receive explicit dependencies. Deleted the replanning and consultation callback
bags, unused actor latency/mode aliases, and runtime environment parsing. The
parser moved unchanged to composition; explicit empty `diff_modes` overrides and
fail-fast validation before port access are preserved. One policy and gate are
shared by scheduling/admission; separate assemblies have separate absorbing state.
No runtime-to-composition compatibility alias or test-only subclass factory flag
was added.

Pure path selection now belongs to `QdlExecutionView.select`: empty paths are
excluded, an exact method anywhere in the chain selects the whole path, and order
is retained. RuntimeState owns freshly derived active path IDs from that binding
selection plus every backlog ID. Removed the executor selection helper and the
cross-component private replanning call. Discovery no longer imports the executor
implementation. Test subclasses became local instrumentation callbacks; their
ordering/fixed-point assertions remain.

Baseline: 209 relevant cases plus five selection/backlog pins passed. Final broad
validation before the subsequent pair shrink: **2242 passed, 1 skipped, 2 known
private-API tests deselected**. **27 import contracts** pass, including discovery
independence from physical executor implementations. Sixty-nine nonconstructor
method ASTs match after projection-call normalization; the parser and selector
body match exactly. Constructor behavior is checked separately for validation
order, explicit mode override, no hidden collaborator/env access, and separate
assembly outcome isolation. This is architecture progress, **not material code
shrink**: changed production **4240 -> 4243 (+3)**; tests **13622 -> 13730 (+108)**.

Evidence: `~/tmp/campaign-assembly-before-20261029/`,
`campaign-assembly-baseline.log`, `campaign-assembly-query-pins.log`,
`campaign-assembly-focused.log` (two stale latency-alias test assertions, then
migrated to the actual owner), `campaign-assembly-boundaries.log`,
`campaign-assembly-broad.log`, `campaign-assembly-imports.log`,
`campaign-assembly-ast.py`, `campaign-assembly-ast.json`,
`campaign-assembly.diff`, and `campaign-assembly-loc.json`.

## Actual factor/payload pair contraction — 2026-10-29

Deleted two repeated executable chains rather than counting their relocation:
`execute_payload_pair` is absorbed by `execute_step_pair`, and the two probe
pair evaluators are replaced by one `_evaluate_pair`. Factor scenario/plan
preparation and payload baseline/canary preparation remain explicit; the bounded
`Checker.execute_pair` call, event scope, finally billing, incomplete-pair error,
measurement dedup, result accumulation and recording each have one implementation.
No new model, forwarding wrapper or production file was added. Production:
**executor.py 516 -> 453 (-63)**; **probes.py 366 -> 301 (-65)**; combined
**882 -> 754 (-128)**. Changed tests: **3791 -> 3858 (+67)**.

Preserved details include executed rather than original checks, factor-only
identity logging, exact mode-specific diagnostics, distinct prerequisite hashes,
canary creation only after dedup and inside the execution error boundary,
success-only measurement keys, and outcome recording outside that error catch.
Factor correlation retains the observation's check ID; payload retains the
returned check's ID. Readback, timing and concurrency were not treated as
removable copies because their semantics differ.

Thirty focused baseline/current cases pass. The broad suite passed **2242 tests,
1 skipped, 2 known exclusions** after the production contraction. Six additional
transport/budget/cancellation cases then passed against both original and current
runtime; the original run used an isolated test-only API adapter and asserted
source origin. They verify zero spend on preflight rejection, both spent legs
and retained partial evidence on second-leg failure, and original BaseException
propagation with finally billing. A deliberate billing-removal canary fails the
four executed-error/cancellation cases while the two preflight cases still pass.
Ruff, formatting, structure checks and all 27 import contracts pass.

Evidence: `~/tmp/pair-shrink-before-20261029/`, `pair-shrink-baseline.log`,
`pair-shrink-focused.log`, `pair-shrink-broad.log`, `pair-shrink-errors-current.log`,
`pair-shrink-imports.log`, `pair_shrink_canary.py`, `pair-shrink-canary.log`,
`pair-shrink.diff`, and `pair-shrink-loc.json`. The neutral/original test adapter
was run inline; no production compatibility layer remains.

The preceding assembly work and this contraction together reduce production by
125 physical lines (+3 then -128), not thousands. Earlier structural work must
not be presented as substantial compression. Next shrink candidates require
proven repeated algorithms and net whole-production savings; role-specific code
is not charged as removable duplication merely because it has similar scaffolding.
The full runtime objective remains active.

Independent pair review completed 48 old/current coordinator parity scenarios,
12 executor accounting cases and four repository checks without finding a fault.
Coverage included mismatched check/observation IDs, dedup-before-canary ordering,
partial failures and outcome-error propagation. Physical transport/generator and
BaseException integration were independently unverified there and are covered
by the parent's real-target tests. The executor worker's eight-case parity
script is retained at `~/tmp/pair-shrink-before-20261029/check_pair_semantics.py`.


## Remove unused post-worker merge projection (2026-10-29)

Committer previously requested a WorkItemMerge but consumed only applied_order.
Its only production call never supplied conflicts; the secondary supersession
calculation had no runtime consumer. Committer now sorts planned work directly
by structural_priority. The existing ID-to-last-index map is retained, including
its duplicate-ID behavior. WorkItemGraph still owns conflict serialization and
planning supersession; accepted graphs remain separate from untrusted proposals.
Deleted the helper, DTO and lazy exports without adding another model or facade.

Whole touched production: 1092 -> 1047 physical LOC (-45); tests: 1869 -> 1862
(-7). This is a small removed abstraction, not a thousand-line contraction.
Baseline 75 and current focused 79 cases pass. The broader runtime/formal/DI/
architecture suite passes 2252 tests, 1 skipped and 2 existing exclusions.
All 27 import contracts and touched Ruff/format checks pass. The 104-line
WorkItemGraph.build structure warning exists in both original and current source.

A comparison of actual original/current Committer calls matches 2080 timeout/
closed-lifecycle ordering traces, including repeated IDs and priority ties;
successful owner-thread admission and shared-cap ordering are covered by the
expanded campaign test. Deliberately reversing structural order fails all six
shared-cap cases. Thirty-seven retained function ASTs outside commit are exact.
Artifacts: ~/tmp/merge-shrink-before-20261029/, merge-shrink.diff,
merge-shrink-loc.json, merge-shrink-baseline.log, merge-shrink-broad.log,
merge-shrink-imports.log, merge-shrink-canary.log, check-merge-order.py.
The full architecture goal remains open.

Independent review found no blockers and matched 3000 original/current traces,
including successful and failed promotions, missing proposals, mid-wave revision
loss, duplicate IDs, stable ties and event/queue ordering. Evidence:
~/tmp/merge-independent-review-20261029/differential.json.

The parallel semantic review rejected merging ConsultationLedger with OutcomePolicy:
public DispatchFlow absorbs the union of successfully dispatched observation refs,
whereas the campaign wave absorbs classified outcomes per exact signature,
including errors. Their identity, reopening and failure behavior differ. This is
not proven removable duplication. The read-only report is retained at
~/tmp/semantic-shrink-recon/strongest-candidate.md.


## Canonical planning contracts (2026-10-29)

Removed fourteen QDL model/query reexports from runtime.planning and migrated
forty consuming modules directly to qdl.reasoning. The exact same objects are
used; forty non-import ASTs are unchanged. No new facade or compatibility alias
was added. The planner package now exports execution services and planning
defaults, rather than being another entry point for the QDL domain contracts.

The new behavioral boundary test constructs a Deficit with a QdlSubgoal while
actively rejecting planner imports. It fails against the original source and
passes after migration. Baseline116 and focused127 cases pass; all touched
Ruff/format checks pass. Eight structural warnings are inherited, matching
after line-offset normalization. Whole touched production:5755->5700(-55);
tests:19961->19979(+18). This is a removed dependency/facade, not large algorithmic
compression. Source snapshots, import previews, delta and logs are retained in
~/tmp/planning-contracts-before-20261029/ and ~/tmp/planning-contracts-*.
Broader runtime/formal/DI/architecture regression: 2253 passed, 1 skipped and
2 existing excluded tests. All 27 import contracts pass. Independent review
found no actionable findings; all fourteen removed and five retained exports
preserve exact identity, and planner implementation hashes remain unchanged.
External consumers outside this repository are unverified.

The separate binding review reproduced an incorrect missing_invariant diagnostic:
a failed chain with one missing scenario is rescanned with an assumption that
every action requires a security norm. This behavioral correction has not been
folded into the import migration. It is recorded with its reproduction and a
second candidate to share one existing InvariantIndex per bind; both remain open.

Of the -55 physical production lines, -30 is the deleted reexport surface in
planning/__init__.py; the remaining -25 comes from reorganized/formatted import
blocks. No planning algorithm was deleted in this slice. Independent reviewer
ran a wider selection:745 passed,1skipped,2failures from the existing Hypothesis/
hypothesis-jsonschema private-API incompatibility (many.more), matching the two
excluded tests in the parent suite. Failure summary:
~/tmp/planning-review-dependency-failures.txt.


## Precise attack-chain binding diagnostics (2026-10-29)

The attack binder returned None on a missing method/scenario, then the projection
rescanned the chain under an incorrect invariant_required assumption. This
invented missing_invariant deficits for valid ordinary steps. Those diagnostics
flow into reactive work and coverage, so removing them is an intentional behavior
correction, separate from the preceding import-only migration.

Attack binding now reports missing contracts at the validation site through the
existing callback/alias-aware record_binding_deficit mechanism. It enumerates all
missing actions, retains method-over-scenario precedence and path context, skips
further invariant construction after the first missing binding and returns no
partial path. Without a recorder, immediate failure is unchanged. Deleted the
reconstruction helper and its export; no new model or adapter.

The sixteen-case regression covers ordinary/value and causal chains, complete
bindings and one/multiple missing methods/scenarios. Eight cases fail before the
fix; all sixteen pass after. Baseline28/focused44 pass. Seventeen other function
ASTs are unchanged. Two thousand seeded original/current bindings match after
removing only the intended false diagnostics from baseline;614 cases are corrected.
Touched Ruff/format/structure checks pass. Production789->763(-26physicalLOC);
tests138->194(+56). Broad regression:2269 passed,1 skipped,2 known exclusions;
all27 import contracts pass. Independent review found no unintended regressions
in98 tests and1596 original/current differential cases. External consumers
outside the source tree remain unverified.
Evidence: ~/tmp/binding-diagnostics-before-20261029/, binding-diagnostics-*.log,
binding-diagnostics-parity.json, check-binding-diagnostics.py,
binding-diagnostics.diff and binding-diagnostics-loc.json.

Reusing one existing InvariantIndex per bind remains a separate unfinished cut.


## Shared norm/action resolution (2026-10-29)

The binder and invariant-index factory both resolved the same norm/action
relation. verification.resolve_actions now computes the raw effect-to-action
table once per distinct effect, retaining empty tuples, action order and
duplicates. The binder's per-norm loop still preserves repeated failed scenario
lookups and unbound changed-resource diagnostics. The same table reaches the
execution-view factory, which creates one fresh four-field InvariantIndex.
No index or relation table is retained across binds; no new DTO/state field.

The index is deliberately constructed at its original point, after secondary
scenario lookups and probe-schema diagnostics. An initial early-construction
prototype changed project_invariant failure ordering and was replaced. The final
implementation preserves the reproduced failure's repository-call sequence and
partial diagnostics. Arbitrary faults inside pure bulk action resolution are
outside demonstrated exception parity; supplied tables require a stable plan/
graph and complete effect coverage, as the internal binder supplies.

Baseline173 pass. Four characterization cases pass on original and current
source: successful/missing scenario retries across repeated binds, and duplicate
changed norms with/without causal producers. Final focused177 pass. Profiling
those repeated-norm binds shows24->8 action projections and four distinct index
instances for four binds. Dropping table forwarding in a negative canary raises
the current count to16 and fails the assertion. Twenty-three retained function
ASTs outside the changed projection path remain identical. Independent final
review passes41 focused tests plus raw ordering/retry/empty-effect/exception
checks, including success on the third scenario retry and two distinct empty
effects. No model or live target calls. Final broad regression:2273 passed,1 skipped,
2 known exclusions;all27 import contracts pass. Ruff/format pass.

Physical production825->822(-3LOC);tests677->777(+100). This removes repeated
computation and ownership, not substantial source volume. The former binder
_resolve_scenarios9-parameter warning is removed; its existing constructor
9-parameter warning remains. Evidence: ~/tmp/invariant-index-before-20261029/,
invariant-index-loc.json, invariant-index.diff, invariant-index-profile.json,
profile-invariant-index.py, invariant-index-clean-canary.log,
invariant-actions-adversarial.py/.log and invariant-actions-verified-*.log.


## Formal proposal cache ownership (2026-10-29)

ScenarioBinder and its Assembler are RunScope-local. Stock campaign binds use
formal_proposal=False, while the optional formal worker uses the same binder.
The callable service API previously reused a single proposal/done flag across
services: grounding A suppressed B, and loading B could merge A's proposal into
B's planner graph. Concurrent direct formal calls could generate twice.

The cache is now keyed by service, and one lock serializes proposal generation.
A shared _get_proposal preserves rejected/empty(None) caching and retries after
model exceptions. Only the creating background call promotes. Contract-only
loads bypass the helper and lock, while load(True) keeps admission against fresh
source. No new class, DTO or alternate architecture was added. The lock guards
generation, not promotion/publication completion; a cached ground call may return
zero while its creator is still saving. This does not make a workflow reusable
across multiple campaigns; other mutable collaborators remain RunScope-local.

Four service-isolation regressions and two concurrency cases fail on original
source; all pass after correction. Nine new cases cover those paths, retry and
fresh-source admission. Baseline152 and focused159pass; final broader regression
2282passed,1skipped,2knownexclusions. All27importcontracts,Ruff,format and touched
structure checks pass. One hundred original/current same-service traces match
across2000operations including revisions, failures and empty sources. Five source/
model/promotion function ASTs are unchanged. Independent15repo+5semanticchecks
found no blocker. Artifacts: ~/tmp/formal-cache-before-20261029/,
formal-cache-*.log/.json/.diff, check-formal-cache-sequences.py, and
formal-cache-independent-review-20261029/. No live model calls were made.

Physical production188->197(+9LOC);tests412->583(+171). This is a correctness and
state-ownership repair, not a source shrink.

### Confirmed remaining lifecycle defect

A blocked formal worker can still persist an accepted batch after runner.close: the
runner discards its result but Assembler promotes/saves internally before result
publication. This predates and survives the cache correction. The independent
reproduction is retained in formal-cache-independent-review-20261029/open-issues.md
and assembler-lifetime-research-20261029/probe-output.txt. Promotion/save must move
behind lifecycle admission; it is an explicit priority1 open cut, not resolved by
the generation lock. The full runtime goal remains active.


## Formal and axis lifecycle admission (2026-10-29)

The late-persistence defect recorded above is resolved. FormalGrounder now has
prepare(service)->ProposalPromotionRequest|None and
commit(service,request)->ProposalPromotionResult, reusing existing canonical
contracts. Assembler implements the port directly. Deleted
ScenarioBinderFormalGrounder, the old run_formal_grounding entry and binder forwarder, plus the
private promotion wrapper. Synchronous load(True) still applies its cached
proposal against fresh source through the same commit path. One shared DI
PromotionPolicy remains in the existing RunScope assembler.

RunCoordinator captures revision before scheduling the outer worker. The formal
worker prepares only; the existing timed consumer awaits the request, then gates
promotion and save together with runner.commit(revision). A timeout never obtains
an admissible request. A late result may populate the run-local proposal cache,
but does not accept or save facts. Source snapshot is carried unchanged; no new
source-hash CAS policy was introduced. Model calls remain outside the lock.
The old separate formal-start/detach methods are one scheduling operation.

The same lease now protects each startup-axis promotion/save. A held axis also
reproduced late persistence before this guard. Rejected batches break out to
sink.finish; generator iteration and model work remain outside admission. The
real production generator cleanup chain was checked independently.

Close-first rejects acceptance; commit-first may finish while close waits, but
its save completes before close returns. Finalizer enrichment status alone is
not proof of acceptance/discard: it can be terminal-discarded while a previously
admitted commit finishes. Tests inspect accepted writes and real policy counters.
The patch does not promise cancellation of synchronous ingestion before lease
capture, nor support for multiple campaigns sharing one workflow.

Formal regression before:3fail/1pass(closed,timed_out,queued_close,active). Axis
regression before:1fail/1pass(closed,active). All six pass now. The queued case
proves a new subtask cannot refresh the old campaign lease after closure.
Baseline55pass;focused230pass before axis guard;final port11pass;broader2287pass,
1skipped,2knownexclusions. All27importcontracts and changed Ruff/format checks pass.
Eight existing structural warnings remain in the broader touched set; none were
introduced, and provider imported-name count improves117->115. Independent
87focused+125architecture(1skip)+7adversarial checks found no blockers, covering
blocked-save/close ordering, source snapshots, injected shared policy, fresh
cached loads, exceptions and generator cleanup. Counts overlap, not additive.

Negative controls: removing revision admission fails queued-close and late-axis
cases(2fail/4pass); moving commit back into prepare fails all three late formal
cases(3fail/1pass). No source mutation was used for these canaries.
Production2464->2431(-33physicalLOC);tests9973->10088(+115). No new DTO, class or
cancellation state machine. Evidence: ~/tmp/formal-lifecycle-before-20261029/,
formal-lifecycle-*.log/.json/.diff,axis-admission-before.log and
formal-lifecycle-implementation-review-20261029/. The full runtime goal remains
active; this closes the startup result-admission cut only.


## Remove unused retained prefix traces (2026-10-29)

CampaignAccumulator remains the mutable campaign owner; ExecutionResult remains
a detached result snapshot. They are not interchangeable representations.
Deleted the unused traces fields from result, round state and accumulator,
recorder prefix retention, merge/snapshot copies, and the extra readback trace
query/callback/injection. Actual Observation.trace, current attempt observations,
oracle history construction, feedback history, provenance, verdicts and minimal
checks remain. Readback classification already obtains its necessary trace from
the evaluator and evidence store.

The old recorder retained a tuple of every observation prefix. On500observations
in one real recorder attempt that was500tuples holding125250observation references.
Current retained prefix count is0; the ordered500observation histories, oracle
inputs, provenance, metadata, classifications and publication sequence match.
This removes quadratic prefix retention within an attempt, not the actual
execution trace. Deliberately clearing actual attempt history fails that
comparison, confirming it protects the retained semantic history.

Public shape migration: ExecutionResult.traces is removed. All31 in-repo
constructor calls were migrated, including positional index2 forExecutionResult
and index1 forCampaignRoundState; CampaignAccumulator.empty was checked too.
No alias, replacement DTO or compatibility facade was added. External consumers
of this public field are unverified and require migration.

Baseline/current76pass with2known exclusions. Expanded broader runtime/formal/
DI/architecture plus OOB/S1R checks:2322passed,1skipped,2knownexcluded. No new
repository tests were needed: existing oracle/feedback fixtures already assert
exact tuple histories and callback order; only obsolete retention assertions
were removed. All27importcontracts and changed Ruff/format checks pass. One
pre-existing canonical-name warning(execution.ExecutionResult) is unchanged.
Twenty-one retained function ASTs are exact. Independent review validated all
31constructor rewrites and additional readback cases(two norms/one measurement,
map placement, snapshot isolation, publication errors).127passed;4failures were
also reproduced against original production:2existinghypothesis_jsonschema
failures and2legacy_shrink_finding cases. V2R collection remains unavailable
without the existing benchmarks dependency; its constructor was checked by AST.

Physical production1162->1143(-19LOC);tests7145->7119(-26). Evidence:
~/tmp/trace-retention-before-20261029/,trace-retention-preview.json,
trace-retention-loc.json,trace-retention.diff,trace-retention-*.log,
check-trace-retention.py,trace-retention-history.json and
trace-retention-independent-review-20261029/. All execution was offline; no live
model requests. The full runtime objective remains active.


## Early path terminal owner (2026-10-29)

PathTerminalizer now owns all runtime QdlPathEvaluated construction, including
missing-witness and symbolic-UNSAT exits. Witness blocking still records every
deficit and reason and uses block_prerequisite without charging retries. Symbolic
blocking still uses record_outcome with empty attempted steps; bootstrap paths
may remain retryable. Metrics, reason/action/step metadata, scope, debug placement
and transport budgets are retained. Other normal path exits already use finish.

Previously an early event computed its signature, published it, and the round
then queried evidence again to remember a possibly different value. The new
owner computes one event signature, validates the event, remembers it for an
actual terminal scheduler outcome, then publishes. Subscribers therefore see
the same snapshot in scheduler memory at publication entry. A publication error
retains that snapshot. Symbolic retryable does not capture. Event validation
failure leaves the cache unchanged, including malformed zero-step forced UNSAT.

Deleted the round fallback and its evidence_signature callback, an execute-result
branch whose two arms published identically, and the now-unread captured_paths
set from RoundReplay, its initializer and writes. This supersedes the historical
per-round capture-membership solution recorded earlier: each actual terminal
owner now refreshes its own snapshot directly. Historical replay outcomes stay
separate from current scheduler state. No new DTO, class or file.

Baseline78pass;four actual BoundPathRunner subscriber cases fail before correction
and pass after(witness/symbolic, successful/failed publication). Final focused82
and broader2326pass,1skipped,2knownexclusions. All27importcontracts,Ruff,format
and touched structure checks pass. Thirty-one retained function ASTs are exact.
Independent review71tests and68old/new differential cases found no remaining
blocker;all20zero-step cases now match baseline state/exceptions. Disabling
remember_evidence fails all4publication-snapshot pins. Source snapshots and
logs: ~/tmp/early-terminal-before-20261029/,early-terminal-*.log/.json/.diff,
early-terminal-independent-20261029/ and early-terminal-final-20261029/.

Physical production1363->1353(-10LOC);tests448->528(+80). Remaining terminal work
is the scheduler-only/budget repair passes and shared event-history reduction;
their different eligibility/partial-failure semantics have not been merged.
The complete runtime objective remains active.

## Ordinary-call execution contraction (2026-10-29)

Removed `CallRunnerMixin` and its three methods. One `calls.execute` function
now owns ordinary step/check event context and finally-based accounting.
Assembly binds Checker and publisher once; the same callback is used by step
candidates, materialized candidates and finding shrinking. Differential spending
continues to use the unchanged `spend_calls` helper. No new class or module.

Step bindings preserve the generator, `max_checks=1`, `reset=False`, final
observation selection and method/step metadata fallback. Materialized checks
retain their exact check identity. Both paths restore outer context before
charging the actual check-count delta, including target failure and cancellation.
Replacing the runner's private Checker or publisher after construction no longer
rebinds ordinary execution; configuration must supply them at construction.

Physical Python LOC across all touched files: production **565 → 551 (−14)**;
tests **3,031 → 3,117 (+86)**. Eight behavioral cases pass before and after the
change. Disabling spending deliberately causes six failures; blocked attempts
remain uncharged. The obsolete mixin-shape test was removed.
Snapshot and patch: `~/tmp/ordinary-call-before-20261029/`,
`~/tmp/ordinary-call.patch`. This completes one contraction, not the runtime
migration.

Validation: **89 focused tests passed**; **2,333 broader tests passed**, one
skipped. Both runs exclude two known Hypothesis compatibility failures.
All **27 import contracts** and touched-file Ruff/format/structure checks pass.
Independent validation matches **120 old/new cases (240 executions)** and six
cold import orders. Its additional suite passes 219 tests with one skip; its two
failures also reproduce on the pre-change snapshot. Detailed artifacts live in
`~/tmp/ordinary-call-independent-review-20261029/`.

## Explicit path execution owner (2026-10-29)

`PathRunnerMixin` is replaced by `paths.Executor`, with eight explicit existing
run-scoped dependencies: Checker, evidence projection/reuse, prefilter, candidate
execution, observation recording, shrinking and terminalization. The campaign
round receives `Executor.execute` directly. There is no runner forwarding method
or compatibility alias. `scope_step` is the existing pure forwarding-scope
transform; candidates no longer call through their parent runner for it.

All three existing algorithm bodies remain identical after dependency-field and
method-name substitutions. Witness/UNSAT exits, reuse-before-budget ordering,
value-only progress, coupling refresh, feedback, shrinking and bool returns stay
unchanged. Dependencies are fixed at assembly; replacing a runner's private
service field after construction does not rebind the path owner. The existing
UNSAT fixture now patches the actual injected prefilter method.

This is an ownership correction, **not a code-size reduction**: physical
production Python LOC **661 → 685 (+24)**, tests **2,948 → 2,937 (−11)**. No new
module, collaborator DTO or forwarding layer. RunnerAssembly still retains
phased wiring state; its separation remains unfinished.

The terminal-repair review rejects merging the existing two repair modes:
history repair must work with orphan step history and recover probe/provenance
metadata; scheduler repair requires current path definitions and records zero
attempts. Run-scoped historical eligibility, fresh reads and partial publication
are observable. Both already belong to PathTerminalizer; combining their shared
indexing would add ceremony without a meaningful reduction. This review does not
prove all event-reduction duplication resolved.

Snapshot: `~/tmp/path-owner-before-20261029/`; patch: `~/tmp/path-owner.patch`.

Validation: 199 baseline / 198 current focused tests passed (one obsolete shape
test removed), one skip and two known exclusions. Broader current validation:
**2,332 passed, one skipped, two known exclusions**; **27 import contracts**
kept. Ruff, format and structure checks pass. Disabling step execution causes
three expected failures in real budget/provenance tests.

Independent review found no actionable regression: **71 differential cases**
match, including call order, partial evidence and exact exception/cancellation
propagation; 74 baseline/current tests have equal outcomes and the same two
pre-existing failures. Another 124 boundary tests pass with one skip. Six cold
import orders and the dependency closure show no new cycle; existing indirect
runner callback cycles remain. Evidence: `~/tmp/path-owner-independent-20261029/`.

## Retire inherited execution assembly (2026-10-29)

Deleted `runtime/execution/assembly.py` and `RunnerAssembly`. The dependency
graph and its options now belong to `composition/execution.py`; RunScope
provider and all 53 allocation calls use `assemble_runner`. BoundPathRunner's
constructor accepts seven ready capabilities. It keeps object identity/hash
semantics and does not own factories, setup options or intermediate services.

EventProjection owns the existing cursor ID, retained event list and scoped
publication. Its callbacks never capture a parent runner. Intent metric
initialization, execution transitions and regression-example eligibility now
belong directly to campaign round Runner. Checker owns executed-check identities.
All moved policy bodies remain equal after declared receiver substitutions;
constructor creation order and the shared ordinary-call callback are preserved.
The path registry is a composition-local dict retained by its actual consumers.

The assembly uses local variables and explicit helper inputs, not phased writes
onto a partially constructed runner. There is no legacy constructor wrapper or
runtime import of composition. External callers must use the composition factory
or inject ready services; old private parent-service replacement is unsupported.
The late-OOB subclass fixture and mock fixtures were migrated explicitly.

Physical LOC across all affected locations: production **3,748 → 3,758 (+10)**;
tests **101,396 → 101,455 (+59)**. Runtime alone is **−238 LOC** because wiring
moved out; that number is **not** a whole-project shrink claim.
Snapshot: `~/tmp/runner-assembly-before-20261029/`; complete patch:
`~/tmp/runner-assembly.patch`.

Validation: **182 baseline tests passed**, one skipped. Current broader suite:
**2,332 passed, one skipped, two known Hypothesis exclusions**. All changed-file
Ruff/format checks, production structure checks and **27 import contracts** pass.
Disabling scoped publication deliberately fails four existing terminal-observer
tests. The new retained-services lifetime test fails against the old assembly
and passes now; its six-test layer-wiring file passes. This later test-only
addition was checked locally rather than repeating the whole broader suite.

Independent review matches **47 contract groups**, **11 scenarios** and **23
execution results**, covering construction and error order, cursor/history,
shared callbacks, replay, examples, budgets and DI scopes. Holding all seven
collaborators with cyclic GC disabled no longer retains their parent runner.
No actionable finding remains. Artifacts: `~/tmp/runner-assembly-independent-20261029/`
and `~/tmp/runner-assembly-consumer-review-20261029/`.

Full repository verification remains limited by absent benchmark code and
existing Hypothesis dependency failures. This migration retires execution
assembly debt; it does not complete campaign/grounding remodularization.

## Grounding forwarding retirement and source ownership (2026-10-29)

Removed ten pure AutoGroundingService forwarding methods: startup, parked
proposal/lead reads, classification list/approval, source loading, typed
consultation and variance prepare/commit/persistence. Consumers call the same
existing lifecycle, promotion, classification, source, consultation and variance
objects directly. Public component references replace six private references;
there are no replacement wrappers, new types or new modules.

Wave and Committer now receive the **same Loader object explicitly**. The
Committer source proxy is deleted. Initial missing source still records failure
without dispatch, including when a base graph exists. Post-worker and
pre-admission revision checks, lifecycle lease and post-outcome source refresh
keep their order; stale output still becomes a transient outcome.

All retained constructor/batch algorithm ASTs match after the six component
field renames. Actual owner implementations are unchanged. Scope remains
limited: aggregate construction and broad preparation/admission references
still belong to AutoGroundingService, and its callbacks still retain it.
This slice does not claim complete grounding separation or improved retention.

Physical Python LOC: production **6,223 → 6,088 (−135)**; tests
**22,131 → 22,126 (−5)** across the complete affected snapshot, including
unchanged files in that scope. No code moved outside that counter.
Snapshot: `~/tmp/grounding-capabilities-before-20261029/`; patch:
`~/tmp/grounding-capabilities.patch`.

Validation: 144 formal baseline tests; current 392 focused and 291 follow-up
tests pass (one skip), plus two approval CLI tests. Broader suite:
**2,333 passed, one skipped, two known Hypothesis exclusions**. All **27 import
contracts** and changed-file Ruff/format checks pass. Structure checks pass on
changed runtime/composition code. The doc-only neutral consultation module retains
seven identical pre-existing SL106 warnings, with no new warnings.
Using a fixed source snapshot in both consumers deliberately fails the two
revision-race tests at the stale-admission boundary.

Independent persisted evidence matches **16 old/new traces**, exact retained
method ASTs and unchanged owner source bytes; real Loader/shared injection
checks pass. Historical independent pytest summaries are recorded explicitly as
transcriptions, not fresh raw logs. Readable evidence and executable scripts:
`~/tmp/grounding-capabilities-independent-20261029/`; migrated consumer evidence:
`~/tmp/grounding-capabilities-consumers-20261029/`. Missing benchmark code and
existing Hypothesis compatibility failures remain outside this slice.

## Retire the grounding aggregate (2026-10-29)

Removed AutoGroundingService completely. Its substantive batch algorithms now
belong to BatchFlow with three direct dependencies: reactive adapter, skip flag
and the shared ProposalPromoter. Methods are prepare_reactive, prepare_branch,
commit and _save; no compatibility aliases or service bundle remain.

`composition.grounding.Provider` registers nine actual RunScope services/state:
LeadLifecycle, ConsultationLedger, ProposalPromoter, Loader, BatchFlow,
RunCoordinator, DifferentialFlow, DispatchFlow and ApprovalFlow. Both public
container roots register it. ServiceOptions moved to composition; its input
validation preserves positive timeout checks and normalizes the disabled default
policy once. The existing policy stays shared with binder/fuzzing in production.
Formal and reactive gates read current policy/capability state dynamically.

Bootstrap gets lifecycle and reactive capabilities separately. Invoker,
Committer and replanning get actual batch/variance/source roles. DeficitCollector
takes its direct capability without the retired single-field callbacks type.
Approval CLI builds only the existing approval owner and its real dependencies;
it retains fail-loud reads, operator policy and save-before-audit ordering.

RunProvider now provides typed grounding settings and one LiveWorkflowOptions.
The workflow assembler has eight explicit inputs; legacy arbitrary configuration
kwargs/from_legacy are removed. All 27 existing workflow allocation sites and
the grounding fixtures were migrated. Test-only grouping exposes actual owners
resolved through the production DI provider; production has no replacement bag.

Physical Python LOC across all affected locations: production
**7,590 → 7,663 (+73)**; tests **101,450 → 101,664 (+214)**. Runtime reduction
comes from moving wiring and retiring the aggregate, not a whole-project shrink.
Snapshot: `~/tmp/grounding-di-before-20261029/`; patch: `~/tmp/grounding-di.patch`.

The first broader run passed 2,332 tests but caught one documentation projection
drift. The provider surface in docs/engine-runtime-2026-10-19.md was regenerated
and its six projection tests pass. The new ledger behavior test passes within
its seven-test layer-wiring file; sharing a ledger dictionary across runs
deliberately makes that isolation test fail.

Final validation after documentation repair and the new ledger pin:
**2,334 passed, one skipped, two known Hypothesis exclusions**. All **27 import
contracts** and changed-file Ruff/format checks pass. New provider and changed
runtime structure checks pass. Existing composition-root diagnostic categories
are unchanged; already oversized import blocks gained explicit DI role imports.
The old live_workflow excessive-parameter warning is removed.

Independent evidence: **77 targeted tests**, **18 baseline/current differential
scenarios**, both public cold container roots, nine shared within-run owners/state
and distinct state across two RUN scopes. Dynamic gates, policy/loader/ledger
identities, startup/error/cancel/stale-source/lease/approval behavior are checked.
No actionable finding remained. Evidence and raw logs:
`~/tmp/grounding-di-independent-20261029/`; provider and consumer artifacts:
`~/tmp/grounding-di-provider-worker-20261029/`,
`~/tmp/grounding-di-test-worker-20261029/`.
This completes aggregate retirement, not the full runtime goal audit.

## Neutral verdict contracts and full remaining-work audit (2026-10-29)

PolicyVerdict, OracleDeficit and OracleDeficitKind now have one domain owner in
model/evidence.py. Their validators and schemas are unchanged. WitnessRolePolicy
and its packaged YAML remain in verification/oracles/roles.py; the misleading
mixed policy_verdict.py module is removed without compatibility aliases.
ExecutionResult.policy_verdicts is now typed with the canonical PolicyVerdict
instead of object, so consumers can use the result contract without loading
verification, runtime or adapters. Thirty-two imports were migrated.

Physical Python LOC across all affected locations: production
**9,160 → 9,147 (−13)**; tests **13,472 → 13,526 (+54)**. Snapshot and patch:
`~/tmp/verdict-contract-before-20261029/`, `~/tmp/verdict-contract.patch`.
A real cold API test fails before the move and passes after it; it also checks
roundtrip, typed result use and invalid PASS rejection behind an import barrier.
All three JSON schemas and default witness policy match; 168 wire cases and both
model ASTs match the source snapshot. 173 baseline / 185 focused tests pass;
the first expanded run caught a canonical export-list expectation, which was
updated and checked with the existing domain/extension boundary suite.
Final expanded validation: **2,515 passed, one skipped, two known exclusions**.
All 27 dependency contracts pass; no complete-runtime signoff follows from them.

Three independent semantic passes cover all **122 files / 24,416 pre-move LOC**:
36 campaign files, 50 execution/evidence files, 36 advisory/planning files.
They identify six remaining gaps, now unique rather than repeated per group:

1. **Correctness first:** a solved path preview is reused for a later adaptive
   candidate; actual FuzzSession selects 0/1 while target receives 0/0 and record
   raises. Candidate identity/marker and current coupling must be preserved.
2. Discovery still crosses replanning proxies and manually copies a
   ClassificationState cursor between campaign and collector.
3. Current-call consumers materialize full Checker history; billing alone
   copies quadratically. Immutable history remains legitimate at boundaries.
4. Partial pair receipt derivation has two owners.
5. Supersession persistence/returned/current views depend on coordinated
   implementations; typed dispatch/current-view differences need explicit policy.
6. Fresh/snapshot planner query policy is assembled twice.

Replay, DAG and terminal reducers have distinct history/eligibility semantics;
consultation worker/owner/result envelopes and ledgers have distinct trust or
lifetimes. Those earlier generic duplication assumptions are not accepted as
findings. Full reports: `~/tmp/runtime-completion-audit-20261029/{campaign,execution,advisory}.md`.
The complete objective remains active and completion is disproven by the six
current gaps; the prefilter identity defect is next priority.

Evidence for neutral verdict contracts: `~/tmp/verdict-contract-parity.py` and
JSON result (51 accepted / 117 rejected wire cases); cold API red/green logs;
`~/tmp/verdict-contract-runtime-AST.json`; final expanded pytest log; import and
structure comparisons. Structure checks introduce no new diagnostic categories;
existing verification/contract naming warnings remain. Updated requirements
matrix: `~/tmp/runtime-completion-audit-20261029/requirements.md`.

## Candidate preview identity and dependent solutions (2026-10-29)

A real adaptive session could emit a second candidate while the executor reused
the first candidate's solved Check. Identity/marker attribution and strict
feedback validation then failed. Two parallel candidate execution methods are
replaced with one path; cached solutions apply only to their exact preview seed.
Changing a selected candidate or actual recorded request invalidates dependent
solved checks, while preserving the original sessions and their budgets/draws.
The path owner retains the updated preview explicitly. Empty solved checks mean
an invalidated solution, not a new session. Deferred solver request rewrites
receive feedback attribution; all actual-occurrence, causal, marker and evidence
validation remains in force. No finding or effect is granted by that metadata.

Seven behavioral cases exercise actual FuzzSession, SymbolicPrefilter, Checker
and in-memory target: identity/marker, one-call budget, retries, exact error and
cancellation, deferred numeric rewrite, and add/add/remove after the second
producer changes its bound value. Baseline: six failed, one passed. Current:
seven passed. Expanded regression: **2,522 passed, one skipped, two known
Hypothesis dependency exclusions**; all 27 import contracts pass. Ruff check,
format and structure lint pass on the changed production modules.

Physical Python LOC, all touched production locations: **718 → 715 (−3)**;
tests **2,908 → 3,084 (+176)**. No new modules, models or dependencies.
Snapshots, exact baseline runner, diff and logs: `~/tmp/candidate-preview-*`.
This fixes the first of the six audit gaps; five remain. Independent review passed 23 focused cases and 18 edge checks, including actual
receipt invalidation in adaptive/one-shot execution, preserved session/draw
identity, and negative causal proof with six forged-identity rejections. No
actionable finding remained; evidence: `~/tmp/candidate-preview-independent-20261029/final-review.md`.

## Direct deficit discovery and canonical pair receipts (2026-10-29)

Campaign sequencing now calls DeficitCollector directly. The two forwarding
methods and collector/campaign-state dependency in replanning are removed.
GroundingState owns one ClassificationState per campaign; no integer cursor is
copied out and returned through three owners. Cursor commit occurs only after
classification gaps and coverage finish successfully, matching the former
campaign writeback. Failed passes retain their prior path/queue mutations and
retry the same observations. Recovery still precedes differential/discovery,
and intent drain follows discovery; expansion/backlog and one-wave yield remain.

Bootstrap.prepare owns the original startup sequence: history snapshot, planning
phase, grounding start, no-model initial binding and campaign construction.
Workflow's duplicate publisher and evaluator dependency are removed, allowing
collector injection within the existing eight-parameter limit. Assembly keeps
its public signature; both existing DI roots use it. Existing Bootstrap and
other campaign/collector method bodies remain equal in the independent AST check.

Discovery physical Python LOC, all six production locations:
**1,505 → 1,452 (−53)**; two test files **1,005 → 1,391 (+386)**.
221 baseline cases passed. Eighteen characterization cases pass on original and
migrated source; ten are new. They exercise interleaved campaigns, A/empty/B
projection, recovery order/provenance, gap/coverage retry and startup error order.
318 related cases pass, one optional skip. Independent verification passed 20
cases; moving cursor commit before gaps/coverage in memory makes both failure
pins fail. No source mutation was used by that canary.

PairPartialResult.from_legs now owns attempted/completed/failed receipt derivation
for Checker and ProbeExecutor. Both private duplicate helpers are deleted; no
new type or module was added. Caller-specific messages, exception handlers,
finally accounting and distinct readback/concurrency receipts remain unchanged.
All 96 synthetic receipt combinations match both old implementations; execution
traces confirm both real callers reach the canonical owner. Deliberate observation
loss makes four evidence pins fail. 226 focused cases pass, one optional skip.
Pair physical Python LOC: **1,161 → 1,146 (−15)**; tests **477 → 556 (+79)**.

Final combined regression for all three cuts: **2,538 passed, one skipped,
two known Hypothesis dependency exclusions**. All 27 import contracts pass;
Ruff/format and production structure checks are clean on all touched modules.
No live target or paid/model calls were made. Optional missing benchmark-package
coverage and full-repository validation are not claimed.

Combined physical Python LOC across twelve touched production locations:
**3,384 → 3,313 (−71)**; four test files **4,390 → 5,031 (+641)**.
No modules or models were added. All moves and both sides of deduplication are
counted. Current runtime inventory: 122 files / 24,155 physical lines.
Three concrete audited cuts remain: current-call history copies,
supersession/current-view ownership, and duplicated planner query policy.
The overall runtime goal remains active.

Evidence: `~/tmp/discovery-before-20261029/`, `~/tmp/discovery.patch`,
`~/tmp/discovery-independent-20261029/`, `~/tmp/pair-receipt-before-20261029/`,
`~/tmp/runtime-three-cuts-{loc.json,final.log,ruff.log,format.log,structure.log}`.

Final independent discovery review also compared five baseline/current traces,
including cancellation and gaps/coverage errors, and verified both DI roots in
two RUN scopes with isolated classification state. No actionable finding or
open investigation remained. Report: `~/tmp/discovery-independent-20261029/review.md`.

## Attempt-ledger queries and one planner policy owner (2026-10-29)

Checker now answers count/latest without snapshots, reads an operation slice
for partial pair receipts, and finds the first matching Check for observation
persistence. Candidate feedback and recorder finalization use the latest query
at exactly their former read timing. identities_for traverses the original
ledger in reverse; duplicate-ID FIRST persistence and LAST identity/history
semantics deliberately remain different. Historical observed_graph indexing,
round results and replay keep immutable full snapshots. No cache, facade state,
receipt DTO or module was introduced.

Actual counting reproduction, same target/budget/attempts: 10 calls formerly
copied 100 ledger references for billing, now zero; 100 calls formerly copied
10,000, now zero. This is copied-reference evidence, not a measured latency
claim or a claim that historical graph projection is constant time. Nine new
pins exercise normal/error/cancel budgets, actual adaptive feedback (one final
round snapshot), duplicate IDs, persistence and immutable snapshots after reset.
The corrected six billing pins fail on the original calls module and pass now.
The first attempted pins lacked required observation data; those failures are
not used as before/after evidence. 125 focused tests pass. Independent review:
151 pass, two known dependency exclusions, plus reentrant transport/current-read
order/partial receipts. No actionable finding remained.

QdlPlanner._build_inference_program is now the sole builder for closure
selection, mixed-context chains, bounded depth and walks. Fresh compile/solve
and snapshot statement/session lifecycles stay distinct; duplicated snapshot
closure-name state is removed. Four injected-engine pins pass before/after;
298 related tests pass, one skip. All 384 old/current fresh/cache scenarios and
engine-program/session-call comparisons match, including revisions/retractions,
contexts, depths, arbitrary rules, state/resource graphs and injected constraints.
A mixed-context closure-loss canary fails as expected. Constructor validation
still rejects unknown closures before engine construction.

Physical Python LOC, all touched owners: history production
**2,180 → 2,200 (+20)**, tests **4,238 → 4,421 (+183)**;
planner production **405 → 409 (+4)**, tests **949 → 1,021 (+72)**.
Combined **2,585 → 2,609 (+24) production**, **5,187 → 5,442 (+255) tests**.
These are ownership/performance improvements, not a claimed LOC shrink.
Final scoped regression: **2,551 passed, one skipped, two known Hypothesis
exclusions**; all 27 import contracts pass, changed-file Ruff/format and
production structure checks are clean. The optional benchmark-dependent
review_V2R module cannot collect in this checkout; its constructor migration
parses/lints, and actual Projection paths are exercised by collected tests.
No full repository/live/paid validation is claimed.

Current runtime: 122 files / 24,155 physical lines. One audited cut remains:
supersession/current-view ownership. Read-only reconstruction verified 431
existing tests and reproduced overly broad closure pruning, missing derived
tombstones and field-role context/holder disagreement. Raw historical proof,
current causal validity, accepted revision delta and merged source are distinct
contracts; they must not be collapsed into a destructively filtered graph.
The implementation plan preserves ordinary/branch save failure order and keeps
QDL current_* closures authoritative. It is not implemented yet, and the overall
runtime goal remains active.

Evidence: `~/tmp/call-history-*`,
`~/tmp/call-history-independent-20261029/review.md`,
`~/tmp/planner-policy-report-20261029.txt`, `~/tmp/planner-policy-*`,
`~/tmp/runtime-history-planner-*`,
`~/tmp/supersession-plan-20261029/{plan.md,probe.json,source-pins.json}`.

## Canonical supersession, current proof and saved revisions (2026-10-29)

The six accepted-revision functions move unchanged from runtime grounding to
qdl/graph_ops.py (all six ASTs match the snapshot). Current causes/has and
confirmed retired providers are read from original-graph Clingo current_*
closures. Other literals, declarations and raw reasoning retain their history;
no destructively filtered graph is ever re-solved or persisted. Trusted field
roles select contract/accepted input before inference and preserve exact holder
and context semantics. Typed extensions sharing internal ASP names or different
arities cannot bypass or confuse the canonical relation readers. The fast path
is limited to plain extensional input without rules, tombstones or explicit
current/retired relations; forced-library comparisons and mutation pins cover it.

Deficit closure no longer deletes every predicate ending in a retired node.
Variance excludes confirmed retired providers while retaining fresh norm-only
and requirement-only explanations. An intermediate overly strict provider guard
was caught independently and corrected; both old/raw and current meanings are
pinned. Evidence binding revocation is a separate verification protocol:
revoked object_ref bindings cannot create typed evidence or consume existing
proofs even when their field classification remains canonical. The first
expanded regression exposed this distinction; shared binding and actual-target
query guards preserve the existing negative contract. All 258 scoped witness
and role/evidence tests then passed; no expectation was weakened.

The persistence owner returns the exact (saved_graph,source_id) tuple after
successful save. DispatchFlow returns that graph, fixing its missing-tombstone
result. ApprovalFlow consumes the ID while preserving admitted hash/count audit
semantics. Ordinary BatchFlow prepares before save and avoids duplicate
revision construction; branch preserves its deliberate post-save pure stage
and failure window. New pins assert identity/hash/count, source/provenance,
errors before save, repository failure and durable-write/no-return after-save.

Validation includes snapshot red/green (eight persistence failures; twenty-one
reader failures), explicit/derived tombstones across all contexts, exact holder
identity, untrusted-role exclusion, raw historical premises, fresh variance
explanations and typed-extension guards. Deliberately removing the latter gives
ten expected failures. Independent reviews found and then closed the two P2
issues; final guards and witness revocation have separate current-source proof.
The final combined run: **2,884 passed, one optional skip, two known baseline
Hypothesis dependency exclusions**. All 27 dependency contracts pass; Ruff and
format checks pass on touched files. Structure lint adds no new violation
category and removes the old role-resolver complexity warning. Existing QDL
canonical-name/complexity and verification projection warnings remain; the
existing consume query grows by one ASP guard line (169→170). A clean global
structure-lint result is not claimed.

The final full-objective audit also found a cache-hit contract defect outside
the earlier cut list: AxisResultCache passed an issues tuple as issue_count and
lost the diagnostic payload. Named fields now retain len(dropped) and issues.
Both valid clean/filtered cache pins fail before the fix; all 72 focused cache
checks pass after it without another model request. The fix adds one production
line and no abstraction.

Relevant unavailable tests have explicit runtime-boundary evidence: the two
original feedback and shrink/save/replay test bodies pass with finite optional
strategy implementations, while the core runner, Checker, oracles, FuzzSession,
JSONL persistence and replay remain real. Dropping feedback or saving in memory
makes the corresponding test fail. This does not validate or repair the broken
Hypothesis grammar dependency. Six real FuzzSession/GoalPayload contracts also
pass. New standalone in-memory physical readback tests cover two later norms on
one original measurement, foreign request/identity/marker rejection, and missing
before-channel isolation without importing the absent benchmark package. Full
benchmark behavior/deployment/paid calls are not claimed.

Current runtime inventory: **122 files / 24,155 physical lines**. All known
semantic audit cuts are resolved; this alone is not objective signoff. The final
requirement matrix must corroborate the original scope and current source hashes.
Artifacts: `~/tmp/runtime-final-integrated.log`, `~/tmp/runtime-final-*`,
`~/tmp/runtime-extension-equivalence*.{py,log}`, related canary logs,
`~/tmp/supersession-*`, `~/tmp/axis-cache-*`, and the final objective audit.

## Final original-objective acceptance (2026-10-29)

The independent requirement-by-requirement audit accepts the ORIGINAL full
runtime rearchitecture objective. It uses semantic ownership and execution
paths, complete partitioned inventory, current migration deltas and meaningful
behavior/negative controls; an empty cut list alone is not the justification.
All five responsibility separations and neutral-contract ownership pass; no
remaining actionable aggregate/God object, duplicate authority or state courier
was established in the audited runtime scope. The late cache-contract defect,
variance and typed-extension issues and witness lifecycle regression are fixed.

Final current set: **122 runtime files / 24,155 physical lines**. All source
hashes match the manifest, with no missing, unexpected or stale records.
The final integrated result remains **2,884 passed, one optional skip, two known
baseline exclusions**, plus accepted core-runtime equivalent proof for relevant
unavailable optional-strategy/benchmark scenarios. Actual Finalizer one/two-norm
cases complement promotion/rebinding/readback tests. All27dependencycontracts
pass; scoped Ruff/format are clean; inherited structural warnings and external
coverage limits are retained explicitly. No new modules or production models
were added in this final cut.

Final-pass physical LOC across ALL touched production owners, including both
sides of moves: **4,052 → 4,148 (+96)**. Tests **10,974 → 12,379 (+1,405)**.
Within runtime alone: **24,366 → 24,155 (−211)**; this subtree decrease is NOT
presented as a project-wide shrink. The additional pure QDL query/correctness
code is counted. Since the first inventory, runtime is25,725→24,155(−1,570),
but no cumulative whole-project delta is inferred from subtree counts.

Authoritative final matrix and limits:
`~/tmp/runtime-final-objective-audit-20261029/acceptance.md`,
`~/tmp/runtime-completion-audit-20261029/requirements.md`.
Exact final-pass LOC and patch:
`~/tmp/runtime-supersession-final-loc.json`,
`~/tmp/runtime-supersession-final.patch`.
No required work remains for this runtime goal; broader package/deployment
migration is not represented as completed by this acceptance.
