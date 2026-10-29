# Cloud DAST engineering rules

## Architecture invariant

Cloud DAST is an application-agnostic DAST engine over one formal substrate:

```text
FormalRepository
  -> canonical QdlGraph
  -> FormalThreatModeler (optional proposal)
  -> QdlPlanner
  -> QdlExecutionView
  -> BoundPathRunner
  -> FuzzSession
  -> ObservationProjector
  -> PrimitiveOracleRouter
  -> FindingEvaluator
```

QDL is the only executable source of truth. Do not reintroduce parallel
`ThreatGraph`, `DfdModel`, `AttackGoal`, `AttackPath`, `TraceGoal`, or a second
threat-model repository.

QDL contexts must remain strict:

```text
contract  — projected contracts and graph-backed facts
proposal  — LLM hypotheses; never executable automatically
accepted  — accepted norms, states, and dependencies
runtime   — observations and evidence
report    — presentation projections
```

LLM output is a constrained QDL proposal. It cannot create findings, accepted
facts, runtime facts, or final security verdicts.

Exploratory proposal promotion must remain explicit and graph-grounded:
promote only action-bound `prevents` norms whose action exists in the source
QDL graph and whose effect has a deterministic primitive.
Model requests must use a deterministic, self-contained action slice; do not
send an entire service contract when a bounded slice is sufficient.

## Execution rules

- A QDL path orders ordinary action occurrences. Before each request,
  deterministic evidence must satisfy all of that action's causal requirements
  with its concrete typed bindings. Value dependencies do not invent causal
  requirements: an independently applicable observer may supply missing values
  while the desired effect remains unproved. Ordinary actions do not require a
  prohibiting security norm.
- Security verdicts remain independent of causal progress. A norm violation
  requires grounded `FAIL`; protocol success alone proves neither a causal
  effect nor a vulnerability. An unproved effect blocks only its current path.
- Ungrounded `FAIL` must not create a finding, publish `FactVerified`, increase
  fuzz reward/failures, or mark progress as confirmed.
- Findings require `FAIL && deterministic && grounded && norm && evidence`.
- Adaptive fuzzing stops only by its local budget/reward/entropy state or the
  campaign-wide check budget.
- Every fuzz strategy must preserve QDL payload hints through
  `GoalPayloadGenerator`.
- Marker and OOB probes must use a unique `probe_marker` per candidate; oracles
  may not attribute another candidate's asynchronous evidence to this check.
- Use library engines: Clingo for Datalog/ASP reasoning, Z3 for symbolic
  constraints, River for bandit selection. Do not write custom engines.
- Sensors are precision-first. Under the deterministic oracle a noisy sensor
  fabricates findings, so heuristic detectors (secret shapes, signatures) only
  produce leads: parked proposal facts for operator review, never
  auto-promoted classifications. Prefer libraries for generation (fuzzing,
  payload corpora) and infrastructure (OOB collaboration); a new hand-written
  detector requires an explicit justification in the change report.

## Naming

- Function names are actions: use a verb and a direct object (`execute_check`,
  `check_scenario`, `select_candidate`, `restore_state`, `render`).
- Keep names short and do not repeat package context in a symbol name.
- Classes name a domain object or role (`CheckGenerator`, `InvariantProposer`,
  `OutcomeOracle`, `EventStore`).
- Do not rename canonical domain terms (`MethodSpec`, `ScenarioPosition`,
  `Invariant`, `Check`, `Observation`, `Finding`) merely for style.
- `run_*` is allowed only when running a workflow is the semantic operation.
- Use `dict` for identifier-addressed mutable registries and `set` only for
  membership/deduplication.
- Validate at trust boundaries and when malformed state would be misinterpreted;
  do not add defensive `None` branches for typed contracts already constructed
  inside the core runtime.

## Layer model

Ports-and-adapters with dependency inversion: core never depends on concrete
infrastructure, and the target architecture has no `application` layer.
Allowed dependency directions:

```text
app/assembly      -> core ports + runtime + extension implementations (wiring)
runtime           -> qdl, model, verification, core ports
verification      -> qdl, model, core ports
qdl               -> model/contracts and the Clingo boundary
integrations      -> core ports and model contracts
packages/reporting -> core model/runtime read contracts and event ports
optional packages -> core public API, contracts, and extension specifications
```

- `model` contains canonical domain entities and evidence contracts.
- `qdl` owns the declarative language, ontology, graph invariants, compiler,
  admission boundary, and Clingo adapter. It owns no campaign lifecycle or I/O.
- `runtime` owns campaign state, sequencing, budgets, replay, binding, and
  execution coordination. It consumes QDL; it does not duplicate QDL facts.
- `verification` owns evidence interpretation, taxonomy, coverage, findings,
  and deterministic oracle decisions.
- `ports` owns capability protocols: `Target`, `EventPublisher`, `ModelClient`,
  `Guardrail`, `ReportPublisher`, and repository protocols.
- `infrastructure` and `integrations` provide concrete transports, stores,
  event journals, and external-call adapters. Only assembly should select them.
- `composition`/`app` are wiring only and construct Dishka scopes; they do not
  become a business-logic layer.
- `presentation` and `packages/reporting` format or publish already computed
  read models; they do not plan or execute campaigns.

Every durable boundary has one repository protocol in `ports` and one concrete
implementation in infrastructure/integrations. Run-local projections are not
repositories. No production import may use `cloud_dast.application`.

## Refactoring and review

- Every rename or move must improve a concrete boundary or execution trace.
- Do not add compatibility wrappers, aliases, duplicate models, or parallel
  package locations during internal migration.
- Tests must assert behavior and execution semantics, not object shape.
- A change report must list changed files, consumers, tests, and remaining
  risks.
- Reviewers may reject ceremony, dead contracts, duplicate models, long
  multi-responsibility functions, and names that merely sound different.

## External project boundaries

- Do not port architecture, abstractions, primitives, or naming from
  `~/projects/cloud-pentest-agent` or external `BugBountyMCP`.
- Those projects are historical context only and are not design authorities.
- Cloud DAST decisions come from this repository's QDL contracts, tests, and
  the current architecture document.
