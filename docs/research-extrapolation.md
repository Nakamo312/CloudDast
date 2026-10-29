# Research Extrapolation: Sefz, PDFuzzer, SymTEE → QDL Algebra

Three 2026 papers independently converge on the division our algebra already
formalizes: **LLM proposes semantics, deterministic engine validates, searches,
and decides**.  This document maps each mechanism onto the QDL basis
(`docs/qdl-algebra.md`) and extracts the concrete deltas to implement.

---

## 1. Sefz — goal-directed semantic fuzzing (arXiv:2605.13044)

### Core mechanism

- Each natural-language guardrail is translated into a **reachability goal**
  over an **annotated execution trace** — a dependency graph of events labeled
  with security predicates.
- A guardrail becomes a **forbidden source→sink path**, possibly intercepted by
  a designated **gate**: "delete requires confirmation" → "user input reaches a
  destructive action with no intervening confirmation step".
- Violation checking reduces to a **deterministic graph query** — a
  reproducible oracle without an LLM judge.
- An LLM-based **semantic mutation engine** generates benign inputs whose
  traces *progressively approach* the violation pattern.
- A **Thompson Sampling bandit** selects operator×goal combinations;
  **goal-proximity is the graded reward**: a trace that gets closer to the
  forbidden path earns credit even before a full violation.
- Ablations: removing semantic mutation costs ~53% of discoveries, the bandit
  ~35%, goal-proximity feedback ~29%.

### Mapping onto the algebra

| Sefz concept | QDL algebra |
|---|---|
| annotated execution trace | runtime QDL evidence graph (`evidence(OBS, effect)` + campaign facts) |
| security predicates on events | the six Σ primitives: `executes`, `binds`, `may`, `causes`, `observes`, `reaches` |
| guardrail | norm / letter formula (S,T,R,I,D,E) or corpus class |
| forbidden source→sink path | witness pattern of a letter in the path monoid: `causes`/`reaches_plus` chain + witness constructor |
| gate that must intercept the path | `may` / `binds` / `required` fact (the control that makes the letter formula false) |
| deterministic graph query | Clingo solve over merged contract+runtime graph |
| mutation operator | generator strategy (template / symbolic / fuzz / llm-mutator) |
| operator×goal bandit | `GeneratorBandit` (already River ThompsonSampling) with arms extended to strategy×letter |
| goal-proximity reward | fraction of the witness-pattern atoms established in the runtime graph |

Sefz hand-designed its security predicates; our algebra derives them from the
closed basis, so the same mechanism generalizes beyond agent skills.

### Deltas to implement

1. **Graded reward (goal-proximity)** — the biggest gap.  Current
   `FuzzSession` reward is binary (+3 violation, +1 pass).  Extend it: for the
   active goal, compile the letter formula into its conjunct set; after each
   probe, count conjuncts already established by runtime evidence
   (`executes(a)` seen, `targets(a,r)` known, `may` still unobserved → 2/3).
   Proximity is a deterministic Clingo query — no LLM judge.
2. **Bandit arms strategy×goal** — today the bandit chooses only the strategy.
   Key the arm by (strategy, letter/goal id) so the policy learns
   which mutation family works for which violation class.
3. **Benign-input mode** — spec violations are reachable with well-formed
   requests (mass assignment with valid fields, legal transitions in a
   forbidden order).  The mutation space includes fully schema-valid inputs,
   not only tampered ones.

---

## 2. PDFuzzer — LLM grammar + relation inference, Z3 sequences (arXiv:2608.06641)

### Core mechanism

- LLM builds context-free grammars per API function/parameter from manuals.
- Undocumented APIs: signatures recovered by differential trace analysis, LLM
  infers full specifications from naming conventions and design patterns.
- Three inter-API relationship types:
  1. **producer-consumer** — return value of A feeds parameter of B;
  2. **value-constraint** — parameters of two calls must satisfy
     equality/inequality (names need not match: `addField`/`removeField` share
     `cName`; `popUpMenuEx.cName` = `search.query.cQuery`);
  3. **implicit** — interaction through shared state rather than parameters
     (`setAction` registers a handler later triggered by `setFocus`).
- Relationships are emitted as **SMT constraints**; Z3 solves concrete API
  call *sequences*.  Up to +48% coverage, 31 zero-days; LLM stage accuracy
  93–98%.

### Mapping onto the algebra

| PDFuzzer concept | QDL algebra |
|---|---|
| per-API grammar | `Struct` schemas + `field_type/field_required/field_minimum/field_maximum` facts (already emitted by contract projection) |
| producer-consumer relation | `reaches(output_field(A,f), input_field(B,g))` |
| implicit relation | `causes(A, write(state))` + `requires(B, value)` — already closed by `chain_plus` |
| value-constraint relation | **new grounded predicate** `coupled(FieldA, FieldB, op)` with `op ∈ {eq, ne, lt, le, gt, ge}` |
| LLM spec extraction | existing semantic compiler: raw graph → proposal QDL facts |
| undocumented-API recovery | existing `unmapped`/`ambiguous` evidence + proposal promotion |
| Z3 sequence solving | `Z3SymbolicGenerator` extended from single-call values to (values, ordering) over a requires-chain |

### Deltas to implement

1. **`coupled/3` value-constraint predicate** — the only genuinely new
   vocabulary.  LLM proposes `coupled` facts from contract semantics; they
   compile into Z3 equality/inequality constraints when a probe spans several
   calls.  Producer-consumer and implicit relations are already expressible —
   they only need to become mandatory LLM-proposal targets.
2. **Sequence-level symbolic solving** — given a requires-chain of actions,
   Z3 solves a model that assigns every input field such that all `coupled`
   and `field_*` constraints hold.  This is the concrete-value/ordering
   counterpart to Clingo's path enumeration.
3. **Trace-driven relationship repair** — when a probe sequence fails on
   precondition, the failure observation feeds back as evidence for inferring
   a missing `requires`/`coupled` edge (LLM proposes, validator gates).

---

## 3. SymTEE — LLM harness + mocks for symbolic execution (arXiv:2605.22058)

### Core mechanism

- AST analysis extracts code slices that may lack input validation.
- LLM converts slices into **KLEE-compatible harnesses with lightweight mock
  environments** — no real TEE hardware or toolchain needed.
- Symbolic execution detects missing validation; 100% precision, 92.3% recall,
  ~$0.05 average cost per analysis.

### Mapping onto the algebra

We are black-box against live APIs: no AST, no in-process execution.  The
analog of each piece:

| SymTEE concept | QDL algebra |
|---|---|
| code slice lacking validation | letter/class formula bound to an action context (the goal) |
| LLM-generated harness | LLM-compiled **Probe IR**: field selection, identity hints, state preparation — expressed as typed QDL terms, never free code |
| mock environment | stand state machine + scenario layer: object creation, credential acquisition, callback registration |
| symbolic execution | Z3 pre-solving of candidate inputs satisfying the schema and violating the norm hypothesis |
| confirmation | live fuzz execution; verdict by П1–П6 primitive oracles |

The paradigm transfers exactly: **symbolic prefilter + live confirmation**.
What does not transfer: KLEE itself (no source), and mock fidelity is bounded
by what the six witness channels can observe — that is the DAST boundary, not
a defect.

### Deltas to implement

1. **Probe IR enrichment by LLM** — today probes compile from deterministic
   templates.  Let the LLM propose, per goal, the probe *shape* (which fields
   to vary, which principal to use, which state to prepare) strictly within
   the closed Probe vocabulary; validator type-checks; Z3 fills concrete
   values.
2. **Two-stage oracle** — Z3 finds a candidate input violating the hypothesis
   symbolically; only then does the live stand run; П1–П6 decides.  This cuts
   live budget by never executing symbolically-refuted probes.
3. **State preparation as first-class probe steps** — the mock-environment
   insight: a probe is a sequence (setup → mutate → observe), where setup is
   derived from the state machine, not hand-written.

---

## 4. Synthesis: the papers close the loop the algebra defines

Each paper supplies one segment of the same cycle:

```
PDFuzzer segment (semantic extraction):
  LLM grounds M + proposes relationships
  (requires / causes / reaches / coupled)
        │
        ▼
  Clingo derives candidate goals
  (letters × targets × corpus classes)
        │
Sefz segment (goal-directed search):
  bandit over strategy × goal
  goal-proximity reward = deterministic
  graph query over runtime evidence
        │
        ▼
SymTEE segment (harness + prefilter):
  LLM compiles goal → typed Probe IR
  Z3 pre-solves values and sequences
  state machine prepares the stand
        │
        ▼
  live fuzz → П1–П6 oracle → findings
        │
        └──► observations update M and coverage ──► loop
```

All three papers make the LLM a *proposer* and keep verdicts deterministic —
the same contract our promotion flow enforces.  None of the three has a
closed security basis: Sefz hand-designs its trace predicates, PDFuzzer's
relations are engine-specific, SymTEE's harnesses are code.  The algebra is
the substrate that lets their mechanisms compose: a Sefz goal is a letter
formula; a PDFuzzer relation is a Σ fact; a SymTEE harness is a Probe IR over
Σ.

## 5. Prioritized backlog

| # | Delta | Source | Where | Status |
|---|---|---|---|---|
| 1 | Graded goal-proximity reward | Sefz | `fuzzing/proximity.py` + `FuzzSession.record` | done* |
| 2 | Bandit arms strategy×goal | Sefz | `GeneratorBandit` arm keying | done |
| 3 | `coupled/3` value constraints | PDFuzzer | `formal/couplings.py` + `Z3SymbolicGenerator` | done |
| 4 | Sequence-level Z3 solving | PDFuzzer | `formal/symbolic.py: solve_sequence` | done |
| 5 | LLM-enriched Probe IR | SymTEE | probe fields + setup identity + seed hints | done |
| 6 | Two-stage symbolic prefilter | SymTEE | `SymbolicPrefilter` in `path_runner` | done (per-step) |
| 7 | State-prep probe steps | SymTEE | `step_setup.py` + fixture pool | done |

Sefz's ablation justifies the order: proximity feedback and the bandit
account for ~29% and ~35% of discoveries respectively — they come before
harness enrichment.

\* Current state (2026-10-19): an ungrounded FAIL is converted to
`UNSCOREABLE` with zero proximity and zero reward in `FuzzSession`,
`ChainFuzzSession`, and the path runner. The remaining A4 caveat is witness
authenticity: the middle OOB/marker rung still uses sent-marker/response-shape
evidence rather than a sink-specific authenticated witness.

## Second wave: campaign automaton papers

Four additional papers close the gap between static threat derivation
and a self-driving campaign.  Their combined design is specified in
[docs/campaign-automaton.md](campaign-automaton.md):

| Paper | Contribution | Maps to |
|---|---|---|
| Intentest (2609.07344) | Persistent fact-intent DAG | QDL + event-log Campaign DAG read model; persistent cross-run graph remains a design gap |
| MazeRunner (2608.14216) | Strategist/Executor/Reviewer + backtracking | Gap-driven scheduling + failure diagnosis |
| PrediQL (2510.10407) | Contextual bandit + execution memory | Action history informs generator selection |
| DRLRM-PT (2405.15908) | Reward machines for POMDP | Each invariant as a lifecycle state machine |

### Implemented semantics (deltas 1–2)

`goal_proximity(effect, observation, verdict)` grades one trace on a
three-step ladder that mirrors the letter witness pattern:

```
0.0   transport never delivered a usable response
1/3   delivered — the call reached the service (executes atom)
2/3   witness channel established — primitive-specific evidence observed
1.0   FAIL verdict — the complete witness pattern
```

The witness marker per goal kind comes from the shared `EFFECT_PRIMITIVES`
table: outcome → ALLOWED/DENIED resolved, response_field → output present,
latency_bound → duration recorded, oob_event → probe marker present,
marker → response summary present, sequence → trace present.

`GeneratorBandit` arms are namespaced `goal_key:strategy`, where the goal key
is the norm's effect constructor (`denied`, `changed`, `external_call`, ...)
so learning transfers across methods of the same violation class.  The arm
reward is the graded proximity (FAIL forces 1.0; ungrounded outcomes are
halved); the session reward keeps its verdict emphasis (FAIL 3.0, PASS 1.0,
unscoreable + proximity).  `best_proximity` in `FuzzSessionState` tracks the
strongest trace so far.

### Implemented semantics (deltas 3–4)

`coupled(left, right, operator)` is a grounded basis predicate with a closed
operator alphabet `eq|ne|lt|le|gt|ge`; sides must be `input_field`/
`output_field` terms so a coupling always identifies its calls.  The LLM
proposes couplings like any other model fact; the promotion validator accepts
them and unknown operators are rejected at extraction.

Within one method the binder attaches same-action couplings to
`VerificationPlan.couplings`; `Z3SymbolicGenerator.build_seed` then solves
fields jointly — including string fields, which become Z3 `String` variables
when coupled (the PDFuzzer `cName` case).

`solve_sequence(seeds, methods, couplings)` binds values for a whole
requires-chain in one Z3 model: variables are keyed by
`(method_id, field_name)`, cross-call couplings constrain them jointly, and
an unsat result returns the original seeds with status `unsat`.

### Implemented semantics (deltas 5–6)

`SymbolicPrefilter` sits between the fuzz session and the live service.
For every candidate it asks Z3 to satisfy the field constraints (bounds,
enums, plan couplings) first:

- `solved` — execute the solver-derived check (coupled fields stay
  consistent, e.g. `from == to`);
- `pass`   — nothing to solve; execute the candidate as is;
- `unsat`  — the request is symbolically impossible; never spend a live
  call on it.

When the solver rewrites the request, the bandit still learns from the
candidate the session emitted (the solver is deterministic post-processing,
not a strategy).  Grounded probe fields close the loop for delta 5:
`has(input_field(a, f), probe_target | oob_target)` facts, proposed by the
LLM and extracted by the binder into `VerificationPlan.probe_fields`, take
priority over name-based field guessing in the payload decorator.  Remaining
parts of delta 5 (identity and state-prep hints) and delta 7 (setup steps in
probes) are not implemented yet.

### Delta 5: identity and seed hints (closed)

Three grounded mechanisms, all LLM-proposable through the existing
``has``-role vocabulary and validated by the promotion flow:

- **probe fields** — ``has(input_field(a, f), probe_target | oob_target)``
  pick the probe-marker field deterministically (delta 5, part 1);
- **setup identity** — ``CLOUD_DAST_SETUP_IDENTITY`` runs fixture-creating
  actions as the stand provisioner, not the attacker (fixtures are
  provisioning, not attacker behavior);
- **seed hints** — ``has(input_field(a, f), setup_value | setup_skip)``:
  ``setup_value`` fills unresolved fields with deterministic fixture
  values, ``setup_skip`` drops a mutually exclusive branch (e.g. the
  password-generation spec when the seed uses explicit payload entries).

Hints flow two ways: setup seeds get them through
``QdlExecutionStep.setup_hints``; probe seeds get the method's own hints
through ``VerificationPlan.seed_hints`` applied by the payload generator.
Empty strings count as unresolved for hint-marked and required fields.

### Delta 7 guard: bounded stand fixtures

Stateful fuzzing at scale must not create one resource per probe.  Setup
steps will be phrased as facts (`FixtureKey`: resource type, state, scope)
and served by `FixturePool`:

- **reuse by fact** — probes with the same key share one resource, so the
  number of created resources equals the number of distinct facts, not the
  number of probes;
- **hard budget** — `register` raises `FixtureBudgetExceeded` at the cap
  (default 64, `CLOUD_DAST_FIXTURE_BUDGET`), so a probe becomes blocked
  instead of growing the stand;
- **irreversible consumption** — delete-type probes call `consume`, forcing
  at most one fresh fixture per irreversible probe;
- **TTL reaper** — expired fixtures are never handed out and are reclaimed
  by `reap_expired` (`CLOUD_DAST_FIXTURE_TTL_SECONDS`);
- **bounded teardown** — `created_resources` returns exactly what the
  campaign created, regardless of how many probes ran.

Setup-step execution (delta 7 proper) will call `acquire` before issuing any
create action and `register` after exactly one creation.

### Implemented semantics (delta 7)

`causes(a, create(t))` is a grounded basis fact (the `create`/`remove`
object-registry effect constructors from the algebra spec, §2.2): the LLM
marks which action creates which resource type.  The binder resolves those
actions into `QdlExecutionStep.setup_method`.

`StepSetupResolver.prepare(step)` runs before each step:

1. derive the fixture fact — (resource type, required state, container
   scope; the container is the stand resource of another type, e.g. the
   folder);
2. `pool.acquire` — a hit substitutes the fixture resource into the step's
   stand, and every generator then addresses that resource;
3. on a miss, check `pool.full` BEFORE any live call, execute exactly one
   create action seeded from the step's scenario, extract the created id
   from the response, and `register` it.

Budget exhaustion and setup failure degrade gracefully: the probe keeps the
original stand resource.  The money test: two steps needing the same fact
execute exactly one create, and both probes address the same fixture.

---

## Third wave: agent orchestration over QDL

The works below do **not** justify replacing the deterministic substrate with
an autonomous LLM agent. They justify a bounded, proposal-only agent layer
above QDL:

- an agent may propose facts, norms, edges, grammars, priorities, and clues;
- it may not select the executable path, verify a step, call the target, or
  issue a verdict.

### Reasoning, memory, and context

| Source | Mechanism | QDL mapping |
|---|---|---|
| [ReAct](https://arxiv.org/abs/2210.03629) | interleaves reasoning and tool use | LLM proposes the next probe; deterministic executor acts |
| [Reflexion](https://arxiv.org/abs/2303.11366) | verbal reinforcement and episodic memory | reflection/clue nodes derived from unscoreable outcomes |
| [Tree of Thoughts](https://arxiv.org/abs/2305.10601) | deliberate branching over candidate plans | assumption branches and alternative path proposals |
| [Graph of Thoughts](https://arxiv.org/abs/2308.09687) | represents reasoning as an arbitrary graph | Campaign DAG with typed dependencies and clue edges |
| [Graph-based Agent Memory](https://arxiv.org/abs/2602.05665) | surveys graph memory for long-horizon agents | QDL + event log as external graph memory |
| [Zep](https://arxiv.org/abs/2501.13956) | temporal knowledge-graph memory | time-scoped facts, clue provenance, and invalidation |
| [CoALA](https://arxiv.org/abs/2309.02427) | separates working, episodic, semantic, and procedural memory | bounded action slices, runtime evidence, QDL semantics, procedures |
| [MemGPT](https://arxiv.org/abs/2310.08560) | hierarchical context management | bounded slices and explicit promotion/eviction policy |
| [Chain-of-Agents](https://arxiv.org/abs/2406.02818) | distributes long-context work across agents | bounded specialist handoffs instead of one monolithic context |
| [Mixture-of-Agents](https://arxiv.org/abs/2406.04692) | aggregates multiple LLM responses | deterministic consultation aggregation over QDL proposals |

### Orchestration and handoff

| Source | Mechanism | QDL mapping |
|---|---|---|
| [MetaGPT](https://arxiv.org/abs/2308.00352) | role specialization and SOP workflows | strategist/executor/reviewer as graph roles, not separate truth owners |
| [AutoGen](https://arxiv.org/abs/2308.08155) | multi-agent conversation with tools and humans | typed, graph-mediated handoffs rather than free chat |
| [LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview) | stateful graph runtime mixing code and LLM nodes | deterministic graph orchestration with LLM proposal nodes |
| [LangGraph Multi-agent](https://docs.langchain.com/oss/python/langchain/multi-agent) | supervisor, subagents, handoffs, and context control | campaign supervisor plus bounded specialists |
| [LangGraph Supervisor](https://reference.langchain.com/python/langgraph-supervisor) | central supervisor delegates to workers | deterministic dispatcher over specialist capabilities |
| [Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/overview) | agents, workflows, sessions, and memory in one runtime | production hybrid orchestration with explicit control flow |
| [Anthropic: Building effective agents](https://www.anthropic.com/engineering/building-effective-agents) | distinguishes deterministic workflows from autonomous agents | keep deterministic workflow; add LLM only where adaptivity is needed |
| [OpenAI Agents SDK Handoffs](https://openai.github.io/openai-agents-python/handoffs) | delegates work to specialized agents | deficit-driven consultation requests |

### Security-testing baselines

| Source | Mechanism | QDL mapping |
|---|---|---|
| [PentestGPT](https://arxiv.org/abs/2308.06722) | LLM-assisted penetration testing | semantic proposer for hypotheses, not a verdict source |
| [RESTler](https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing/) | stateful REST fuzzing over producer-consumer dependencies | `chain_plus` / `requires` as deterministic path substrate |
| [MazeRunner](https://arxiv.org/html/2608.14216v1) | task and clue orchestration for LLM-driven pentesting | campaign agent over clue graph with deterministic gates |
| [Hypothesis](https://hypothesis.readthedocs.io) | property-based strategies, shrinking, example database | S3: strategy algebra, minimal PoC, replay via A17 |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | schema-driven API fuzzing, negative testing via schema mutation | S3: reactive constraint inference; heuristic checks rejected (verdict-gate) |
| [Gramatron](https://github.com/HexHive/Gramatron) | grammar automaton input representation | S3/S5: representation determines mutation and speed |
| [Grammarinator](https://github.com/renatahodovan/grammarinator) | parse-then-mutate over ANTLR grammars with real seeds | S5: textual formats (XXE, SSTI, deserialization), seed reuse |
| [ChatAFL](https://mboehme.github.io/paper/NDSS24-chatafl.pdf) | LLM grammar extraction, seed enrichment, saturation handler | S3: LLM emits grammar facts, never strategy code |

### Decision rule

An agent may change **proposals**, not truth:

1. Path ownership stays with `QdlPlanner`, `CoverageDrivenScheduler`, and
   `BoundPathRunner`.
2. Verdict ownership stays with deterministic oracles.
3. LLM-to-LLM communication is allowed only as typed, budgeted, logged
   consultation requests over bounded graph slices.
4. Invalid proposals are rejected by the QDL promotion validator.

### Integration status (2026-10-19)

- `EventGraph` and `build_campaign_dag` project QDL plus the event log into
  an immutable Campaign DAG read model.
- `ConsultationRequest` / `ConsultationDispatcher` implement the typed,
  budgeted, provenance-carrying handoff protocol.
- `build_slice` provides deterministic depth- and token-bounded graph slices.
- ~~`ProposalOnlyAgentLayer` implements the four proposal-only roles~~ —
  demolished by C16 (decision 2026-10-20; drift record in campaign-automaton
  Layer 5 and engine-runtime §16).
- `HttpJsonTarget` and `GenericPolicyProjector` implement generic transport
  and policy adapters; default production wiring remains gRPC plus generic
  policy projection backed by the Neo4j stand source.

Demolition check (2026-10-20): every mapping above lives in a component that
survives C16 — the typed consultation protocol, the Campaign DAG read model,
the reactive deficit loop, bounded slices, the promotion validator, and the
deterministic gates. The demolished package only re-derived consultations the
core drain already dispatches; no cited mechanism is lost. The Anthropic
"Building effective agents" mapping ("keep deterministic workflow; add LLM
only where adaptivity is needed") is itself the argument for the demolition:
the reactive loop is already that workflow.

### Conscious deviations → hybrid candidates (2026-10-20)

The four deliberate deviations are correct only in their naive form. Each
mechanism has a compatible hybrid that preserves the verdict-gate,
monotonicity, and reproducibility. None is a task yet: each enters the plan
only when its trigger fires from a real e2e observation (the agent-layer
lesson: build after evidence, not before).

| Mechanism | Incompatible form | Compatible hybrid | Trigger | Gate | Cost |
|---|---|---|---|---|---|
| ReAct multi-turn | agent acts on the target | evidence-navigation investigation loop: bounded (≤3–4 turns), read-only over EvidenceView / Campaign DAG, full trace logged and hashed, output stays one typed proposal | anomaly survives K reactive rounds | verdict-gate untouched; the trace is a replay artifact | M |
| Reflexion | lesson stored as a fact | reflection-as-context: per-action note generated after N failed consultations, capped, provenance-tagged, injected into subsequent consultations only — never promotable | same action fails N consultations | A21 (deficit closure semantics) fixed first | S |
| MoA | N× sampling on every call | quorum escalation: after repeated unscoreable consultations, sample N and promote only facts independently proposed by ≥2 samples; quorum is a confidence signal in `LLMSemanticPromotionPolicy` | deficit survives 2 consultations | never applies to classifications (A15: source-only); deterministic aggregation | S/M |
| Zep invalidation | fact retraction | bi-temporal supersession: `supersedes(fact2, fact1)` edges are facts; the current-state view is derived by a deterministic rule; append-only preserved | differential variance across state drift, long campaigns, replay-at-time-T requirement | RFC for the rule layer and version-aware path identity | L |

General principle: LLM mechanisms enter as context builders and proposal
diversifiers — never as truth owners; memory mechanisms enter as add-only
versioning — never as retraction.
