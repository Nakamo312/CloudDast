# Campaign Automaton: Fact-Intent Architecture

How four research papers (Intentest, MazeRunner, PrediQL, DRLRM-PT) combine
with three already-implemented papers (Sefz, PDFuzzer, SymTEE) and the QDL
algebra into one closed-loop campaign design.

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAMPAIGN AUTOMATON                            │
│                                                                 │
│  INIT (every run):                                              │
│    1. AutoGrounding — contract + stand + parallel LLM           │
│    2. Algebra (Clingo) — derive threats from facts + hypothesis │
│    3. Threat → Intent compiler — threats become graph nodes     │
│    4. Load persisted facts from previous runs                   │
│    5. Update intent DAG (dependencies, blocks)                  │
│                                                                 │
│  LOOP (until budget exhausted OR coverage closed):              │
│                                                                 │
│    STRATEGIST — select next intent:                             │
│      eligible = prerequisites met AND not blocked               │
│      score = coverage gain × bandit prior × reward machine state│
│      backtrack: find alternative prerequisite path              │
│      branch switch: switch to sibling goal                      │
│                                                                 │
│    EXECUTOR — run selected intent:                              │
│      reward machine: INIT → PREPARE → EXECUTE → OBSERVE         │
│      contextual bandit selects generator (template/symbolic/    │
│      fuzzing) based on action history                           │
│      Z3 prefilter eliminates impossible candidates              │
│      fixture provisioning through ProvisionerPort               │
│      live call through transport                                │
│      oracle П1-П6 gives deterministic verdict                   │
│                                                                 │
│    REVIEWER — diagnose outcome:                                 │
│      PASS → close coverage cell, unlock dependent intents       │
│      FAIL → finding, close cell                                 │
│      UNSCOREABLE → diagnose and produce recovery intent:        │
│        NOT_FOUND → fixture missing → provision intent           │
│        PERMISSION_DENIED → gate holds → mark, deprioritize      │
│        INVALID_ARGUMENT → seed invalid → fix seed intent        │
│        TRANSPORT_ERROR → retry/defer                            │
│                                                                 │
│    UPDATE:                                                      │
│      verified fact → persist to Neo4j (immutable)               │
│      coverage cell → closed/open                                │
│      bandit reward → update prior                               │
│      intent state → reward machine transition                   │
│                                                                 │
│  STOP: budget exhausted                                         │
│        OR coverage closed (no eligible intents)                 │
│        OR all intents BLOCKED                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Layer 1: Fact-Intent DAG (from Intentest)

### The problem it solves

Currently, derived threats exist only as Clingo atoms — they vanish after
each solve.  Campaign state (what was verified, what failed) lives in
JSONL event logs but not in the reasoning graph.  Every run starts from
scratch.

### The design

Separate immutable **facts** from mutable **intents**:

```
FACTS (verified, immutable, accumulate across runs):
  fact:fixture:secret-abc123:created
  fact:action:Get:executed:denied
  fact:permission:lockbox.secrets.get:not-granted-for-attacker

INTENTS (pending, mutable, resolve to facts or get blocked):
  intent:verify:elevation:Get
  intent:verify:bola:Get:foreign-secret
  intent:chain:steal-token→use-token→read-secret

EDGES (typed, in the campaign graph):
  intent ──DEPENDS_ON──► fact     (prerequisite: intent needs this fact)
  intent ──PRODUCES──►   (expected: intent will produce this fact)
  intent ──BLOCKED_BY──► fact     (observed: this failure blocks intent)
```

### How it maps to QDL

Facts are QDL facts in the `runtime` context; proposed intents live in the
`proposal` context.  The intent graph uses a small set of QDL predicates:

```prolog
% Intent with prerequisites, effects, and assumptions
is(IntentId, Intent).
is(FactKey, Fact).
intent_prerequisite(IntentId, FactKey).
intent_effect(IntentId, FactKey).
intent_assumption(IntentId, AssumptionKey).
```

`depends_on`, `produces`, `blocked_by`, and the other campaign relationships
are projection edges in the immutable Campaign DAG, not a second QDL
predicate layer.  `EventGraph` replays runtime facts and proposal intents;
`build_campaign_dag` projects them together with the event log.

### Compilation from algebra threats

Each Clingo-derived threat becomes an intent:

```
elevation("principal:attacker", "action:...Get")
  → intent("intent:elev:Get", "action:...Get", elevation, none)
    + depends_on: none (single-step)
    + produces: denied("action:...Get") — if gate holds, this is the
      expected observation

owasp_api1_bola("action:...Get", "principal:attacker")
  → intent("intent:bola:Get", "action:...Get", elevation, api1_bola)
    + depends_on: fact:fixture:secret-foreign:exists
    + produces: denied("action:...Get")
```

Multi-step chains from effect dependencies:

```
causes(action:auth, identity(attacker, victim))
requires(action:Get, identity(attacker, victim))

  → intent("intent:chain:auth→Get", ...)
    step 1: intent:spoof:auth  (produces identity fact)
    step 2: intent:elev:Get    (depends on identity fact)
    gate: AND (both steps must succeed)
```

### Why this matters

- **Persistence**: campaign state survives restarts.  Run 1 verifies
  10 intents, Run 2 picks up where it left off.
- **Dependency-aware execution**: intent B that depends on fact F only
  becomes eligible after some intent A produces F.
- **Blocked intents are explicit**: NOT_FOUND doesn't silently kill a
  path — it produces a diagnostic fact that blocks the intent and
  suggests a recovery action.

### Current implementation boundary

The implemented Campaign DAG is a pure read model: the same QDL graph and
event sequence always produce the same canonical DAG, contexts remain
`runtime`/`proposal`/`report`, and no projection edge can execute a path or
issue a verdict.  It is used as external graph memory by the proposal-only
agent layer.  A persistent cross-run Fact-Intent control-plane with
recovery intents remains a design gap.

## Layer 2: Three Roles + Backtracking (from MazeRunner)

### The problem it solves

Currently, the path runner executes paths sequentially.  A failed step
blocks the path; there is no diagnosis, no recovery, no alternative
route.

### The design

Three explicitly separated roles, each a pure function over the
fact-intent DAG:

```
STRATEGIST (selects next intent):
  Input:  fact-intent DAG + coverage matrix + bandit state
  Output: one selected intent OR backtrack signal

  Selection criteria:
    1. Prerequisites satisfied (facts exist)
    2. Not blocked (no blocking facts)
    3. Closes most coverage gaps
    4. Best bandit prior (goal proximity)
    5. Lowest cost (fewest steps to reach)

  Backtracking: if intent I is blocked because prerequisite P is
    missing, look for another intent J that also produces P.
    If J exists and is eligible, select J instead.

  Branch switching: if no intent can produce prerequisite P,
    look for sibling goals (same letter, different action) that
    don't need P.

EXECUTOR (runs selected intent):
  Input:  one intent + its reward machine state
  Output: observation + verdict

  Already implemented: generator selection (bandit), Z3 prefilter,
  fixture provisioning, live call, oracle.

REVIEWER (diagnoses outcome):
  Input:  observation + verdict + intent context
  Output: diagnostic fact + optional recovery intent

  Diagnosis table:
    NOT_FOUND        → fixture missing → new intent: provision
    PERMISSION_DENIED → gate holds → close cell, deprioritize
    INVALID_ARGUMENT  → seed invalid → new intent: fix seed
    TRANSPORT_ERROR   → endpoint issue → retry or defer
    UNSCOREABLE       → oracle can't judge → review manually
```

### How it maps to existing code

The path_runner already has the executor role.  What's missing:
- The **strategist** replaces the sequential `for path in paths` loop
  with a selection function.
- The **reviewer** replaces the current "unscoreable → break" with a
  diagnosis step that produces recovery intents.

## Layer 3: Contextual Bandit + Execution Memory (from PrediQL)

### The problem it solves

Our Sefz goal-proximity bandit selects strategy by (strategy × goal),
but doesn't know that this specific action already failed 3 times with
template and 2 times with symbolic.  It re-selects blindly.

### The design

```
EXECUTION MEMORY (per-action, from observation history):
  action:Get:
    template → NOT_FOUND ×3
    symbolic → INVALID_ARGUMENT ×2
    fuzzing  → NOT_FOUND ×1
  action:Create:
    template → PERMISSION_DENIED ×5

CONTEXTUAL BANDIT:
  context = (action_id, past_outcomes, scenario_type,
             prerequisite_status, coverage_state)
  arms = (template, symbolic, fuzzing)
  reward = goal_proximity × coverage_gain

  With context, the bandit sees: "Get failed with template 3 times"
  → shifts probability to symbolic → if symbolic also fails
  → shifts to fuzzing with specific boundary values.
```

### Evolution from current bandit

Current: `GeneratorBandit` keyed by `(goal_key, strategy)` — no action
history.

Evolved: `ContextualGeneratorBandit` keyed by `(goal_key, strategy,
context_hash)` where context_hash captures the action's failure pattern.
This is a drop-in replacement — the bandit interface stays the same,
only the arm keying changes.

## Layer 4: Reward Machine per Invariant (from DRLRM-PT)

### The problem it solves

Invariants currently have two outcomes: pass/fail.  There is no notion
of "preparation done, waiting for execution" or "executed but couldn't
observe".  The campaign doesn't know WHERE each intent is in its
lifecycle.

### The design

Each intent carries a reward machine — a finite state automaton over
the verification lifecycle:

```
States:
  INIT        — intent created, nothing done
  READY       — prerequisites met, fixture provisioned
  EXECUTED    — probe sent, response received
  OBSERVED    — oracle evaluated the response
  PASS        — gate holds, norm intact (terminal)
  FAIL        — gate failed, finding raised (terminal)
  REVIEW      — unscoreable, needs diagnosis (non-terminal)
  BLOCKED     — blocked by observed failure (terminal)

Transitions (with rewards):
  INIT → READY       (reward: +1, prerequisites met)
  READY → EXECUTED   (reward: 0, expected — just execution)
  EXECUTED → OBSERVED (reward: 0, expected)
  OBSERVED → PASS    (reward: +3, norm intact)
  OBSERVED → FAIL    (reward: +5, finding!)
  OBSERVED → REVIEW  (reward: -1, needs work)
  REVIEW → READY     (reward: +1, recovery successful)
  REVIEW → BLOCKED   (reward: -2, dead end)
```

### How it guides the strategist

The strategist reads reward machine states:
- Intent in READY with high coverage value → high priority
- Intent stuck in REVIEW for N cycles → suggest backtrack
- Intent in BLOCKED → skip, look for alternatives
- Intent in INIT with unsatisfied prerequisites → provision first

### Formal grounding

The reward machine IS the algebra's letter formula operationalized:

```
elevation(S, A) :- executes(S, A), targets(A, R), ¬may(S, A, R)

Becomes the reward machine:
  INIT: ¬may not yet checked
  READY: ¬may verified (from IAM), fixture exists
  EXECUTED: probe sent to A
  OBSERVED: response received
  PASS: response = DENIED (gate holds, threat not realized)
  FAIL: response = OK (threat realized, finding)
  REVIEW: response = ERROR (can't judge)
```

The reward machine is not new algebra — it's the SAME letter formula,
viewed as a state machine over the verification lifecycle.

## Implementation plan (by independent value)

| # | Component | Source paper | Effect | Est. lines |
|---|---|---|---|---|
| 1 | Threat → Intent compiler | Intentest | 142 threats → persistent intents in Neo4j | ~150 |
| 2 | Coverage-driven scheduler | MazeRunner + PrediQL | Sequential → gap-driven selection | ~200 |
| 3 | Failure reviewer | MazeRunner | Unscoreable → diagnosis → recovery | ~150 |
| 4 | Contextual bandit | PrediQL | Action history informs strategy selection | ~80 |
| 5 | Reward machine states | DRLRM-PT | Lifecycle tracking per intent | ~100 |

Total: ~680 lines, 0 new modules, 0 changes to Σ (the algebra).

## Relationship to existing implementations

| Already built | Paper | How it fits |
|---|---|---|
| Goal-proximity reward (FuzzSession) | Sefz | Feeds into reward machine transition rewards |
| Coupled constraints + sequence Z3 | PDFuzzer | Used by executor for multi-step validation |
| Z3 prefilter + Probe IR + fixtures | SymTEE | Used by executor before live calls |
| Parallel grounding (4 axes × batches) | — | Feeds facts into the fact-intent DAG |
| Algebra threat derivation (Clingo) | — | Produces the threats that become intents |
| Bounded fixture pool | — | Provisioner port serves READY transition |

---

## Layer 5: Typed consultation protocol

### Decision

The campaign automaton remains deterministic. An LLM is admitted only through
a typed, budgeted consultation request, not as a control-plane owner. There is
no separate agent package.

This is not a second formal engine and not a vulnerability dictionary.

### Allowed consultation capabilities

- read a bounded graph slice;
- propose missing QDL facts, norms, and edges;
- propose setup, fixture, state, or payload-grammar hypotheses;
- turn an `UNSCOREABLE` outcome into a typed clue or deficit according to the
  core deficit policy.

### Forbidden consultation powers

A consultation must not:

- select the next executable path;
- decide that a prerequisite is satisfied;
- call the target directly;
- promote a proposal into `accepted`, `runtime`, or `report`;
- issue a verdict;
- keep hidden memory outside the event-sourced QDL graph.

### Reactive consultation protocol

```text
deficit / coverage gap
  -> consultation_request(kind, bounded_slice, budget)
  -> deterministic dispatcher
  -> specialist LLM
  -> schema-valid QDL proposal
  -> promotion validator
  -> planner / scheduler
```

Every handoff records the model version, prompt hash, graph-slice hash,
deficit ID, token cost, latency, and outcome.

### Implementation after C16

| Component | Responsibility |
|---|---|
| `campaign.py` / `campaign_dag.py` | Preserve the immutable Campaign DAG read model |
| `live_workflow.py` | Drain runtime deficits and build consultation requests |
| `formal/consultation.py` | Dispatch typed, budgeted, provenance-carrying requests |
| `formal/grounding.py` | Validate and deterministically promote proposals |
| `benchmarks/nsfy_bench/cold_score.py` | Contain the benchmark-only B23 deficit ordering arm |

The engine never imports the benchmark package. There are no
`CLOUD_DAST_AGENT_*` environment variables.

### Drift record and demolition decision (2026-10-20)

The built layer diverged from this design: it implemented the repair half
(deficit routing that duplicates the core `_DEFICIT_CONSULTATION_KINDS`
mapping in `deficits.py`) and skipped the novel half — coverage-gap reading,
payload-grammar specialists, and fixture-hint specialists. The step
specialist maps deficit kinds to the same consultation kinds the core already
dispatches; the path proposer asks the same `alternatives` question with path
counters; the reflection node conflicts with the core policy on
`missing_baseline` (core: never consult; agent: availability). Prefixed
deficit ids bypass dedup against the core `consultation_id`.

Decision: demolish the agent package. The vision survives elsewhere:
coverage priorities → B23; payload grammars → S3/S4; the typed consultation
protocol stays in the core and serves the reactive loop. `EventGraph` /
`CampaignDag` remain (non-agent consumers). The critic's
`_DEFICIT_PRIORITY` table moves to the B23 benchmark as one cold_score arm.
