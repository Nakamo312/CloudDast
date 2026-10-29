# Audit remediation ledger — 2026-10-16

## Scope and source

This ledger records the disposition of the consolidated five-auditor report
supplied for the Cloud DAST remediation wave. The source report contains 113
findings:

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 23 |
| Medium | 51 |
| Low | 37 |
| **Total** | **113** |

This wave intentionally does not attempt to fix all 113 findings at once. It
prioritizes the two critical findings, all high findings that had a safe local
remediation path, and the configuration/integration findings owned by this
worker. Remaining items are explicitly deferred or marked as design work
rather than silently left unowned.

Status definitions:

- **Fixed now** — code and focused regression coverage are present in this
  working tree.
- **Intentionally deferred** — accepted as follow-up work because it is low
  priority, test-only/dead-code cleanup, or requires a separate batch.
- **Needs design** — a direct patch would either hard-code another
  application-specific assumption or change a formal/domain contract; an
  explicit design decision is required first.

## Status summary

| Status | Count |
|---|---:|
| Fixed now | 20 |
| Intentionally deferred | 79 |
| Needs design | 14 |
| **Total** | **113** |

The source report enumerated every critical/high finding, but only the top ten
medium findings and a key low-finding summary. The 41 unlisted medium findings
are therefore recorded as an intentionally deferred itemized-backlog group, not
given fabricated per-finding statuses.

## Critical findings

| ID | Finding | Status | Owner | Files |
|---|---|---|---|---|
| C1 | Proposal-context facts could become executable semantics because Clingo/Algebra erased context before ThreatIntentCompiler, SemanticNormCompiler, and PayloadHints consumed the graph. | Fixed now | Carver | `cloud_dast/application/verification/formal/threat_compiler.py`, `semantic_norm_compiler.py`, `payload_hints.py` |
| C2 | Axis grounding promoted every LLM fact without the action-bound, deterministic-primitive, self-containment, and max-norm policy used by explicit proposal promotion. | Needs design | Russell | `cloud_dast/application/verification/formal/grounding.py`, `axis_grounding.py`, `proposal_promotion.py` |

The response-semantics axis now narrows that one axis to `is`, `exposes`, and
role-bearing `has` facts, but `AutoGroundingService._promote()` remains a
separate general promotion path. Until all axes share one explicit promotion
policy, C2 remains open as design work rather than being marked fixed by a
single-axis restriction.

## High findings

| ID | Finding | Status | Owner | Files |
|---|---|---|---|---|
| H1 | Closed semantic-role alphabet is duplicated across several formal components. | Needs design | Carver / Russell | `semantic_norm_compiler.py`, `axis_grounding.py`, `threat_model.py`, `threat_compiler.py` |
| H2 | `action:` prefix handling is inconsistent across compilers and oracles. | Needs design | Carver / Boyle | `threat_compiler.py`, `oracles/action_alignment.py`, formal compilers |
| H3 | Domain model is tied to Yandex Cloud IAM concepts (folder, cloud, organization, service account). | Needs design | Unassigned — domain design | `cloud_dast/domain/models.py` |
| H4 | `status_code` is constrained to the HTTP 100–599 range even though the production transport is gRPC. | Needs design | Dalton | `cloud_dast/domain/models.py`, `cloud_dast/infrastructure/runtime/grpc.py` |
| H5 | Fields named `state`/`status` are treated as control states by naming convention. | Needs design | Dalton / Russell | `observation_projection.py`, `live_contracts.py`, `deficits.py` |
| H6 | `resource_key_field()` guesses `{type}_id` names instead of using grounded `object_ref` facts. | Needs design | Euclid | `cloud_dast/workflow/execution/live_contracts.py`, `binder.py` |
| H7 | Generic Neo4j invocation repository contains a Yandex-specific namespace alias. | Needs design | Unassigned — infrastructure design | `cloud_dast/infrastructure/neo4j/invocations.py` |
| H8 | `SeedMutator` produced only an empty string for scalar string fields. | Fixed now | Euclid | `cloud_dast/application/verification/generators/fuzzing.py` |
| H9 | Runtime QDL coverage was disconnected from live observations and evidence targets. | Fixed now | Dalton / Russell | `observation_projection.py`, `deficits.py`, `live_workflow.py`, `grpc.py`, `protobuf.py` |
| H10 | External OOB collaborator generated URLs but did not collect/return events. | Fixed now | Dalton | `cloud_dast/infrastructure/runtime/oob.py` |
| H11 | Clingo computes `reaches_plus`, but norm compilers consume only direct `reaches` facts. | Needs design | Carver | `clingo_engine.py`, `semantic_norm_compiler.py`, `threat_compiler.py` |
| H12 | Production `TraceStep` evidence fields remained empty even when runtime evidence existed. | Fixed now | Dalton | `cloud_dast/application/verification/formal/observation_projection.py`, `cloud_dast/workflow/execution/checks/runner.py`, `grpc.py` |
| H13 | `cloud_dast.infrastructure.repositories` imported a nonexistent `events` module and crashed on import. | Fixed now | Banach | `cloud_dast/infrastructure/repositories/__init__.py` |
| H14 | Action alignment was checked only by `GroundedOutcomeOracle`; other primitive oracles could score a mismatched action. | Fixed now | Boyle | `cloud_dast/application/verification/oracles/action_alignment.py` and primitive oracles |
| H15 | Formal validator allowlist lags behind `PREDICATE_SCHEMAS` (missing `executes`, `owner`, `paired`). | Needs design | Carver | `cloud_dast/application/verification/formal/validator.py`, `contract_projection.py` |
| H16 | ThreatIntentCompiler and SemanticNormCompiler generated duplicate synthetic norms for one effect. | Fixed now | Carver | `threat_compiler.py`, `semantic_norm_compiler.py` |
| H17 | Setup/create calls were not counted against the campaign `max_checks` budget. | Fixed now | Integrator | `cloud_dast/workflow/execution/path_runner.py`, `step_setup.py` |
| H18 | `path_id` versioned only probe fields; couplings and setup inputs reused the same scheduler arm. | Fixed now | Euclid | `cloud_dast/workflow/execution/binder.py` |
| H19 | Neo4j formal save executes several independent transactions instead of one atomic save. | Needs design | Unassigned — infrastructure design | `cloud_dast/infrastructure/neo4j/formal_repository.py` |
| H20 | Contract projection ignores `MethodSpec.fields` and relies only on Neo4j `Param`/`HAS_PARAM`. | Needs design | Unassigned — infrastructure design | `cloud_dast/infrastructure/neo4j/contract_graph.py`, `contract_projection.py` |
| H21 | Proposal promotion rejected semantic effects (`has`, `changed`, `transition`) even when deterministic oracles exist. | Fixed now | Carver | `proposal_promotion.py`, `norms.py`, `oracle_compiler.py` |
| H22 | Profiles could override stale model/allowlist values but could not clear them. | Fixed now | Banach | `cloud_dast/composition/profile.py` |
| H23 | `CLOUD_DAST_SKIP_LLM_GROUNDING=on` was accepted by CLI but rejected by RunProvider; invalid values were silently false. | Fixed now | Banach | `profile.py`, `live_cli.py`, `run_provider.py` |

## Medium findings

The source report listed the ten most significant medium findings:

| ID | Finding | Status | Owner | Files |
|---|---|---|---|---|
| M1 | Magic marker/OOB field-name hints could insert a URL into an arbitrary ID field. | Fixed now | Euclid | `cloud_dast/application/verification/generators/goal_payload.py` |
| M2 | `CLOUD_DAST_SKIP_LLM_GROUNDING=on` behaved differently in CLI and RunProvider. | Fixed now | Banach | `profile.py`, `live_cli.py`, `run_provider.py` |
| M3 | Startup grounding did not load accepted-batch/diff history. | Fixed now | Russell | `cloud_dast/application/verification/formal/grounding.py` |
| M4 | Role/effect alphabets diverge between axis grounding, threat modeler, and STRIDE. | Needs design | Russell / Carver | `axis_grounding.py`, `threat_model.py`, `semantic_norm_compiler.py` |
| M5 | Model uncertainties were fed to alternatives but not reactive grounding. | Fixed now | Russell | `grounding.py`, `axis_grounding.py` |
| M6 | `_ground_custom()` and `_ground_slice()` duplicate roughly 80 lines of LLM request logic. | Needs design | Russell | `axis_grounding.py` |
| M7 | Neo4j `CONTAINS*0..` traversal was unbounded. | Fixed now | Integrator | `cloud_dast/infrastructure/neo4j/live/live_repository.py`, `scenario_repository.py` |
| M8 | Token provider used one global token for all identities. | Fixed now | Integrator | `cloud_dast/infrastructure/runtime/tokens.py` |
| M9 | Protobuf codec silently dropped unknown fields and accepted invalid safe paths. | Fixed now | Dalton | `cloud_dast/infrastructure/runtime/protobuf.py` |
| M10 | `classify_path_event()` is a test-only parallel implementation with an off-by-one risk. | Intentionally deferred | Russell | `cloud_dast/workflow/execution/deficits.py` |

The remaining 41 medium findings were not individually enumerated in the source
report. They remain intentionally deferred until the auditors supply their
itemized IDs; assigning them invented statuses would make this ledger less
accurate, not more complete.

## Low findings

All 37 low findings are intentionally deferred. The source report groups them
as dead code and duplicate abstractions, including:

- `ensure_grounded()`
- `SequenceExecutor`
- `IntentProposed` event that is never emitted
- `Context.REPORT`
- legacy `VerificationPlan` hints
- `target_gaps` / `target_blind_spots`
- `GeneratorSelector.update()`
- test-only `execute_plan()`
- `AllowAllGuardrail` in production paths
- `pytest` in production requirements

These should be removed in a separate cleanup batch after the critical/high
integration changes are stabilized; deleting them now would mix contract
changes with behavior changes and enlarge review risk.

## Configuration fixes implemented in this wave

### Unified boolean flag parsing

`parse_environment_flag()` is now the single parser for the launch flags owned
by composition. It accepts:

```text
true:  1, true, yes, on
false: 0, false, no, off, empty
```
An invalid value such as `maybe` fails immediately with a `RuntimeError`
naming the environment variable. `live_cli` and `RunProvider` now call the
same parser for `CLOUD_DAST_SKIP_LLM_GROUNDING`.

The CLI parses this flag before resolving the remaining campaign settings, so
invalid configuration fails before an unrelated missing-profile error can mask
it.

### Explicit profile reset semantics

Only fields explicitly present in the TOML profile override process
environment values. This preserves environment-backed defaults for omitted
fields.

Explicit reset values are:

```toml
event_log = ""

[model]
id = ""

[grounding]
cache_dir = ""

[neo4j]
password_file_env = ""

[runtime]
allowed = []
setup_identity = ""
descriptor_set_env = ""
```

An empty list clears `CLOUD_DAST_ALLOWED_SERVICES`. An empty reference clears
the referenced setting; a named reference whose source variable is absent also
clears the stale derived value instead of retaining it.

### Repository import repair

The dead `InMemoryEventRepository` re-export was removed from
`cloud_dast.infrastructure.repositories`. The namespace now imports cleanly
and exports no compatibility aliases; concrete repositories remain beside
their infrastructure adapters.

## Validation

Owned configuration/integration checks:

```text
pytest -q \
  tests/infrastructure/composition/test_live_cli.py \
  tests/infrastructure/composition/test_profile.py \
  tests/infrastructure/composition/test_run_provider.py
```
Result at the time of this ledger: **38 passed**.

The full composition suite also passed:

```text
pytest -q tests/infrastructure/composition
```

Result: **49 passed**.

Post-integration application/infrastructure/workflow regression run:

```text
pytest -q tests/application tests/infrastructure tests/workflow
```

Result: **848 passed**.

```text
ruff check \
  cloud_dast/composition/live_cli.py \
  cloud_dast/composition/run_provider.py \
  cloud_dast/composition/profile.py \
  cloud_dast/infrastructure/repositories/__init__.py \
  tests/infrastructure/composition/test_live_cli.py \
  tests/infrastructure/composition/test_run_provider.py \
  tests/infrastructure/composition/test_profile.py
```

Result: **All checks passed**.

Repository-wide `ruff check .` and `ruff format --check .` now pass. The
integration follow-up formatted the two previously reported files:

- `cloud_dast/workflow/execution/norm_coverage.py`
- `tests/workflow/execution/test_path_runner_fuzzing.py`

## Remaining validation risks

A full repository pytest run was also executed for integration visibility. It
produced:

```text
989 passed
1 failed
4 errors
```

- The four `tests/benchmarks/test_server.py` errors are sandbox socket-binding
  failures (`Operation not permitted` while binding `127.0.0.1:0`), not an
  application assertion failure.
- The STF-chain failure in that snapshot was resolved by the integration
  follow-up: the scheduler legitimately executed the cheaper one-step synthetic
  outcome path before the multi-step marker path, while the test selected the
  first ship check. The test now selects the marker-bearing ship check without
  changing application payload policy.

Follow-up validation:

```text
pytest -q tests/benchmarks/test_stf_chain.py
1 passed in 3.05s

pytest -q tests/application/verification/generators
76 passed in 0.15s

pytest -q tests/application/verification/formal
278 passed in 1.81s

pytest -q tests/workflow/execution
156 passed in 1.40s

ruff check .
All checks passed.

ruff format --check .
302 files already formatted.
```
