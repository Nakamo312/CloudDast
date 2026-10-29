# Cloud DAST: формальный субстрат и application-agnostic ядро

Дата: 2026-10-10  
Статус: QDL-миграция завершена; live pipeline работает без legacy threat-моделей  
Текущая проверка: `472 passed`

---

## Implementation status

### Migration completion

Live pipeline теперь QDL-only:

```text
FormalRepository
  -> canonical QdlGraph
  -> FormalThreatModeler (optional proposal)
  -> QdlPlanner
  -> QdlExecutionView
  -> BoundPathRunner
  -> FuzzSession
  -> ObservationProjector
  -> FormalRepository runtime facts
  -> deterministic oracle
  -> FindingEvaluator
```

Runtime progress использует QDL-native event:

```text
QdlStepEvaluated
```

Legacy `RewardTransitionRecorded` и `FailureReviewRecorded` пути удалены.

Удалены из production path:

```text
ThreatGraphWorkflow
ThreatPlan
ThreatGraph
Threat
AttackGoal
AttackPath
AttackStep
DfdModel
StrideAnnotation
TraceGoal
TraceGate
ThreatRepository
Neo4jThreatRepository
legacy element × STRIDE coverage
legacy service execution path
```

Остались только boundary DTO:

```text
MethodSpec
FieldSpec
Invariant
VerificationPlan
Check
Observation
GraphNode
GraphEdge
ServiceGraphSlice
```

`GraphNode`, `GraphEdge` и `ServiceGraphSlice` перенесены в ingestion boundary:

```text
cloud_dast/application/verification/formal/contract_models.py
```

и используются только adapter’ами, а не domain truth.

### Phase 0 — runtime usefulness

Реализовано и затем скорректировано:

- Протокольные статусы остаются adapter evidence и не становятся глобальными domain-категориями.
- Убраны `RuntimeFailureKind`, `Observation.failure_kind` и глобальный `unavailable_method_ids`.
- Наблюдение без наблюдаемого policy-результата остаётся `UNSCOREABLE`.
- `PERMISSION_DENIED` интерпретируется как denied только при grounded норме.
- `UNIMPLEMENTED`, `INVALID_ARGUMENT`, `UNAUTHENTICATED`, `UNAVAILABLE` могут быть естественным результатом фаззинга или инвентаризационной находкой, поэтому не должны глобально исключать метод или интерпретироваться как чистый infrastructure noise.

Целевое представление — формальные observation facts:

```text
observes(observation:o, response_status(action:a, "UNIMPLEMENTED"))
observes(observation:o, outcome(action:a, unknown))
observes(observation:o, duration(action:a, 12))
```

Интерпретация статуса зависит от цели:

```text
policy probe        -> unscoreable
inventory check     -> endpoint mismatch evidence
input-validation    -> INVALID_ARGUMENT может быть ожидаемым PASS
fuzzing             -> статус является сигналом, а не глобальным фильтром
```

### Phase 1 — QDL core

Реализовано:

- `cloud_dast/domain/formal.py`
- `tests/domain/test_formal.py`

Core поддерживает:

- `Atom`, `Variable`, `Struct`, `Context`, `Predicate`, `Fact`, `Rule`, `QdlGraph`;
- base predicates `is/part/has/may/requires/causes/prevents/observes`;
- typed constructors;
- canonical serialization и stable content hash;
- unknown predicate/arity/reference rejection;
- safe rules и запрет прямых/транзитивных рекурсий;
- strict contexts;
- запрет cross-context promotion в правилах: все literals одного правила обязаны находиться в одном context.

### Phase 2 — contract projection

Реализовано:

- `cloud_dast/application/verification/formal/contract_projection.py`
- `tests/application/verification/formal/test_contract_projection.py`

Adapter проецирует:

- `Service`, `ApiSurface`, `Method`, `Permission`, `ResourceType`, `Param`, `Endpoint`, `Alias`, `DocPage`, `Source`, `Role` в QDL-факты;
- `EXPOSES`, `HAS_METHOD`, `PARENT_OF`, `OWNS`, `DEFINED_IN`, `APPLIES_TO`, `SERVES`, `KNOWN_AS`, `DESCRIBES`, `REQUIRES`, `TARGETS`, `REFERS_TO`, `GRANTS`;
- input fields с path-qualified идентификаторами;
- field schema: type, required, repeated, oneof, enum values, minimum, maximum;
- source data-classification annotations from `DocPage`/`DESCRIBES` metadata into
  contract-context `has`, `reaches`, and sink `is` facts through a curated
  classification profile.

Гарантии:

- детерминизм;
- canonical hash;
- логические ID, не Neo4j `elementId`;
- явный отчёт `mapped / unmapped / ambiguous / conflict`;
- отсутствие молчаливого разрешения конфликтов.

### QDL Neo4j repository

Реализовано:

- `cloud_dast/infrastructure/neo4j/formal_repository.py`
- `tests/infrastructure/neo4j/test_formal_repository.py`

Схема:

```text
QdlSource
QdlProjection
QdlFact
QdlRule
QdlIssue
```

Связи:

```text
QdlProjection -DERIVED_FROM-> QdlSource
QdlFact       -DERIVED_FROM-> QdlSource
QdlRule       -DERIVED_FROM-> QdlSource
QdlProjection -PRODUCED->    QdlFact | QdlRule
QdlProjection -HAS_ISSUE->   QdlIssue
```

Репозиторий сохраняет:

- `canonical_json`;
- `content_hash`;
- provenance;
- adapter version;
- mapping report;
- append-only history.

### Formal ingestion

Реализовано:

- `cloud_dast/application/verification/formal/ingestion.py`
- `tests/application/verification/formal/test_ingestion.py`

Сервис выполняет:

```text
ContractGraphRepository
  -> ContractProjector
  -> QdlGraph
  -> FormalRepository
```

и сохраняет provenance + mapping report.

CLI:

```bash
python -m cloud_dast.composition.formal_cli \
  --service lockbox \
  --adapter-version contract-projection-v2
```

Live `ScenarioBinder` также подключён к `FormalRepository`: при наличии репозитория он автоматически сохраняет формальную проекцию контракт-графа перед threat modeling. Это делает QDL persistent-слоем live-run, а не только offline-миграцией.

### Runtime observation projection

Реализовано:

- `cloud_dast/application/verification/formal/observation_projection.py`
- `tests/application/verification/formal/test_observation_projection.py`

Проекция:

```text
Observation
  -> runtime QDL facts
```

Фиксируются:

```text
response_status(action, raw_status)
outcome(action, observed_outcome)
duration(action, milliseconds)
source(kind, observation_id)
```

Правило:

```text
статус = evidence
статус != security verdict
```

Проектор не вводит `RuntimeFailureKind`, не фильтрует методы и не интерпретирует протокольные статусы. Интерпретация выполняется только конкретным oracle на основе формальной нормы.

### LLM formal output and validator

Реализовано:

- `cloud_dast/application/verification/formal/model_output.py`
- `cloud_dast/application/verification/formal/validator.py`
- `tests/application/verification/formal/test_model_output.py`

Модель возвращает:

```text
context = proposal
facts   = formal QDL facts
rules   = formal QDL rules
```

Validator проверяет:

```text
strict proposal context
known predicate
base predicates + contract extension predicates
correct arity
typed terms
graph references
no free-text effects
no cross-context promotion
```

Ошибки возвращаются как structured issues, а не как generic exception, чтобы repair loop мог перегенерировать только невалидные артефакты.

### Formal threat modeler

Реализовано:

- `cloud_dast/application/verification/formal/threat_model.py`
- `tests/application/verification/formal/test_threat_model.py`

`FormalThreatModeler` — QDL-native LLM threat modeler:

```text
QdlGraph
  -> ModelClient
  -> FormalModelOutput
  -> FormalModelOutputValidator
  -> proposal QdlGraph
```

Поддержано:

```text
proposal context
structured validation issues
one-shot repair loop
preservation of valid artifacts
no accepted/runtime/report promotion
```

LLM остаётся главным генератором семантических гипотез:

```text
semantic roles
threats
norms
causal effects
state-machine hypotheses
```

Но итог всегда остаётся QDL proposal, а не свободным текстом и не второй моделью истины.

Live `ScenarioBinder` использует `FormalThreatModeler` опционально:

```text
contract:{service}
+ state-machine:{service}
  + accepted:{service}
  -> FormalThreatModeler
  -> proposal QdlGraph
  -> QdlPlanner
```

Proposal не сохраняется и не повышается до `accepted`. По умолчанию planner строит executable paths только из `contract` и `accepted`, поэтому LLM-гипотезы остаются provenance, пока не будут явно одобрены.

Для exploratory-прогона добавлена явная политика продвижения:

```text
CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS=1
CLOUD_DAST_MAX_PROMOTED_NORMS=32
CLOUD_DAST_MAX_FORMAL_ACTIONS=12
```

Файлы:

```text
cloud_dast/application/verification/formal/proposal_promotion.py
cloud_dast/application/verification/formal/graph_slice.py
tests/application/verification/formal/test_proposal_promotion.py
tests/application/verification/formal/test_graph_slice.py
```

Перед запросом к модели граф нарезается детерминированно по action. В срез
попадают только факты, связанные с выбранными actions, и все declarations,
необходимые для self-contained QDL. Это устраняет context saturation и резко
сужает возможность invent action ID.

Продвигаются только `prevents`-нормы, для которых одновременно выполняется:

```text
action объявлен в исходном QDL-графе
primitive != unknown
NormView.action_id привязан к известному action
все references self-contained в accepted context
```

Нормы `changed`/`has` без прямого action и нормы с неизвестным action не
продвигаются. Исходный proposal сохраняется в graph; продвижение не создаёт
finding и не даёт LLM статус oracle.

### Norm compiler and oracle router

Реализовано:

- `cloud_dast/application/verification/formal/norms.py`
- `cloud_dast/application/verification/formal/oracle_compiler.py`
- `tests/application/verification/formal/test_norms.py`
- `tests/application/verification/formal/test_oracle_compiler.py`

`NormCompiler` превращает:

```text
accepted:prevents(norm, effect)
```

в:

```text
primitive
evidence requirements
verdict policy
```

`OracleCompiler` выбирает детерминированный oracle primitive:

```text
changed       -> marker / differential
allowed       -> outcome
completed     -> sequence
denied        -> outcome
duration      -> latency_bound
external_call -> oob_event
has           -> response_field
identity      -> outcome
reached       -> marker
```

Если норму или evidence нельзя детерминированно оценить, результат остаётся `UNSCOREABLE`/`LEAD`, а не `FAIL`.

`Invariant` хранит `norm_fact` — canonical QDL `prevents`-факт. Legacy `TraceGoal` удалён; генераторы и оракулы работают через `NormView`.

Переходный `TraceGoal`-adapter, `StepExecutor` и generic `ModelPolicyOracle` удалены. Live execution использует `PrimitiveOracleRouter` и `NormView`:

```text
invalid QDL norm        -> UNSCOREABLE
no deterministic oracle -> UNSCOREABLE
valid QDL norm          -> deterministic primitive oracle
```

### Clingo Datalog/ASP engine

Реализовано:

- `cloud_dast/application/verification/formal/clingo_engine.py`
- `tests/application/verification/formal/test_clingo_engine.py`

Используется библиотечный `clingo`.

Поддержано:

```text
QdlGraph
-> ASP program
-> Clingo stable models
```

Контексты сохраняются как первый аргумент предиката:

```text
requires("contract", "action:get", "permission:read")
```

Это заменяет самописный Datalog-движок библиотечным solver’ом.

### QDL state machine

Реализовано:

- `cloud_dast/application/verification/formal/state_machine.py`
- `tests/application/verification/formal/test_state_machine.py`

Состояния, действия, нормы, initial states, transitions и forbidden states остаются обычными QDL-фактами:

```text
is(state, State)
is(action, Action)
is(norm, Norm)
initial(state)
transition(action, from_state, to_state)
forbidden(norm, state)
```

`StateMachineEngine` добавляет библиотечный Clingo-query layer:

```text
reachable states
bounded paths
forbidden-state violations
stratified spec/observed mismatches
```

Отдельной FSM-модели не появляется. QDL остаётся единственным источником истины, а state machine — query/projection layer.

Поддержано:

```text
max_depth
reachability
path actions
forbidden state
mismatch(observed, not specification)
```

`mismatch` использует stratified negation только на уровне Clingo-query, а не как persisted QDL rule.

### QDL coverage

Реализовано:

- `cloud_dast/application/verification/coverage_models.py` — QDL coverage
  algebra and read models;
- `cloud_dast/application/verification/runtime_ledger.py` — action runtime
  projection and typed binding deficits;
- `cloud_dast/application/reporting/norm_coverage.py` — per-norm coverage
  read model and projection over QDL execution evidence;
- `cloud_dast/workflow/execution/coverage_builder.py` — imperative builder
  that selects runtime evidence;
- `cloud_dast/workflow/execution/norm_coverage.py` удалён: расчёт norm
  coverage больше не владеется workflow;
- `cloud_dast/workflow/execution/coverage.py` — explicit public facade;
- `tests/workflow/execution/test_coverage.py`

`CoverageMatrixBuilder` принимает `QdlGraph` и строит coverage как проекцию над одним источником истины:

```text
action
× input/output/resource field
× semantic role
× primitive
```

и first-class state-machine coverage:

```text
action
× state
× transition
× forbidden state
```

Semantic role и detector capability остаются QDL-фактами (`field_role`, `supports_primitive`). Primitive также выводится из accepted `prevents`-нормы, связанной с `causes`-эффектом. Runtime evidence связывается с точным target-ом через `evidence_target(observation, action, field, role, primitive)` в `runtime` context; сам факт `observes` без этой привязки не закрывает поле.

Legacy `element × STRIDE` projection удалена. Coverage, progress и отчёты работают только с QDL target/state-machine projections.

Модель coverage, action-runtime и per-norm reporting projection не принадлежат
workflow: workflow только собирает evidence и передаёт его через структурные
контракты в application. Это не создаёт второго дерева данных —
`CoverageMatrix`, `ActionRuntimeLedger` и `NormCoverageRow` имеют по одному
владельцу в application; workflow facade сохраняет только необходимые
публичные runtime imports.

Reactive deficit algebra разделена тем же образом:

- `cloud_dast/application/verification/deficits.py` владеет immutable `Deficit`
  и его canonical identity (`key`, `consultation_id`, `work_item_key`);
- `cloud_dast/workflow/execution/deficits.py` владеет только queue state,
  dispatch budget, wave scheduling и runtime closure.

Одна и та же `Deficit`-сущность используется очередью через application
контракт; workflow больше не объявляет второй value object с тем же смыслом.

QDL norm projection разделена аналогично:

- `cloud_dast/application/verification/invariant_projection.py` владеет
  canonical `InvariantIndex`, deduplication norm keys и индексами
  `action/effect/exposes`;
- `cloud_dast/workflow/execution/binder.py` использует этот projection и
  оставляет у себя только binding методов/сценариев, setup и runtime metadata.

QDL-derived setup views разделены по той же границе:

- `cloud_dast/application/verification/setup_projection.py` владеет чистыми
  проекциями grounded QDL: provider selection для resource types, `refers_to`
  targets, typed object references, resource parameters и setup hints;
- `cloud_dast/workflow/execution/binder.py` не вычисляет эти представления
  заново: он только прикрепляет их к `QdlExecutionPath`, создаёт
  `SetupRequirement` и связывает их с discovery/runtime provisioning;
- `setup_projection.py` не импортирует workflow/infrastructure/composition, а
  тесты обращаются к проекциям через application boundary.

Граница намеренно не переносит `_setup_requirements` и `_apply_*`: это
imperative binding/runtime attachment, где учитываются discovery plans,
method contracts и execution metadata. Следующий шаг миграции должен отделять
их по семантике, а не превращать application в второй workflow runner.

В следующем bounded batch чистая часть этой границы также закреплена в
`cloud_dast/application/verification/setup_requirements.py`:

- `target_resources`, `target_resource_type` и `required_setup_states` читают
  только executable QDL;
- `setup_requirements` материализует typed `SetupRequirement`, выбирает
  QDL-derived setup walk и переносит hints/resource projections в контракт;
- `binder.py` оставляет только вызов этой application-алгебры и
  `_apply_setup_methods`, то есть attachment к исполняемым шагам.

Discovery plan остаётся данными application-port, а само provisioning и
исполнение walk не пересекают application boundary.

Оставшийся path metadata-пласт также закреплён в
`cloud_dast/application/verification/execution_metadata.py`:

- irreversibility/removal выводятся из явных `causes` и `transition`;
- probe-carrier, sink types, grammar facts, object/principal parameters и
  value couplings прикрепляются к `QdlExecutionPath` как application
  projections;
- content-versioned executable path identity строится там же, поэтому
  `binder.py` не владеет сериализацией executable inputs и hash identity.

Workflow по-прежнему вызывает эти проекции в нужном порядке, но не содержит
вторых реализаций их семантики. Это сохраняет один QDL source of truth и не
смешивает path construction с live execution.

Собственно связывание плана с executable path вынесено в
`cloud_dast/application/verification/path_binding.py`:

- attack-path и invariant-path binding работают только с `QdlPlan`,
  `QdlExecution*`, методами, сценариями и инвариантами;
- path identity, transition projection и forbidden-state statement также
  являются application functions;
- workflow оставляет у себя только orchestration binding batches и typed
  `BindingDeficit` reporting, которому нужен runtime-owned diagnostic sink.

Так разделены две разные ответственности: построение исполнимого QDL
контракта и объяснение, почему конкретный runtime leaf не удалось к нему
привязать.

Forbidden-state binding использует ту же границу: `path_binding.py` строит и
валидирует переходы из QDL, а workflow передаёт callback для записи
`BindingDeficit`. Callback не переносит workflow-зависимость в application и
не меняет поведение: при отсутствии/неоднозначности transition path остаётся
заблокированным, а diagnostic записывается прежним владельцем.

Сборка полного `QdlExecutionView` также принадлежит application:
`cloud_dast/application/verification/execution_view.py` индексирует методы и
сценарии, оркестрирует attack/forbidden/invariant/smoke paths, прикрепляет
QDL-derived metadata и setup requirements и удерживает retained invariants.
Workflow `ScenarioBinder` оставляет у себя загрузку графа, разрешение сценариев
и репозиториев и передаёт в application только resolved mappings и
`FixtureDiscoveryPlan` как данные. Благодаря этому workflow больше не содержит
вторую сборку execution view и не дублирует application-диагностику.

Identity attachment следует той же границе:

- `cloud_dast/application/verification/formal/identity_projection.py` выводит
  typed `PrincipalRef` для execution steps из `IdentityView` и stand principals;
- smoke paths сознательно не получают norm identity projection;
- `binder.py` оставляет только `identity_deficit` как workflow-owned diagnostic,
  потому что его результатом является `BindingDeficit`, связанный с runtime
  binding report.

Построение finding также закреплено в application:
`cloud_dast/application/verification/finding_projection.py` владеет
fingerprint, sink identity и созданием `Finding` из проверенного observation.
Workflow checks-модуль оставляет только публичные runtime-экспорты, а
`path_runner` обращается к application напрямую. Это отделяет интерпретацию
доказательства и identity finding от orchestration/event runtime.

Контракты physical execution и evaluation находятся рядом в
`cloud_dast/application/verification/execution_results.py`: `ExecutionResult`,
`ObservationProvenance` и `EvaluationResult` имеют один источник истины.
`cloud_dast/application/verification/finding_evaluator.py` владеет проверкой
deterministic/grounded verdict, deduplication finding witnesses и replay
projection событий через application ports. Workflow facade сохраняет только
публичные импорты для старых runtime-клиентов; production orchestration
обращается к application напрямую.

Оставшиеся setup lookup-операции также не дублируются workflow: principal
`refers_to` targets живут в `setup_projection.py`, а QDL-derived service/resource
mapping — в `setup_requirements.py`. В workflow остаётся только выбор и
создание scenario, потому что это уже repository/runtime policy.

### River bandit engine

Реализовано:

- `cloud_dast/application/verification/generators/selector.py`

Используется библиотечный `river`:

```text
river.bandit.ThompsonSampling
river.proba.Beta
```

Самописный generator bandit удалён. Отдельный custom POMDP/search-стек (`application/search`, `workflow/search`) удалён полностью: QDL planner и state machine заменяют его глобальный planning.

Если позже понадобится полноценный RL, а не contextual bandit, предпочтительный путь:

```text
Gymnasium environment
+ Stable-Baselines3 / Ray RLlib
```

но не ещё один самописный RL-движок.

### Clingo engine

Реализовано:

- `cloud_dast/application/verification/formal/clingo_engine.py`
- `tests/application/verification/formal/test_clingo_engine.py`

Используется библиотечный `clingo` Python API для materialization QDL правил:

```text
QdlGraph
  -> ASP program
  -> stable models
```

Контексты сохраняются как первый аргумент предиката, поэтому context separation остаётся явной на уровне solver’а.

#### Recursive closures

QDL core разрешает рекурсию только для whitelist-предикатов:

```text
part_plus
requires_plus
chain_plus
may_plus
affected_plus
reachable
```

`ClingoEngine` умеет материализовать эти предикаты опционально:

```python
ClingoEngine().solve(graph, closures={"part_plus", "chain_plus"})
```

Также доступен bounded path search:

```python
ClingoEngine().find_path(
    graph,
    "part_plus",
    "resource:grandchild",
    "resource:parent",
)
```

Произвольная рекурсия по-прежнему запрещена. Это сохраняет завершаемость и предсказуемость семантики.

### State machine in the main pipeline

Реализовано:

```text
cloud_dast/application/verification/formal/state_machine.py
tests/application/verification/formal/test_state_machine.py
cloud_dast/application/verification/formal/state_machine_ingestion.py
tests/application/verification/formal/test_state_machine_ingestion.py
cloud_dast/composition/state_machine_cli.py
```

Состояния, действия и нормы — это обычные QDL факты:

```text
is(state, State)
is(action, Action)
is(norm, Norm)
initial(state)
transition(action, from_state, to_state)
forbidden(norm, state)
```

`StateMachineEngine` предоставляет:

```text
reachable_states
bounded paths
shortest path
forbidden-state violations
stratified spec/observed mismatches
```

Stratified negation используется только в Clingo-query:

```text
observed transition
and not specification transition
```

и не сохраняется как QDL rule.

State machine не является отдельным срезом или второй моделью. Те же факты читаются основной coverage-проекцией и planner’ом:

```text
action coverage        <- is(action, Action) + transition
state coverage         <- is(state, State) + initial + reachability
transition coverage    <- specification transition + runtime transition
forbidden coverage     <- forbidden(norm, state) + bounded witness
```

Таким образом одна QDL-выборка одновременно даёт target-level coverage, state-machine coverage и paths для планирования.

Добавлена декларативная ingestion-цепочка:

```text
YAML specification
  -> StateMachineSpecification
  -> state_machine_graph
  -> FormalRepository
```

CLI:

```text
cloud_dast/composition/state_machine_cli.py
```

### QDL planner

Реализовано:

- `cloud_dast/workflow/execution/qdl_planner.py`
- `tests/workflow/execution/test_qdl_planner.py`

`QdlPlanner` работает только с `QdlGraph` и возвращает `QdlPlan` — view/DTO, а не источник истины:

```text
graph_hash
attack_paths
state_paths
forbidden_paths
invariants
closures
bound_paths
```

Он не использует:

```text
ThreatGraph
TraceGoal
DfdModel
ServiceGraphSlice
```

Основной live pipeline использует `QdlPlanner` для state-machine и forbidden-state путей и встраивает их в единый план кампании.

### Business-logic workflow integration

Основной pipeline теперь работает над одним canonical QDL graph:

```text
FormalRepository
  -> canonical QDL graph
  -> CoverageMatrixBuilder
     -> action × field × semantic role × primitive
     -> action/state/transition/forbidden-state coverage
  -> CampaignPlanner
  -> runtime execution
  -> ObservationProjector
  -> append-only runtime QDL facts
```

`StateMachineEngine` остаётся query layer над этим же graph: он возвращает reachability, bounded paths и forbidden-state witnesses, но не создаёт отдельную FSM-модель. Обычные threat paths сохраняются, а business-logic paths добавляются как отдельные планы и инварианты.

### Runtime observation projection

Реализовано:

- `cloud_dast/application/verification/formal/observation_projection.py`
- `tests/application/verification/formal/test_observation_projection.py`

Проекция сохраняет:

```text
response_status(action, raw_summary)
outcome(action, generic_outcome)
source(observation, observation_id)
duration(action, milliseconds)
```

и не интерпретирует статус как security verdict. Все факты находятся в `runtime` context.

Live `BoundPathRunner` теперь принимает `FormalRepository` и `ObservationProjector`. Каждое runtime observation сохраняется в QDL repository как отдельный append-only projection с provenance:

```text
source_id = observation:{observation_id}
adapter_version = observation-projection-v1
```

Таким образом runtime evidence тоже становится частью canonical QDL graph, а не только событием в event log.

Live execution публикует `QdlStepEvaluated` — детерминированное событие прогресса QDL-шага. Старые `RewardTransitionRecorded` и `FailureReviewRecorded` удалены.

Текущая проверка:

```text
472 passed
ruff check: passed
ruff format --check: passed
```

---

## 0. TL;DR

Cloud DAST перестаёт быть набором параллельных моделей `Threat`, `TraceGoal`, `Fact`, `Intent`, `AttackPath`, `CoverageMatrix` и становится движком над одной формальной основой.

Основное решение:

```text
один typed contextual fact substrate
+ application-specific adapters
+ LLM как constrained compiler
+ deterministic planner / fuzzer / oracle
+ STRIDE, OWASP, coverage и отчёт как views
```

Мы не вводим пять отдельных IR:

```text
World IR
Action IR
Threat IR
Probe IR
Evidence IR
```

Вместо этого используется один минимальный алфавит и typed constructors. Всё остальное — проекции над ним.

---

## 1. Цель продукта

Cloud DAST должен быть application-agnostic DAST-движком, который:

1. принимает формализованные факты о приложении: контракты, методы, поля, ресурсы, принципалов, права, состояния, потоки данных;
2. генерирует проверки не только для auth/authz, а для любых классов нарушений безопасности;
3. использует LLM для генерации гипотез и семантической компиляции норм;
4. исполняет проверки через детерминированные генераторы, фаззеры, symbolic execution и runtime-адаптеры;
5. выносит вердикты только на основе evidence;
6. честно различает `finding`, `lead`, `unscoreable` и инфраструктурную ошибку.

Задача — не чёрный ящик-пентест и не верификатор SAST.

Задача — автономное открытие нарушений поверх богатого графа фактов, с формальными нормами и детерминированным заземлением.

---

## 2. Не-цели

### 2.1. Не делаем универсальный LLM-судью

LLM не является финальным оракулом по умолчанию.

LLM может:

- предлагать нормы;
- предлагать гипотезы;
- уточнять semantic role полей;
- выбирать стратегию фаззинга;
- объяснять результат.

LLM не может:

- без evidence подтверждать finding;
- подменять отсутствие формальной нормы своей интерпретацией;
- быть одновременно и источником нормы, и финальным оракулом.

### 2.2. Не размазываем семантику облака по ядру

Ядро не знает про:

- Yandex Cloud;
- IAM;
- folder/cloud/org;
- service account;
- gRPC.

Это знают только адаптеры:

```text
IAM role              -> capability
service account       -> principal
folder/cloud/org      -> resource containment
gRPC method           -> action
protobuf field        -> input/output field
```

### 2.3. Не делаем big-bang rewrite

Текущая система имеет 501 проходящий тест. Миграция должна быть инкрементальной:

```text
QDL появляется рядом
-> адаптеры строят QDL-проекцию
-> эквивалентность проверяется тестами
-> старая логика заменяется по частям
```

---

## 3. Текущая базовая линия и её ограничения

Зафиксированные проблемы текущей архитектуры:

1. **Несколько источников истины.**  
   `Threat`, `TraceGoal`, `Fact`, `Intent`, `AttackPath`, `Clue`, `CoverageMatrix` описывают пересекающиеся понятия независимо.

2. **Текстовая семантика эффектов.**  
   Attack chain строится через нормализацию строк `preconditions/effects` и `_CANONICAL_PREDICATES`.

3. **Грубая STRIDE-разметка.**  
   Один `element × STRIDE` недостаточен, когда у действия много полей и несколько возможных target.

4. **Раздутые `TraceGoal`.**  
   Один объект содержит специальные поля для outcome, field exposure, OOB, latency, marker, sequence.

5. **Слабое заземление стохастических вердиктов.**  
   Недетерминированный вердикт без формальной нормы не должен считаться прогрессом или finding.

6. **Много `UNIMPLEMENTED`/`INVALID_ARGUMENT` в живом прогоне.**  
   Перед основной миграцией нужно улучшить фильтрацию доступных методов и генерацию валидных protobuf-запросов.

---

## 4. Формальный субстрат: QDL

Рабочее название — **QDL** (`Quad / Contextual Datalog`).

### 4.1. Базовые конструкции

```text
Term  = Atom | Variable | Struct(name, args)
Fact  = Context, Predicate, args...
Rule  = body -> head
Graph = set(Fact)
```

Пример:

```prolog
contract:is(action:get_secret, Action)
contract:requires(action:get_secret, permission:secret.get)
contract:causes(action:get_secret, has(principal:attacker, secret))

norm:prevents(norm:secret_visibility, has(principal:attacker, secret))

runtime:observes(observation:o1, has(principal:attacker, secret))
```

### 4.2. Минимальный алфавит предикатов

| Предикат | Значение | Пример |
|---|---|---|
| `is` | типизация | `is(action:a, Action)` |
| `part` | вложенность/иерархия | `part(secret:s1, folder:f1)` |
| `has` | обладание/видимость значения | `has(principal:p, field(resource:r, "payload"))` |
| `may` | разрешённая возможность | `may(principal:p, action:a, resource:r)` |
| `requires` | precondition | `requires(action:a, capability:c)` |
| `causes` | effect/переход | `causes(action:a, changed(resource:r, field:"role"))` |
| `prevents` | запрет/норма | `prevents(norm:n, effect:e)` |
| `observes` | evidence | `observes(observation:o, effect:e)` |

Восемь предикатов — ядро.

Для положительных обязательств вида «аудит-событие обязано существовать» возможен отдельный предикат:

```prolog
obligates(norm:n, effect:e)
```

Но его добавляем только тогда, когда появится реальная потребность. Пока положительные нормы можно выражать через `prevents(norm, missing(effect))` с явным closed-world assumption и таймаутом. Если это станет грязным — вводим `obligates`.

### 4.3. Typed constructors

Минимальный алфавит не означает, что все аргументы — строки.

Нужны типизированные конструкторы:

```text
input_field(action, name)
output_field(action, name)
changed(resource, field)
has(principal, field(resource, name))
external_call(action, marker)
duration(action, milliseconds)
reached(action, sink)
completed(flow)
identity(attacker, victim)
missing(effect)
```

Пример правильного выражения:

```prolog
prevents(
  norm:no_mass_assignment,
  changed(resource:user, field:"role")
)
```

Пример неправильного:

```prolog
prevents(norm:n, "mass assignment")
```

Строки нельзя использовать как скрытую таксономию. Любой эффект обязан быть typed term.

### 4.4. Contexts и provenance

Факт всегда принадлежит контексту:

| Context | Что содержит | Статус |
|---|---|---|
| `contract` | immutable факты из контрактов/спеков/графа | доверенный источник |
| `proposal` | гипотезы LLM | не доверенный |
| `accepted` | одобренные нормы/гипотезы | проверенный |
| `runtime` | наблюдения и evidence | доказательный |
| `report` | производные findings/leads | view |

Контексты решают главную проблему смешения истины:

```text
LLM может предложить факт
observation может подтвердить факт
но proposal никогда не становится verified fact без evidence
```

### 4.5. Канонизация

Обязательно:

```text
stable IDs
sorted facts
typed literals
canonical serialization
content hash
predicate arity validation
reference validation
context validation
```

Канонический хеш используется для:

- дедупликации;
- сравнения графов;
- replay;
- миграций;
- тестов эквивалентности;
- стабильных ID угроз и норм.

---

## 5. STRIDE: правильная гранулярность

### 5.1. Разделение понятий

STRIDE — не источник истины и не точная локация бага. Это lens для полноты.

Разделяем три уровня:

```text
DFD element
  -> STRIDE category applicability
    -> concrete Threat instance with target
```

Где target может быть:

```text
action
input_field(action, name)
output_field(action, name)
resource_type
resource_id
data_flow
state_transition
downstream_call
audit_event
```

### 5.2. Пример

Для `UpdateUser` может быть несколько угроз:

```text
t1: T — input.role                -> mass assignment
t2: T — input.email               -> integrity violation
t3: I — output.private_key        -> information disclosure
t4: E — method without permission -> privilege escalation
t5: S — input.user_id as identity -> spoofing
```

Формально:

```prolog
proposal:is(threat:t1, Threat)
proposal:category(threat:t1, T)
proposal:target(threat:t1, input_field(action:update_user, "role"))
proposal:causes(threat:t1, changed(resource:user, field:"role"))
norm:prevents(norm:no_mass_assignment, changed(resource:user, field:"role"))
```

### 5.3. Mapping STRIDE на формальные эффекты

| STRIDE | Формальная суть | Типовой effect/norm |
|---|---|---|
| S | принятие ложной личности | `identity(attacker, victim)` |
| T | недопустимое изменение данных | `changed(resource, field)` |
| R | невозможность доказать действие | `missing(audit_event)` |
| I | несанкционированный доступ к данным | `has(principal, field(resource, name))` |
| D | недоступность/исчерпание ресурса | `unavailable(resource)`, `duration(action, ms)` |
| E | получение запретной возможности | `may(principal, privileged_action, resource)` |

STRIDE остаётся полезным для coverage и промптов, но вердикт и планирование работают через `causes/requires/prevents/observes`.

---

## 6. Методы и поля: формализуем, но не отдельным IR

Методы и поля обязаны быть формализованы. Без этого невозможно:

- построить валидный запрос;
- сделать BOLA/IDOR;
- сделать mass assignment;
- найти excessive exposure;
- сгенерировать цепочки create/get/update/delete;
- запустить symbolic execution;
- фаззить конкретные поля;
- сделать read-back после изменения состояния.

Но они не образуют отдельный `Action IR`. Это generic facts внутри QDL.

### 6.1. Action

```prolog
contract:is(action:update_user, Action)
contract:name(action:update_user, "UpdateUser")
contract:part(action:update_user, service:example)
contract:requires(action:update_user, permission:user.update)
contract:causes(action:update_user, changed(resource:user, field:"payload"))
```

### 6.2. Input/output fields

```prolog
contract:input(action:update_user, field:role)
contract:name(field:role, "role")
contract:type(field:role, string)
contract:required(field:role, false)
contract:repeated(field:role, false)

contract:output(action:get_user, field:private_key)
contract:type(field:private_key, bytes)
contract:sensitivity(field:private_key, secret)
```

### 6.3. Field roles

Поля нужно классифицировать по semantic role:

| Role | Пример угрозы |
|---|---|
| `credential` / `token` / `signature` | Spoofing |
| `identity_ref` | Spoofing или BOLA |
| `object_ref` | BOLA/IDOR |
| `privileged_attribute` | mass assignment, Elevation |
| `immutable_field` | Tampering |
| `sink_input` | SQLi, SSTI, command injection, XXE |
| `external_url` | SSRF |
| `response_secret` | Information Disclosure |
| `cardinality` / `limit` / `page_size` | DoS/resource exhaustion |
| `state_transition` | business flow violation |

LLM не должен перечислять все поля и придумывать к ним угрозы. Правильный pipeline:

```text
contract adapter
  -> детерминированно извлекает action/fields/types/permissions/resource refs
  -> строит базовые QDL-факты

LLM
  -> уточняет semantic roles
  -> добавляет локальные requires/causes/prevents

planner/fuzzer
  -> использует полную field schema без LLM
```

---

## 7. Роль LLM

LLM — constrained compiler, а не свободный рассказчик.

### 7.1. Формат выхода

LLM возвращает только формальные факты:

```json
{
  "context": "proposal:uuid",
  "facts": [
    ["is", "threat:t1", "Threat"],
    ["category", "threat:t1", "T"],
    ["target", "threat:t1", "input_field(action:update_user, 'role')"],
    ["causes", "threat:t1", "changed(resource:user, field:'role')"],
    ["prevents", "norm:no_mass_assignment", "changed(resource:user, field:'role')"]
  ]
}
```

### 7.2. Validator

Обязательные проверки:

```text
predicate известен
arity корректен
term типизирован
graph reference существует
context допустим
нет синонимов
нет неизвестных идентификаторов
нет свободного текста в effect
```

Невалидный вывод:

```text
reject
или repair loop
```

Но repair не должен бесконечно генерировать новые сущности.

### 7.3. Что LLM не делает

LLM не:

- создаёт verified fact;
- меняет `contract` context;
- подтверждает finding без observation;
- выступает единственным финальным судьёй;
- придумывает ID, которых нет в графе.

---

## 8. Нормы и оракулы

### 8.1. Базовое правило нарушения

```prolog
violation(Norm, Observation, Effect) :-
    prevents(Norm, Effect),
    observes(Observation, Effect),
    compatible(Norm, Observation).
```

Человекочитаемо:

```text
норма запрещает эффект
observation увидел этот же эффект
=> нарушение
```

### 8.2. Правило одного или двух

Архитектурный инвариант:

```text
норма или оракул обязаны быть детерминированными
```

Расшифровка:

```text
если норма вероятностная, oracle должен быть детерминированным
если oracle вероятностный, норма должна быть формальной и заземлённой
если оба вероятностные -> UNSCOREABLE / LEAD, не finding
```

### 8.3. Детерминированные primitive-оракулы

| Primitive | Effect | Evidence | Вердикт |
|---|---|---|---|
| P1 outcome | `allowed(action)` / `denied(action)` | status/outcome | FAIL/PASS |
| P2 field | `has(principal, field(resource, name))` | response field | FAIL/PASS |
| P3 OOB | `external_call(action, marker)` | collaborator callback | FAIL |
| P4 latency | `duration(action, ms)` | timing | FAIL/PASS/lead |
| P5 differential | `changed(...)` / diff | paired execution + read-back | FAIL/PASS |
| P6 sequence | `completed(flow)` / `missing(step)` | trace | FAIL/PASS |

### 8.4. Статусы

| Статус | Значение |
|---|---|
| `FAIL` | детерминированное нарушение нормы |
| `PASS` | в данном probe нарушение не обнаружено |
| `UNSCOREABLE` | недостаточно evidence или норма неоднозначна |
| `ERROR` | инфраструктурная ошибка |
| `LEAD` | семантическая гипотеза, требующая ревью или дополнительного evidence |

Важно:

```text
PASS != система безопасна
PASS = нарушение не наблюдается в этом probe
```

### 8.5. Grounded semantic oracle

Допустимый стохастический oracle — только как:

1. компилятор нормы;
2. grounded semantic matcher;
3. triage-помощник.

Пример:

```text
Документация:
  “Только владелец ресурса может изменять payload”

LLM обязан вернуть:
  prevents(norm:owner_only, changed(resource, field:'payload'))
  requires(action:update, ownership(resource))

Validator:
  проверяет существование action/resource/field

Runtime oracle:
  детерминированно сравнивает факты
```

Если LLM говорит «похоже на нарушение», но не может указать формальную норму и evidence — это `LEAD`, не finding.

### 8.6. Каналы evidence

Если эффект нельзя наблюдать напрямую, добавляем канал:

```text
read-back вызов
OOB collaborator
mock downstream
state diff
canary resource
audit log hook
trace id
snapshot/restore
```

Если канала нет — `UNSCOREABLE`.

---

## 9. Vulnerability classes как детекционные шаблоны

Каталог классов не является источником истины. Это набор шаблонов над:

```text
Effect constructor
+ Norm source
+ Generator strategy
+ Oracle primitive
+ Evidence requirements
```

Примеры:

| Класс | Effect/norm | Oracle |
|---|---|---|
| BOLA | `allowed(action)` при отсутствии права на объект | P1 |
| Function-level authz | `allowed(action)` при отсутствии права на метод | P1 |
| Broken authentication | `allowed(action)` для anonymous/чужого token | P1 |
| Excessive exposure | `has(principal, field(...))` | P2 |
| Mass assignment | `changed(resource, forbidden_field)` | P1 + P5 |
| SSRF | `external_call(action, marker)` | P3 |
| Resource exhaustion | `duration(action, bound)` / `unavailable(resource)` | P4 |
| Injection/SSTI | `reached(action, sink)` / marker result | P3/P5 |
| Business flow | `completed(flow)` при `missing(step)` | P6 |

Плановые классы остаются в каталоге с обязательным полем `requires_primitive`.

---

## 10. Coverage

Coverage перестаёт быть независимой моделью и становится projection over QDL. Источник истины — `QdlGraph`: contract facts, accepted norms, state-machine facts и runtime observations.

### 10.1. Минимальная granularность

Legacy `element × STRIDE` projection удалена.

Целевая target-level granularность:

```text
action
× input/output/resource field
× semantic role
× primitive
```

Пример фактов:

```text
field_role(input_field(action:update_user, "role"), privileged_attribute)
supports_primitive(
  action:update_user,
  input_field(action:update_user, "role"),
  privileged_attribute,
  marker
)
```

Runtime-привязка одного наблюдения к конкретному target-у:

```text
evidence_target(
  observation:o,
  action:update_user,
  input_field(action:update_user, "role"),
  privileged_attribute,
  marker
)
```

Primitive выводится также из accepted `prevents`-нормы, если её эффект связан с `causes(action, changed(resource, field))`.

State machine является first-class частью того же denominator:

```text
action
state
transition(action, from_state, to_state)
forbidden(norm, state)
```

### 10.2. Статусы

| Статус | Значение |
|---|---|
| `covered` | проверка выполнена и scoreable |
| `unresolved` | не хватает фактов/нормы/канала |
| `blind` | нет primitive/evidence-канала |
| `not_applicable` | target не применим |

Правило:

```text
один успешный probe не закрывает всю группу полей
```

Если у метода 20 полей и проверено только `role`, нельзя помечать весь метод как покрытый по Tampering.

Отдельный успешный probe также не закрывает всю state-machine группу: action, state, transition и forbidden state учитываются независимо.

Интерпретация для target-ячейки:

| Условие | Статус |
|---|---|
| есть primitive и exact `evidence_target` с runtime `observes` | `covered` |
| есть primitive, но нет exact runtime-привязки | `unresolved` |
| нет primitive | `blind` |

Интерпретация для state-machine:

| Слой | `covered` | `unresolved` | `blind` |
|---|---|---|---|
| action | есть runtime transition | есть specification, нет runtime | нет transition |
| state | transition затрагивает state | reachable, нет runtime | не reachable |
| transition | specification + runtime | spec-only или runtime-only | — |
| forbidden state | — | witness или отсутствие bounded witness | нет initial state |

---

## 11. Attack planning

### 11.1. Основные правила

```prolog
chain(ActionA, ActionB) :-
    causes(ActionA, Effect),
    requires(ActionB, Effect).

alternative(ActionA, ActionB) :-
    causes(ActionA, Effect),
    causes(ActionB, Effect),
    ActionA != ActionB.
```

### 11.2. Branch switching

Если prerequisite не подтверждён, это не блокирует навсегда.

Планировщик создаёт sibling branch:

```text
primary branch:
  producer -> consumer

assumption branch:
  consumer
  assumption = prerequisite unverified
```

Правила:

- assumption branch имеет штраф;
- assumption явно записан;
- успешный результат помечается как conditional;
- при подтверждении producer условия пересчитываются.

### 11.3. QDL step progress

Отдельная reward machine удалена. Прогресс представляется событием и view:

```text
QdlStepEvaluated
QdlPlan
QdlExecutionView
```

Bandit используется локально только для выбора generator strategy. Глобальный planning остаётся детерминированным QDL/Clingo reasoning.

---

## 12. Adaptive fuzzing

Целевая структура:

```text
FuzzSession
  CheckContext
  SeedBuilder
  LLMStrategyProposer
  StrategyValidator
  CandidateBuilder
  Bandit
  LocalRewardMachine
  StateGuard
  OracleRouter
```

Поток:

```text
QDL goal
  -> seed
  -> LLM strategy proposal
  -> deterministic candidate builder
  -> bandit selection
  -> runtime execution
  -> evidence materializer
  -> oracle
  -> reward / next candidate
```

Bandit arms:

```text
seed
mutation operator
payload template
identity
resource
field targeting strategy
```

LLM предлагает стратегию, но:

- стратегия валидируется;
- кандидаты строятся детерминированно;
- verdict даёт oracle;
- reward считает детерминированная машина.

---

## 13. Symbolic execution

QDL — естественный интерфейс к solver.

### 13.1. Маппинг

| QDL | Symbolic execution |
|---|---|
| `FieldSpec` | переменная, домен, границы |
| `requires(action, effect)` | path condition |
| `causes(action, effect)` | postcondition |
| `prevents(norm, effect)` | assertion/violation goal |
| `may(principal, action, resource)` | policy constraint |
| `part(resource, container)` | ownership/scope constraint |
| `observes(obs, effect)` | oracle |

### 13.2. Задача solver

```text
найти последовательность действий и значения полей
такую, что:
  все requires выполнены
  хотя бы одно causes порождает forbidden effect
  runtime observation фиксирует этот effect
```

Символический результат — кандидат, а не finding.

Finding появляется только после live observation.

---

## 14. Non-idempotent и stateful действия

Каждое action классифицируется:

```text
read_only
create
update
delete
state_transition
external_side_effect
```

Обязательные механизмы:

```text
state ledger
canary resources
unique resource names
snapshot/restore
cleanup
state epochs
read-back validation
```

Нельзя слепо фаззить деструктивные или stateful методы.

Для мутаций нужен guard:

```text
мутация разрешена?
какой ресурс?
как восстановить состояние?
какие downstream эффекты допустимы?
какой epoch?
```

---

## 15. Связь с исследовательскими идеями

| Идея | Что берём в ядро |
|---|---|
| Persistent fact-intent DAG | immutable facts + intents в QDL contexts |
| Planner / Executor / Reviewer | роли как views, не отдельные модели |
| Branch switching | assumption branches |
| Deterministic mediator | deterministic planner/oracle вокруг LLM |
| Schema-validated artefacts | LLM emits QDL facts only |
| Budget caps / authorization | runtime guardrails |
| Clue graph | `observes` facts |
| Contextual bandit | выбор seed/mutation/strategy |
| Trace goals | `prevents` + typed effect |
| QDL step evaluation | прогресс к forbidden fact |
| Automata from trajectories | mined state machines как QDL view |
| LLM semantic mutator | candidate generation, не verdict |

---

## 16. План реализации

### Phase 0 — prerequisite: живой прогон

Цель: уменьшить бесполезные вызовы.

Задачи:

1. фильтровать недоступные методы до execution;
2. различать `UNIMPLEMENTED`, `INVALID_ARGUMENT`, `PERMISSION_DENIED`;
3. строить валидные protobuf seeds;
4. не считать infrastructure failure threat progress.

Acceptance:

```text
доля UNIMPLEMENTED/INVALID_ARGUMENT в основном прогоне существенно снижена
нет false confirmed из-за ungrounded verdict
```

### Phase 1 — QDL core

Файлы:

```text
cloud_dast/domain/formal.py
tests/domain/test_formal.py
```

Сущности:

```text
Term
Atom
Variable
Struct
Context
Fact
Rule
Predicate
QdlGraph
```

Функции:

```text
canonical serialization
content hash
fact equality
reference validation
predicate arity validation
acyclic rule validation
```

Acceptance:

```text
roundtrip serialization
stable hash
unknown predicate rejected
wrong arity rejected
unknown reference rejected
```

### Phase 2 — contract adapter

Файлы:

```text
cloud_dast/application/verification/formal/contract_projection.py
tests/application/verification/formal/test_contract_projection.py
```

Проекция:

```text
MethodSpec        -> Action facts
FieldSpec         -> input/output field facts
Permission        -> requires facts
ResourceRef       -> resource facts
GraphEdge         -> part/targets facts
```

Старый pipeline не меняется.

Acceptance:

```text
по фиксированному graph slice QDL-проекция детерминированна
canonical hash стабилен
все action/field/permission/reference присутствуют
```

### Phase 3 — LLM formal output

Файлы:

```text
cloud_dast/application/verification/formal/model_output.py
cloud_dast/application/verification/formal/validator.py
tests/application/verification/formal/test_model_output.py
```

Задачи:

1. новый response schema — только facts;
2. validator;
3. repair loop;
4. token accounting;
5. локальный QDL subgraph вместо полного `ContextPack`.

Acceptance:

```text
unknown term rejected
unknown action rejected
unknown field rejected
free-text effect rejected
proposal context enforced
token usage измеряется
```

### Phase 4 — attack chain через QDL

Файлы:

```text
cloud_dast/application/verification/formal/planner.py
tests/application/verification/formal/test_planner.py
```

Заменяем:

```text
text normalization
_CANONICAL_PREDICATES
threats_by_effect
```

На:

```prolog
chain(A, B) :- causes(A, F), requires(B, F).
alternative(A, B) :- causes(A, F), causes(B, F), A != B.
```

Acceptance:

```text
существующие attack path тесты проходят
появляются более длинные цепочки
branch switch работает
canonical ID конфликты исчезают
```

### Phase 5 — target-level STRIDE и coverage

Статус: QDL coverage реализована; legacy `element × STRIDE` projection удалена.

Файлы:

```text
cloud_dast/application/verification/coverage_models.py
cloud_dast/application/verification/runtime_ledger.py
cloud_dast/workflow/execution/coverage_builder.py
cloud_dast/workflow/execution/coverage.py  # public facade
cloud_dast/presentation/console/progress.py
tests/workflow/execution/test_coverage.py
```

Задачи:

1. построить denominator `action × field × semantic role × primitive`;
2. включить state machine в coverage: action, state, transition, forbidden state;
3. не закрывать всю группу полей одним probe;
4. показывать field-level и primitive-level gaps.

Acceptance:

```text
coverage честно отражает field gaps
одна проверка role не закрывает все Tampering-поля метода
```

### Phase 6 — norm compiler и oracle router

Файлы:

```text
cloud_dast/application/verification/formal/norms.py
cloud_dast/application/verification/formal/oracle_compiler.py
cloud_dast/application/verification/oracles/*
```

Задачи:

```text
prevents(norm, effect)
-> primitive selection
-> evidence requirements
-> verdict policy
```

Acceptance:

```text
нарушение всегда = prevents + observes
ungrounded FAIL не влияет на reward
missing evidence -> UNSCOREABLE
```

### Phase 7 — FuzzSession

Статус: реализовано и встроено в основной live pipeline.

Файлы:

```text
cloud_dast/application/verification/fuzzing/session.py
tests/application/verification/fuzzing/test_session.py
cloud_dast/workflow/execution/path_runner.py
cloud_dast/composition/run_provider.py
tests/workflow/execution/test_path_runner_fuzzing.py
```

Задачи:

```text
seed
strategy
candidate
bandit
local reward
state guard
oracle
```

Acceptance:

```text
check перестаёт быть one-shot
фаззинг останавливается по budget/entropy/reward
stateful методы защищены guard
```

Интеграция в `BoundPathRunner`:

```text
QdlExecutionStep
  -> FuzzSessionFactory
  -> FuzzSession.next()
  -> candidate Check
  -> ServiceWorkflow.execute_check()
  -> deterministic oracle verdict
  -> FuzzSession.record(check, verdict)
  -> River GeneratorBandit + local reward
```

Правила остановки:

```text
one-shot mode: один QDL step -> один candidate
fuzz mode:     один QDL step -> несколько candidates
```

Фазз-сессия не останавливается на `PASS`; она продолжает перебор до:

```text
budget | reward | entropy | exhausted
```

Если сессия завершилась без `FAIL`, эффект текущего QDL-шага не считается
подтверждённым. Такой AND-path блокируется: следующие шаги этой цепочки не
исполняются, но sibling paths продолжают работу.

Правило grounding сохраняется и в локальном reward: ungrounded `FAIL` остаётся
lead/`UNSCOREABLE` для фаззера, не увеличивает failures/reward и не подтверждает
эффект для следующих шагов AND-path.
Такой результат также не публикует `FactVerified` и отображается в прогрессе как
`UNSCOREABLE`, а не confirmed step.

Глобальный campaign budget (`LiveRequest.max_checks`) остаётся внешним предохранителем
и применяется поверх локального бюджета сессии.

Runtime wiring:

```text
CLOUD_DAST_FUZZ_MAX_CHECKS=3
```

по умолчанию. Нулевое или нечисловое значение конфигурации отвергается.

Stateful output forwarding сохраняет `check_id`; `FuzzSession.record` принимает
такую копию, но запрещает подмену уже заданного значения, identity или метода.

Каждая стратегия (`template`, `symbolic`, `fuzzing`, `llm`, `grammar`)
оборачивается в
`GoalPayloadGenerator`. Поэтому адаптивный фаззинг не теряет QDL-подсказки:
marker для `reached/changed` и OOB URL для `external_call` добавляются к каждому
кандидату до transport execution.

Единая точка расширения закреплена в
`cloud_dast/application/verification/generators/catalog.py`:
`GeneratorCatalog` принимает зарегистрированные реализации `TestCaseGenerator`
и отдаёт два представления одного контракта — `one_shot()` и
`session_generators()`. Composition больше не дублирует wrapping стратегий и не
может подключить adaptive generator без тех же seed hints, runtime markers,
OOB URL и feedback semantics. Исключение `llm` для bounded fuzz-session
остаётся явной policy-операцией каталога, а не второй веткой runner-а.

Для model-backed стратегий модель задаёт только форму носителя и обязана
использовать runtime-placeholder (`{probe_marker}` или `{oob_url}`). Движок
детерминированно подставляет уникальный token, проверяет типы, enum, bounds,
oneof и couplings, и отбрасывает невалидные кандидаты до live-вызова.

Каждый кандидат получает уникальный `probe_marker`:

```text
{norm.marker}-{probe_nonce}
```

`run_check` переносит его в `Observation`, а marker/OOB-оракулы ждут именно этот
маркер. Callback или отражение от другого кандидата не может быть ошибочно
приписано текущему шагу.

`FuzzSession`:

```text
next()      -> novel guardrail-allowed candidate
record()    -> verdict + River bandit update + local reward
stopped     -> budget | reward | entropy | exhausted
```

Chain-seed fuzzing не является вторым режимом состояния `FuzzSession`:
`cloud_dast/application/verification/fuzzing/chain_session.py` отдельно владеет
`ChainFuzzSession`, `ChainCandidate` и мутациями setup seed для multi-step
цепочек. `session.py` содержит только локальное состояние одного QDL step.
Обе сессии используют общую `GeneratorPolicy` и guardrail, но не смешивают
state, budget и reward semantics.

### Phase 8 — symbolic integration

Статус: реализовано.

Файлы:

```text
cloud_dast/application/verification/formal/symbolic.py
tests/application/verification/formal/test_symbolic.py
```

Acceptance:

```text
requires/causes/prevents компилируются в constraints
решения проверяются live runtime
symbolic candidate не является finding
```

`Z3SymbolicGenerator`:

```text
base seed
  -> QDL NormView
  -> Z3 constraints
  -> concrete numeric / bool / enum values
  -> Check
```

Marker и OOB payload остаются за `GoalPayloadGenerator`, чтобы symbolic solver не конкурировал с детерминированной инъекцией.

---

## 17. Definition of Done архитектурной миграции

Миграция считается успешной, когда:

1. один QDL-граф является canonical truth;
2. старые `TraceGoal`/`AttackPath`/legacy coverage удалены; остались только QDL views/DTO;
3. LLM не может записать факт вне `proposal`;
4. unknown symbols отклоняются;
5. attack chain строится по `causes/requires`, а не по текстовой нормализации;
6. STRIDE coverage target-level;
7. finding всегда имеет:

```text
norm
effect
observation
evidence refs
context compatibility
```

8. недетерминированные вердикты не создают false confirmed;
9. фаззинг и symbolic execution используют одну целевую функцию;
10. ядро не содержит application-specific semantics.

---

## 18. Главные риски и защита

| Риск | Защита |
|---|---|
| QDL станет ещё одним параллельным IR | canonical truth + generated views + equivalence tests |
| Строки вернутся как скрытая семантика | typed terms + validator |
| LLM начнёт выдумывать ID | whitelist graph references |
| Proposal загрязнит verified state | contexts + promotion policy |
| Formal schema задушит creativity | proposal context и controlled new term declarations |
| Coverage станет иллюзорной | target-level denominator |
| Оракулы превратятся в LLM-мнения | правило одного или двух |
| Фаззинг сломает стенд | state guard + canary + cleanup |
| Symbolic result будет считаться bug | live observation обязателен |
| Код временно разрастётся | инкрементальные фазы + удаление старых моделей после эквивалентности |

---

## 19. Анти-паттерны

Запрещено:

```text
делать World/Action/Threat/Probe/Evidence IR отдельно
хранить semantics в свободных строках
давать LLM доступ к mutation contract facts
считать LLM FAIL прогрессом без grounding
помечать целую группу полей covered по одному probe
использовать STRIDE как execution semantic
превращать symbolic candidate в finding
фаззить деструктивные методы без state guard
оставлять Yandex Cloud термины в ядре
```

---

## 20. Финальные инварианты

1. **Одна истина.**  
   Все executable semantics живут в QDL.

2. **Типизация.**  
   Эффекты и нормы — typed terms, не prose.

3. **Контексты.**  
   `contract`, `proposal`, `accepted`, `runtime`, `report` не смешиваются.

4. **Гипотеза ≠ факт.**  
   LLM proposal не становится verified fact.

5. **Finding = norm + evidence.**  
   Без `prevents` и `observes` finding невозможен.

6. **Недетерминированность честна.**  
   Если нельзя оценить — `UNSCOREABLE`, если можно только предположить — `LEAD`.

7. **Application-agnostic core.**  
   Доменные термины приходят только из адаптеров.

8. **Инкрементальность.**  
   Каждый phase сохраняет работоспособность системы и проверяется тестами.
