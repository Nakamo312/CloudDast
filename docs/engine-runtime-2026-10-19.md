# Как реально работает движок NSFy — агрегированная карта рантайма

Дата: 2026-10-19. Объединяет два независимых разбора рантайма (аудиторский и
второй, внешний) со сверкой по коду; спорные утверждения проверены. Это
канонический reference «как устроен движок», дополняющий
`formal-substrate-architecture-2026-10-10.md` (проектирование) и
`security-audit-2026-10-18.md` (дефекты).

Обновление S22R (2026-10-25): документация ниже рассматривается как проекция
фактического runtime. Машинные блоки проекции сверяются тестом
`tests/architecture/test_runtime_docs_projection.py`.

## 0. Одной фразой

Движок — не линейный pipeline, а **fix-point event loop**: формальный
планировщик (Clingo) строит execution views над QDL-графом, детерминированный
scheduler выбирает порядок, Z3 отсекает доказанно неисполнимых кандидатов,
детерминированные оракулы выносят вердикты, LLM работает фоново как
constrained proposer (semantic facts / norms / кандидаты), бандиты управляют
выбором стратегий генерации, а реактивная петля
`deficits → grounding → re-plan` достраивает план посреди прогона.

## 0.1. Runtime/docs инвариант (S22R)

Обозначим через `R` фактическую runtime-поверхность: селекторы QDL-источников,
контексты planner, поля `QdlPlan`, DI-провайдеры `RunProvider` и уже принятые
алгебраические инварианты. Пусть `D` — документация. S22R требует

```text
π: R → D
D = π(R)
Δ(D, R) = (D \ π(R)) ∪ (π(R) \ D) = ∅
```

`π` — тотальная детерминированная проекция. Она может быть lossy: документация
не обязана копировать каждую локальную переменную. Но на выбранном замкнутом
множестве обсерваблей она не может добавлять несуществующие факты и не может
терять ни один факт. Поэтому `Δ ≠ ∅` — дефект теста или документации, а не
«допустимое отставание текста». Тест вычисляет `π(R)` из кода и сверяет
машинные блоки ниже; ручные счётчики прогонов в canonical-документации не
хранятся, потому что это runtime-артефакты, а не архитектура.

Формальные свойства проекции:

```text
totality       ∀r ∈ R: ∃! π(r)
determinism    r₁ = r₂ ⇒ π(r₁) = π(r₂)
idempotence    π(π(R)) = π(R)
monotonicity   R₁ ⊆ R₂ ⇒ π(R₁) ⊆ π(R₂)
```

Totality и determinism делают документацию воспроизводимой; idempotence
запрещает второй слой описания; monotonicity означает, что добавление
runtime-обсервабли требует расширения проекции, а не ручного «уточнения»
старого текста.

### Совместимость с S21R/S24R/S32R/S33R

| Инвариант | Условие совместимости с S22R | Результат |
|---|---|---|
| S21R | документировать только тотальную функцию `axis = f(predicate_class, evidence_context)` и typed absence, а не список «фич» | конфликта нет |
| S24R | документировать факторную алгебру терма, а не legacy-оси action/path | конфликта нет; старое описание двух осей удалено |
| S32R | документировать belief revision и повтор только при новом evidence, а не числовые attempts | конфликта нет |
| S33R | документировать шесть absorbing outcomes и одну transition на evidence signature, а не retry counters | конфликта нет |

Все четыре инварианта входят в `R` как runtime-обсервабли и проецируются тем
же `π`; S22R не вводит второй источник истины и не переопределяет их алгебру.

## 0.2. Машинная проекция runtime

QDL-селекторы, читаемые `ScenarioBinder` (`*` — merge по префиксу):

<!-- runtime-projection:qdl-sources -->
accepted-batch:{service}:*
accepted:{service}
contract:{service}
diff:{service}:*
stand:{service}
state-machine:{service}
<!-- /runtime-projection:qdl-sources -->

Планировщик:

<!-- runtime-projection:qdl-planner -->
planning contexts: contract, accepted
non-planning contexts: proposal, runtime, report
plan fields: graph_hash, attack_paths, state_paths, resource_state_paths, forbidden_paths, invariants, closures, reveal_edges
default max depth: 8
default closure: chain_plus
<!-- /runtime-projection:qdl-planner -->

DI-поверхность `RunProvider`:

<!-- runtime-projection:run-provider -->
AppScope providers:
  scenario_repository
RunScope providers:
  advisory_pre_scan
  bound_path_runner
  campaign_metrics
  event_bus
  event_projection
  evidence_channel
  field_exposure_oracle
  finding_evaluator
  finding_example_store
  finding_shrinker_factory
  formal_ingestion_service
  fuzz_session_factory
  fuzzing_generator
  generator_bandit
  generator_catalog
  generator_policy
  generator_selector
  grammar_request_solver
  grounded_outcome_oracle
  grounding_runner
  grounding_settings
  latency_oracle
  live_workflow
  marker_oracle
  minimal_seed_generator
  observation_projector
  oob_coordinator
  oob_oracle
  oob_url_factory
  payload_compiler
  payload_corpus
  planner
  primitive_oracle_router
  promotion_policy
  report_publisher
  runtime
  scenario_binder
  scenario_checker
  sequence_oracle
  stand_source
  symbolic_generator
  symbolic_prefilter
  template_generator
  test_case_generator
  textual_generator
  witness_oracle
  workflow_options
Explicit ports:
  EventPublisher
  EvidenceChannel
  FindingExampleStore
  GeneratorPolicy
  GroundingRunner
  OobUrlFactory
  ReportPublisher
  RequestSolver
  ScenarioRepository
  TestCaseGenerator
<!-- /runtime-projection:run-provider -->

Sibling-инварианты 6.11:

<!-- runtime-projection:sibling-invariants -->
S21R: axis = f(predicate_class, evidence_context); absent image = consultation_deficit(predicate_class)
S24R: coverage(term) = semantic × setup × oracle × runtime
S32R: lead_key = action, holder, role, evidence_signature
S33R: outcomes = conflict, missing_evidence, parked, promoted, rejected, transient_error
<!-- /runtime-projection:sibling-invariants -->

## 1. Рантайм целиком

```text
                    ┌────────────────────────────┐
                    │ QDL sources: contract,     │
                    │ state-machine, accepted,   │
                    │ accepted-batch, stand, diff│
                    └─────────────┬──────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
 AutoGrounding / LLM        Clingo algebra             State machine
 (фоновые треды, осей 6+)   (may, STRIDE, OWASP)       (domain FSM)
        │                         │                         │
        └────────────┬────────────┴────────────┬────────────┘
                     ▼                         ▼
                  QdlGraph ──────► IncrementalQdlPlanner (walks как атомы)
                                   │
                                   ▼
                            QdlPlan (derived view)
                                   │
                          ScenarioBinder → QdlExecutionView
                                   │
                                   ▼
                      CoverageDrivenScheduler (cold_score)
                        │           │
              Backtracking       Differential sweep
                        │           │
                        └─────┬─────┘
                              ▼
                         BoundPathRunner (AND-chain, шаг за шагом)
                              │
              ┌───────────────┼────────────────┐
        Z3 prefilter     FuzzSession        Setup resolver
        (unsat → skip)   (bandit выбирает   (fixtures, identity)
              │           стратегию)             │
              └───────────────┴────────┬─────────┘
                                       ▼
                     GuardedTarget: endpoint policy → токен → transport
                                       │
                                       ▼
                                 Observation
                                       │
                     Primitive oracle / Diff oracle (только verdict)
                                       │
                     EventStore + runtime QDL facts
                                       │
        ┌────────────────────────┼────────────────────────┐
  Deficit queue            Coverage matrix            Findings
        │                        │                  (gate: FAIL &&
        ▼                        │                   deterministic &&
  Reactive LLM grounding         │                   grounded && norm)
        │                        │
  parked proposals (lead)        │
        └────► rebind / incremental re-plan / scheduler ◄────────┘
```

Фикспойнт: `grounding finished AND scheduler empty AND branch backlog empty
AND no dispatchable deficits`. Это не «конец конвейера», а отсутствие новой
работы.

## 2. Карта компонентов

| Слой | Файл | Роль |
|---|---|---|
| Clingo-планировщик | `runtime/planning.py` | attack walks, state/forbidden paths, invariants — как derived atoms |
| Clingo-движок | `formal/clingo_engine.py` | QDL→ASP, closures, algebra (may/STRIDE/OWASP) |
| Domain FSM | `formal/state_machine.py` | Clingo-запросы над `initial/transition/forbidden` |
| Campaign FSM | `runtime/metrics.py` | lifecycle интентов (сейчас metrics/reward-machine) |
| Campaign DAG | `runtime/campaign_dag.py` | immutable проекция QDL + event log; graph memory для агентов |
| Consultation protocol | `formal/consultation.py` | deterministic dispatcher, budgets, provenance |
| Bounded slice | `formal/slices.py` | token/depth-limited model context |
| Z3 | `formal/symbolic.py` | prefilter (unsat → skip), генерация значений, cross-action chains |
| Binder | `runtime/binding.py` | QdlPlan → QdlExecutionView (methods, scenarios, hints, setup) |
| Scheduler | `runtime/scheduler.py` | детерминированный выбор пути (cold_score), retry, canonical keys |
| Runtime loop | `runtime/campaign/runtime.py` | fix-point цикл, differential rounds, reactive drain |
| Path runner | `runtime/execution.py` | исполнение AND-chain, fuzz, setup, классификация вердиктов |
| Bandit | `generators/selector.py` | River Thompson, arm = `goal:strategy`; contextual — per-action фильтр |
| LLM grounding | `formal/axis_grounding.py`, `formal/grounding.py` | startup оси + reactive/alternatives/variance |
| LLM generator | `generators/llm.py` | стратегии `llm`/`grammar` (schema-valid гипотезы запросов) |
| Oracles | `oracles/*` | **единственный** слой verdict |
| Target-порт | `ports/execution.py` + `runtime/grpc.py` | transport-адаптер; gRPC — текущая реализация |
| HTTP/JSON target | `runtime/http_json.py` | generic `Target`-адаптер (не default wiring) |
| Policy projector | `qdl/policy_projection.py` | generic policy snapshot → `may`-family QDL facts |

## 3. Clingo: как строится план

Clingo не «выбирает следующий чек» — он материализует **логические следствия**
из QDL-фактов. Порядок исполнения выбирает scheduler.

**Вход.** `ScenarioBinder` мержит источники (`contract:` / `state-machine:` /
`accepted:` + `accepted-batch:*` / `stand:` / `diff:*`) и добавляет attacker
hypothesis, universal exposes, availability norms, algebra-derived threats,
semantic norms.

**Closures** (`clingo_engine.py:37-87`): `part_plus`, `requires_plus`,
`chain_plus`, `may_plus`, `affected_plus`, `reachable`, `reaches_plus` —
транзитивность как Datalog-правила.

**Алгебра** (`_ALGEBRA_RULES`): вывод `may` из binding/grants/requires/targets,
`owner`, STRIDE-буквы (`spoofing/tampering/repudiation/disclosure/denial/
elevation`), OWASP API (bola и др.). Негация — только через context-erasing
хелперы (стратифицированная).

**Walk-правила** находятся в `runtime/planning.py`: `_EFFECT_EDGE_RULE`,
`_REVEAL_EDGE_RULE`, `_WALK_RULES`. План выводится как атомы Clingo.
Для effect-ребра требуется один и тот же typed effect в `current_effect`
действия A и `requires` действия B. Посылки из `contract` и `accepted`
совместимы; смешанный вывод относится к `accepted`. Proposal/runtime/report
не открывают executable цепочку. Reveal-ребро дополнительно требует
`exposes`, текущий `object_ref` и `refers_to` к создаваемому ресурсу.
Default depth = 8. Каждый walk имеет content-addressed `path_id`.

**Повторное планирование.** `IncrementalQdlPlanner` переиспользует grounded
программу для неизменившегося snapshot. При изменении фактов или правил
программа пересобирается: `supersedes` и default negation в current-проекциях
могут отзывать выводы даже при append-only хранении исходных фактов.
Канонические идентификаторы путей сохраняются; результат должен совпадать
с fresh planning того же snapshot.

**QdlPlan ≠ executable.** `ScenarioBinder` превращает его в
`QdlExecutionView`: action→MethodSpec, action→ScenarioPosition,
`prevents`→Invariant, payload hints, sink types, resource params, setup
methods, couplings, versioned path id. Только после этого scheduler выбирает
порядок.

## 4. Три уровня автоматов состояний (не путать)

1. **Domain FSM** (`formal/state_machine.py`) — машина состояний самого
   приложения: обычные QDL-факты (`is/initial/transition/forbidden`),
   Clingo-запросы `solve()/find_paths()/mismatches()`. Кормит planning
   (state/forbidden paths), coverage (state-матрица) и sequence.Oracle (P6).
2. **Campaign FSM** (`runtime/metrics.py`) — lifecycle проверки:
   `PENDING → READY → EXECUTING → OBSERVED → VERIFIED/UNSCOREABLE/BLOCKED`
   с явной таблицей `INTENT_TRANSITIONS`. Сейчас — metrics/reward-machine, не
   control-plane.
3. **Fact-Intent projection** — `EventGraph` накапливает verified facts в
   `runtime` и proposed intents в `proposal`, а `build_campaign_dag`
   проецирует QDL + event log в immutable Campaign DAG. Это read model и
   graph memory, не persistent control-plane и не второй formal engine.
   Cross-run Fact-Intent DAG остаётся design gap.

## 5. Z3: где именно

Z3 не занимается QDL-graph reasoning (это Clingo) и не выносит вердикты.

- **SymbolicPrefilter** (`formal/symbolic.py`, вызов из `path_runner`):
  строит ограничения по типам/min/max/enum/couplings (в т.ч. cross-action,
  одним solver-вызовом через `solve_sequence`). Результаты: `sat` →
  подставить значения; `unsat` → **доказанно** неисполним, live-call не
  тратится; `unknown` → не блокирует (консервативно); `no-symbolic-fields` →
  как есть.
- **Z3SymbolicGenerator** — одна из стратегий генерации (значение ≠ seed,
  schema-valid, с учётом couplings).
- `smt.py` / `z3_solver.py` — **experimental**, вне production-пути.

## 6. DAG: два разных «DAG»

**Effect-graph (живой):** `A --causes--> E <--requires-- B` → ребро `A → B`;
`chain_plus` — замыкание. Циклы допустимы; рекурсия ограничена `max_depth`;
`path_id` content-addressed и версионирован (`:pv`), новые probe fields/setup
inputs создают новую версию пути. Плюс runtime work graph: scheduler state
(completed/blocked/in_flight/attempts/covered/canonical_attempts) + DeficitQueue
+ BacktrackingCoordinator — но это per-run, не persistent.

**Fact-Intent projection (реализована как read model):** `EventGraph` +
   `build_campaign_dag` дают типизированные hypothesis/deficit/reflection узлы
   и рёбра для агентного слоя. Persistent cross-run control-plane и
   recovery-интенты остаются design gap.

## 7. Бандиты

- **`GeneratorBandit`** (River `ThompsonSampling`, Beta): arm =
  `{goal_key}:{strategy}` — «класс нарушения × стратегия» (например
  `marker:grammar`, `elevation:template`). Учит, какие мутации работают для
  каких классов.
- **`ContextualGeneratorBandit`**: per-action trailing-счётчик
  UNSCOREABLE/ERROR — стратегия, стабильно не скорящаяся на данном действии,
  временно исключается; если исключены все — фильтр снимается (anti-deadlock).
- **Wiring:** `FuzzSession` использует contextual; `ChainFuzzSession` —
  базовый campaign-бандит (осознанно: docstring — «learning accumulates across
  chains»). Chain-руки — структурные трансформации setup-сида, поэтому вызовы
  бандита не передают `action_id`/`verdict`: per-action фильтр не подавляет
  перенос обучения между chains (C13 закрыт).
- Награда: verdict + groundedness + trace proximity (лестница
  delivered → witness → FAIL).

Выбор **пути** — не бандит, а детерминированный `cold_score`
(coverage/cost) в scheduler'е: «execution reward is not a learned ranking».

## 8. LLM: четыре точки вызова, никогда вердикт

1. **Optional formal threat proposal** (`FormalThreatModeler`): bounded
   self-contained action-slice; предложение norms только в `proposal`.
2. **Startup semantic grounding** (`axis_grounding.py`): параллельные оси
   (roles, dataflows, exposures, authentication, availability, norms; semantic
   → norms на обогащённом графе), bounded action-slices.
3. **Reactive grounding** (`grounding.py`): по типизированным deficits
   (blocked_step, fixture_type_deficit, missing_baseline, missing_role,
   missing_exposes, response_semantics_ungrounded, unexplained_variance) —
   bounded slice + evidence + OOB + prior uncertainties → QDL-факты.
4. **Seed enrichment** (`SeedEnrichmentConsultant`): модель может предложить
   payload-data дополнения только через валидированный consultation-контракт.
   Прямая `llm`-стратегия остаётся в `GeneratorSelector` для других workflow,
   но локальная `FuzzSession` её исключает.

Границы (после фиксов Wave 1 + residual): LLM не создаёт findings, не пишет
accepted-классификации (source/evidence provenance), гипотезы классификаций
паркуются как leads; per-axis predicate allowlists; untrusted-data контракт в
промптах.

## 9. Event loop по шагам

1. `RunCoordinator.start_grounded()` — фоновый LLM.
2. Первичный bind **не ждёт LLM** — execution идёт по contract-фактам.
3. Scheduler получает initial paths; при diff-mode — initial differential
   sweep до ordinary execution (не потерять pre-state).
4. Ordinary round: выбор пути → setup → Z3 prefilter → FuzzSession
   (бандит-стратегия) → GuardedTarget (endpoint policy → токен → transport)
   → Observation → primitive_router.Oracle → events.
5. ObservationProjector → runtime QDL facts; DeficitQueue классифицирует
   блокировки; Backtracking ищет альтернативные ветки.
6. Reactive LLM обрабатывает deficits → promoted facts → rebind →
   incremental planner добавляет пути → scheduler продолжает.
7. Differential sweep по новым actions; финальный bind + FindingEvaluator +
   coverage matrix.

## 10. Алгебра доступа: `may`-интерфейс policy-agnostic

Проверено внешним разбором на Clingo (воспроизводимо: правила — данные):
RBAC, DAC и MAC компилируются в **один интерфейс** `may(Subject, Action,
Resource)`, а `elevation(S,A) :- executes(S,A), targets(A,R), not may(S,A,R)`
один для всех:

```prolog
% RBAC
may(S,A,R) :- binding(S,Role,Scope), grants(Role,P), requires(A,P),
              targets(A,RT), applies_to(P,RT), is(R,RT), part_plus(R,Scope).
% DAC
may(S,A,R) :- owner(R,S), requires(A,P), targets(A,RT),
              applies_to(P,RT), is(R,RT).
% MAC
may(S,A,R).  % adapter normalizes effective decisions to this fact
```

Значение: **ядро не привязано к IAM** — `ClingoEngine` получает replaceable
`PolicyRulePack`, а production stand-source проектируется в `PolicySnapshot`
через `GenericPolicyProjector`. DAC/MAC или произвольная политика —
альтернативный rule-pack / policy-адаптер, эмитящий один и тот же
`may`-интерфейс, без переделки ядра.
Ограничение: это выразительность access-control-фрагмента, не «все
уязвимости мира».

## 11. Generic adapters и production wiring

- **Транспорт:** core зависит от порта `Target = Callable[[Check], Observation]`.
  `CLOUD_DAST_TARGET` выбирает `grpc` (default) или `http-json`. Оба варианта
  оборачиваются в `GuardedTarget`; endpoint policy проверяется до разрешения
  токена. `HttpJsonTarget` рендерит path/query/header/cookie/body и проецирует
  response в safe fields + bounded response tree. GraphQL и local-process
  адаптеры остаются будущими задачами.
- **Политика:** `GenericPolicyProjector` реализован и превращает
  transport-independent `PolicySnapshot` в QDL-факты `may`, `owner`,
  `binding`, `grants`, `requires`, `targets`, `applies_to` и `part` в
  accepted-контексте. Production wiring по умолчанию читает file-based
  stand-source в `PolicySnapshot` и делегирует QDL-эмиссию этому проектору;
  rule-pack в `ClingoEngine` replaceable. Neo4j остаётся optional extra за
  портом `StandSource`.

## 12. Разделение ответственности

| Кто | Что |
---|---|
| Clingo | graph reasoning: closures, walks, algebra, state paths |
| Z3 | concrete values, unsat-prefilter, cross-action chains |
| LLM | semantic proposals (facts/norms), candidate proposals |
| Bandit | выбор стратегии генерации (goal × strategy × action) |
| Scheduler | выбор пути (детерминированный coverage/cost) |
| Oracle | **единственный** verdict |
| FindingEvaluator | finding только на deterministic grounded FAIL |

CWE/OWASP/STRIDE — presentation projections над нарушенной QDL-нормой.
`class_catalog` не выбирает проверки и не меняет verdict; это не vulnerability
dictionary для генерации.

## 13. Где магия (vs «нейронка сама»)

| Фейл LLM-агента | Механизм движка |
|---|---|
| Не заметила (CVE в функции) | Coverage-матрица + исчерпывающее перечисление walks: незамеченного в пределах графа не бывает; непокрытое видно в отчёте |
| Зацикливалась | Event log + path identity: исполненное не повторяется структурно |
| Делала одно и то же | Z3 UNSAT — доказательство исчерпанности; дедупликация сигнатур |
| Читала огромные исходники | bounded action-slices для модели |
| Невнимательность | Вердикт — не мнение: детерминированный оракул с гейтом |
| Хорошо решала STF | И должна: LLM остаётся генератором гипотез |

Честная оговорка: движок всевидящ **в пределах графа** — чего нет в
контрактах/интроспекции, не увидит и Clingo (нужен сенсор на входе). И вокруг
магии много обвязки-«перекладывания» (бог-методы, projection-слои) — это
долг из аудита, а не ценность.

## 14. Текущие пробелы (сверено с планом)

1. Fact-Intent control-plane не persistent: Campaign DAG — replay/read model,
   cross-run recovery-интенты не сохраняются.
2. Campaign FSM — metrics-only, не control-plane.
3. S26R fair scheduling algebra ещё не закрыта: требуется
   `maximize information_gain subject to max_min_fairness(deficit_class)`.
4. S34R deterministic intersection ещё не закрыта: требуется
   `accepted = ∩ independent_grounded_proposals`.
5. Кодовые долги (бог-методы, тихая деградация, replay identity) отслеживаются
   в remediation plan; их статус не дублируется здесь, чтобы не создавать
   вторую историю изменений.

## 15. Сверка двух разборов

**Совпали полностью:** walk-правила и semantics рёбер; роль binder
(QdlPlan → execution view); closures; Z3-роли (prefilter/generator,
unsat-семантика); бандит-архитектура (arm `goal:strategy`,
contextual per-action фильтр); три LLM-роли; fix-point цикл; DAG-gap;
разделение ответственности.

**Новое из второго разбора (принято):** campaign FSM в `metrics.py`
(PENDING→…→BLOCKED — проверено по коду); RBAC/DAC/MAC → единый `may`
(архитектурно корректно, помечено как проверенное внешним разбором);
e2e-наблюдение о непокрытых методах; явная формулировка «планировщик строит
views, scheduler выбирает порядок».

**Уточнено после сверки с кодом:** `ChainFuzzSession` использует базовый
бандит — это осознанный выбор (docstring: learning accumulates across
chains), а не непоследовательность. C13 закрыт: chain-вызовы бандита не
передают per-action контекст, поэтому фильтр не действует на chain-руки.

---

## 16. Consultation-протокол над детерминированным ядром — итог C16

### Решение

Детерминированный оркестратор остаётся control-plane. LLM участвует только
через typed, budgeted и provenance-carrying consultation requests. Отдельного
агентного слоя нет.

Это не новый formal engine и не vulnerability dictionary: Campaign DAG —
проекция QDL и runtime-событий, а не второй источник истины.

Ответ на вопрос «один LLM-участник на цепочку или участник на каждый шаг»:

- ни один из них не владеет цепочкой;
- глобальных campaign-агентов нет; reactive-цикл ядра сам строит bounded
  consultation requests из дефицитов;
- владелец пути, продвижения шага и вердикта остаётся детерминированным.

### Что consultation может

- читать bounded graph slice;
- предлагать недостающие QDL-факты, нормы и рёбра;
- предлагать setup/fixture/state-гипотезы;
- предлагать payload-грамматики;
- предлагать приоритеты coverage;
- превращать `UNSCOREABLE` в typed clue или deficit.

### Что consultation не может

- выбирать исполняемый путь;
- решать, что шаг доказан;
- вызывать target;
- повышать proposal в `accepted`/`runtime`;
- выносить verdict;
- хранить скрытую память вне event-sourced QDL.

### Реактивные LLM-to-LLM вызовы

```text
deficit
  -> consultation_request(kind, bounded_slice, budget)
  -> deterministic dispatcher
  -> specialist LLM
  -> schema-valid QDL proposal
  -> promotion validator
  -> planner / scheduler
```

Ограничения:

- максимум один-два уровня делегации;
- обязательный budget;
- обязательный provenance;
- вывод только как QDL proposal;
- никаких прямых side effects;
- никаких вердиктов.

### Связь с текущими гэпами

| Текущий гэп | Помогает ли consultation-протокол | Что делать |
|---|---|---|
| Fact-Intent DAG не persistent | частично | Campaign DAG как проекция QDL + событий |
| Campaign FSM metrics-only | нет | FSM как control-plane; reactive deficits как источник запросов |
| Clue graph write-only | да | clue → consultation_request |
| Coverage gaps | нет | B23 InterestPrioritizer и benchmark-only deficit arm |
| HTTP/JSON target не default wiring | нет | `HttpJsonTarget` реализован; добавить composition selection |
| Бог-методы | нет | рефакторинг C1 |

### Статус после C16

1. Campaign DAG как проекция QDL и runtime-событий — реализовано как
   immutable read model.
2. Typed consultation/handoff protocol — реализовано.
3. Bounded graph slice API — реализовано.
4. Promotion policy — общий deterministic core `promote_proposal` используется
   formal и axis путями; residual фильтры пакетов находятся в `BatchFlow`.
5. Replay и provenance для каждого consultation-вызова — реализовано для
   consultations и Campaign DAG.
6. Тесты: consultation не выдаёт verdict, невалидные proposal отклоняются, replay
   восстанавливает тот же набор путей — реализовано.

Обоснование и источники: `docs/research-extrapolation.md`, раздел
«Third wave: agent orchestration over QDL».

### Исторический агентный слой и снос (2026-10-20)

Сверка видения Layer 5 с кодом показала дрейф: построена repair-половина
(deficit-маршрутизация), exploration/generation-половина не построена.
Из «Что агент может» не реализованы: setup/fixture/state-гипотезы,
payload-грамматики, приоритеты coverage. StepSpecialist дублирует таблицу
`_DEFICIT_CONSULTATION_KINDS` ядра (`deficits.py`) один в один;
PathProposer задаёт тот же alternatives-вопрос с путевыми счётчиками;
ReflectionNode конфликтует с политикой ядра на `missing_baseline`
(ядро: never consult; агент: availability). Namespace-префиксы
(`critic:`/`step:`/`path:`/`reflection:`) ломают дедуп с
`consultation_id` ядра — один дефицит может консультироваться дважды.

Решение (2026-10-20): агентный слой снесён целиком. Ценность видения
мигрировала: coverage-приоритеты → B23; payload-грамматики → S3/S4;
UNSCOREABLE-обработка → ядро (`response_semantics_ungrounded`); typed
consultation protocol остаётся в ядре и обслуживает reactive-цикл.
`EventGraph`/`CampaignDag` сохраняются — у них есть потребители вне
агентов (`campaign.py`, `path_runner.py`). Приоритетная таблица критика
(`_DEFICIT_PRIORITY`) и evidence tie-break перенесены в
`benchmarks/nsfy_bench/cold_score.py` как одна из cold_score-рук B23. Engine
не импортирует benchmark-пакет.

### Независимые grounding-компоненты (2026-10-29)

`composition.grounding.Provider` отдельно регистрирует в `RunScope`:
`LeadLifecycle`, `ConsultationLedger`, `ProposalPromoter`, `Loader`, `BatchFlow`,
`RunCoordinator`, `DifferentialFlow`, `DispatchFlow` и `ApprovalFlow`.
`RunProvider.grounding_settings` создаёт только параметры и адаптеры; агрегата
`AutoGroundingService` больше нет. Оба корня приложения подключают этот provider.

Внутри прогона используются общие promoter, Loader, policy и ledgers. Другой
`RunScope` получает новое состояние. Formal gate читает актуальные
`policy.enabled`/`policy.exhausted`, reactive gate — текущую capability BatchFlow.
Старт, measured evidence, подготовка и owner-thread admission остаются
раздельными операциями. `assemble_workflow` принимает отдельные роли и один
`LiveWorkflowOptions`; произвольные kwargs настроек больше не поддерживаются.
