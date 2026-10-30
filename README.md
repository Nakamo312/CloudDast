# NSFy

NSFy (NeuroSymbolicFuzzing) — application-agnostic DAST-движок над одним
формальным субстратом QDL. Внутренний Python-пакет пока называется
`cloud_dast`; это техническое имя, а не продуктовый бренд.
Он превращает контракты API, IAM-факты, спецификации состояний и runtime-наблюдения
в проверяемые цепочки вызовов, исполняет их на изолированном стенде и подтверждает
нарушения только детерминированными, заземлёнными оракулами.

Полная архитектурная документация:
[`formal-substrate-architecture-2026-10-10.md`](formal-substrate-architecture-2026-10-10.md).
Карта фактического runtime и S22R-инвариант:
[`docs/engine-runtime-2026-10-19.md`](docs/engine-runtime-2026-10-19.md).
Дифференциальный цикл обнаружения (paired execution → компаратор →
норма → верификация):
[`docs/differential-discovery-rfc.md`](docs/differential-discovery-rfc.md).
План внешней валидации на OWASP Juice Shop:
[`docs/external-validation-juice-shop.md`](docs/external-validation-juice-shop.md).
Отчёт полного локального E2E на NSFy Bench:
[`docs/nsfy-e2e-2026-10-15.md`](docs/nsfy-e2e-2026-10-15.md).
Отчёт прогона со всеми пятью дифференциальными режимами:
[`docs/nsfy-e2e-full-2026-10-15.md`](docs/nsfy-e2e-full-2026-10-15.md).

## Ключевая идея

```text
один typed contextual QDL substrate
  + application-specific adapters
  + LLM как constrained semantic compiler
  + deterministic planner / fuzzer / oracle
  + STRIDE, OWASP, coverage и отчёт как views
```

QDL — единственный источник executable truth. Отдельные `World IR`, `Action IR`,
`Threat IR`, `Probe IR` и `Evidence IR` не создаются.

Live runtime читает шесть селекторов QDL-источников (звёздочка — merge
по префиксу):

<!-- runtime-projection:qdl-sources -->
```text
accepted-batch:{service}:*
accepted:{service}
contract:{service}
diff:{service}:*
stand:{service}
state-machine:{service}
```
<!-- /runtime-projection:qdl-sources -->

Контексты QDL не смешиваются:

```text
contract  — спроецированные контракты и graph-backed факты
proposal  — гипотезы LLM, не исполняются автоматически
accepted  — принятые нормы, состояния и зависимости
runtime   — наблюдения и evidence
report    — презентационные проекции
```

## Live pipeline

```text
FormalRepository
  -> canonical QdlGraph
  -> ScenarioBinder (optional FormalThreatModeler proposal)
  -> IncrementalQdlPlanner (default)
  -> QdlExecutionView
  -> CoverageDrivenScheduler
  -> BoundPathRunner
       -> StepSetupResolver
       -> SymbolicPrefilter
       -> FuzzSession
  -> Observation
  -> primitive_router.Oracle
  -> ObservationProjector
  -> FindingEvaluator
```

`IncrementalQdlPlanner` использует Clingo для рекурсивных замыканий, bounded
walks и путей, а отдельный state-machine engine — для переходов. Z3 не входит
в planner: `SymbolicPrefilter` отсекает доказанно неисполнимых кандидатов, а
`Z3SymbolicGenerator` порождает solver-derived значения. Самописных
Datalog/SMT/RL-движков в ядре нет.

Проекция planner-поверхности проверяется тестом:

<!-- runtime-projection:qdl-planner -->
```text
planning contexts: contract, accepted
non-planning contexts: proposal, runtime, report
plan fields: graph_hash, attack_paths, state_paths, resource_state_paths, forbidden_paths, invariants, closures, reveal_edges
default max depth: 8
default closure: chain_plus
```
<!-- /runtime-projection:qdl-planner -->

`proposal` и `runtime` остаются provenance-контекстами и по умолчанию не
создают bound paths.

## Runtime/docs инвариант (S22R)

Пусть `R` — фактическая runtime-поверхность (селекторы QDL, контексты
planner, поля плана, DI-провайдеры и sibling-инварианты), а `D` —
документация. Документация является тотальной детерминированной проекцией
`π: R → D`, а не параллельным описанием. Инвариант:

```text
D = π(R)
divergence(D, R) = (D \ π(R)) ∪ (π(R) \ D) = ∅
```

Проекция может быть lossy, но не может добавлять факты или терять выбранные
runtime-обсервабли. Проекция тотальна, детерминирована, идемпотентна и
монотонна по добавлению runtime-фактов. Непустое множество расхождений —
дефект теста/документации, а не допустимое упрощение. Тест
`tests/architecture/test_runtime_docs_projection.py` вычисляет `π(R)` из кода
и сверяет машинные блоки проекции.

State machine — не отдельный slice. Это обычные QDL-факты:

```text
is(state, State)
is(action, Action)
is(norm, Norm)
initial(state)
transition(action, from_state, to_state)
forbidden(norm, state)
```

## Границы моделей

Доменные boundary DTO:

```text
MethodSpec
FieldSpec
Invariant
VerificationPlan
Check
Observation
Finding
```

Raw ingestion DTO живут только в
`packages/core/src/cloud_dast/application/verification/formal/contract_models.py` и сразу
проецируются в QDL. После проекции старые параллельные threat-модели не
используются.

## Планирование и coverage

S24R считает coverage по QDL-термам:

```text
coverage(term) = semantic × setup × oracle × runtime
oracle(term) = channel × primitive
```

Дефицит — первый недостающий фактор в порядке
`semantic → setup → channel → primitive → runtime`; он типизирован фактором,
а не action/path. Запрос, фактически попавший в request, и свидетель oracle —
различные runtime-проекции.

STRIDE и OWASP — проекции над QDL, а не отдельные источники истины. Coverage
не может пометить целую группу полей covered по одному probe.

Ядро не импортирует benchmark-пакет и не использует benchmark-специфичные
идентификаторы; граница зафиксирована тестом
`test_engine_never_imports_the_benchmark_package`.

## Исполнение и адаптивный фаззинг

`BoundPathRunner` исполняет QDL-пути. Каждый QDL-шаг получает локальную
`FuzzSession`:

```text
QdlExecutionStep
  -> FuzzSession.next()
  -> candidate Check
  -> ServiceWorkflow.execute_check()
  -> deterministic oracle verdict
  -> FuzzSession.record(check, verdict, grounded)
  -> River GeneratorBandit + local reward
```

Стратегии:

```text
template
symbolic (Z3)
fuzzing
llm
grammar (LLM)
```

Каждая стратегия оборачивается в `GoalPayloadGenerator`, поэтому marker и OOB URL
из QDL-нормы не теряются.

Marker и OOB-канарейка уникальны для каждого кандидата:

```text
{norm.marker}-{probe_nonce}
```

`run_check` переносит `probe_marker` в `Observation`; оракул ищет именно этот
маркер, поэтому асинхронный callback от другого кандидата не приписывается
текущему шагу.

Runtime-evidence сохраняется в append-only sidecar (`<event-log>.evidence.jsonl`, или
явный `CLOUD_DAST_EVIDENCE_LOG`). Оракул и формальная проекция наблюдения
читают этот ledger по correlation-id (для marker-проб — уникальному маркеру).
Каждая строка — один JSON-object с полями `event_id`, `correlation_id`,
`channel`, `event_type`, `source`, `observed_at`, `attributes`;
внешний collector обязан дописывать только завершённые строки и при конкурентной
записи использовать sidecar-лок `.lock`.

Внешний OOB-канал использует модель Interactsh: `CLOUD_DAST_OOB_SERVER_URL`
обязательно указывает HTTPS-origin токен-защищённого сервера
(`CLOUD_DAST_OOB_TOKEN` или `CLOUD_DAST_OOB_TOKEN_FILE`). Клиент регистрирует
RSA public key, генерирует callback-домены вида
`<correlation-id><nonce>.<server-host>`, опрашивает `/poll`, расшифровывает
взаимодействия и дерегистрируется на остановке. Interactsh-сервер владеет
callback/DNS-поверхностью и её лимитами; клиент принимает только ожидаемые
маркеры и ограничивает размер ответа и число событий. Без сервера включается
локальный fallback — loopback-only HTTP listener с ephemeral-портом, expected
marker set и rate limit. Ошибка конфигурации или регистрации блокирует канал с
явной причиной, а не даёт тихий PASS.

Interactsh-server разворачивается отдельно как Go-контейнер с выделенным
доменом/DNS, токеном и ресурсными лимитами; Cloud DAST не встраивает этот
сетевой сервис в свой процесс.

Отсутствие callback за окно ожидания — это `UNSCOREABLE` с явным negative
evidence, а не grounded `PASS`. Поздний callback не теряется: durable ledger
сохраняется, таймаут-кандидат остаётся pending, а campaign-final sweep
переоценивает его по тому же marker. Interactsh-остановка делает финальный
poll перед deregistration, чтобы не потерять взаимодействия, пришедшие после
последнего регулярного опроса.
Memory- и JSONL-store держат bounded recent ring/index; полная история остаётся
в durable JSONL и доступна через marker-indexed persistent query.

Управление:

```text
CLOUD_DAST_GENERATOR=template
CLOUD_DAST_FUZZ_MAX_CHECKS=3
```

Доступные стратегии генерации:

```text
template
symbolic
fuzzing
llm
grammar
```

`llm` — model-backed generator: движок передаёт модели request schema, seed,
QDL-норму и сценарий, а модель предлагает только schema-valid значения. В
движке нет словаря уязвимостей и фиксированных payload'ов; итог по-прежнему
решает deterministic oracle.

`grammar` — отдельная model-backed стратегия payload grammar: модель выводит
грамматику носителя из schema/нормы/seed и применяет generic-операторы
(разделитель, сегмент, parent-reference, повторение, quoting/escaping и т.д.).
Уникальный canary подставляется только через placeholder `{probe_marker}` (для
OOB — `{oob_url}`), поэтому движок не перезаписывает модельную грамматику
простой канарейкой и не содержит фиксированных payload'ов.
Model output проходит детерминированную проверку типов, enum, bounds, oneof и
couplings; невалидные кандидаты отбрасываются до live-вызова. `FuzzSession`
запрашивает у каждой стратегии один ограниченный batch на QDL-шаг и переиспользует его.
Если модель недоступна или не дала валидных кандидатов, стратегия честно
возвращается к template-seed (маркерные grammar-кандидаты без placeholder
отбрасываются), а не притворяется grammar-результатом.

Live CLI также возвращает `norm_coverage` — по каждой executable норме:

```text
norm_id, effect, path_count, scheduled, selected, executed,
oracle_called, verdict, blocked_reason, action_ids, path_ids,
check_count, finding_count
```

`blocked_reason` объясняет первый потерянный этап: нет executable-пути, путь не
попал в scheduler, не был выбран/исполнен, бюджет проверок исчерпан, oracle не
вызван, либо возвращает rationale deterministic-оракула.
`scheduled` означает «путь зарегистрирован в scheduler»; фактический pull
отдельно отражается в `selected`, а реальное выполнение — в `executed`.

`CLOUD_DAST_FUZZ_MAX_CHECKS` — локальный бюджет кандидатов на один QDL-шаг.
Campaign-wide `--max-checks` остаётся внешним предохранителем.

QDL-path — AND-chain. Следующий шаг исполняется только после grounded `FAIL`,
который подтверждает ожидаемый эффект. `PASS`, `UNSCOREABLE` и ungrounded `FAIL`
блокируют текущий путь, но не sibling paths.

Ungrounded `FAIL`:

```text
не создаёт finding
не публикует FactVerified
не увеличивает failures/reward
не разблокирует следующий шаг
отображается как UNSCOREABLE
```

## Оракулы

| Primitive | Oracle | Детекция |
|---|---|---|
| P1 outcome | `grounded.Oracle` | observed vs graph-grounded expected outcome |
| P2 response field | `field_exposure.Oracle` | запрещённое поле в ответе |
| P3 OOB | `OobOracle` | callback коллаборатора |
| P4 latency | `latency.Oracle` | duration vs baseline/threshold |
| P5 marker/diff | `marker.Oracle` | маркер в ответе/trace |
| P6 sequence | state machine / trace | достижение запрещённого состояния |

Finding создаётся только при:

```text
FAIL
&& deterministic
&& grounded
&& norm
&& observation/evidence
```

Стохастическая модель может предложить гипотезу, но не может присвоить себе
детерминированный grounded verdict.

CWE/OWASP/STRIDE — presentation projections над нарушенной QDL-нормой
(`class_catalog`). Они не выбирают проверки, не расширяют базис и не меняют
verdict.

## LLM

LLM подключается только через `ModelClient` и используется как constrained
semantic compiler в четырёх runtime-точках: optional `FormalThreatModeler`,
startup `AxisGroundingService`, reactive `ConsultationDispatcher` и
`SeedEnrichmentConsultant`. Прямая `llm`-стратегия доступна в
`GeneratorSelector` другим workflow, но локальная `FuzzSession` её исключает;
модель вызывается только через seed-enrichment hook.

Разрешённые выходы:

```text
semantic roles
causal effects
norms
state-machine hypotheses
payload-corpus deltas (seed enrichment)
```

Всё возвращается в QDL `proposal`-контексте. Модельные rules остаются
proposal-артефактами: они не исполняются и не промоутятся автоматически. Facts
становятся executable только после явной deterministic promotion policy.

LLM:

```text
не исполняет запросы
не создаёт finding
не пишет accepted/runtime facts
не решает итоговый security verdict
```

Для exploratory-режима можно явно включить продвижение proposal-норм:

```text
CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS=1
CLOUD_DAST_MAX_PROMOTED_NORMS=32
CLOUD_DAST_MAX_FORMAL_ACTIONS=12
```

`FormalThreatModeler` получает детерминированный self-contained срез по action,
а не весь контракт целиком. Это защищает запрос от context saturation и не даёт
модели изобретать action ID вне графа.

Продвигаются только нормы, у которых:

```text
действие объявлено в исходном QDL-графе
эффект имеет детерминированный primitive
все references можно сделать self-contained в accepted context
```

Исходный proposal сохраняется. Продвижение не превращает LLM-вердикт в finding;
finding по-прежнему требует детерминированный grounded oracle.

### Campaign DAG и consultation-протокол

`CampaignState` накапливает verified facts в `runtime`-контексте и proposed
intents в `proposal`-контексте. `build_campaign_dag` проецирует этот QDL-граф
и event log в immutable Campaign DAG — это read model для памяти кампании, а не
второй formal engine и не persistent control-plane.

Агентный слой удалён (C16). Ядро сохраняет typed consultation-протокол,
bounded graph slices и reactive deficit loop: `LiveWorkflow` строит запросы из
runtime-дефицитов, а `AutoGroundingService.ground_consultation` детерминированно
диспетчеризует и валидирует LLM-proposal. LLM не выбирает путь, не вызывает
target, не продвигает proposal и не выносит verdict.

Приоритизация дефицитов для B23 живёт только в benchmark-пакете
(`benchmarks/nsfy_bench/cold_score.py`) и не влияет на engine wiring. Отдельных
`CLOUD_DAST_AGENT_*` параметров больше нет.

### Advisory pre-scan

Внешние advisory-знания входят только через явный pre-scan перед live-кампанией.
Он читает OSV/GHSA/NVD только с allowlisted HTTPS-хостов, нормализует записи,
кладёт их в версионируемый кеш и проецирует совпадения инвентаря пакетов как
`affects(pkg, version)` в `contract`-контексте. Runtime LLM не обращается к
интернету и не порождает advisory-факты.

```text
CLOUD_DAST_ADVISORY_PRESCAN=1
CLOUD_DAST_ADVISORY_CORPUS_VERSION=2026.10.20
CLOUD_DAST_ADVISORY_SOURCES=[
  {"kind": "osv", "url": "https://api.osv.dev/v1/advisories"}
]
CLOUD_DAST_ADVISORY_PACKAGES=[
  {"ecosystem": "pypi", "name": "example", "version": "1.5.0"}
]
CLOUD_DAST_ADVISORY_CACHE_DIR=~/.cache/cloud-dast/advisory
```

Инвентарь пакетов можно задать файлом через
`CLOUD_DAST_ADVISORY_PACKAGE_FILE` вместо inline JSON. Кеш идентифицируется
версией схемы, версией корпуса и источником; повреждённый или подменённый файл
отклоняется и вызывает повторную загрузку.

### Grounding cache и токены

LLM-grounding кешируется на уровне валидированных QDL-предложений:

```text
key = hash(
  model namespace
  prompt strategy
  instruction
  response schema
  contract+stand slice hash
)
```

Кеш сохраняет только результат, прошедший `FormalModelOutputValidator`. Invalid
output никогда не попадает в кеш. Уже принятые семантические факты не меняют
ключ — иначе второй прогон всегда был бы cache miss.

Управление:

```text
CLOUD_DAST_GROUNDING_CACHE=1
CLOUD_DAST_GROUNDING_CACHE_DIR=~/.cache/cloud-dast/grounding
```

Для разового обхода кеша:

```sh
python -m app.cli ... --refresh-grounding
```

Промпт упакован для prefix caching: стабильные `task`, `instruction` и schema
идут перед переменным `context`. Единственный источник schema — переданный
`response_type`: адаптер использует её для native structured output и промпта,
поскольку совместимые endpoints могут не применять native schema.
Разбор ответа, token caps и usage принадлежат `infrastructure/runtime/model.py`;
прикладные потребители валидируют `ModelResponse.structured`, не разбирая
`content` повторно. Неполный usage не считается измеренным нулём.

## События

Основные события прогона:

```text
CheckCompleted
CoverageUpdated
FindingRaised
FactVerified
IntentProposed
EvidenceRecorded
InvestigationActionExecuted
QdlStepEvaluated
QdlPathEvaluated
```

`JsonlEventStore` — append-only хранилище с защитой от duplicate event id и
восстановлением оборванной последней строки. `EventBus` — синхронный
infrastructure adapter, а не архитектура ядра.

## Composition root

Зависимости собирает Dishka:

```text
AppScope — graph repositories, SQLite formal store и долгоживущие объекты
RunScope — сервисы одного прогона и CloudDastRuntime
```

`SessionFactory` и `EventStore` передаются через context. Live-Target собирается
в контейнере из repository-портов. Основные контракты:

```text
MethodRepository        <- Neo4jMethodRepository
ContractGraphRepository <- Neo4jContractGraphRepository
FormalRepository        <- SqliteFormalRepository (Neo4j — optional extra)
InvocationRepository    <- Neo4jInvocationRepository
ScenarioRepository      <- CLOUD_DAST_STAND_SOURCE selection
TestCaseGenerator       <- GoalPayloadGenerator(GeneratorSelector)
FuzzSessionFactory      <- FuzzSession + River GeneratorBandit
primitive_router.Oracle   <- P1..P6 oracles
Guardrail               <- AllowlistGuardrail (deny by default)
```

`ScenarioRepository` выбирается по `CLOUD_DAST_STAND_SOURCE`: по умолчанию
файловый `FileScenarioRepository`, при `neo4j` — `Neo4jScenarioRepository`.

## Generic adapters

Ядро зависит только от портов, поэтому transport и policy остаются адаптерами:

- `HttpJsonTarget` реализует `Target` для HTTP/JSON: рендерит path/query/
  header/cookie/body, проверяет endpoint policy до разрешения токена и
  проецирует response в safe fields + bounded response tree;
- `LocalProcessTarget` реализует `Target` для локального бинарного интерфейса:
  рендерит argv из graph-метаданных, передаёт отфильтрованный stdin в codec
  и проецирует exit code/stdout без shell;
- `SocketTarget` реализует `Target` для протокольных сообщений: кодирует
  graph-описанный message type, отправляет его через replaceable socket
  transport и проецирует ответ в safe fields + response tree;
- `EvidenceChannel` — generic evidence-port для response, OOB, eBPF и app-log;
  join идёт по `correlation_id`/marker, а OOB-потребители дополнительно
  фильтруют события по `channel="oob"`, чтобы не приписывать eBPF или
  response-evidence другому каналу;
- `GenericPolicyProjector` превращает transport-independent `PolicySnapshot`
  в QDL-факты `may`, `owner`, `binding`, `grants`, `requires`, `targets`,
  `applies_to` и `part` в accepted-контексте.

Production composition по умолчанию использует gRPC-target и generic policy
projection: file-based `FileStandSource` читает версионируемый `stand.json`,
`PolicySnapshot` проходит через `GenericPolicyProjector`, а `ClingoEngine`
принимает replaceable `PolicyRulePack` (RBAC/DAC derivation; MAC
нормализуется в `may`). Neo4j остаётся optional extra за портом `StandSource`
для живых стендов.
Live-композиция выбирает транспорт через `CLOUD_DAST_TARGET=grpc|http-json`
(default `grpc`). `LocalProcessTarget` и `SocketTarget` реализуют тот же порт
для не-HTTP execution surfaces, но не входят в текущий live target resolver.

Формат stand-снапшота:

```json
{
  "bindings": [
    {"subject": "victim", "role": "viewer", "scope": "secret-1"}
  ],
  "resources": [
    {"resource": "secret-1", "resource_type": "lockbox.secret"}
  ],
  "containments": [
    {"child": "secret-1", "parent": "folder-1"}
  ]
}
```

Источник выбирается через `CLOUD_DAST_STAND_SOURCE=file|neo4j` (по умолчанию
`file`), путь файла — `CLOUD_DAST_STAND_FILE` (по умолчанию `stand.json`).
Для миграции живого стенда:

```sh
python -m cloud_dast.composition.stand_cli export \
  --service lockbox \
  --output stand.json
```

Проекция стенда в SQLite formal store:

```sh
python -m cloud_dast.composition.stand_cli project --service lockbox
```

## Подготовка данных

Контракты в QDL:

```sh
python -m cloud_dast.composition.formal_cli \
  --service yandex.cloud.lockbox.v1.PayloadService
```

`formal_cli` сохраняет результат в SQLite formal store по умолчанию
(`CLOUD_DAST_FORMAL_STORE=sqlite`); Neo4j formal store остаётся опцией.

Запаркованные LLM-классификации не исполняются автоматически. Оператор сначала
просматривает очередь, затем явно подтверждает один факт по его content hash:

```sh
python -m cloud_dast.composition.approval_cli \
  --service yandex.cloud.lockbox.v1.PayloadService \
  --list

python -m cloud_dast.composition.approval_cli \
  --service yandex.cloud.lockbox.v1.PayloadService \
  --approve FACT_HASH \
  --operator staff-login \
  --reason 'Owner confirmed this credential classification.'
```

Approval добавляет только недостающую provenance для классификации: action
binding, self-contained declarations и детерминированная проверка остаются
обязательными. CLI не создаёт finding и не продвигает lead-нормы; каждая
операция дополнительно пишется в приватный hash-chained audit log
(`CLOUD_DAST_APPROVAL_AUDIT_LOG`, по умолчанию
`cloud-dast-approvals.jsonl`).

State machine в QDL:

```sh
python -m cloud_dast.composition.state_machine_cli \
  --service orders \
  --specification state-machine.yaml
```

Пример `state-machine.yaml`:

```yaml
states: [created, approved, shipped]
actions: [approve, ship]
norms: [no_ship_without_approval]
initial_states: [created]
transitions:
  - action: approve
    from_state: created
    to_state: approved
  - action: ship
    from_state: approved
    to_state: shipped
forbidden_states:
  - norm: no_ship_without_approval
    state: shipped
```

Спека вводов локального бинарного интерфейса или описание протокольного
сообщения проецируется тем же контрактом: `InputSpecification` →
`MethodSpec`/`FieldSpec` → `SpecProjector` → QDL. Отдельной threat-модели или
vulnerability dictionary для этих источников не появляется.

## Live запуск

Запуск через профиль:

```sh
python -m app.cli \
  --profile profiles/lockbox.toml
```

Для внутренней GLM 5.2 через Eliza используйте отдельный профиль:

```sh
python -m app.cli \
  --profile profiles/lockbox-eliza-glm52.toml
```

Профиль использует OpenAI-compatible endpoint
`https://api.eliza.yandex.net/internal/glm-5-2/v1` и модель
`internal/glm-5-2`. OAuth-токен Eliza передаётся через
`CLOUD_DAST_MODEL_TOKEN` или `CLOUD_DAST_MODEL_TOKEN_FILE`; в профиль токен не
записывается. Для контейнера нужны сетевой доступ к Eliza и IDM-доступ к
внутренним моделям.

Быстрый прогон проверок без LLM-grounding:

```sh
python -m app.cli \
  --profile profiles/lockbox.toml \
  --skip-llm-grounding
```

Если в окружении остался `CLOUD_DAST_SKIP_LLM_GROUNDING=1`, а нужно принудительно
запустить семантическое заземление:

```sh
python -m app.cli \
  --profile profiles/lockbox.toml \
  --force-llm-grounding
```

Профиль содержит только non-secret настройки. Идентификаторы, пути к секретам
и токены остаются в окружении:

```toml
service = "lockbox"
identity_env = "CLOUD_DAST_IDENTITY"
resource_id_env = "CLOUD_DAST_RESOURCE_ID"

[model]
id = "glm-5.3"
api = "responses"
reasoning_effort = "low"

[grounding]
cache = true
workers = 4

[classification]
path = "data-classification.toml"
```

Явные CLI-аргументы имеют приоритет над профилем. Сам профиль авторитарен для
non-secret настроек кампании и перезаписывает устаревшие значения из общего
`.env` — иначе старый `CLOUD_DAST_ALLOWED_SERVICES` или `CLOUD_DAST_MODEL_ID`
может тихо превратить прогон в нулевой. Секреты в профиле не живут; профиль
только ссылается на их environment-backed источники.

`classification.path` указывает на курируемый файл рядом с launch-профилем. Он
проецирует source-labels документации в закрытый алфавит QDL-ролей и sink-типов;
это не vulnerability dictionary и не набор benchmark-подсказок.

Если профиль задает `runtime.setup_identity`, для этого identity нужен свой
токен. Иначе провижинер fallback-нет на общий `CLOUD_DAST_IAM_TOKEN_COMMAND`
и создает фикстуру токеном атакующего:

```sh
# identity aje3jl913cf556h8b4qo -> AJE3JL913CF556H8B4QO
export CLOUD_DAST_TOKEN_AJE3JL913CF556H8B4QO_COMMAND="
  .venv/bin/python scripts/fetch_iam_token.py --key-file /path/to/setup-key.json
"
```

Совместимый явный запуск без профиля:

```sh
python -m app.cli \
  --service lockbox \
  --principal-id attacker \
  --identity attacker \
  --resource-id secret-victim \
  --method-id grpc-priv:yandex.cloud.priv.lockbox.v1.PayloadService.Get \
  --environment preprod \
  --event-log /tmp/cloud-dast-events.jsonl \
  --progress live
```

Exit codes:

```text
0 — проверки исполнены, finding нет
1 — есть finding
2 — ни одной проверки не исполнено
```

Обязательное окружение:

```text
CPA_NEO4J_URI
CPA_NEO4J_USER
CPA_NEO4J_PASSWORD или CPA_NEO4J_PASSWORD_FILE
CLOUD_DAST_DESCRIPTOR_SET
CLOUD_DAST_ALLOWED_SERVICES
CLOUD_DAST_ALLOWED_IDENTITIES
IAM token: CLOUD_DAST_TOKEN_<IDENTITY> или CLOUD_DAST_TOKEN_<IDENTITY>_COMMAND
```

Модель:

```text
CLOUD_DAST_MODEL_URL=https://api.z.ai/api/v1
CLOUD_DAST_MODEL_ID=glm-5.3
CLOUD_DAST_MODEL_API=responses
CLOUD_DAST_MODEL_TOKEN или CLOUD_DAST_MODEL_TOKEN_FILE
```

Для host-запуска можно включить:

```text
CLOUD_DAST_IAM_TOKEN_PREFER_COMMAND=1
```

Payload, authorization metadata и ответы модели не пишутся в операционные логи.
В `ResponseData` попадают только явно разрешённые scalar `safe_fields`.

## Docker и локальный E2E

```sh
docker build -t cloud-dast:llm .

docker run --rm \
  --env-file cloud-dast.env \
  -e CLOUD_DAST_MODEL_TOKEN_FILE=/run/secrets/glm_api_key \
  -e CPA_NEO4J_PASSWORD_FILE=/run/secrets/neo4j_password \
  -e CLOUD_DAST_TOKEN_ATTACKER_FILE=/run/secrets/iam_attacker \
  -e CLOUD_DAST_DESCRIPTOR_SET=/run/config/private-api.pb \
  -v "$PWD/secrets/glm_api_key:/run/secrets/glm_api_key:ro" \
  -v "$PWD/secrets/neo4j_password:/run/secrets/neo4j_password:ro" \
  -v "$PWD/secrets/iam_attacker:/run/secrets/iam_attacker:ro" \
  -v "$PWD/private-api.pb:/run/config/private-api.pb:ro" \
  -v "$PWD/events:/var/lib/cloud-dast" \
  cloud-dast:llm \
  --service <service> \
  --identity <identity> \
  --resource-id <resource> \
  --environment preprod
```

Локальный E2E:

```sh
cp .env.example .env
# заполните .env, secrets, descriptor path и путь к stand.json
./scripts/fetch-iam-token.sh
docker compose up --build
```

Neo4j при первом старте пустой. Контракты и state-machine спецификации нужно
спроецировать в QDL отдельным шагом или подключить volume с существующими
`QdlProjection`/`QdlFact`.

## Тесты и линтер

```sh
.venv/bin/python -m pytest -q --ignore=tests/benchmarks/test_server.py
.venv/bin/python -m ruff check packages/core/src/cloud_dast tests benchmarks
.venv/bin/python -m ruff format --check cloud_dast tests benchmarks
.venv/bin/python tools/structure_lint.py packages/core/src/cloud_dast
# Targeted S22R rerun:
.venv/bin/python -m pytest -q tests/architecture/test_runtime_docs_projection.py
```

`structure_lint.py` — отдельный структурный quality gate для постепенно
снижаемого технического долга. Он проверяет `SL100` (размер функции), `SL101`
(число параметров), `SL102` (размер верхнего блока импортов), `SL103`
(цикломатическую сложность), `SL104` (длинные имена классов, функций и методов)
и `SL105` (тавтологичные имена), `SL106` (повтор родительского namespace в
дочернем имени) и `SL107` (перегруженные word-soup имена). Пороги задаются в секции
`[tool.structure-lint]` в `pyproject.toml`; текущие значения — 100 строк,
8 параметров, 40 импортируемых имён, complexity 15, 48 символов и 5 слов в имени.

Полные счётчики тестов не дублируются в документации: они являются runtime
артефактами конкретного запуска и быстро расходятся с кодом. S22R-проверка
входит в обычный pytest-набор.
