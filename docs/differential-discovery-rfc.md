# Differential Discovery RFC

Дата: 2026-10-14 · Статус: draft, согласованный с владельцем проекта

## 1. Цель

Дать движку орган обнаружения: превращать **измеренные различия поведения**
в формальные нормы через существующую петлю грундинга, не меняя главный
инвариант — finding создаёт только детерминированный grounded оракул.

Дифф — это **генератор норм**, а не источник находок. Цикл:

```
пара наблюдений (control / treatment, один фактор отличается)
  → детерминированный компаратор → DiffReport
  → runtime-факты (paired / differs) + Deficit(unexplained_variance)
  → LLM-грундинг (shape-only контекст) → QDL-предложение
  → валидатор + promotion (action-bound, deterministic primitive)
  → planner → пробы → существующие оракулы P1–P6
  → finding только по FAIL && deterministic && grounded
  → persistence diff:{service}:* → следующий прогон стартует шире
```

## 2. Не-цели

- Не вводим LLM-судью: модель компилирует наблюдённые различия в факты,
  но не решает security-вердикт.
- Не привязываем ядро к транспорту: всё новое входит через доменный словарь
  (`error(action, reason)`, `field(action, name)`, `differs`, `paired`),
  адаптеры его заполняют.
- Не вводим LLM-судью и не отдаём модели сырой транспортный blob. Полное
  наблюдение попадает в модель только как bounded structured `EvidenceView`.
- `differential.Oracle` — verdict-слой для уже измеренного read-back; он не
  создаёт новый comparator и не исполняет повторные запросы.
- Не расширяем словарь ролей и не трогаем Σ.

## 3. Мотивация

1. `scripts/formal_limits_proof.py` машинно доказал: язык счётно-бесконечен,
   заземлённое пространство норм конечно, а реализованная проекция наблюдения
   неинъективна — различимые миры (error details, вложенные payload'ы)
   схлопываются в одинаковое `Observation`.
2. STF-каталог: категории `authorized-attacker` и `oracle-blind` недостижимы,
   потому что гипотезы берутся из документации, а не из поведения.
3. Реактивная петля и персистентность уже построены
   (`accepted-batch:{service}:reactive:*` живёт между прогонами) — не хватает
   только источника сигнала и парного исполнения.

## 4. Дизайн

### 4.1 Паринг (Phase D2)

- `contracts.Spec` в `verification/differential/contracts.py`: control/treatment
  `ScenarioPosition`, различие ровно в одном факторе
  (сравнение факторов выполняется внутри `contracts.Spec`, без
  группировочного ключа доменной модели).
- `BoundPathRunner._execute_step_pair(...)` рядом с `_execute_step`
  (`path_runner.py:456-470`): обе ноги через `ScenarioChecker`, с изоляцией
  output-forwarding между ногами (snapshot/restore `ScenarioChecker._outputs`).
- Пара живёт внутри одного шага: AND-gate пути не меняется, scheduler не
  трогаем.
- `FuzzSession._signature` дополняется дискриминантом `StandState.bindings`,
  иначе дедуп съест вариант, отличающийся только identity.

### 4.2 Компаратор (Phase D1/D3)

Детерминированная чистая функция `(Observation, Observation) → DiffReport`.
Безопасные размерности — **без сырых значений**:

| Размерность | Источник |
|---|---|
| `outcome_differs` | `observed_outcome` |
| `status_differs` | `status_code` |
| `fields_only_control/treatment` | имена полей (shape) |
| `value_differs(field)` | равенство whitelisted-значений (bool, не значения) |
| `error_differs` | наличие/равенство `error_reason` (redacted, cap 512) |
| `latency_class_differs` | класс тайминга против baseline |

### 4.3 Представление диффа в QDL

- Evidence-конструктор `differs(action, dimension)` — регистрируется в
  `STRUCT_SCHEMAS` + `EVIDENCE_EFFECT_CONSTRUCTORS`; dimension из закрытого
  набора: `outcome, status, fields, value, error, latency`.
- Предикат `paired(control_obs, treatment_obs)` — runtime-связь пары.
- Проекция диффа (`differential/projection.py`) эмитит в `Context.RUNTIME`:
  `is`-декларации, `paired(...)`,
  `evidence(obs_treatment, differs(action, dim))` — со ссылкой на action,
  чтобы факт попадал в action-центричный срез LLM.

### 4.4 Deficit и грундинг (Phase D3)

- `DeficitKind += "unexplained_variance"`;
  `classify_variance_event(DiffReport)` →
  `Deficit(axis="variance", context=(diff-сигнатура, ...))`.
- Ключ дедупа дополняется diff-дискриминатором (сейчас `(kind, action, field?)`
  слишком груб — разные диффы по одному action схлопнутся).
- Ось `variance` + инструкция в `axis_grounding.py`: модель получает срез
  графа + **paired shape-only блок** (два наблюдения без значений, только
  имена полей/размерности различий) и обязана вернуть `FormalModelOutput`
  (`prevents`/`exposes`/`has` в proposal-контексте).
- Значения полей в промпт не попадают (prompt-injection поверхность
  `_live_observation_block` не наследуется).

### 4.5 Верификация (Phase D4)

- v1: treatment-нога оценивается существующими оракулами; дифф только породил
  норму. Продвижение — по действующим правилам (`promote_proposal`):
  action-bound + deterministic primitive + self-contained.
- Персистентность: `save(f"diff:{service}:{campaign_key}", ...)`,
  чтение `load_merged(f"diff:{service}:")` в `binder._load_graph`
  (`binder.py:383-390`) + в reactive-загрузки (`grounding.py:261-264,
  334-337`). Бюджет по образцу `CLOUD_DAST_MAX_PROMOTED_NORMS`.
- Finding: `evidence_refs` обеих Observation пары.

### 4.6 Обвязка

- Событие `DiffPairComputed` (event store), счётчики
  `diff_pairs_evaluated / diff_norms_promoted / diff_norms_reused` в
  `CampaignMetrics`, секция `[differential]` в профиле + CLI-флаги.

## 5. Фазы и приёмка

| Фаза | Содержимое | Приёмка |
|---|---|---|
| **D1 сигнал** | `GrpcResult.error_reason` + захват `exc.details()` (cap 512); `ResponseData.field_names` (shape без значений, включая вложенные); `Observation.error_reason`; projector эмитит `error(action, reason)` и `field(action, name)` для shape | SQLi-маркер из `error_message` виден в `Observation` через реальный bench gRPC-сервер (`benchmarks/nsfy_bench/server.py:123` кладёт summary в `context.abort`) |
| **D2 паринг** | `contracts.Spec`, `_execute_step_pair`, изоляция outputs, фикс fuzz-сигнатуры | пара Observations для `export_data`: attacker vs victim, один запрос |
| **D3 формализация** | `differs`/`paired` в словаре, компаратор + `DiffReport`, проекция runtime-фактов, `unexplained_variance` + variance-ось + `ground_variance` | из пары наблюдений создаётся deficit; fake-model возвращает валидную норму; `score_grounding` меряет качество |
| **D4 цикл** | wiring компаратора в pair-flow, persistence `diff:*`, чтение в binder, e2e-тест | **authz-export-other найден без заранее данной нормы** (`app.py:879-893`); второй прогон переиспользует норму; scorer: recall ↑, false_positives = 0 на контроле |

## 6. Риски и митигации

| Риск | Митигация |
|---|---|
| Output-forwarding загрязняет вторую ногу (`reset=False`) | snapshot/restore `_outputs` вокруг ног пары |
| Fuzz-дедуп съедает identity-вариант | `_signature` += `StandState.bindings` |
| `Deficit.key` схлопывает разные диффы | diff-дискриминатор в ключе |
| Diff-факт выпадает из среза LLM (action-центричность) | обязательная ссылка на action в факте |
| Prompt-injection через значения полей | paired-блок строго shape-only |
| Взрыв гипотез от `diff:*` | бюджет продвижения + гейтинг свежести baseline |
| Нет run_id → ненадёжный baseline между прогонами | v1: дифф внутри одного прогона (пары control/treatment), межпрогонный дифф — позже |
| `load_merged` не возвращает rules | v1: дифф-продукты — только факты |
| Норма привязывается не к тому сценарию (false positive на легитимном использовании) | e2e-тест обязан проверять PASS на control-ноге; scorer считает false_positives |

## 7. Тест-план

- Unit: транспорт (error_reason, field_names), компаратор (все размерности),
  словарь (`differs`/`paired` валидны в `evidence`), deficits
  (unexplained_variance), grounding (paired-блок shape-only).
- Integration: `_execute_step_pair` на NSFy Bench (`export_data`,
  attacker/victim).
- E2E (D4): полный цикл через реальные компоненты по шаблону
  `tests/benchmarks/test_stf_chain.py`; цель — `authz-export-other`
  (`benchmarks/nsfy_bench/app.py:879-893`).

## 8. Открытые вопросы

1. Межпрогонный дифф (baseline = прошлый прогон) — после появления run_id.
2. Отдельный oracle-primitive для bare `transition(...)`-норм: сейчас
   state-machine эффекты исполняются через существующие supported effects.
3. `authz-include-payments` из STF v2 не реализован в `app.py` — добавить при
   необходимости расширения бенчмарка.

## 9. Full-fidelity ответ (post-D4)

Статус: реализовано.

Модель развёртывания: движок работает исключительно на **локальных копиях**
приложения (изолированные стенды, синтетические данные) — полный retention
ответа допустим и является дефолтом.

Реализация:

```
Observation.response_tree
      ├─ flat dotted-path → scalar-leaf
      ├─ заполняется gRPC-кодеком и BenchTarget
      ├─ value_differs по всем общим путям
      ├─ Observation.response_digest = sha256(canonical tree)
      └─ marker-поиск по всем string-листьям
```

- `decode_full` обходит nested/repeated/enum/bytes с бюджетами 64 уровня и
  4096 листьев; усечение помечается листом `__truncated__`.
- Whitelist `safe_fields` остаётся только как механизм dataflow-форвардинга
  значений между шагами цепочки (`ScenarioChecker._outputs`), не как
  security-граница.
- LLM получает bounded full-fidelity `EvidenceView`: request/response
  значения, `response_tree`, diff-пути со старыми/новыми значениями,
  error/status/duration, trace и OOB. Это structured data-channel, а не
  свободный текст инструкции; verdict по-прежнему выдаёт только
  deterministic oracle.

## 9.1. Общность дифференциального органа

Движок не специализируется на auth-атаках и не выбирает класс бага. Класс
определяет норма, которую LLM компилирует из измеренного различия; алгебра
покрывает классы как проекции (STRIDE/OWASP). Режимы диффа:

| Режим | Что варьируется | Какие классы ловит |
|---|---|---|
| факторные пары | любой из 6 факторов `ScenarioProfile` (уже в `contracts.Spec`) | access control, BOLA, disclosure |
| payload-пары | тот же сценарий, мутированный запрос | injection, error-handling, парсинг |
| before/after read-back | пишем → читаем, дифф состояния | tampering, mass assignment, state machine |
| timing-пары | классы латентности | blind injection, user enumeration |
| concurrency-пары | параллельные одинаковые пробы | race, double-spend |

Реализованы все пять режимов: факторные пары, payload-пары, before/after
read-back, timing-пары и concurrency-пары. Режим выбирается
`CLOUD_DAST_DIFF_MODES` (comma-list, default `factors`); master-switch остаётся
`CLOUD_DAST_DIFF_MODE`.

Все режимы дают одинаковый конвейер:
`DiffReport → Deficit(unexplained_variance) → LLM-норма → детерминированная
верификация`.

Timing использует минимум три повторения на каждую ногу и median/MAD-класс;
два одиночных duration не считаются variance. Concurrency исполняет четыре
одинаковых probes параллельно, агрегирует allowed/denied/error counts,
status counts, уникальные response digest’ы и опциональный state read-back.
Оба режима имеют preflight-бюджет: эксперимент выполняется целиком или не
выполняется вообще.

## 9.2. Staged semantic grounding и deterministic norm compiler

Статус: реализовано.

Startup grounding больше не запускает `norms` параллельно с семантическими
осями. Порядок теперь такой:

```text
roles / dataflows / exposures / authentication / availability
  → merge semantic proposals
  → enriched graph
  → norms prompt + EvidenceView
  → validator / promotion
```
Это устраняет главный источник однотипных `prevents(N, allowed(A))`: norms-промпт
видит уже заземлённые roles/reaches/exposes, а не только структурный контракт.

`SemanticNormCompiler` дополнительно детерминированно проецирует семантику в
candidate-нормы:

```text
sensitive exposure      -> has(attacker, field(resource, field))
interpreter reach       -> reached(action, sink)
external_net reach      -> external_call(action, marker)
privileged input field  -> changed(resource, field)
numeric duration facts  -> duration(action, ms)
permission gap          -> allowed(action)
```

Компилятор не содержит LLM и vulnerability-словарей. `ThreatIntentCompiler`
теперь выбирает effect по доступной evidence и не делает fallback на
`allowed(action)`.

`differential.Oracle` замыкает read-back цикл: promoted `changed`-норма
получает PASS/FAIL/UNSCOREABLE по паре read-before/read-after, а finding
по-прежнему возможен только при deterministic grounded FAIL.

## 9.3. Product policy для generic outcome-находок

Generic `allowed(action)` остаётся детерминированным grounded сигналом, но не
каждый permission gap является продуктовым finding. Finding поднимается только
при security-relevant сигнале:

```text
object reference / victim resource
privileged/admin permission gap
```

Все конкретные эффекты — `changed`, `has`, `reached`, `external_call`,
`duration`, sequence/transition — остаются security-relevant без дополнительного
гейта. Ordinary permission gap сохраняется в event log как lead (`CheckCompleted`)
и не публикует `FindingRaised`.

## 10. Внешняя валидация (Phase E)

Статус: принято; первый таргет — OWASP Juice Shop.

Собственный бенчмарк (NSFy Bench) остаётся regression-слоем (субстрат +
grounding), но не доказывает transfer на цель, которую мы не проектировали.
Внешняя валидация — живые независимые таргеты, а не датасеты. Для DAST
стандарт — уязвимое приложение как чёрный ящик.

Детальный план: `docs/external-validation-juice-shop.md` — курируемая
API-only когорта, REST-контракт, generic HTTP/JSON transport, скоринг по
переходам `Challenges.solved: false → true`, артефакты прогона и сравнение
с Nuclei/LLM-agent на одинаковом бюджете.

Первая итерация — P0-подмножество Juice Shop, затем crAPI и VAmPI как
независимые повторы того же протокола.

E1–E2 (REST-контракт и HTTP transport) — адаптеры, необходимые продукту
независимо от валидации: без них
claim «application-agnostic» опирается только на gRPC/Neo4j-путь.
