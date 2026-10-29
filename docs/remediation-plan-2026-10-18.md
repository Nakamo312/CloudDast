# Remediation plan — Cloud DAST (NSFy), 2026-10-18

## 1. Контекст и источники

План построен на полном аудите от 2026-10-18 (шесть независимых проходов +
родительская сводка) и закрывает четыре оси, а не только security:

- **корректность логики** — ложные FAIL/PASS, нарушение инвариантов исполнения,
  бюджеты, identity, replay;
- **дизайн/архитектура** — QDL как единственный источник истины, layer model,
  единые политики, событийная модель, DI;
- **качество кода** — god-методы, дублирование, dead code, конфигурация;
- **security-гигиена** — доверенные границы, данные, witness-аутентичность,
  integrity персистентности.

Источники находок:

- [`security-audit-2026-10-18.md`](../security-audit-2026-10-18.md) — полный
  отчёт (ID находок: A-1, A-2, H-*, SYN-*, D-*, LP-*, DW-*, FE-*, INF-*, WF-*);
- [`docs/audit-remediation-2026-10-16.md`](audit-remediation-2026-10-16.md) —
  прошлая волна (статусы C1–M10 сверены аудитом);
- сводка дизайн/quality-прохода — раздел «Дизайн-аудит и качество кода»
  основного отчёта.

## 2. Принципы работы с планом

1. **Приёмка = behavior-тест.** Каждая задача закрывается только тестом
   наблюдаемого поведения (adversarial/negative), не проверкой формы объектов
   (`review_policy.md`).
2. **Никакой тихой деградации.** Ошибка солвера/фильтра/модели — явный статус
   в результате, никогда «пустое множество = чисто».
3. **QDL — единственный executable source of truth.** Naming-эвристики из
   исполняемой семантики удаляются, а не дополняются.
4. **Одна политика на сквозную заботу.** Promotion, guardrail, бюджет, identity —
   по одному объекту политики, применяемому во всех путях.
5. **Без compatibility-обёрток.** Внутренние миграции делаются сразу
   (правило AGENTS.md); каждый rename/move обязан улучшать границу.
6. Статус задачи обновляется в этом файле; одна задача — один PR; ruff + pytest
   обязательны в каждом PR.
7. **Moat = только формальный слой.** Своим остаётся QDL-субстрат: контексты,
   нормы, promotion policy, вердикт-гейт, планирование путей,
   differential-семантика. Всё прикладное — IAM-модель авторизации, транспорт,
   хранилище, сценарии/фикстуры — **заменяемые адаптеры**; связанность ядра с
   ними — архитектурный долг (B3/B8, H3/H4/H7), а не ценность. Сенсоры
   (генерация, коллабораторы, корпуса) — приоритет библиотекам;
   эвристические детекторы — только lead-уровень (паркинг), никогда
   auto-promotion.

Приоритеты:

- **P0 (Wave 1)** — блокеры корректности вердиктов и доверенных границ;
- **P1 (Wave 2)** — дизайн-унификация, witness-аутентичность, integrity;
- **P2 (Wave 3)** — качество кода, cleanup, конфигурация.

Effort: S ≤ 0.5 дня, M 0.5–2 дня, L > 2 дней (на одного инженера).

Статусы: ☐ todo · ✅ done (с датой) · 🔶 частично · ❌ отклонена. Волна 1
начата 2026-10-19:
A2, A15, D1 закрыты (детали — в `security-audit-2026-10-18.md`, раздел
«Wave 1»).

## 3. Трек A — Корректность логики

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| A1 | Убрать auto-promotion extra-предикатов (`requires/accepts/binds/required/applies_to`) либо прогнать их через общую политику: все non-action термы source-declared, evidence grounding, глобальные caps | `grounding.py:45-59,595-660`, `proposal_promotion.py` | A-1, LP-F01 | P0 | M | — | ✅ 2026-10-20 (extra-предикаты паркуются в proposal-контексте) |
| A2 | Permission-gap считать только по Clingo IAM-выводу (`may` derived), не по отсутствию явного факта | `semantic_norm_compiler.py:300-343` | A-1, DW-F2 | P0 | M | A1 | ✅ 2026-10-19 (остаток — A10: ON_RESOURCE/`applies_to`) |
| A3 | Единый promotion policy: axis-promotion за явным флагом, глобальные caps (не per-batch), action-scope для reactive/alternatives/variance, measured reach через политику | `grounding.py`, `run_provider.py:249-289`, `binder.py` | A-2, DW-F1, LP-F09/F13/F14 | P0 | L | A1 | ✅ 2026-10-20 (`PromotionPolicy` + env-флаг и глобальные caps) |
| A4 | Ungrounded FAIL: proximity=0, reward/bandit не растут, coverage cell не закрывается | `proximity.py`, `session.py:210-257`, `checks/runner.py`, `coverage.py`, `norm_coverage.py` | FE-H2, WF-09 | P0 | S | — | ✅ 2026-10-20 (ungrounded FAIL → UNSCOREABLE + zero proximity/reward/bandit) |
| A5 | Latency error-гейт: ERROR/UNKNOWN → UNSCOREABLE; baseline только по доставленным observations | `latency.py:93-116`, `live_workflow.py:804-815`, `path_runner.py` | WF-F04, DW-F16 | P0 | S | — | ✅ 2026-10-20 (delivered-only baseline + error gate) |
| A6 | SequenceOracle: успешная непрерывная подпоследовательность вместо «все attempts успешны» | `sequence.py:59-79` | FE-H3 | P0 | S | — | ✅ 2026-10-20 (longest successful contiguous run) |
| A7 | Marker: echo ≠ sink-witness; без grounded `probe_fields` → UNSCOREABLE/LEAD; 404-heuristic учитывать sink type | `marker.py:91-147`, `goal_payload.py:146-238` | FE-H4, FE-M5, D-07 | P0 | M | — | ✅ 2026-10-20 (echo-gate + sink-aware 404) |
| A8 | Identity-нормы scoreable: actionless binding вместо `args[1]` как action | `norm_view.py:89-99`, `grounded.py`, `primitive_router.py` | FE-H5 | P0 | S | — | ✅ 2026-10-20 (identity остаётся actionless и scoreable) |
| A9 | Response completeness: `__truncated__`/`not_available` → UNSCOREABLE в oracles и comparator; digest усечённых ≠ полный | `protobuf.py`, `grpc.py`, `field_exposure.py`, `marker.py`, `comparator.py` | D-05 | P0 | M | — | ✅ 2026-10-20 (incomplete response gate + digest separation) |
| A10 | IAM-алгебра: `part_plus`/ON_RESOURCE reflexivity, `applies_to` в `may`, unprefixed actions не теряются threat-компилятором | `clingo_engine.py:40-43,146-149`, `stand_projection.py`, `contract_projection.py:993`, `threat_compiler.py:232-280` | DW-F3/F5/F9 | P1 | M | B4 | ✅ 2026-10-20 (`part_plus` reflexivity + `applies_to` gate + positional threat extraction) |
| A11 | State machine: runtime evidence → grounded violation; mismatch с учётом reachability; bounded/incomplete статус при depth-limit | `state_machine.py:209-399`, `observation_projection.py` | DW-F4 | P1 | M | — | ✅ 2026-10-20 (runtime-grounded violation + reachability-aware mismatch + `bounded_incomplete`) |
| A12 | Тихая деградация: executable rules сохраняются при фильтрации; invalid graph ≠ пустой; Clingo error ≠ «нет угроз»; пустой LLM-ответ не кешируется | `semantic_norm_compiler.py:290-295`, `payload_hints.py:95-100`, `threat_compiler.py:223-229`, `validator.py:176-249` | DW-F6, DW-F10, LP-F05 | P1 | M | — | ✅ 2026-10-20 (filter_executable_graph + явные ошибки + empty-response guard) |
| A13 | Execution identity: output-forwarding изолирован per path; ключ readback/concurrency evidence `(method, scenario, resource, invariant)`; multi-round бюджет по checks/live-calls | `runner.py`, `path_runner.py:170,554-576`, `live_workflow.py:318-328,506-509` | WF-F01/F02/F03, SYN-6 | P0 | M | — | ✅ 2026-10-20 (per-path forwarding + EvidenceKey + live-call budget) |
| A14 | AND-chain: продвигать шаг только по FAIL инварианта, соответствующего эффекту edge, а не `candidates[0]` | `binder.py:1441-1459`, `application/verification/planning.py`, `path_runner.py:341-456` | WF-F06 | P1 | M | — | ✅ 2026-10-20 (edge_effects → effect-bound invariant) |
| A15 | Provenance-политика семантических ролей: LLM не может вводить `sensitive`/`credential`/`privileged`/sink-классификации — только source-декларация, оператор или evidence-политика; структурные факты (`exposes`) можно из evidence. Закрывает BL-01 — минимальный LLM→finding путь | `proposal_promotion.py:425-459`, `grounding.py:548-587`, `semantic_norm_compiler.py:80-102` | BL-01, A-1 (уточнение) | P0 | M | A3 | ✅ 2026-10-19 (evidence-exception: наблюдённые response-поля; + per-axis allowlists) |
| A16 | Prefiltered fuzz loop: solver seed не потребляет fuzz-слот; исполнение через `session.next()` или one-shot; recorded check = фактически исполненный check (reward/feedback по исполненному) | `path_runner.py:316-325,395-403,650-681`, `fuzzing/session.py:177-271` | BL-02 | P0 | M | — | ✅ 2026-10-20 (preview + next per executed check) |
| A17 | Replay outcome: `blocked` ≠ `completed` (хранить previous outcome, явная retry-политика); campaign/run scope для events/coverage/terminal events — исторические события не закрывают текущую кампанию | `path_runner.py:173-227,578-628`, `live_workflow.py:494-499`, `coverage.py:569-618` | BL-17, BL-18 | P0 | S | B5 | ✅ 2026-10-20 (event scope + previous outcome/retry policy) |
| A18 | Latency: baseline threshold реально используется (или baseline удаляется); baseline только по delivered-семплам; отдельный availability-оракул для explicit timeout (не blanket-запрет ERROR) | `latency.py:96-116`, `live_workflow.py:794-816` | BL-20, FE/A5-уточнение | P0 | S | — | ✅ 2026-10-20 (runtime threshold + AvailabilityOracle) |
| A19 | Partial failures: аккумулялировать executed checks/observations до raise; partial result object для pair/readback/concurrency (одна нога упала после live call — вызовы и события не теряются из бюджета) | `runner.py:164-317`, `path_runner.py:802-908`, `live_workflow.py:851-1140` | BL-06 | P1 | M | B14 | ✅ 2026-10-20 (partial results preserve executed work) |
| A20 | Lead-политика классификаций: protected-role без provenance создаёт норму-подозрение с UNSCOREABLE-вердиктом (видна в отчёте как lead, не finding), а не отбрасывается. Паркинг уже реализован (2026-10-19), это следующий шаг — сделать запаркованные гипотезы видимыми в рантайме | `proposal_promotion.py`, `norm_view.py`, `oracles/` | A15-residual, BL-01-баланс | P1 | M | A15 | ✅ 2026-10-20 (classification leads + report rendering) |
| A21 | Semantics закрытия дефицитов: `record_success` закрывает deficit по любому non-None grounding-результату, без проверки, что gap реально закрыт (бесполезный/чужой граф закрывает задачу навсегда — BL-28); ключ `blocked_step` = kind+action без step/effect/path — разные blocked-эффекты одного действия схлопываются (BL-29; ключи других видов уже расширены field/fields/diff/resource_type) | `deficits.py:467-477`, `live_workflow.py` drain | BL-28, BL-29 | P1 | M | — | ✅ 2026-10-20 (semantic closure + path/step/effect key) |
| A22 | Ре-оценка поздних OOB-свидетельств: уникальный marker означает, что callback, пришедший после таймаута кандидата, никогда не переоценивается — реактивность теряет async-сигналы; нужен pending-OOO re-evaluation по marker или campaign-final sweep | `oracles/oob.py:41-60`, `runtime/oob.py` | BL-27 | P2 | S | D4 | ✅ 2026-10-20 (pending marker/sweep re-evaluation + final Interactsh drain) |

## 4. Трек B — Дизайн / архитектура

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| B1 | Убрать naming-эвристики из executable-семантики (6 мест): `state/status`, `{type}_id`, irreversible-глаголы, get/list → readback, owner «первый другой principal», token-матчинг типа. Замена — явные QDL-факты; нет факта → deficit, не догадка | `observation_projection.py`, `live_contracts.py`, `provisioning.py`, `step_setup.py`, `binder.py`, `live_workflow.py` | WF-F16, WF-F07, D-08, H5/H6 | P1 | L | — | ✅ 2026-10-20 (explicit QDL facts replace naming heuristics) |
| B2 | Layer model по исправленной модели AGENTS.md (ports-and-adapters; модель уже поправлена в доке 2026-10-18). Конкретно: V1 `Guardrail` → `application/ports` (`session.py:29`); V2 подписка progress через `EventPublisher`-порт (`progress.py:39`); V3–V5 read-модели `CoverageMatrix`/`CampaignMetrics` → `application/reporting` (`progress.py:40-41`, `report.py:7`); V6 `CloudProvisioner` → infrastructure (`provisioning.py:27`); V7 `InvocationRepository` → `application/ports` + Dishka (`invocation.py:16-18`, `grpc_target.py:23-32`); V8 инжекция `SessionFactory` в `auto_grounding` (`run_provider.py:522-543`) | `fuzzing/session.py`, `presentation/`, `provisioning.py`, `runtime/invocation.py`, `grpc_target.py`, `run_provider.py` | FE-M3, D-20, WF-F17, INF-11, INF-13 | P1 | M | — | ✅ 2026-10-20 (ports-and-adapters refactor) |
| B3 | Единый semantic-role alphabet: один источник истины; prompts/catalog/coverage деривятся из него; validator/promotion отклоняют unknown roles; engine-roles (`probe_target`, `setup_skip`) не принимаются от LLM | `axis_grounding.py`, `threat_model.py`, `class_catalog.py`, `semantic_norm_compiler.py` | H1, M4, LP-F10, FE-M7 | P1 | M | — | ✅ 2026-10-20 (single semantic-role alphabet + rejection) |
| B4 | Канонизация action ID на ingestion-границе (`action:` префикс один раз); threat-парсер позиционный по предикату | `state_machine_ingestion.py`, `threat_compiler.py`, `oracles/action_alignment.py` | H2, DW-F3 | P1 | S | — | ✅ 2026-10-20 (canonical action ID + positional parser) |
| B5 | Событийная identity: `path_id` = canonical identity (graph hash, kind, actions, effects, invariants, scenario), полный SHA-256; semantic idempotency key для событий; context-валидация `FactVerified`/`IntentProposed`/`EvidenceRecorded` | `application/verification/planning.py:718-729`, `binder.py:1151-1187`, `events.py`, `campaign.py`, `jsonl_store.py` | WF-F11, D-10, D-25, SYN-5 | P1 | M | A13 | ✅ 2026-10-20 (canonical path/event identity + semantic replay + context validation) |
| B6 | Boundary API LiveWorkflow ↔ BoundPathRunner: публичный контракт вместо private-методов (`_execute_step_pair`, `_pair_check`, `_execute_readback`) | `live_workflow.py`, `path_runner.py` | WF-susp-10 | P1 | M | — | ✅ 2026-10-20 (public `execute_step_pair` / `pair_check` / `execute_readback`) |
| B7 | Transport-neutral domain: transport-typed status (http/grpc) вместо 100–599; Yandex-иерархия → adapter DTO | `domain/models.py`, `grpc.py`, `grpcio_transport.py` | H3, H4, D-09, D-19 | P2 | L | — | ✅ 2026-10-20 (`Observation.transport_status: HttpStatus \| GrpcStatus` — discriminated union; HTTP-диапазон 100–599 валидируется только в `HttpStatus` и HTTP-адаптере; таблица gRPC→HTTP удалена, статус → `AccessOutcome` остаётся в адаптерах; оракулы больше не сравнивают gRPC-наблюдения с HTTP-числами) |
| B8 | Vendor-alias из generic infra (`yandex.cloud.priv`) → adapter/profile | `neo4j/invocations.py:88-102` | H7, INF-12 | P2 | S | — | ✅ 2026-10-20 (profile-declared method-prefix aliases wired into composition) |
| B9 | DI-чистота: инжекция `SessionFactory` в `auto_grounding` (один driver lifecycle); все durable repositories через Dishka-порты | `run_provider.py:522-543`, `app_provider.py`, `live.py` | INF-11, INF-13 | P2 | M | B2 | ✅ 2026-10-20 (AppScope durable repositories + in-container live target) |
| B10 | Differential через общий execution path: `StepSetupResolver`, бюджет, dedup по `(action, scenario)` | `live_workflow.py:560-628,880-1197` | WF-F08 | P1 | M | A13 | ✅ 2026-10-20 (shared setup/budget/dedup boundary) |
| B11 | Порт `FormalGrounder` (application/ports); grounding-раннер (треды/executor) вне application; workflow-колбэк через порт — устранить runtime-зависимость application→workflow; threading-контракт задокументирован | `grounding.py:437-477,660-740`, `run_provider.py:569-571`, `axis_grounding.py:526-570` | N4, N7 | P1 | M | — | ✅ 2026-10-20 (`FormalGrounder` + `GroundingRunner` ports) |
| B12 | Presentation-каналы: убрать `progress` из `LiveRequest`; новый `EventSubscriber`-порт; события `PhaseChanged`/`PlanReady`/`CoverageSnapshot`; metrics как immutable snapshot; markdown использует существующий `QdlCoverageMatrixView` | `live_contracts.py:521-546`, `ports/events.py`, `live_cli.py:82-85`, `markdown/report.py` | N9, N10, T4 | P1 | M | — | ✅ 2026-10-20 (`EventSubscriber` + presentation events + immutable plan/coverage snapshots) |
| B13 | Разделить `CampaignMetrics`: runtime-счётчики с lock (workflow) → события → immutable snapshot для презентации; threading-контракт `EventPublisher`; изоляция/lock рендерера (активная гонка N5) | `metrics.py`, `axis_grounding.py:839-1022`, `progress.py` | N5, N6 | P1 | M | — | ✅ 2026-10-20 (locked runtime metrics + immutable snapshot + renderer lock) |
| B14 | `Budget`-объект: единый владелец checks/live-calls/setup/diff-legs; удалить `budget_offset`-протаскивание и дубль `_fits_budget` | `path_runner.py:784-800`, `live_workflow.py:318-328,737-747` | N18, SYN-6 | P1 | M | — | ✅ 2026-10-20 (single `Budget` owner; no `budget_offset`/duplicate `_fits_budget`) |
| B15 | Root `__init__` god-import → минимальный (фасады только в composition/CLI) — разблокирует честный import-lint | `cloud_dast/__init__.py` | N12 | P2 | S | — | ✅ 2026-10-20 (root package reduced to docstring; no import facade) |
| B16 | Event store: in-memory projection/cursor per consumer (убрать flock-holding reads и O(rounds×N) перечитывания) | `jsonl_store.py:36-63`, `path_runner.py:185-192`, `finding_evaluator.py:55-77` | N13 | P1 | M | B5 | ✅ 2026-10-20 (in-memory store + per-consumer cursors/projections) |
| B17 | Source-аннотации data-classification: производитель source-ролей/sink-типов — проекция из DocPage/DESCRIBES-метаданных контрактного графа + курируемый classification-профиль. Сегодня source-канал не существует (проверено rg), всё держится на evidence-исключении | `contract_projection.py`, `ingestion.py`, профиль | A15-residual | P2 | M | — | ✅ 2026-10-20 (contract-context source roles/sink reachability + curated label profile) |
| B18 | Operator approval: чтение запаркованных `proposal:{service}:*` источников + CLI/явное продвижение классификаций оператором (паркинг реализован 2026-10-19, approval-очереди нет) | `grounding.py`, CLI | A15-residual | P1 | M | A15 | ✅ 2026-10-20 (`approval_cli` + deterministic approval queue + hash-chained audit log) |
| B19 | Generic policy adapter: эмиттер `may/owner/binding/grants/requires/targets` как replaceable rule-pack вместо Yandex-IAM-специфичного `stand_projection` (доказано внешним разбором: RBAC/DAC/MAC компилируются в один `may`-интерфейс). `GenericPolicyProjector` доведён до production wiring | `stand_projection.py`, `clingo_engine.py` (rule-pack), `application/verification/formal/policy_projection.py` | engine-runtime §10-11, H3 | P2 | M | B3 | ✅ 2026-10-20 (Neo4j source → `PolicySnapshot` → `GenericPolicyProjector`; replaceable `PolicyRulePack`; RBAC/DAC/MAC → `may`) |
| B20 | HTTP/JSON Target-адаптер: порт `Target` уже transport-agnostic, нужен адаптер + protobuf-independent Observation-проекция (первый шаг к non-gRPC целям). `HttpJsonTarget` доведён до composition selection | `infrastructure/runtime/http_json.py` | engine-runtime §11 | P2 | M | — | ✅ 2026-10-20 (`CLOUD_DAST_TARGET=grpc|http-json`; transport-agnostic `Invocation` and `TokenProvider`; protobuf-free Observation projection) |
| B23 | InterestPrioritizer — ablation-эксперимент по переносу обучения с уровня генератора на уровень work item (литература: Patil&Kanade energy allocation, TCP-MAB, active learning; дизайн уже в campaign-automaton: Strategist score = coverage gain × bandit prior × reward state, Layer 5 campaign-critic «proposes priorities»). Варианты: A фикс-генератор / B текущий бандит / C learned work-item priorities / D оба. Реализация C: bandit-prior как advisory-фича cold_score (детерминированная комбинация, seeded/логируемая) ИЛИ LLM campaign-critic через reactive consultation protocol. Метрики: findings/budget, first-finding time, cells closed, blocked recovered, deficit closure, LLM cost. **Gate: чистота сигналов A4/A16/A17/A21 — иначе политика учится на отравленных признаках** | `scheduler.py`, `deficits.py`, `benchmarks/nsfy_bench` | research-extrapolation §5, campaign-automaton Layer 5, внешний разбор 2026-10-19 | P1 | M/L | A4, A16, A17, A21 | ✅ 2026-10-20 (deterministic seeded cold_score + quarantine-aware signals + benchmark-only deficit/evidence arm) |
| B24 | Formal persistence → SQLite-адаптер за существующими портами/репозиториями: `qdl_fact(content_hash PK, canonical_json)`, `qdl_rule`, `qdl_issue`, `qdl_projection` + `projection_fact(projection_id, content_hash)`; `INSERT OR IGNORE` вместо Cypher `MERGE`; latest-by-`saved_at` → `ORDER BY … LIMIT 1`; WAL для конкурентного чтения. Neo4j остаётся **только read-адаптером чужих stand-данных** (Live*-ноды мы никогда не создаём; связка с B19) — наших записей в сетевой СУБД больше нет. Обоснование (проверено 2026-10-20): во всём neo4j-слое ноль variable-length paths / shortestPath / APOC / GDS, все запросы фиксированные 0–2 хопа; `formal_repository` — content-addressed document store с двумя FK; reasoning живёт в Clingo in-memory. Бонус: минус сетевой сервис из security-периметра (D5), минус auth/flood-поверхность, нулевая ops-нага. Debug-визуализация — экспорт DOT/GraphML | новый `infrastructure/sqlite/`, `formal_repository`, `invocations`, `composition/` | аудит necessity 2026-10-20 (Neo4j vs SQLite) | P1 | M | B2 | ✅ 2026-10-20 (SQLite formal repository + WAL + idempotent writes) |
| B25 | **Local/protocol targets — трек «бинарь+спека» / IoT-протокол**: (1) `EvidenceChannel` порт — обобщение OOB из специального случая в generic evidence-channel (response / oob / **ebpf** / app-log), join по correlation-id/маркеру; eBPF-адаптер: exec/file/net-события, маркер в argv = прямой RCE-witness без OOB-канала; (2) spec-projector — спека вводов бинаря / описание сообщений протокола → QDL-факты (та же контрактная проекция, другой источник); (3) `LocalProcessTarget` / `SocketTarget` адаптеры (порт `Target` транспорт-агностичен, grammar engine schema-driven по построению — FieldSpec не знает источника полей). Ядро не меняется — ports-and-adapters; продолжение B19/B20. Позиционирование: движок = автоматический verification-стейдж SAST-пайплайна (SAST — recall-движок кандидатов, движок — precision-движок вердиктов; eBPF — сильнейший witness-канал для локальных целей) | `application/ports/` (EvidenceChannel), `infrastructure/runtime/` (LocalProcessTarget, SocketTarget), `contract_projection.py` / новый spec-projector | решение владельца 2026-10-20 (application-agnostic: бинарь+спека, IoT-протокол как схема) | P2 | L | B20, S8 | ✅ 2026-10-21 (generic channel + channel filter, eBPF witness, SpecProjector, local/socket targets) |
| B26 | **Снос Neo4j-зависимости — file-based stand source как дефолт** (решение владельца 2026-10-21: «не нравится, что зависим»). Neo4j сейчас — только read-источник stand-данных: `Neo4jStandProjector` делает 4 Cypher-запроса (LivePrincipal→LiveBinding→ON_*→scope, LiveResource, LiveFolder, LiveCloud) → generic `PolicySnapshot` → `GenericPolicyProjector` (IAM-специфика уже вынесена, B20). Что делаем: (1) `FileStandSource` — `stand.json` → `PolicySnapshot` → тот же `GenericPolicyProjector` (pydantic-native, одна строка десериализации); формат: `bindings[]` (subject/role/scope), `resources[]`, `containments[]` — уже generic; (2) утилита экспорта Neo4j → JSON для миграции живого стенда; (3) wiring `CLOUD_DAST_STAND_SOURCE=file\|neo4j`, дефолт `file`; (4) `pyproject`: `neo4j` → `[project.optional-dependencies]`; (5) `formal_cli` → sqlite-репозитории. Принцип хранения: **стенд — input-snapshot (launch fixture), не operational data** → JSON (git-diffable, ревью, fixtures для e2e/benchmark, консистентно с TOML-профилями/YAML-корпусом/file-кешами); formal store (QDL facts, events) — operational → SQLite (B24, уже дефолт); опциональный SQLite-mirror для больших живых стендов — вне scope. Итог: `pip install cloud-dast` без neo4j-driver; стенды как версионируемые JSON; Neo4j — optional extra за портом `StandSource` для тех, у кого данные там живут | `infrastructure/stand/` (новый FileStandSource), `composition/run_provider.py:647` (wiring), `composition/stand_cli.py`, `composition/formal_cli.py`, `pyproject.toml`, `profiles/` | решение владельца 2026-10-21; recon: `stand_projection.py` уже generic через PolicySnapshot | P1 | M | B24 ✅ | ✅ 2026-10-21 (file default + Neo4j export/optional extra + SQLite CLI) |

## 5. Трек C — Качество кода

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| C1 | Декомпозиция god-методов по use-case boundary (инкрементально, начиная с топ-6: `execute_round` 408, `LiveWorkflow.execute` 296, `_drain_chain_session` 224, `_build_execution_view` 166, `_drain_reactive` 138, `_promote` 136). Цель: ≤15 функций ≥80 строк | `path_runner.py`, `live_workflow.py`, `binder.py`, `grounding.py` | quality-сводка | P2 | L | A-трек P0 | ✅ 2026-10-20 (top-6 god methods decomposed; 0 functions ≥80 lines in target files) |
| C2 | Дедуп LLM-запросов `_ground_custom`/`_ground_slice` (~80 строк) | `axis_grounding.py:826,977` | M6 | P2 | S | — | ✅ 2026-10-20 (shared axis-result builder + common response schema) |
| C3 | Dead-code cleanup: `ensure_grounded`, `AllowAllGuardrail` → tests, `classify_path_event` → tests, `IntentProposed` (emit или удалить), `Neo4jLiveRepository` (порт или убрать экспорт), `project_stride`, `payload_hint`, проверить execution path `SequenceExecutor`, удалить `reviewer.pyc` | по списку в отчёте | ledger-lows, quality-сводка | P2 | M | — | ✅ 2026-10-20 (dead paths removed; `IntentProposed` retained as a consumed event contract; `reviewer.pyc` absent) |
| C4 | `CampaignMetrics` — lock; `ClueCache` — bounded/deque вместо O(n²) | `metrics.py:252-265`, `backtracking.py:95-151` | WF-susp-6/7 | P2 | S | — | ✅ 2026-10-20 (metrics lock hardened; bounded clue cache) |
| C5 | Lockfile с hashes; `pytest` → dev-only | `requirements*.txt`, `Dockerfile` | D-18 | P2 | S | — | ✅ 2026-10-20 (`uv.lock` + hashed requirements exports; pytest/ruff dev-only) |
| C6 | Redaction/bound для логирования raw model response (2000 chars) и target-значений | `axis_grounding.py`, `model.py` | LP-susp-2 | P2 | S | D3 | ✅ 2026-10-20 (2000-char diagnostic bound for model/target logs) |
| C7 | Compose/Docker hardening: порты 127.0.0.1, secret modes, `NEO4J_AUTH` вне env | `compose.yaml`, `Dockerfile`, `.env.example` | D-15, D-16 | P2 | S | — | ✅ 2026-10-20 (loopback Neo4j ports + file-backed auth secrets + private secret mounts) |
| C8 | Магические константы → именованный config-модуль (probe timeout, `max_depth`, leaves/depth, semantic facts, hash length) | по месту | quality-сводка | P2 | S | — | ✅ 2026-10-20 (единый `cloud_dast.config` + покрытие defaults) |
| C9 | Sanitize service slug в default event filename (path traversal) | `live_cli.py:62-70` | INF-14 | P2 | S | — | ✅ 2026-10-20 (service slug sanitised in default event filename) |
| C10 | Markdown output-encoding: escape `|`/newline/backtick/HTML для всех target-контролируемых значений | `presentation/markdown/report.py:52-90` | N22, D-11 | P1 | S | — | ✅ 2026-10-20 (contextual HTML/Markdown escaping for all target-controlled report values) |
| C11 | O2-proof: включить `has`/`transition`; формализовать grounding-policy как проверяемое ограничение (или ослабить заявление O2/O4) | `scripts/formal_limits_proof.py:92-131`, `domain/formal.py` | E-1 (матревью) | P2 | S | — | ✅ 2026-10-20 (`has`/`transition` graph references + machine-checked grounding policy) |
| C12 | «unknown»-сентинел в state machine: реальное состояние с именем `unknown` неверно классифицируется как partial | `state_machine.py:331-339` | A-8 (матревью) | P2 | S | — | ✅ 2026-10-20 (объявленное состояние `unknown` сравнивается как обычный source-state; сентинел работает только для необъявленного идентификатора) |
| C13 | Решить и привести к единому виду бандит в `ChainFuzzSession`: сейчас базовый campaign-бандит (осознанно — learning across chains), per-action contextual-фильтр не действует на chain-руки; либо задокументировать выбор, либо добавить контекст | `fuzzing/session.py:335+` | engine-runtime §7/§15 | P2 | S | — | ✅ 2026-10-20 (campaign-scoped bandit documented and enforced: chain calls omit per-action context) |
| C14 | Generator bandit → детерминированный селектор без River: inline Beta-сэмплер (~20 строк) вместо `river.bandit.ThompsonSampling`; переименовать `ContextualGeneratorBandit` в честное имя (`FailingStrategyFilter`) — это per-action failure-фильтр, а не контекстный бандит; `pytest` из requirements.txt → requirements-dev.txt. River импортируется только в selector.py. Возврат MAB-библиотеки — только после B23-данных | `generators/selector.py`, `requirements.txt`, `requirements-dev.txt` | аудит necessity 2026-10-20; B23 | P2 | S | — | ✅ 2026-10-21 (inline Beta sampler + `FailingStrategyFilter`; River removed) |
| C15 | `presentation/console/progress.py` (830 строк, 75% presentation-слоя) → ~100 строк простого логгера; `rich` уходит из зависимостей целиком (используется только там) | `presentation/console/progress.py`, `requirements.txt` | аудит necessity 2026-10-20 | P2 | S/M | — | ✅ 2026-10-21 (simple thread-safe logger; `rich` removed) |
| C16 | **Снос агентного слоя** (решение 2026-10-20; дрейф видения vs реализации задокументирован в engine-runtime §16 и campaign-automaton Layer 5): удалить `application/verification/agent/` целиком + тесты; вычистить wiring — `live_workflow._drain_agent_layer`, параметр/импорт `agent_layer`, env-парсеры и блок в `run_provider`. Перед сносом перенести `_DEFICIT_PRIORITY` + evidence tie-break (~15 строк из campaign_critic) в benchmarks как cold_score-руку B23. Обоснование: 3 из 4 ролей — доказанные дубликаты ядра (таблица `_DEFICIT_CONSULTATION_KINDS` 1:1, тот же kind/action/slice); ReflectionNode конфликтует с политикой `missing_baseline`; namespace-префиксы ломают дедуп с `consultation_id` ядра. Остаётся: EventGraph/CampaignDag (потребители вне агентов: campaign.py, path_runner.py), consultation-протокол (в ядре, обслуживает reactive-цикл) | `application/verification/agent/`, `live_workflow.py`, `run_provider.py`, tests | аудит 2026-10-20 (сверка Layer 5 с кодом), engine-runtime §16 | P2 | M | — | ✅ 2026-10-21 (agent package/tests and wiring removed; B23 arm migrated; Campaign DAG and consultation protocol preserved) |

## 6. Трек D — Security-гигиена (параллельный)

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| D1 | Transport chokepoint: endpoint/network allowlist; IAM-токен прикрепляется только после destination policy; запрет raw `Target` в обход guardrail | `grpcio_transport.py`, `grpc.py`, `guardrails.py`, `grpc_target.py` | H-1, INF-01, SYN-4 | P0 | M | — | ✅ 2026-10-19 (`EndpointPolicy` + `AllowlistEndpointPolicy` + `GuardedTarget`; остатки: lint-правило raw Target, `.env.example`) |
| D2 | Token identity binding: убрать global fallback для explicit identity; детект коллизий identity-key; короткий TTL файловых токенов | `tokens.py:36-130`, `live.py` | INF-04, D-04 | P0 | S/M | — | ✅ 2026-10-20 (identity isolation + collision guard + file TTL) |
| D3 | Data minimization: только `EvidenceView` в промптах (убрать raw blocks); redaction-политика для LLM и event log; 0600/0700 для артефактов | `axis_grounding.py:645-735,1377-1433`, `evidence_view.py`, `jsonl.py` | D-01, D-02, LP-F06, INF-07 | P1 | M | — | ✅ 2026-10-20 (EvidenceView-only prompts + redaction/private artifacts) |
| D4 | Witness authenticity: OOB source validation, marker echo policy, paired latency baseline, политика для adversarial target | `oob.py`, `oracles/oob.py`, `marker.py`, `latency.py` | SYN-2, INF-02 | P1 | M/L | A5, A7 | ✅ 2026-10-20 (OOB source validation + marker echo + paired latency + adversarial target policy) |
| D5 | Persistence integrity: grounding cache key/version/hash + инвалидация по accepted facts; event/OOB hash-chain; защита reserved namespaces; атомарный Neo4j save | `grounding_cache.py`, `jsonl_store.py`, `formal_repository.py`, `ingestion.py` | SYN-3, INF-08/09/10, LP-F05/F15, DW-F15 | P1 | M/L | A12 | ✅ 2026-10-20 (cache/event integrity + reserved namespaces + atomic save) |
| D6 | OOB listener hardening: expected marker set, rate limit, size caps, bounded threads/queue | `oob.py` | INF-03 | P2 | S/M | D4 | ✅ 2026-10-20 (loopback-only fallback + expected markers + rate/size caps + bounded server thread/queue; external Interactsh owns DNS/flood surface) |
| D7 | Solver resource limits: Z3 timeout/memory; Clingo limits; тип-диапазоны constraints | `symbolic.py`, `z3_solver.py`, `clingo_engine.py` | DW-F12, WF-F15 | P2 | S/M | A12 | ✅ 2026-10-20 (`Z3Limits` + `ClingoLimits` + integer/float ranges) |
| D8 | Measured canary echo ≠ interpreter sink: measured structural evidence через отдельную политику (не компилировать `reached(interpreter)` из echo напрямую через `_accept_graph`) | `grounding.py:1045-1359` | BL-24 | P1 | M | A15 | ✅ 2026-10-20 (separate measured-evidence policy; echo never becomes interpreter sink) |
| D9 | SMT-слой → **удалить** (аудит 2026-10-20): `smt.py`/`z3_solver.py` не имеют production-потребителей (только re-export в `formal/__init__` + тест); рендер QDL как FOL над неинтерпретированными предикатами семантически расходится с Datalog/closed-world (признано в docstring самого файла); `ViolationGoal` как SAT-вопрос тривиально sat при любых двух фактах с общим эффектом — не отвечает на вопрос движка; `forall` над рекурсивными datatype — слабейший режим Z3; arity-конфликты конструкторов глотаются молча (`setdefault` в `_collect_constructor`); `CustomGoal` — невалидируемая сырая строка в SMT-текст. Удалить оба файла + тесты + re-export; Z3 остаётся только в production-пути `symbolic.py`; детерминированный рендер уже существует как `canonical_json` | `smt.py`, `z3_solver.py`, `formal/__init__.py`, `config.py`, `tests/application/verification/formal/test_smt.py`, `tests/application/verification/formal/test_z3_solver.py` | матревью B-1/B-2/B-8 + аудит necessity 2026-10-20 | P2 | S | — | ✅ 2026-10-20 (generic SMT layer removed; Z3 remains only in `symbolic.py`) |
| D10 | Symbolic: тип-диапазоны (`integer_range`/`float_range`), IEEE-семантика float (Z3 FP-сорта вместо Real), обработка repeated-полей, флаг dropped-couplings | `symbolic.py:104-213,262-296`, `models.py:14-30` | B-3/B-4/B-5/B-6 (матревью) | P2 | M | — | ✅ 2026-10-21 (type ranges + IEEE FP + repeated fields + dropped-couplings flag) |

## 6.1 Трек S — Сенсоры: buy-vs-build (по решению владельца, 2026-10-19)

Moat — только формальный слой (QDL: нормы, контексты, promotion,
вердикт-гейт, планирование, differential-семантика); готовых аналогов нет.
Всё прикладное — IAM-модель, gRPC, Neo4j, сценарии/фикстуры — адаптеры
(владелец: движок не должен быть завязан на них; связанность = долг B3/B8).
Сенсоры — commodity: порты + адаптеры над готовым; эвристические детекторы —
precision-first, только lead (под детерминированным оракулом шумящий сенсор —
фабрика ложных findings). Доступность в internal mirror (pypi.yandex-team.ru):
`hypothesis` ✓ (6.170.1), `semgrep` ✓ (только факт, не рекомендация —
фолозит), `detect-secrets` ✗, `interactsh` ✗ — план под фактическую
доступность.

Уроки реальных движков (разбор 2026-10-20: Hypothesis, Schemathesis,
Gramatron, Grammarinator, ChatAFL) и куда они легли:

| Источник | Урок | Куда легло |
|---|---|---|
| Hypothesis | композиционные стратегии; shrinking → минимальный PoC; ExampleDatabase → replay | S3 (+ связь с A17) |
| ChatAFL (NDSS'24) | LLM извлекает грамматику, обогащает сиды, обрабатывает насыщение — но не стоит в цикле генерации | S3 (LLM эмитит факты); deficit queue — уже есть |
| Gramatron (ISSTA'21) | представление входа определяет мутацию и скорость | S3/S5 |
| Grammarinator | parse-then-mutate реальных сидов; ANTLR для текстовых форматов | S5 |
| Schemathesis | 4-фазный пайплайн; negative testing = мутация схемы; feedback от ответов сервера | S3 (reactive inference валидационных констрейнтов); эвристические checks НЕ берём — обходят verdict-gate |
| RESTler / stateful links | producer-consumer зависимости | уже отражено: `chain_plus`/`requires` (research-extrapolation) |

Принцип S-трека: **LLM никогда не пишет код стратегий** — только
грамматические факты (`format`, `constraint`, `reaches`, dialect), которые
детерминированный компилятор превращает в `st.strategy`/grammar automaton.
Грамматика отвечает «какое значение», QDL — «какая клетка
`(field, sink-class, norm)` и почему», оракул — вердикт.

| ID | Задача | Files | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| S1 | ~~`SecretDetector`-порт + вендорный rules-пак (gitleaks/truffleHog)~~ — **отклонена владельцем 2026-10-19**: секрет-детекторы фолзят, а под детерминированным оракулом FP-сенсор = фабрика ложных findings (та же BL-01-механика с regex-provenance). `secret_shapes.py` понижен до **lead-only**: факты паркуются под `proposal:*:secret-shapes` для ревью, никогда не auto-промоутятся | `secret_shapes.py`, `grounding.py` (готово) | решение владельца | — | — | — | ❌ отклонена (lead-only реализован) |
| S2 | OOB → interactsh-модель: деплой interactsh-server (Go, отдельный контейнер) + тонкий клиент-адаптер к его REST-протоколу (registration/polling); встроенный listener — локальный fallback. Чужой код закрывает INF-02 (auth) и INF-03 (flood/DNS-канал) | `runtime/oob.py` → порт + адаптер | INF-02, INF-03 | P1 | M/L | D6 | ✅ 2026-10-20 (HTTPS+token REST registration/polling/deregistration, encrypted interactions, callback/DNS delegation; interactsh-server остаётся отдельным operator-managed Go-контейнером) |
| S3 | **SinkAwareGrammarEngine**: детерминированный `GrammarCompiler` — грамматические факты (`format(field)`, `constraint(field)`, `reaches(field, sink)`, dialect) компилируются в `st.strategy`; три слоя: structural (schema → hypothesis-jsonschema) × payload (грамматика sink-класса) × couplings (Z3). LLM/source-graph эмитят факты, **никогда код стратегий**; sink-классификация — source-graph first, LLM proposal-tier (не открывать LLM→finding путь). Shrinking → минимальный PoC; ExampleDatabase → replay (A17); `hypothesis.target` ≈ существующий goal-proximity. `SeedMutator` — deprecate | новый `generators/grammar_compiler.py`, `generators/fuzzing.py`, `generators/symbolic.py` | Hypothesis, ChatAFL, Gramatron; разбор 2026-10-20 | P1 | L | A17 | ✅ 2026-10-20 (QDL facts → deterministic Hypothesis/Z3 grammar) |
| S4 | Payload-грамматики по sink-классам — версионируемые данные, компилируемые в productions: SQLi (quote/dialect/terminator), traversal (bounded `../` + encodings + валидационный префикс вида `.pdf`), command (metachar + witness). Корпус (SecLists/fuzzdb-подмножество) — данные движка, не текст промпта (правило AGENTS.md для GrammarGenerator сохраняется) | `generators/goal_payload.py`, новый `payload_corpus/` | Grammarinator (корпус как данные), разбор 2026-10-20 | P1 | M | S3 | ✅ 2026-10-20 (versioned payload corpus + sink-specific productions) |
| S5 | Parse-then-mutate для текстовых форматов: XXE (XML: DTD/entities/SYSTEM), SSTI (template-грамматики), deserialization (формат-специфичные блобы: pickle/Java/JS-custom) — реальные сиды парсятся и мутацией дерева (модель Grammarinator) либо композиционные стратегии для простых форматов. Именно здесь достижим класс Seroval: payload = структурно валидный сериализованный объект с гаджетом внутри | новый `generators/textual.py` | Grammarinator (parse-then-mutate), Gramatron (representation) | P1 | M | S3, S4 | ✅ 2026-10-20 (safe XML/template/pickle/Java parse-and-mutate generator) |
| S6 | AdvisoryResolver: pre-scan корпус OSV/GHSA/NVD (allowlist источников, версионируемый кеш) → `affects(pkg, version)` source-tier факты. Интернет-знания входят только здесь — детерминированно, до старта кампании (runtime LLM без интернета). Связка: advisory → формат → грамматика гаджета (S5) → валидный payload (S3/S4) → witness (S7) | новый `advisory/`, `composition/run_provider.py` | разбор CVE-2026/Seroval, 2026-10-19 | P1 | M | — | ✅ 2026-10-20 (allowlisted HTTPS corpus, versioned cache, contract-context affects projection) |
| S7 | Witness-оракулы по классам для grammar engine: SQLi — differential-пары (`OR 1=1` vs `OR 1=2`) + time-based (dep A18); traversal — known-file content witness + differential read; XXE — in-band entity reflection + OOB (dep S2); command — OOB/timing; XSS — без DOM-оракула честно candidate-tier (reflection ≠ finding). Грамматика закрывает генерацию, вердикт — только эти оракулы | `oracles/`, `marker.py`, `latency.py` | разбор 2026-10-20 | P1 | M/L | S3, S4, S2, A18 | ✅ 2026-10-20 (class-specific deterministic witness oracles) |
| S8 | **Witness re-layering — signal-first** (смена формы S7 по решению владельца): оценка наблюдения извлекает ВСЕ дешёвые сигналы (marker echo, latency delta, OOB callback, content delta, known-content) независимо от ожидаемого класса; интерпретация переносится в QDL threat-rules (`signal ∧ sink ∧ norm → finding`; прецедент — `elevation`/`owasp_a01` в clingo_engine). Классовые обёртки (`SqlWitnessOracle`, `TraversalWitnessOracle`, `XxeWitnessOracle`, `CommandWitnessOracle`, `XssCandidateOracle`) растворяются в сигнальные примитивы + rule-паки; роутер `_n(norm, sink_types)` (pre-observation dispatch) → post-observation signal-интерпретация. Реактивное открытие оракулов: сигнал без интерпретации → deficit (расширение variance/response_semantics). Обоснование: сигналы полиморфны — SSTI светится как XSS, SQLi уходит в OOB/RCE-сигнал вместо error/timeout, XXE отражается как XSS; жёсткая связка production↔oracle теряет кросс-манифестации. Сигнальные примитивы уже class-free (marker/latency/oob/differential) — переносится только слой интерпретации | `oracles/witness.py`, `oracles/primitive_router.py`, `clingo_engine.py` (rules), `deficits.py` | решение владельца 2026-10-20 (развязка production↔oracle) | P1 | M/L | S7 | ✅ 2026-10-20 (signal-first witness primitives + QDL threat rules + reactive signal deficits) |

**Волна Corpus learning loop (2026-10-21, по решению владельца).** Сверка
зафиксированных уроков источников (research-extrapolation:404-408) с кодом
показала: из 13 уроков 8 ✅, 3 ⚠️, 3 ❌ — и все три провала одного класса:
**разовые находки не накапливаются** (S3 обещал shrinking/ExampleDatabase, но
не реализовал; критика владельца «99% SQLi сложнее `OR 1=1`» бьёт в потолок
regular-формата). Три задачи ниже превращают корпус из статичного seed в
обучающийся: каждая кампания стартует с мощностью всех предыдущих. Порядок:
S9 → S10 → S11 (S9 независимо и самый дешёвый).

| ID | Задача | Files | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| S9 | **Shrinking + ExampleDatabase** (уроки Hypothesis, обещанные в S3, не реализованы): (1) bounded minimization — найденный finding сжимается до минимального воспроизводящего payload (переигрывание выбранных терминалов/repeat «в сторону проще» через те же Hypothesis-strategies; каждый shrink-шаг = live-call → жёсткий бюджет, например ≤10 шагов, критерий воспроизведения — дешёвый witness-сигнал, не полная цепочка); результат — минимальный PoC в отчёте и понимание ядра триггера; (2) findings-replay — персистентный store находок (SQLite formal store / JSONL рядом с event log); при старте кампании по тем же нормам сначала replay прошлых findings: witness не воспроизводится → PASS за 1 вызов (фикса работает), воспроизводится → FAIL за 1 вызов (регрессия). Превращает движок в regression-инструмент, а не только discovery | `fuzzing/session.py`, `finding store` (новый), `live_workflow.py`, `path_runner.py`, `reporting/` | Hypothesis (shrinking, ExampleDatabase); сверка уроков 2026-10-21; S3-promise | P1 | M | A4 ✅, A17 ✅ | ✅ 2026-10-21 (bounded shrinking, JSONL ExampleDatabase, replay, minimal PoC reporting) |
| S10 | **Seed enrichment loop — пятый гибрид** (урок ChatAFL: LLM вызывается только в точке насыщения): `entropy` stop → typed consultation «насытились, вот история» — LLM получает saturated history (сигнатуры испробованных кандидатов, witness-сигналы, sink-type, schema, дифф-пары) → предлагает НОВЫЕ продукции/альтернативы слотов как proposal-tier ДАННЫЕ (терминалы/диалекты/repeat-границы, никогда код стратегий — принцип S3) → существующий promotion validator (A15-политика: классификации не промоутятся) → corpus вырос → кампания продолжается, а не останавливается. LLM не в цикле генерации каждого запроса — только в точке тупика; guardrail на размер corpus-дельты и полный audit-trail | `fuzzing/session.py` (entropy hook), `generators/payload_corpus/`, consultation protocol, `proposal_promotion.py` | ChatAFL NDSS'24 (saturation handler + LLM seed enrichment); пятый гибрид unicorn-разбора | P1 | M/L | S3 ✅, A15 ✅, S9 | ✅ 2026-10-21 (entropy hook, bounded saturated history, payload-data schema, source-grounded promotion, versioned store/audit trail, campaign resume) |
| S11 | **Grammar representation v2 — CFG-уровень формата корпуса** (урок Gramatron: представление входа определяет мутацию и скорость): schema v2 для `payloads.yaml` с рекурсивными правилами и контекстной зависимостью — вложенность (сбалансированные скобки/кавычки через состояние глубины), условные альтернативы (диалект → валидные терминаторы: MySQL-backtick ⇒ `#`, не `--`), ветвление по уже сгенерированному префиксу. Движок готов: `st.recursive` выражает это, компилятор — компиляция продукций в рекурсивные strategies (automaton-friendly прогулка вместо дерева разбора на каждый пример — тезис Gramatron о скорости). Закрывает критику владельца «99% SQLi — гораздо более сложная строка»: вложенные подзапросы, blind-цепочки, полиморфные payload'ы невыразимы в текущем плоском template+slots | `payload_corpus/payloads.yaml` (schema_version: 2), `corpus.py`, `compiler.py`, `grammar_compiler.py` | Gramatron ISSTA'21 (automaton representation); критика владельца 2026-10-21 | P2 | M/L | S10 (расширять имеет смысл уже растущий корпус) | ✅ 2026-10-21 (recursive grammar v2, context conditions, repeat bounds, v1→v2 migration) |

### 6.2 Трек R — Репортинг и ablation-метрики (по решению владельца, 2026-10-21)

Контекст (recon 2026-10-21): после прогона findings лежат только в event log;
`MarkdownReportRenderer` существует, но orphaned — его вызывают только тесты,
CLI wiring отсутствует. При этом модель уже несёт всё нужное: `Finding` имеет
`cwe`/`owasp`/`stride`/`severity`/`confidence`/`norm_fact`, классификация —
детерминированный join violated-norm effect × QDL role/sink facts ×
`classes.yaml` (29 классов), `TokenUsageSnapshot` считает input/cached/output
by phase с cache_hit_rate. Дыры: CWE/OWASP не рендерятся, time spent отсутствует
везде, SARIF/JSON/HTML рендереров нет, ground truth → нет precision/recall,
нет ablation-раннера.

Принципы трека:

1. **Рендеринг — тонкие модули** за единым `ReportRenderer` protocol над одним
   immutable `ReportBundle`; ядро не знает про форматы (расширение B2-границы
   на presentation).
2. **Классификация не трогается** — она уже presentation-only и детерминирована
   над QDL; R-трек только доводит её до вывода.
3. **Метрики без ground truth бессмысленны** (Klees et al. 2018: coverage ≠
   bugs; проблемы найдены во всех 32 оценках) — precision/recall появляются
   только после R7.
4. **Ablation = повторы × конфигурации × значимость**: одиночный прогон не
   доказывает ничего; минимум — mean±std по N повторам, Mann-Whitney U для
   сравнения конфигураций.
5. **Negative result требует positive control** (R10): абляция «компонент не
   нужен» валидна только при доказательстве, что в arm'е ON компонент реально
   работал (invocations, полнота входа, consumed output); иначе результат —
   INVALID, а не «useless».

| ID | Задача | Files | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| R1 | `ReportBundle` — immutable read model (findings + `CampaignMetricsSnapshot` + coverage + campaign info) + `ReportRenderer` protocol (`render(bundle)` возвращает str или bytes); единая точка входа для всех форматов | `application/reporting/`, `presentation/` | обсуждение 2026-10-21 | P1 | S | — | ✅ 2026-10-21 (immutable `ReportBundle` + `ReportRenderer`) |
| R2 | Time tracking: campaign wall time + per-phase elapsed (агрегация по event timestamps); попадает в `ReportBundle` | `domain/events.py`, `application/reporting/metrics.py` | recon 2026-10-21 (time spent отсутствует) | P1 | S | — | ✅ 2026-10-21 (`CampaignTimingSnapshot` + durable `PhaseChanged`) |
| R3 | Markdown renderer: вывести CWE/OWASP/STRIDE/tokens/time (модель несёт — рендер отстаёт); **подключить renderer к CLI wiring** (сейчас orphaned — вызывают только тесты) | `presentation/markdown/report.py`, `composition/` | recon 2026-10-21 | P1 | S | R1, R2 | ✅ 2026-10-21 (Markdown renderer wired to CLI; CWE/OWASP/STRIDE/tokens/time rendered) |
| R4 | JSON renderer: canonical machine-readable вывод `ReportBundle` — для ablation-pipeline и пост-обработки; стабильная схема, версионирование | `presentation/json/` | обсуждение 2026-10-21 | P1 | S | R1 | ✅ 2026-10-21 (canonical JSON schema v1 + live CLI wiring) |
| R5 | SARIF 2.1.0 renderer: `results[].ruleId` → `rules[]`, CWE через well-known taxonomy, `partialFingerprints` из content-addressed `path_id`; GitHub/IDE-совместимость | `presentation/sarif/` | OASIS SARIF v2.1.0 (проверено 2026-10-21) | P2 | M | R1 | ✅ 2026-10-21 (SARIF renderer + live CLI wiring) |
| R6 | HTML renderer: self-contained (без JS-зависимостей) + **SVG radar по OWASP API Top 10** (оси из `classes.yaml` `owasp_api`; значения: с ground truth — recall per class, без — доля findings по классам); маппинг номенклатуры 2019→2023 в рендере, не в каталоге | `presentation/html/` | запрос владельца 2026-10-21 (dota-style radar) | P2 | M | R1 | ✅ 2026-10-21 (self-contained HTML + inline SVG radar, GT/fallback values, CLI wiring) |
| R7 | Ground truth manifest: версионируемый формат ожидаемых багов на benchmark-стенде (CWE + method + условие/фингерпринт) + matcher `finding ↔ expected` → TP/FP/FN классификация | `benchmarks/nsfy_bench/` | Klees et al. 2018, Magma (ground-truth канарейки) | P1 | M | B23 (закрыт) | ✅ 2026-10-21 (schema-v1 manifest + TP/FP/FN matcher) |
| R8 | Ablation-метрики: precision/recall/F1, FP/FN counts, time-to-first-finding, findings per budget (checks/tokens/wall time), coverage cells closed, blocked paths recovered, deficit closure rate; повторы → mean±std | `benchmarks/`, `application/reporting/` | Klees 2018, Magma (reached/triggered/detected), FuzzBench, CVE-Bench | P1 | M | R7 | ✅ 2026-10-21 (artifact-based metrics + mean/std aggregation) |
| R9 | Ablation runner: N повторов × конфигурации (generator fix/bandit, grammar engine on/off, LLM grounding on/off, differential on/off, Z3 prefilter on/off, InterestPrioritizer on/off); фиксация бюджета на прогон; Mann-Whitney U для значимости отличий; JSON-вывод для сравнения; **каждый arm обязан проходить activation proof (R10) — INVALID-прогоны не интерпретируются как «компонент бесполезен»** | `benchmarks/nsfy_bench/` | Klees (повторы обязательны), дизайн B23, positive control | P2 | L | R8, R10 | ✅ 2026-10-21 (generic runner, fixed budgets, R7/R8/R10 integration, exact Mann-Whitney, canonical JSON) |
| R10 | **Ablation Observability — positive control для интерпретации negative results** (решение владельца 2026-10-21): без доказательства «компонент реально работал» ablation-результат «не нужен» неотличим от «рукожопная реализация / wiring-баг / пустой вход». Три слоя: (1) **component lifecycle телеметрия** через существующий event bus — `ComponentInvoked(input_digest)` / `ComponentSkipped(reason)` (0 bandit pulls, empty sink facts, disabled by flag) / `ComponentOutput(summary)` / `DownstreamDecision(consumed, by, outcome)`; делает различимыми `grammar selected 0 times` vs `selected 50 times, 0 witnesses`; (2) **input completeness** — компонент репортит полноту входа (`sink_facts=3, probe_fields=2, dialects=1` vs `sink_facts=0 → fell back to generic`), иначе абляция меряет отсутствие данных, а не компонент; (3) **activation proof per arm** — fail-fast валидация для конфигураций «компонент ON»: invocations ≥ 1, input non-empty, candidates produced ≥ 1, candidates survived prefilter/guardrail ≥ 1, scored ≥ 1; невыполнение → run помечается `INVALID(reason)`, scorer отказывается выводить «useless». Агрегация в `CampaignMetricsSnapshot.component_activity: dict[component, ActivityReport]`; correlation по существующей цепочке `check_id → observation_id → path_id` | `application/reporting/metrics.py`, event bus (`domain/events.py`, `infrastructure/events/`), `benchmarks/nsfy_bench/scorer.py`, R8/R9 wiring | вопрос владельца 2026-10-21 (отличить «не нужен» от «сломан/не подключён»); positive control из экспериментальной науки | P1 | M | — (event bus уже есть) | ✅ 2026-10-21 (component activity events/metrics, activation proof, INVALID refusal) |

Примечание: R3/R4 полезно закрыть **до** большого benchmark-прогона —
machine-readable вывод и полнота markdown резко упрощают разбор e2e; R7/R8 —
precondition для любых заявлений «движок находит X% багов» (CVE-Bench-класс).

### 6.3 Волна Post-e2e findings (по решению владельца, 2026-10-22)

Контекст: первый полный e2e-прогон (300 checks, 37 путей, 44 findings,
24/39 методов, Layer A без LLM). Прогон вскрыл не регрессию волны, а три
скрытых дефекта (ранее похороненных под fixture-блокировками) и две доводки.
Ключевой принцип волны — **фаззинг не гасится** (решение владельца: разные
payload'ы могут быть разными root causes); шум лечится identity модели
findings, а не остановкой поиска.

| ID | Задача | Files | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| A23 | **Finding fingerprint — identity модель вместо finding-per-observation**: finding identity = `(invariant_id, scenario_id, sink_id(s), probe_field, witness_kind)`; повторный FAIL того же fingerprint → **не новый finding, а witness**: `evidence_refs += observation_id`, `minimal_poc` обновляется при более коротком (shrink поверх), victim-ресурсы (order_id и т.п.) → witnesses; новый fingerprint (другой sink/поле/witness-канал) → новый finding. Обоснование: e2e показал 5 findings одной нормы одного сценария (разные order_id-жертвы — один root cause); `FindingEvaluator._raise_findings` сейчас поднимает finding на каждую FAIL-observation без identity. Фазз-сессия НЕ гасится после первого FAIL (решение владельца 2026-10-22: разные payload'ы = потенциально разные root causes — гашение теряло бы их); InterestPrioritizer получает сигнал «норма сломана каналом X» → энергия на нераскрытые каналы/sink'и | `workflow/execution/finding_evaluator.py`, `checks/evaluator.py`, `fuzzing/session.py` (сигнал), scheduler interest | разбор e2e 2026-10-22 (ShipOrder × 5 идентичных norm+scenario) | P1 | M | — | ✅ 2026-10-22 (fingerprint model + witness merge + shorter PoC update; fuzzing continues after FAIL) |
| R11 | **Report summary grouping**: сводная таблица findings по `(vulnerability_class, CWE, severity, count)` в markdown/HTML/SARIF/JSON. Сейчас Summary = 2 строки, дальше 44 секции подряд — распределение (bola 34 / fla 9 / ssrf 1; CWE-639/285/918; high 44) существует в данных, рендер не группирует. Прогон: отчёты сгенерированы пост-фактум (прогон без `--report-dir` — задокументировать в bench-README обязательный флаг) | `presentation/markdown/report.py`, `presentation/html/report.py`, `presentation/sarif/report.py`, `benchmarks/nsfy_bench/README.md` | разбор отчётов e2e 2026-10-22 | P1 | S | R1 ✅ | ✅ 2026-10-22 (deterministic summary projection in Markdown/HTML/JSON/SARIF) |
| B27 | **Бенчмарк-валидация synthetic allowed**: 28/44 findings — `norm:synthetic:allowed:*` по 13 методам при planted 2 authz-бага (GetOrder BOLA, DeleteOrder FLA). Различить: (а) бенчмарк реально разрешает ручки без авторизации → манифест неполн, движок нашёл вне-manifest баги (unexpected 16, false_positives 0) → дополнить ground truth; (б) policy-факты стенда неполны (у attacker'а должны быть bindings на ShipOrder/PayOrder/...) → дополнить accepted-факты. Ключ-улика из blocked-причин: `IAM-grounded denied; missing permissions: nsfy.order.pay` — IAM-модель описывает отсутствие прав → вероятнее (а). Отвечает на вопрос «precision 0.111 — баг движка или манифеста» | `benchmarks/nsfy_bench/` (manifest, norms, stand) | разбор e2e 2026-10-22 | P1 | S | — | ✅ 2026-10-22 (policy facts added for 13 authorized attacker methods; planted defects remain ungranted) |
| R12 | **method_id в check_completed events**: все 300 событий пришли с method_id=None — method-coverage приходилось считать через trace steps, R10-телеметрия по методам слепая. Wiring-фикс в event emission | `domain/events.py`, `workflow/execution/path_runner.py` (emit) | разбор e2e 2026-10-22 (top_methods: None × 300) | P2 | XS | R10 ✅ | ✅ 2026-10-22 (top-level method_id preserved even when check payload is redacted) |
| A24 | **Coverage 15 отсутствующих методов** (24/39): GetUser — второй прогон подряд вне coverage; полный список: GetDocument, BuyGiftCard, SpendGiftCard, ReserveInventory, GetInvoice, EscalateApiKey, ExecuteRefund, TransferFunds, ExecutePayout, AcceptTransfer, CreateTransfer, ActivateUser, ExportData, GetUser, UpdateProfile. Диагностика планировщика: почему пути на эти методы не строятся/не выбираются (setup-цепочки? interest-score? норм нет?) | `workflow/execution/scheduler.py`, `binder.py`, `application/verification/planning.py`, benchmark norms | method_coverage_missing e2e 2026-10-22 | P2 | M | A23 | ✅ 2026-10-22 (optional refs, self-reference, no-setup irreversibility, output IDs, chain facts, and stand fixtures fixed) |
| A25 | **Observation-walk через обычные QDL-запросы**. Отдельные FixturePool/Provisioner/DiscoveryPlan удалены (§6.17). Требуется восстановить outputless Create → Read, List → Create → List и marker correlation в общем runtime: получать typed bindings из наблюдений, отдельно доказывать причинные эффекты, блокировать пустую/неоднозначную выборку, сохранять общий budget и guardrail. Read не объявляется причиной create; отсутствие witness не становится PASS. | `application/verification/planning.py`, `runtime/path_binding.py`, `runtime/execution.py`, `verification/projection.py`, `runtime/runner.py` | e2e 2026-10-22 и решение владельца 2026-10-27 | P1 | L | A24, §6.17 | Переоткрыто 2026-10-27: общий discovery ещё не восстановлен |
| A26 | **Irreversibility deficit wiring — соединить существующие части, не новая способность** (вопрос владельца 2026-10-22: «разве LLM не делает это на старте, и разве дефицит не делает реактивный вызов?» — проверка кода: да, но провод не подключён). Факты: (а) startup-grounding уже умеет предлагать `causes` — три оси включают его в словарь (`axis_grounding.py`: dataflows `{is,reaches,causes}`, availability `{is,required,causes}`, alternatives `{is,causes,requires,has}`); (б) reactive-петля есть для многих блокировок; (в) НО `missing_irreversibility_fact` **не создаёт deficit вообще**: его нет в `DeficitKind` (`deficits.py`), а `_block_setup_unavailable` (`path_runner.py:1736`) при `SetupUnavailable` пишет reason строкой в `QdlPathEvaluated` и молча блокирует путь — reactive LLM не узнаёт, что именно нехватка `causes`-факта; (г) e2e-прогон шёл Layer A без LLM — предложений не генерировалось, а benchmark-граф декларирует `causes` не для всех мутаторов. Что делаем: (1) новый `DeficitKind` для missing-irreversibility + эмит из `SetupUnavailable`-обработки (step + missing effect в context); (2) маппинг на consultation axis=`alternatives` (словарь уже содержит `causes`) — reactive LLM предлагает `causes(action, changed|create|remove)` для мутирующего шага; (3) promotion → rebind → путь возвращается в scheduler (существующий цикл, ноль новой механики); (4) fallback: startup dataflows-ось предлагает effects для мутаторов без явных `causes`, когда LLM включён; (5) Layer A deterministic: benchmark-граф обязан декларировать effects для мутирующих методов — иначе `missing_irreversibility_fact` остаётся честным сигналом «нет источника фактов», это не баг движка. Закрывает 14/49 fixture-блокеров e2e | `workflow/execution/deficits.py` (DeficitKind + mapping + close-check), `workflow/execution/path_runner.py` (`_block_setup_unavailable` → deficit emit), `workflow/execution/step_setup.py` (reason → recovery intent), `application/verification/formal/grounding.py` (consultation prompt), `benchmarks/nsfy_bench/contract.py` (effects для всех мутаторов) | разбор e2e после A24 (14 × missing_irreversibility_fact) + вопрос владельца 2026-10-22; код-ревью: deficit-петля не подключена к setup-блокировкам | P1 | S | A25 (логически; механически независима) | ✅ 2026-10-22 (typed deficit, alternatives consultation, closure by explicit causes, benchmark effects) |
| B28 | **Полный отказ от Neo4j в benchmark e2e — file-stand с прямыми permissions, никаких сидов** (решение владельца 2026-10-22: «не должен быть какой-либо neo4j стенд, всё с нуля начинается, почему для запуска какие-то сиды»). Диагноз остаётся валидным, фикс меняется: `PolicySnapshot.permissions` — уже effective decisions («common may interface»), поэтому **никакая LivePrincipal→LiveBinding→Role→Permission цепочка не нужна** — attacker-права пишутся напрямую в `stand.json` (`permissions: [{subject, action, resource}]`). Что делаем: (1) benchmark-профиль `nsfy-bench-llm.toml` — убрать секцию `[neo4j]`, перевести прогон на `CLOUD_DAST_STAND_SOURCE=file`; (2) `stand.json` для NSFy — прямые permissions для всех AUTHORIZED_ATTACKER_METHODS + provisioning identity на 6 create-методов (закрывает 28 fixture-блокеров pre-target guardrail/IAM deny одним файлом) + 2 unexpected findings (CreateApiKey/ImportPickle: effective_permissions перестают быть пустыми → oracle видит expected allowed); (3) scenario-путь e2e обязан идти через FileStandSource, не через Neo4jScenarioRepository — если repo ещё тащит live-цепочку, заменить на snapshot-permissions; (4) regression test: `method.permissions ⊆ scenario.stand.effective_permissions` для authorized-методов + grounded oracle PASS при observed ALLOWED; (5) Neo4j остаётся только optional extra за портом StandSource для внешних стендов, в benchmark-е2e отсутствует полностью; ground truth НЕ трогать | `benchmarks/nsfy-bench/profiles/nsfy-bench-llm.toml`, benchmark `stand.json`, `composition/run_provider.py` (scenario wiring), `infrastructure/neo4j/live/scenario_repository.py` (замена на file-путь в e2e), tests | диагностика A25-прогона (Hegel: 6 FixtureKey pre-target deny; Darwin: effective_permissions пустые) + решение владельца 2026-10-22 | P1 | S/M | A25 ✅ | ✅ 2026-10-22 (file stand.json 19 permissions, [neo4j] removed, FileScenarioRepository, 26+93+41 tests; e2e pending; Neo4j остаток в AppProvider → B29) |
| A27 | **Norms-grounding policy-контекст — root cause того, почему LLM предлагает норму противоречащую политике** (решение владельца 2026-10-22: «не уверен в guard — надо чинить root cause, почему LLM предлагает норму противоречащую policy»). Root cause подтверждён кодом: norms-промпт (`axis_grounding.py:147-175`) инструктирует «use this for authorization checks» с примером admin-only Delete, но **в срез не подаются `may(...)`-факты стенда** — модель видит `CreateApiKey(scope=privileged)`, честно предлагает authz-норму и не могла увидеть противоречие, потому что факта не было в контексте. Fix: (1) включить существующие `may(principal, action, resource)`-факты в bounded slice для norms-оси; (2) инструкция: «не предлагай `prevents(N, allowed(A))`, если для campaign attacker есть `may(attacker, A, resource)` — это не уязвимость, это ожидаемое поведение»; (3) promotion guard как safety net (не primary): `prevents(N, allowed(A))` при `may(attacker, A, resource)` в графе → park как lead, не auto-promote — модель может ошибиться и с контекстом, guard защищает класс так же как verdict-gate; (4) тест на Grounder/PromotionPolicy (B27-тест покрывал только deterministic compilers); (5) regression: оба unexpected findings A25-прогона не воспроизводятся | `application/verification/formal/axis_grounding.py` (norms prompt + slice), `application/verification/formal/proposal_promotion.py` (guard), `application/verification/formal/grounding.py`, tests | диагностика Darwin 2026-10-22 (оба findings из promoted `prevents(allowed(A))` при `may` в графе) + решение владельца: root cause, не симптом | P1 | S | B28 (нужны корректные may-факты в стенде) | ✅ 2026-10-22 (may-slice в norms prompt + park-as-lead guard + persistence, 103 tests) |
| A28 | **Unlimited reactive-режим + consultation observability** (решение владельца 2026-10-22: «не понимаю, почему вообще бюджеты; нужен флаг запускать без бюджетов — бюджеты сейчас не должны ничего резать»). Подтверждено кодом: (а) `CLOUD_DAST_REACTIVE_BUDGET` парсится только как non-negative int, дефолт 8, **значения «unlimited» не существует** (0 = полный запрет, не безлимит); (б) внутри `DeficitQueue` generic-класс (alternatives, blocked_step) ограничен отдельным cap `max_tasks − variance_reserve(4) − response_reserve(2)` = 2 слота из 8 — alternatives голодал дважды (глобальный лимит + generic-кап), поэтому A26-петля не получила ни одного вызова. Fix: (1) `CLOUD_DAST_REACTIVE_BUDGET=all` — безлимитный режим (DeficitQueue без max_tasks-гейта), валидное значение наравне с числом; (2) unlimited-LLM профиль выставляет `all`; (3) при числовом бюджете — fair-share: generic-класс получает гарантированную долю, не остаток после reserves (голодание 4-й приоритета — bug, не feature); (4) observability: ConsultationDispatcher публикует component lifecycle (invoked/input/proposed/promoted) в R10, deficit queue trace (`deficit_enqueued/popped/budget_blocked`) — сейчас R10 слеп к consultations; (5) per-fixture `fixture_provisioning_failed` event (FixtureKey + guardrail decision + first_observation summary) — diagnoses закрыл бы разрыв «28 путей → 6 ключей» без ручной реконструкции | `composition/run_provider.py` (unlimited-семантика), `workflow/execution/deficits.py` (fair-share + trace), `workflow/execution/live_workflow.py`, `application/verification/formal/consultation.py` / `axis_grounding.py` (component events), `application/reporting/metrics.py`, `domain/events.py` | диагностика Leibniz 2026-10-22 (0 alternatives-вызовов, бюджет исчерпан variance+response) + решение владельца: бюджеты не должны резать | P1 | M | A26 ✅ | ✅ 2026-10-22 (REACTIVE_BUDGET=all → unlimited, fair-share 4/2/2, deficit trace, consultation R10 lifecycle, 88+164 tests; profile.py wiring родителем — 228 integration tests) |
| B29 | **Neo4j-остаток в AppProvider/make_live_container — выкинуть Neo4j из benchmark e2e полностью** (остаток B28, out-of-scope воркера): `AppProvider` всё ещё использует Neo4j для method/contract repository, а `make_live_container` eagerly создаёт Neo4j session factory — B28 закрыл stand/scenario-путь (FileStandSource + FileScenarioRepository + [neo4j] убран из llm-профиля), но полный Neo4j-free e2e требует: (1) contract/method repository на file/sqlite-пути (контракт уже проектируется из descriptor set — проверить, зачем AppProvider'у Neo4j); (2) make_live_container без eager Neo4j session (lazy/optional только при CLOUD_DAST_STAND_SOURCE=neo4j); (3) e2e-прогон без Neo4j-контейнера как acceptance. Проверить после: benchmark e2e запускается без Neo4j вообще | `composition/app_provider.py`, `composition/run_provider.py` (make_live_container), docker/compose benchmark wiring | остаток B28 (Fermat 2026-10-22) | P2 | M | B28 ✅ | ✅ 2026-10-24 (contract.json + FileMethod/Invocation/ContractGraph repositories; eager Neo4j session только при neo4j-выборе; [neo4j] убран из всех профилей; compose без neo4j-сервиса; acceptance: e2e 40 checks / 2 planted findings / neo4j-драйвер не установлен / CPA_NEO4J_* отсутствуют; 368 тестов) |
| A29 | **Incremental planner monotonicity violation при rebind — блокер безбюджетного режима**. Безбюджетный e2e (reactive=all, promotion=all) упал на ~50-й минуте: `IncrementalQdlPlanner._assert_monotonic` (application/verification/planning.py:401) — «previously grounded facts or rules are missing» при `_rebind_and_extend_paths → binder.bind → planner.plan`. Механика: безбюджетный промоушен породил 120 accepted-batch + 116 proposal sources; на очередном rebind объединённый граф потерял ранее grounded факты (вероятная причина: accepted-batch-ревизия той же оси заменяет предыдущую — binder выбирает свежий батч, старый исключается из выборки, а его факты уже в Clingo). Ограниченные бюджеты (8 консультаций) маскировали это — до A28 промоушенов не хватало, чтобы наткнуться. Fix-направления: (1) воспроизвести на минимальном графе (стартовый bind + два последовательных rebind с ревизией accepted-batch одной оси); (2) binder-выборка источников должна быть ревизионно-монотонной: новая ревизия оси включает факты предыдущей, либо planner-assert переносит недостающие факты как явную дельту вместо исключения; (3) regression-тест: два rebind с растущим числом батчей не падают; (4) прогон без бюджетов до естественного завершения — acceptance | `application/verification/planning.py` (assert/delta), `workflow/execution/binder.py` (source selection), `application/verification/formal/grounding.py` (batch revision), tests | безбюджетный e2e 2026-10-22 (1238 events, падение на rebind) | P1 | M | A28 ✅ | ✅ 2026-10-22 (graceful rebuild вместо abort: `_handle_non_monotonic` логирует missing facts (диагностика причины) и пересоздаёт Control поверх текущего графа; строгий assert → информированный rebuild; тест rebuild+последующий рост; 366 workflow-тестов; перезапуск безбюджетного e2e пошёл) |
| A30 | **Bi-temporal supersession для runtime/diff-фактов — устранение первопричины немонотонности** (вопрос владельца 2026-10-22: «в статье говорили — монотонность можно сохранить, не создавая новых графов, внося факт, который перекрывает старый»; фиксация из третьей волны: «Zep-инвалидация во времени → append-only монотонный граф — требование incremental Clingo»). A29 — аварийная защита (rebuild при потере), A30 — целевая архитектура: потери не возникает вообще. Подтверждённая причина из warning'а: теряются runtime `is(reached(action, sink), Effect)`-декларации (31 факт за первый rebuild) — diff-source ревизируется, `load_merged` берёт latest projection per source_id, новая версия не содержит старых reached-фактов → «удаление». Модель: (1) **append-only проекции**: observation/diff-источники никогда не перезаписывают существующий source_id — ревизия = новый content-addressed source, старый остаётся; (2) **supersession-предикат**: логический отзыв факта = добавление `supersedes(New, Old)` (tombstone), не удаление; (3) **правила актуальности** в Clingo: `current_reached(A,S) :- reached(A,S,V), not superseded(A,S,V)` — граф монотонно растёт как множество, логическое состояние меняется свободно; (4) диагностика: какой именно source сейчас переписывается с потерей reached-деклараций (audit `load_merged` дельт); (5) A29-rebuild остаётся страховкой. Экономика: одна добавка факта вместо полного re-ground программы при каждой ревизии | `infrastructure/sqlite/formal_repository.py` (append-only policy для diff/observation sources), `domain/formal.py` (supersedes-предикат), `workflow/execution/binder.py` (load_merged без потери), `application/verification/formal/clingo_engine.py` (current_* правила), tests | безбюджетный e2e warning (missing reached-факты), решение владельца 2026-10-22 | P2 | M | A29 ✅ | ✅ 2026-10-23 (union append-only для diff/observation/runtime в load_merged, supersedes-предикат + current_effect/current_reached правила, rowid-хронология latest, 123 теста; продюсеры tombstone — следующая волна, union консервативен)
| A31 | **Типология верифицируемости фактов + сквозной evidence-контекст + пер-факт промоушен + жизненный цикл lead'ов** (решение владельца 2026-10-23: «быстрый фикс — костыль; баг вскрыл архитектурную дыру»). Диагноз: 144 parked / 0 promoted за прогон — consultation-пакет смешивает утверждения разной природы (causes — гипотеза о поведении, falsifiable исполнением; has(field, sensitive) — интерпретация, только source/evidence), а Promotion режет весь пакет по худшему классу; measured evidence, породивший консультацию (живой create-вызов, observation), не доезжает до promotion; lead-карман без пути реабилитации = вечная мусорка в автономном режиме; R10 не меряет конверсию. Fix — НЕ исключение «пропустить causes с живым вызовом», а завершение типологии доверия: (1) **класс верифицируемости в онтологии** — атрибут PredicateSchema: `runtime_falsifiable` (causes, exposes, requires, targets), `evidence_gated` (role-классификации sensitive/credential/privileged, sink-типы), `structural` (контрактные is/reaches); новые предикаты получают класс по определению, политика — таблица «класс × доступное доказательство», не код с if-ами; (2) **сквозной evidence-контекст**: ConsultationRequest/результат несёт observation_ids из deficit-контекста; факты proposal наследуют provenance с evidence_refs — «это предложение основано на живом наблюдении X»; (3) **пер-факт промоушен**: гранулярность решения = факт, не пакет; causes с evidence-контекстом → promote по типу (следствие системы, не исключение); классификации без source-evidence → park как раньше; A27-guard (prevents(allowed(A)) при may) остаётся; (4) **жизненный цикл lead'ов**: дедупликация, evidence_refs у lead'а, счётчик подтверждений при новых наблюдениях, порог → promote; минимальная итерация — dedup + счётчик + hook переоценки, полная реабилитация — следующая волна; (5) **конверсия в R10**: ActivityReport.parked/promoted per component (consultation:*); нулевая конверсия за N консультаций → ComponentSkipped(reason=promotion_conversion_zero) — система видит пробку сама. Acceptance: в e2e alternatives-консультации с живыми observation дают promoted causes (144:0 → ненулевая конверсия), классификации по-прежнему паркуются, echo→sink-атака по-прежнему невозможна (structural evidence исключён), A27-regression зелёный | `domain/formal.py` (PredicateSchema.verification_class), `application/verification/formal/proposal_promotion.py` (пер-факт + evidence_refs), `application/verification/formal/consultation.py`/`axis_grounding.py` (observation_ids в контексте), `application/verification/formal/grounding.py` (lead lifecycle), `application/reporting/metrics.py` (conversion), tests | разбор финального безбюджетного e2e 2026-10-23 (144 parked / 0 promoted / 1.2M токенов alternatives впустую) + решение владельца | P1 | L | A27 ✅, A28 ✅ | ✅ 2026-10-23 (verification_class в PredicateSchema, observation_ids сквозь consultation→provenance, пер-факт промоушен, LeadLifecycle dedup+подтверждения, R10 conversion + zero-conversion skip; 620 тестов; интеграция с A30: 646+7 passed; transport-семантика уточнена: is_transport_failure на домене, discovery 404-before — валидные данные)

E2E-валидация A24 (2026-10-22, чистый SQLite formal store): прогон завершился
успешно, 226 checks / 156 observations / 6 findings; покрыто 12 из 39 методов.
Это меньше исходных 24/39, потому что B27 убрал 13 легитимных
authorized-attacker `allowed(...)`-норм, которые ранее давали основную часть
method coverage. Оставшиеся блокеры — по-прежнему fixture provisioning и
chain-facts, а не планировщик: `fixture_provision_failed`, `fixture_unavailable`
и остаточные `missing_irreversibility_fact`.

E2E-валидация A25/A26 с unlimited LLM-профилем (2026-10-22, чистый SQLite
formal store, `--refresh-grounding`, без campaign-wide `max_checks`): прогон
завершился естественно за 6m53s; CLI exit code 1 ожидаем — он означает наличие
findings, а не падение. Итог: 233 `check_completed` / 160 observations /
8 findings / 67 путей (9 completed, 58 blocked) / 12 из 39 методов; LLM — 38
запросов и 319 672 токенов. Benchmark: M1 strict и semantic — 2/9, full strict
и semantic — 2/34, precision 0.25; control false positives — 0, unexpected
findings — 6. Прогон добавил два completed-пути и два finding относительно
A24, но не улучшил recall: оба новых finding лежат вне planted answer key
(`CreateApiKey`, `ImportPickle`). Критический результат: счётчики setup-блокеров
не изменились — `fixture_create_failed` 28 (прежний `fixture_provision_failed`),
`missing_irreversibility_fact` 14, `fixture_unavailable` 7. Значит, A25/A26
не закрыли существующие blocked-пути. В логе есть успешные create-вызовы,
возвращающие идентификаторы, но без per-fixture provisioning-trace нельзя
связать их с 28 заблокированными setup-путями; deficit-петля также не
превратила 14 missing-effect блокеров в promoted `causes(...)`-факты. Это
следующий приоритет диагностики, а не основание откатывать
reveal-edge/discovery-модель.

Механический разбор «почему счётчики не сдвинулись» (код-ревью 2026-10-22):
(1) **`fixture_create_failed` 28 — это blocked paths, не уникальные факты**:
`StepSetupResolver._failed_keys` кеширует первый провал навсегда («will not
retry this fact in this campaign»), один упавший create каскадно блокирует
все пути с тем же `FixtureKey` без повторного вызова — чинить надо первый
провал каждого key, а не число путей; (2) **`fixture_create_failed` — не
discovery-класс**: A25 закрывала «create OK, ID не извлечён» (теперь честный
`fixture_id_not_extracted` + discovery-план), а 28 — это «create сам падает»
(seed-валидация, IAM, nested dependency вроде BuyGiftCard ← transfer ←
account-balance) — таксономия A25 сработала (разделила классы и показала,
где масса), но прогноз «A25 закроет 15–22 блокеров» был неверен: фактически
почти все former provision_failed — create-fails; (3) **A26: BLOCKED —
terminal**: `IntentState.BLOCKED` не имеет переходов, scheduler с reward=0 не
даёт retry — promoted causes-факт может вернуть путь только через rebind с
новым path_id, значит диагностический вопрос — дошла ли вообще
alternatives-consultation до promotion (R10 component_activity:
invoked/input/proposed/promoted), и если дошла — доехал ли новый путь до
scheduler до fix-point; (4) два unexpected findings (`CreateApiKey`,
`ImportPickle`) — отдельный triage по образцу B27: неполн planted key или FP.
Следующие шаги: R10-разбор consultation/promotion активности → per-fixture
provisioning-trace (какие resource_type/scope падали первыми — причина уже
пишется в лог `fixture_create_failed resource_type=…`) → root-cause первых
create-провалов → triage unexpected findings.

Честный безбюджетный e2e (2026-10-23, insecure=1 + fixture_transport_failed
классификация + intent-фикс; EXIT_CODE=1 = findings; ~80 мин): **3668 событий /
696 checks (484 OK / 212 FAIL — реальные ответы) / 78 путей / 23 из 39 методов /
12 findings / 291 model requests / 152 alternatives + 29 response_semantics + 26
roles + 18 variance consultations / 5 non-monotonic rebuild пережиты**. Findings:
минимум 3 planted (SearchOrders SQLi marker sink:sql_engine; DeleteOrder
FLA admin-delete; ShipOrder STF ship-unpaid marker sink:unpaid_shipment) +
STF-кандидаты (DispatchOrder dispatch-twice, CancelOrder uncancel) + 4
synthetic:allowed (ParseConfig/TransferFunds/CreateTransfer/UpdateOrder —
B27-класс triage) + 2 synthetic:has field-exposure. Blocked: fixture_create_failed
14 (vs 31 TLS-прогон), missing_irreversibility 12, setup_other 11, хвост —
честные oracle-отказы (marker/forbidden/echo/transition). Прогресс против
A25-бюджетного: findings 8→12, methods 12→23, checks 233→696.

Финальный безбюджетный e2e с A29-фиксом (2026-10-22, EXIT_CODE=0, естественное
завершение): 1256 событий / 117 checks / 110 observations / 81 путь / 15 из 39
методов / **0 findings** / 278 model requests (vs 38 у бюджета-8) / **192
alternatives-consultations (vs 0)** / 26 roles / R10 component_activity полная
(consultations+generators+prefilter) / **3 × non-monotonic rebuild пережиты без
краша** — A29-фикс валидирован в бою. Точная причина монотонности локализована
warning'ом: теряются runtime `is(reached(action, sink), Effect)`-декларации (31
факт за первый rebuild) — observation-projector/diff-ревизии немонотонны,
следующая диагностика. Остаточные блокеры: fixture_create_failed 31,
missing_irreversibility 16, setup_other 13 — alternatives-консультации идут
(192), но promoted-факты не возвращают пути (promoted causes не закрывают
deficit или rebind-пути не доехали); 0 findings при живом исполнении —
planted-баги всё ещё за fixture/irreversibility-блокерами, а оба бывших
authz-findings корректно исчезли (A27+B28). Качественные метрики безбюджетного
режима хуже бюджетного по findings — поиск ушёл в консультации и fixture-циклы,
а не в продуктивные пробы; это предмет следующей итерации приоритизации
(InterestPrioritizer для consultations vs checks).

Безбюджетный e2e-прогон B28/A27/A28 (2026-10-22, `run-b28.sh`: reactive=all,
fixture=4096, promotion=all; упал на ~50 мин — см. A29): 1238 событий / 124
checks / 56 путей / 18 из 39 методов (vs 12) / 0 findings (не дошёл до
evaluation) / 251 component_invoked. Результаты волн: (1) **B28 сработала** —
guardrail пропускает provisioner, create-вызовы исполняются: typed-таксономия
A25 теперь показывает честную причину `fixture_id_not_extracted` × 5
(api_key, gift_card, payout, refund, transfer — ровно те 5 из 6 прошлых
ключей) + `fixture_discovery_failed` (order); 24 blocked-пути = те же ~6
ключей через `_failed_keys`-каскад — класс сместился с «pre-target deny» на
«create OK, ID не извлечён»; (2) **A26/A28-петля живая**: 138
alternatives-consultations (vs 0 в прошлом прогоне), 29 roles-consultations,
все с component-lifecycle телеметрией; но 14 missing_irreversibility путей не
вернулись до падения — rebind упал (A29); (3) coverage 18/39 без завершения.
Безбюджетный режим вскрыл: (а) A29-блокер — падение; (б) A25-discovery в
рантайме не закрыл id_not_extracted — вероятная причина: нет exposes-фактов
для read-методов (benchmark-граф их не задаёт, reveal-ребро не строится) —
диагностировать после A29; (в) 138 consultations на один прогон — стоимость
без лимитов видна и измерима (R10), это осознанный trade-off exploratory-режима.


Диагностика регрессии A30+A31-прогона тремя воркерами (2026-10-23):
(1) **current_effect НЕ виноват** — Schrodinger: на seed-графе планы идентичны
с/без current_effect (attack_paths 10=10, causes=current_effect=34, supersedes=0);
(2) **настоящая причина — accepted-batch latest-per-source**: A30 сделала union
только для diff/observation/runtime, A31 пер-факт промоушен пишет меньшие сабсеты
под тем же source_id → load_merged берёт latest → **597 фактов потеряно** (161
causes, 123 has, 32 prevents, 28 requires, 16 exposes), план теряет 20 attack
paths, 30 invariants, 29 closures, 13 rebuilds; тестовый fake-repository уже
предполагал union → юнит-тесты маскировали; **фикс применён**: accepted-batch:
добавлен в _APPEND_ONLY_SOURCE_PREFIXES + параметризованный production-тест
(528 тестов); (3) **A31 не режет seed** (Cicero): seed 116 фактов (47 requires/
39 targets/30 refers_to) в CONTRACT-контексте минуют promotion, оффлайн-план даже
лучше (65 vs 59 путей); НО 208/240 alternatives-консультаций без live_observation
→ их requires корректно паркуются — `_observation_for_deficit` не доносит evidence
(следующий фикс); (4) **фаззинг-аудит** (Bacon): base fuzz-loop ✅ (59 инвокаций),
Z3 prefilter ✅ (59), **S9 shrink+ExampleDB ✅ работают** (18 записей, 13 совпадают
с minimal_poc — «0 событий» было телеметрия-пробелом, не механикой!), chain-fuzz ❌
(79 setup-blocked путей — та же fixture-пробка), S10 ❌ (нет entropy: FUZZ_MAX_CHECKS=3
+ 0 sink_types в планах), S11 payload-grammar ❌ (0 sink facts → только структурная
генерация), factors/timing ❌ (нет owner/victim principal в stand.json — control-пара
не создаётся). Цепочка разрыва: setup/fixture держит chain-fuzz + readback + chain-находки;
один блокер каскадно глушит 4 подсистемы.

Диагностика трёх треков по артефактам прогона (2026-10-22, контейнер
`cloud-dast-e2e-a25-runner`, `/tmp/cloud-dast-e2e-a25/`, run
`run:74526d5af0fc4ad39f903902f3e572c6`): (1) **A26-петля оборвалась на шаге 1 —
alternatives-consultation не вызвана ни разу**: reactive-бюджет
`CLOUD_DAST_REACTIVE_BUDGET` (дефолт 8, unlimited-профиль его не переопределяет)
исчерпан другими осями — 6×variance + 2×response_semantics; alternatives —
приоритет 4 в `DeficitQueue.pop_next` (deficits.py:766-816), слоты до него не
дошли; 38 model requests = 30 startup + 8 reactive, фаза
`consultation:alternatives` отсутствует в report.json, 0 promoted
alternatives-фактов в qdl_projection; это не валидатор и не модель — бюджет;
(2) **28 fixture_create_failed путей = всего 6 уникальных FixtureKey**
(реконструкция через ScenarioBinder/QdlPlanner из formal store): `order` (14
путей, 50%), `api_key` (6), `transfer` (4), `gift_card` (2), `payout` (1),
`refund` (1); для всех шести провал — **pre-target guardrail/IAM denial** (0
`setup:*`-наблюдений, seed строится валидно, транспорт исключён — при
guardrail-пропуске даже ошибка вернула бы Observation); вероятен один
policy-фикс (setup identity в `CLOUD_DAST_ALLOWED_IDENTITIES` / create-методы в
`CLOUD_DAST_ALLOWED_METHODS`), разблокирующий все 28; latent-дефекты после
policy: `CreateTransfer.recipient` и `BuyGiftCard.payment_transfer_id` —
object-ref на `transfer` остаётся None (граф-факт неверен: recipient не
transfer); (3) **оба unexpected findings — policy-факты live-стенда неполны**:
benchmark `policy_facts()` даёт attacker `may(...)` на оба метода
(AUTHORIZED_ATTACKER_METHODS, norms.py:344-366), но live Neo4j IAM не содержит
LiveBinding/Role/Permission для attacker → `effective_permissions` пустые →
oracle корректно выводит «expected denied, observed allowed» → finding; это не
манифест-неполнота (ground truth НЕ дополнять) и не FP oracle; **реальный
дефект движка — promotion guard**: LLM-proposal `prevents(N, allowed(A))`
промоутится даже при `may(principal:attacker, A, resource)` в графе
(proposal_promotion.py:1072-1084), именно так появились оба findings; planted
OOB-баг ImportPickle (`norm:stf-deser-rce`) по-прежнему blocked — callback не
пришёл, отдельная задача; (4) телеметрия-пробелы: per-fixture provisioning
trace отсутствует (QdlPathEvaluated не несёт FixtureKey), guardrail decision не
пишется, ConsultationDispatcher не публикует component lifecycle events — R10
слеп к consultations, docker logs пусты.

Что эта волна НЕ делает (осознанно): не гасит фаззинг после первого FAIL —
fingerprint мержит witnesses, поиск продолжает искать разные root causes; не
трогает `semantic_norm_compiler`/`binder`/`witness` — механика норм в e2e
сработала корректно (дифф-пары, oracle confidence 1.0, shrink-minimized PoC);
не является «откатом волны» — R10-телеметрия, S9-examples/evidence,
differential 34 пары, диагностика blocked-причин — всё работает и именно оно
вскрыло эти дефекты. Порядок: R11 + R12 (XS, сразу) → B27 → A23 → A24.

### 6.4 Semantic-boundary hardening и самоинференция (по итогам код-ревью 2026-10-23)

Контекст: живой runtime уже разделяет deterministic-ядро и LLM-proposer, но
часть семантических решений всё ещё принимается до QDL — в naming-эвристиках,
format/dialect fallback и report-only deficits. Цель волны — перенести эти
решения в closed QDL-факты, которые предлагает LLM и валидирует
deterministic promotion. Новый параллельный formal engine не создаётся.

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| S12 | **Redaction/replay через QDL-роли**: заменить `*_id`-эвристики в `check_event_policy`, `jsonl`, `evidence_view` на accepted-факты `has(field, object_ref/credential/sensitive/replay_safe)`; отсутствие факта = default redact + deficit | `domain/check_event_policy.py`, `infrastructure/jsonl.py`, `formal/evidence_view.py`, `semantic_norm_compiler.py` | код-ревью 2026-10-23 | P0 | M | — | ✅ 2026-10-23 (field_roles.py: resolve_field_roles из has-фактов; *_id-эвристики удалены из check_event_policy/jsonl/evidence_view; нет факта = redact + FieldRoleDeficit; object_ref/replay_safe → retain, credential/sensitive veto; 2000 тестов; wiring в live-конвейер — S13+) |
| S13 | **Убрать name-based binding в Template/Symbolic**: удалить `subject_id`, `principal_id`, `.role_id`, `{type}_id`, `resource_id` из executable-резолверов; требовать QDL-роли и `refers_to` | `generators/template.py`, `generators/symbolic.py`, `binder.py` | код-ревью 2026-10-23 | P0 | M | S12 | ✅ 2026-10-23 (подстановка только has(role)+refers_to; 8 имени-эвристик удалены; role без refers_to → missing_refers_to deficit; subject/role-таргеты в principal-неймспейсе; readback read-ноги несут типы read-метода; 2011 тестов) |
| S14 | **Настоящая symbolic-стратегия**: подключить `Z3SymbolicGenerator` в composition или переименовать текущий `SymbolicGenerator` в `MinimalSeedGenerator`; убрать fallback `anonymous` | `composition/run_provider.py`, `formal/symbolic.py`, `generators/symbolic.py` | код-ревью 2026-10-23 | P1 | M | S13 | ✅ 2026-10-24 (Z3SymbolicGenerator в composition; MinimalSeedGenerator честное имя; anonymous-fallback убран; 2158 тестов) |
| S15 | **Carrier/format/dialect только из QDL**: убрать fallback «unknown sink = quoted canary», «unknown template = `{{ }}`», «unknown serialization = JSON»; использовать `format`, `dialect`, `reaches`, `is(Sink, …)`; отсутствие факта = deficit или generic structural fuzz | `generators/goal_payload.py`, `generators/grammar_compiler.py`, `generators/textual.py`, `axis_grounding.py` | код-ревью 2026-10-23 | P1 | M | S13 | ✅ 2026-10-24 (unknown sink → raw marker; no quote-wrap; no {{}} default; no magic-byte sniff; carrier/dialect только из QDL) |
| S16 | **Provisioning semantics**: заменить `_marker_field` и `_location_resource_id` на explicit `probe_target` / extraction-факты; отсутствие факта = deficit | `workflow/execution/provisioning.py`, `infrastructure/runtime/provisioning.py`, `step_setup.py` | код-ревью 2026-10-23 | P1 | M | S12 | ✅ 2026-10-23 (probe_target/extraction как QDL-факты через FixtureDiscoveryStep/Witness/Plan; _marker_field и имя-парсинг Location удалены; нет факта = typed ProvisioningFactDeficit + fixture_discovery_deficit до live-call; transport/create-failure семантика сохранена; 909+ тестов) |
| S17 | **Resource identity/container без строковых алиасов**: удалить `_resource_type_aliases`, `rsplit('.')`, `replace('.', '_')`, folder-first fallback; использовать canonical type facts и `contained_in` / `container_ref` | `workflow/limits.py`, `step_setup.py`, `template.py`, `contract_projection.py` | код-ревью 2026-10-23 | P1 | M | S13 | ✅ 2026-10-24 (_resource_type_aliases/rsplit/replace/folder-first/any-other удалены; canonical exact-match; kms.secret ≠ lockbox.secret) |
| S18 | **Payload-pair по явной роли**: заменить «все строки, кроме object_ref/credential» на closed role `payload` / `mutable_input`; unknown = deficit | `live_contracts.py`, `semantic_norm_compiler.py` | код-ревью 2026-10-23 | P1 | S | S12 | ✅ 2026-10-23 (payload/mutable_input в закрытом алфавите; payload_fields только по has-фактам; «все строки кроме» удалена; per-field missing_role deficit; payload/mutable_input в SEMANTIC_ROLES для LLM-предложений; 1412+512+159 тестов; read-back write-нога value-fallback — interim до S19-path_runner) |
| S19 | **Response path и STRIDE без строковых правил**: заменить `_response_leaf_field` и `_letter_from_path` на `output_path`, `exposes`, `semantic_role_stride` | `deficits.py`, `path_runner.py`, `coverage.py` | код-ревью 2026-10-23 | P2 | M | S12 | ✅ 2026-10-23 (_response_leaf_field/_letter_from_path удалены; полный output path verbatim — items.0.foo.bar ≠ metadata.bar; граунтинг через exposes/has-факты + S12 field_roles; STRIDE через единую catalog-таксономию, нет факта = unknown; coverage-ячейки из exposes-фактов; 2084 теста; field_exposure.py суффикс-правило — отдельная задача) |
| S20 | **Exposes ownership только явно**: убрать `_augment_missing_exposes`; требовать `exposes` / `owns` | `axis_grounding.py`, `proposal_promotion.py` | код-ревью 2026-10-23 | P2 | S | S19 | ✅ 2026-10-24 (_augment_missing_exposes удалена; exposes только явным фактом) |
| S21 | **Reactive deficit expansion**: добавить consultation-оси для `dataflows`, `authentication`, `availability`, `norms`; закрыть startup-only gap | `deficits.py`, `consultation.py`, `axis_grounding.py`, `grounding.py` | код-ревью 2026-10-23 | P1 | L | S15, S16 | ☐ |
| S22 | **Live-path/docs alignment**: привести документацию к фактическому runtime: LlmGenerator исключён из FuzzSession, Z3SymbolicGenerator не wired, consultation идёт через Grounder, textual жив; убрать/пометить dead paths | `README.md`, `docs/engine-runtime-2026-10-19.md`, `run_provider.py`, `application/verification/planning.py` | код-ревью 2026-10-23 | P2 | M | S14, S21 | ☐ |
| S23 | **Замкнуть fixture_type_deficit**: убрать `axis=None`, добавить consultation-kind, предлагать `refers_to`, `targets`, `causes(create)` | `deficits.py`, `consultation.py`, `axis_grounding.py`, `binder.py` | разбор владельца 2026-10-23 | P1 | M | S12 | ◐ 2026-10-23 (binder-часть: typed_object_ref derived view, setup_for provides/requires-join по 6.6, без эвристик, 2104 теста; fixture-kind в deficits/consultation — remaining после S30: план минимального диффа задокументирован Godel) |
| S24 | **Coverage-дефициты по всем declared actions/fields**: не только `_path_actions(binding)`, а весь contract graph; отсутствие пути = graph-growth deficit | `deficits.py`, `coverage.py`, `binder.py` | разбор владельца 2026-10-23 | P1 | M | S23 | ☐ (scoped by 6.6) |
| S25 | **State semantics и state-machine induction**: `unmapped(state, …)` → `missing_state_semantics` deficit → consultation → гипотезы `transition` / `forbidden` | `observation_projection.py`, `deficits.py`, `state_machine.py`, `axis_grounding.py` | разбор владельца 2026-10-23 | P1 | L | S23 | ☐ (scoped by 6.6) |
| S26 | **Fair reactive budget**: гарантировать долю слотов для alternatives/fixture/state; запретить starvation одной осью | `deficits.py`, `grounding.py`, `live_workflow.py` | разбор владельца 2026-10-23 | P1 | M | S23–S25 | ☐ (scoped by 6.6) |
| S27 | **Promotion fixed-point proof**: e2e-тест `deficit → consultation → proposal → promotion → rebind → new path → oracle` | `grounding.py`, `live_workflow.py`, `proposal_promotion.py`, tests | разбор владельца 2026-10-23 | P1 | M | S23–S26 | ✅ 2026-10-23 (test_promotion_fixed_point: полный цикл deficit→consultation→promotion→rebind→new path→oracle FAIL→deficit closed на реальных компонентах; S28 per-revision проверен SQL; S12+S13 в цикле; 400+103 теста) |

Приёмка:

- **S12**: `session_id` редактируется; `order_id` восстанавливается только при
  accepted `object_ref`; unknown поле не попадает в replay.
- **S13**: нет QDL-факта — нет подстановки; есть факт — подставляется
  правильный subject/role/resource.
- **S14**: symbolic-стратегия даёт Z3-derived candidate; `unsat` пропускает
  live-call; `unknown` помечается консервативно.
- **S15**: unknown format не мутируется как Jinja/JSON; explicit
  `format=xml` даёт XML-кандидата.
- **S16**: marker пишется только в declared `probe_target`; Location парсится
  только при declared extraction.
- **S17**: два resource type с одинаковым коротким суффиксом не схлопываются;
  container выбирается только из факта.
- **S18**: `locale`, `currency`, `page_size` не мутируются без явной
  payload-роли.
- **S19**: `items.0.foo.bar` и `metadata.bar` остаются разными полями; STRIDE
  берётся из role taxonomy.
- **S20**: без `owns`/`exposes` факт не создаётся.
- **S21**: missing dataflow/auth/state факт порождает consultation и после
  promotion добавляет путь.
- **S22**: документация совпадает с composition wiring.
- **S23**: `fixture_type_deficit` получает axis и consultation.
- **S24**: unbound action создаёт `missing_role` deficit.
- **S25**: unmapped state триггерит consultation; наблюдаемые переходы
  предлагают `transition` / `forbidden`.
- **S26**: alternatives/fixture/state получают гарантированную долю бюджета.
- **S27**: e2e доказывает полный цикл
  `deficit → consultation → promotion → rebind → new path → oracle`.

### 6.5 Consultation throughput и монотонный promotion (по итогам b28-разбора 2026-10-23)

Контекст: в безбюджетном b28-прогоне повторные consultations по одним и тем же
action’ам и большой объём parked-вывода показывают не «плохую модель», а
системный loop:

- 240 alternatives-консультаций, из них 208 — без live observation;
- 169 `proposal_parked` и 228
  `classification_parked_without_provenance`;
- 13 `qdl_planner_non_monotonic_rebuild`, все с потерей `accepted`-фактов;
- `supersedes(...)` есть в онтологии и Clingo-правилах, но в production-run
  не эмиттируется ни одним продюсером.

Цель — убрать повторную модельную работу и потерю фактов, не ослабляя
deterministic promotion и не создавая параллельный formal engine.

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| S28 | **Монотонный accepted/proposal persistence и supersession lifecycle**: заменить latest-wins для `accepted-batch:` и `proposal:` на append-only per-fact/per-revision source ID; добавить production-эмиттер `supersedes(New, Old)` при логической замене факта; распространить current-view на релевантные predicate classes, не только `causes`/`reached` | `infrastructure/sqlite/formal_repository.py`, `infrastructure/neo4j/formal_repository.py`, `formal/grounding.py`, `formal/clingo_engine.py`, `domain/formal.py`, `workflow/execution/binder.py`, tests | b28: 13 non-monotonic rebuild, 0 production `supersedes` | P0 | M | A30 ✅ | ✅ 2026-10-23 (per-revision content-addressed source ID для proposal/accepted-batch; production supersedes-эмиттер с цепочками и переносом tombstones; current_has/superseded_has в Clingo + reveal-edge/algebra на current_has; Neo4j union-симметрия; 962+1893 тестов; авто-supersession ограничена reached/duration и setup_value/setup_skip — расширение на классификации требует решения об эксклюзивных role-семействах) |
| S29 | **Declaration-closure-safe filtering**: любой пост-валидационный фильтр proposal-графа обязан сохранять declaration closure; если declaration отбрасывается, dependent fact тоже отбрасывается; invalid facts должны превращаться в typed issues, а не в `ValidationError`/exception | `formal/axis_grounding.py`, `formal/validator.py`, `formal/proposal_promotion.py`, tests | b28: повторяющиеся `unknown reference` на `field(resource:order, label)` | P0 | M | S28 | ✅ 2026-10-23 (filter_declaration_closure: итеративное удаление с сохранением closure, каждая зависимость → typed issue; AxisResult.issues + ProposalPromotionResult.issues; response-semantics фильтр closure-safe; ValidationError → ValidationIssue(code=graph), не исключение; 519+103 теста; persistence issues — S30/S32) |
| S30 | **Deficit work-item graph and algebraic coalescing (v2)**: не просто дедуп `Deficit.key`, а derived `WorkItem` projection по `missing_fact_signature + effect_neighborhood + evidence_signature`; построить отношения `duplicate / co-factorable / dependent / complementary / conflict / affects`; один LLM-вызов закрывает пачку path-fanout deficits; параллелить только independent work items на одном immutable graph snapshot; после wave-commit пересчитывать все pending deficits и разделять `closed / stale / unchanged`; provenance несёт `work_item_id + deficit_ids`; `fan_out` влияет на приоритет; attempts/saturation — на work item | `workflow/execution/deficits.py`, `workflow/execution/live_workflow.py`, `formal/consultation.py`, `formal/axis_grounding.py`, tests | b28: 34/22/16/16/14 повторных consultations по top-action | P0 | M | S28, S29 | ✅ 2026-10-24 (стадии 1-5 (closure propagation добавлена): WorkItem-проекция stdlib, отношения duplicate/co-factorable/dependent/complementary/conflict/independent, DAG+волны+SCC Tarjan, parallel independent через GroundingRunner, deterministic merge canonical-order, конфликты → supersedes не LLM; 20 fanout → 1 вызов; S31-gate интегрирован; стадии 5-6 remaining; 2144 теста) |
| S31 | **Evidence-first alternatives и effect-neighborhood slice**: если deficit требует live evidence, а observation отсутствует — создавать `evidence_deficit` и не звать LLM; строить deterministic sibling-action slice из QDL-отношений (`causes`, `requires`, `targets`, общий resource type), а не из natural-language uncertainties | `workflow/execution/live_workflow.py`, `workflow/execution/deficits.py`, `formal/slices.py`, `formal/axis_grounding.py`, tests | b28: 208/240 alternatives без live observation; модель repeatedly asks for response/sibling actions | P1 | M | S30 | ✅ 2026-10-24 v2 (re-scoped: гейт только для response_semantics/variance где observation ожидаем; blocked-дефициты без гейта — chicken-and-egg устранён; control+treatment pair для variance; 425+2004 теста) |
| S32 | **Parked-classification lifecycle**: стабильный lead key `(action, holder, role)`; дедупликация перед повторным save; отсутствие source/evidence → один `classification_deficit`/`missing_evidence`, а не повторные модельные вызовы; reevaluation только при новом evidence или operator approval | `formal/grounding.py`, `formal/proposal_promotion.py`, `application/reporting/metrics.py`, tests | b28: 228 parked classifications, повторные консультации | P1 | M | S28, S30 | ☐ |
| S33 | **Per-work-item saturation**: attempt budget на work item, не на path-deficit и не на action; после N неудач помечать work item saturated; reset только при новом evidence/effect; превратить report-only `promotion_conversion_zero` в runtime-сигнал | `workflow/execution/deficits.py`, `workflow/execution/live_workflow.py`, `formal/grounding.py`, `application/reporting/metrics.py`, tests | b28: повторные консультации по одним и тем же action | P1 | S | S30–S32 | ✅ 2026-10-24 (per-work_item_key saturation: max_attempts env-конфигурируем (дефолт 3), saturated items не диспетчатся, reset только при новом evidence; 8→3 вызова −62.5%) |
| S34 | **Quorum escalation только для runtime-falsifiable фактов**: после повторных unscoreable work items сэмплировать N ответов и детерминированно интерсектить canonical facts; продвигать только пересечение, всё ещё через PromotionPolicy; никогда не применять к protected classifications и sink types | `formal/consultation.py`, `formal/axis_grounding.py`, `formal/proposal_promotion.py`, tests | research-extrapolation: MoA как confidence signal | P2 | M | S30, S33 | ☐ |
| S35 | **Идемпотентный runtime-projection**: ObservationProjector сворачивает наблюдения в дедуплицированные агрегаты (`observed_outcome(action, outcome)`, `observed_transition(action, from, to)`, `observed_reached(...)`); observation_ids уходят в provenance/агрегат-счётчик, НЕ в аргументы факта; повторное наблюдение того же смысла = идемпотент (как insert-into-set); опровержение = `supersedes` (A30-механика). Проблема: сейчас каждый check пишет ~5 evidence-фактов с уникальным observation_id → 194 checks = 15 368 фактов (71% графа), логически ~200-300 уникальных смыслов; event log (JSONL) уже полный поток — QDL-граф не должен быть вторым event store'ом. Ожидание: сжатие runtime-части в ~50×, граф planner'а с 16K до ~5K | `application/verification/formal/observation_projection.py`, runtime projector, tests | бюджетный e2e 2026-10-23: evidence 15 368/21 570 фактов; вопрос владельца «наблюдение должно привносить только новую информацию» | P1 | M | A30 ✅ | ✅ 2026-10-23 (10 observed_*-предикатов; evidence(obs,payload) → плоские агрегаты без observation_id в аргументах; provenance через per-observation проекции + content-addressed связи; supersedes-опровержение протестировано; сжатие 13-26×, evidence→0; 1935+164 теста) |
| S36 | **Срезы графа по потребителю**: planner-view = contract+accepted БЕЗ evidence/runtime-потока и БЕЗ proposal-пере-деклараций; oracle/diff-view = с runtime; proposal-батчи дедуплицируют `is`-декларации против контракта. Проблема: merged-граф — «все слои докера в одном образе для каждого потребителя»: planner компилирует 71% ненужных ему evidence-фактов; 1 683 proposal-источника пишут 200-360 фактов каждый, в основном пере-декларации. Реализация: проекция в `load_merged`/binder по контексту+назначению (planner не грузит runtime-evidence; proposal-декларации схлопываются против contract) | `workflow/execution/binder.py` (_load_graph), `infrastructure/sqlite/formal_repository.py` (view-проекция), tests | бюджетный e2e: 16K фактов на 39-методном бенчмарке, 71% evidence в planner-пути | P1 | M | S35 | ✅ 2026-10-23 (planner-view в _load_graph: runtime-evidence исключён, is-редекларации схлопываются к contract; diet после детерминированных слоёв; −68.8% на fixture; model/proposal на полном графе; 226 тестов) |
| S37 | **Threat-compiler кеш (docker-layers модель)**: ThreatIntentCompiler кешируется по content-hash релевантного threat-среза (attacker, targets, causes, may) — слой зависит только от своих входов; добавление roles/exposes не инвалидирует кеш. Проблема: 92 перекомпиляции algebra-угроз за прогон, по одной на каждый rebind, при неизменных входах — 53-минутная rebind-фаза тратит CPU на пересчёт того же | `application/verification/formal/threat_compiler.py` (кеш), `workflow/execution/binder.py` (инвалидация по срезу), tests | бюджетный e2e: 92 threat_compiler-события при 60.7 мин | P2 | S | — | ✅ 2026-10-23 (compile_cached + threat_slice: content-hash среза, roles/exposes не инвалидируют, may — да; in-memory per-run; 226 тестов) |
| S38 | **Бенчмарк-роли в contract.py**: дополнить seed-граф бенчмарка полными ролями — `refers_to` для всех object_ref-полей (S13-семантика), `payload`/`mutable_input` для мутабельных полей (S18), `probe_target`/`extraction` для provisioning (S16), по образцу test-сборки McClintock/Dewey. Проблема: волна 6.4/6.5 сделала движок честным («нет факта = нет подстановки»), но бенчмарк не декларирует факты → 0 findings при живом исполнении (35 fixture_create + 27 setup-блокеров) | `benchmarks/nsfy_bench/contract.py` (`_FIELD_ROLES`, refers_to, probe_target), tests | бюджетный e2e: findings 12→0 из-за неполноты бенчмарк-фактов | P0 | S | S13 ✅, S16 ✅, S18 ✅ | ✅ 2026-10-23 (reveal-факты для 6 create-выходов: exposes+has+refers_to; 15 payload-ролей; probe_target для CreateOrder.note/CreateApiKey.scope; refers_to-полнота 27 input-полей regression-тестом; binder-приёмка executable-путей для всех 6 пар create→consumer; 164 бенчмарк-теста) |

#### S30 v2 — Deficit work-item graph and algebraic coalescing

S30 v2 не создаёт новый formal engine и не делает LLM-агентов автономными.
Это планировочная проекция над существующими `Deficit`, `ConsultationRequest`
и deterministic promotion.

Границы scope: S31 остаётся evidence-first gate, S32 — parked lifecycle,
S33 — saturation; S30 строит только work-item graph и планирует parallel waves.

**Стартовая точка:**

- startup grounding уже параллельный;
- reactive `_drain_reactive()` сейчас последовательный;
- плоский `Deficit.key` хорошо идентифицирует один дефицит, но плохо
  группирует path-fanout и связанные семантические вопросы.

**WorkItem — derived projection, не источник истины:**

```text
WorkItem =
    missing_fact_signature
  + effect_neighborhood
  + evidence_signature
  + axis / consultation kind
  + affected deficit IDs
  + immutable graph snapshot
```

Один `WorkItem` может закрывать много `Deficit`.

**Отношения между дефицитами:**

1. **Duplicate** — одинаковый canonical key.
2. **Co-factorable** — разные дефициты требуют один и тот же missing fact.
3. **Dependent** — ответ одной консультации нужен другой.
4. **Complementary** — разные вопросы, но одно evidence/slice.
5. **Conflict** — потенциально несовместимые outputs.
6. **Independent** — нет общих unknowns, зависимостей и конфликтов.

**Условие безопасного параллелизма:**

```text
parallel(W1, W2) :-
    independent(W1, W2),
    same_graph_snapshot(W1, W2),
    budget_available(W1, W2).
```

Промоушены параллельных work items обязаны быть коммутативными:

```text
(G ⊕ Δ1) ⊕ Δ2 = (G ⊕ Δ2) ⊕ Δ1
```

Если это не так — work items нужно сериализовать или связать dependency edge.
Циклы не должны порождать рекурсивные агентные вызовы; они сворачиваются в
SCC macro work item или обрабатываются как bounded fixed-point.

**Closure propagation и stale invalidation:**

Coalescing не доказывает глобальную независимость work items. Промоушен одного
`WorkItem` может закрыть или обесценить другой pending deficit через общий
граф, а не только через общий missing fact. Поэтому независимость — сильное
условие: отсутствие влияния не только на unknowns, но и на closure и slice
другого дефицита.

Нужны явные отношения:

```text
closes(W, D)
invalidates(W, D)
affects(W, D)
```

и post-commit пересчёт всех pending deficits:

```text
after_commit(Wave, G, G'):
    for D in pending_deficits:
        if closure(D, G'):
            close(D)
        elif signature(D, G') != signature(D, G):
            invalidate_and_requeue(D, G')
        else:
            keep(D)
```

Состояния после commit:

- **closed** — дефицит стал истинным на новом графе, повторная консультация
  не нужна;
- **stale** — slice/signature дефицита изменились, вопрос нужно переформулировать
  на новом graph snapshot;
- **unchanged** — дефицит остаётся валидным и остаётся в очереди.

Это закрывает текущий gap: `DeficitQueue` закрывает только тот deficit, для
которого был сделан вызов, и не пересчитывает остальные pending entries после
промоушена. В результате одна консультация может закрыть другой дефицит, но
он всё равно уйдёт в LLM.

**Стадии реализации:**

1. **Python deterministic grouping** — первая версия S30 без нового solver-слоя.
2. **Dependency DAG** — `supplies(W,U)` / `needs(W,U)`.
3. **Parallel waves** — только independent work items.
4. **Deterministic merge** — конфликты через `supersedes` / merge policy, не LLM.
5. **Closure propagation / stale invalidation** — после wave-commit
   пересчитываются все pending deficits и разделяются на
   `closed / stale / unchanged`.
6. **Library split later** — NetworkX закрывает SCC / topological sort /
   condensation / longest-path layering (S39), Clingo — set-cover и budget
   optimization, через существующий `ClingoEngine`, не как новый formal engine.

Приёмка:

- **S28**: две ревизии одного action не теряют ранее promoted факты; при
  логической замене появляется явный `supersedes`; planner не выдаёт
  non-monotonic rebuild из-за `accepted-batch` latest-wins.
- **S29**: фильтрация proposal-графа не создаёт dangling references; invalid
  fact дропается как issue, а не ломает всю consultation.
- **S30**: 20 path-fanout deficits с одним action/effect/missing-fact
  signature дают один LLM-вызов; новый `path_id` без нового effect не создаёт
  новый вызов; один promotion закрывает все affected deficits; independent
  work items параллелятся на одном immutable graph snapshot; dependent items
  упорядочены, а циклы сворачиваются в SCC macro work item; конфликты
  разрешаются deterministic merge/supersedes, не LLM; после commit pending
  deficits пересчитываются: закрытые не уходят в LLM, stale переформулируются
  на новом graph snapshot, unchanged остаются в очереди.
- **S31**: deficit без observation не порождает LLM-guess; sibling actions
  попадают в slice только из QDL-отношений.
- **S32**: одна и та же parked classification не перегенерируется без нового
  evidence; approval queue видит все уникальные leads.
- **S33**: после N неудач одного work item повторные вызовы прекращаются до
  нового evidence/effect.
- **S34**: quorum продвигает только факты, предложенные ≥2 независимыми
  ответами; protected classifications остаются source/evidence/operator gated.

### 6.6 Математическое замыкание resource/state/FSM (по итогам разбора 2026-10-23)

Контекст: S23–S27 остаются открытыми. Эта секция уточняет их формальную
модель, а не создаёт новые task ID. Цель — не допустить «второй логики
фикстур» и заставить будущих воркеров расширять существующие сущности,
а не строить параллельный слой.

**Reuse-first rule для воркеров:**

1. Сначала искать существующую реализацию в `QdlPlanner`,
   `StateMachineEngine`, `ScenarioBinder`, `StepSetupResolver`,
   `DeficitQueue`, `deficits.py`, `consultation.py` и
   `proposal_promotion.py`.
2. Расширять существующие сущности; новый слой допустим только если
   существующий механизм доказуемо неверен.
3. Если механизм неверен, перепроектировать его на месте, с тестами и
   обоснованием, а не строить параллельный.
4. Не вводить новый базовый предикат, пока не доказана невыразимость через
   текущий QDL-базис.

#### Математическая постановка

Пусть:

- `A` — конечное множество действий;
- `T` — типы ресурсов;
- `Q` — абстрактные состояния;
- `Σ` — мировое состояние;
- `Eff` — свободная алгебра эффектов;
- `δ_a : Σ ⇀ Σ` — частичная функция перехода для действия `a`.

QDL уже задаёт `Σ` как произведение:

```text
Store × Policy × ControlState × ObjectRegistry × Environment
```

и эффекты как термы:

```text
write / changed
grant / has
transition
create / remove
call / external_call
```

Задача fixture/setup сводится к задаче достижимости в конечной типизированной
transition system.

#### Каноническое QDL-отображение

| Математическое понятие | QDL-представление |
|---|---|
| типизированная ссылка на ресурс | `has(input_field(a,f), object_ref)` + `refers_to(input_field(a,f), t)` |
| требуемое состояние | `requires(b, q)` + типизированная ссылка |
| создание ресурса | `causes(a, create(t))` |
| переход состояния | `transition(a, q0, q)` / `causes(a, transition(q0,q))` |
| setup-план | derived walk over `causes` / `requires` |
| дефицит типизации | `fixture_type_deficit` |
| дефицит семантики состояния | `state_semantics_deficit` |
| достижимость FSM | `reachable_state` closure |

Новый базовый предикат `object_ref(t)` не вводится. Если он нужен как удобное
имя, это derived view, а не новый примитив:

```prolog
typed_object_ref(a, f, t) :-
    has(input_field(a, f), object_ref),
    refers_to(input_field(a, f), t).
```

Аналогично, `resource_state(t, q)` — не новый базовый терм, а производное
отношение:

```prolog
requires_resource_state(b, f, t, q) :-
    requires(b, q),
    typed_object_ref(b, f, t).
```

#### Setup как derived plan

Setup выбирается только по эффектам и предусловиям:

```prolog
provides_resource_state(p, t, q) :-
    path_effect(p, create(t)),
    path_state(p, q).

setup_for(p, b, f, t, q) :-
    provides_resource_state(p, t, q),
    requires_resource_state(b, f, t, q).

fixture_deficit(b, f, t, q) :-
    requires_resource_state(b, f, t, q),
    not setup_for(_, b, f, t, q).
```

Здесь:

- `path_effect` и `path_state` — planner-derived atoms, не persisted QDL-факты;
- путь `p` — bounded walk в существующем `QdlPlanner`;
- `create(t)` остаётся type-level эффектом;
- instance-level binding значений выполняется через `coupled` / Z3, а не через
  новый ресурсный примитив;
- негация `not setup_for` обязана оставаться стратифицированной.

#### FSM

Состояния и переходы остаются обычными QDL-фактами:

```prolog
initial(q0).
transition(a, q0, q1).
forbidden(n, q1).

reachable_state(q, q') :-
    transition(_, q, q').

reachable_state(q, q'') :-
    reachable_state(q, q'),
    transition(_, q', q'').
```

FSM — не отдельная сущность, а проекция одной transition system:

```text
Q = Σ / ≡
```

где `≡` — наблюдаемая эквивалентность состояний.

#### Индукция FSM

QDL может хранить и проверять `transition` / `forbidden`, но не может сам
индуцировать FSM из наблюдений. Это отдельная задача automata learning:

```text
traces
  -> prefix tree
  -> state merging
  -> hypothesis FSM
  -> QDL proposal
  -> deterministic validation
  -> counterexamples
  -> refined hypothesis
```

LLM может предлагать переходы и состояния, но только в `proposal` context.
Promotion — детерминированный и evidence-grounded.

#### Ограничения

- бесконечные домены требуют абстракции или Z3;
- value binding между действиями решается через `coupled` / SMT;
- линейность ресурсов требует явного моделирования владения и потребления;
- FSM-индукция недоопределена конечными наблюдениями и всегда остаётся
  гипотезой до контрпримера.

#### Приёмка

- **S23**: типизированный `refers_to` + `causes(create)` выбирает setup без
  name-based эвристик.
- **S24**: coverage считается по действиям, полям, ролям, эффектам и
  состояниям, а не только по уже связанным путям.
- **S25**: `observed_transition` порождает `state_semantics_deficit` и
  proposal, но не accepted-факт.
- **S26**: reactive budget не допускает starvation осей `fixture` / `state`.
- **S27**: полный цикл `deficit → consultation → promotion → rebind → new
  path` подтверждается тестом.

### 6.7 Buy-vs-build для текущих задач (решение 2026-10-23)

Контекст: владельца интересует, можно ли упростить реализацию S30–S34 и
FSM-индукции, переиспользуя библиотеки вместо hand-rolled алгоритмов.

**Решения:**

| Кандидат | Вердикт | Обоснование |
|---|---|---|
| `river` | ❌ не возвращать | C14 уже заменила на inline Beta-сэмплер (~20 строк). Бандит тривиально реализуется в Python; тянуть тяжёлую ML-библиотеку ради одного Thompson-sampler — избыточно. Возврат — только после B23-данных, когда сложность политики реально превысит ~50 строк |
| `networkx` | ✅ ввести сейчас | Код-аудит 2026-10-24 нашёл две самописные Tarjan SCC и ~145 строк дублированных графовых алгоритмов; порог «> ~100 строк / дублирование» из 6.7 превышен. Вводится через S39 только как graph-utility, не как formal engine |
| `hypothesis` | ✅ уже используется | Уже в runtime-зависимостях, `st.recursive` уже применяется в grammar_compiler. Действий не требуется |
| `pydantic` / `pydantic-settings` | ✅ уже используется | Pydantic-native весь QDL-домен. Профили уже читаются из TOML. Действий не требуется |
| `aalpy` | ⚠️ отложить до S40 | Passive automata learning для FSM-индукции (S25/S26). Вводить только за adapter-портом, эмиттящим QDL proposal; реализация зафиксирована в S40 |

**Не вводить (запрещено архитектурой):**

- `langgraph` / любые agent-orchestration фреймворки — второй planner;
- `celery` / `redis` — лишняя инфраструктура для параллелизма, который
  решается на уровне `ThreadPoolExecutor` / `GroundingRunner`;
- `deepdiff` — не может быть oracle, только diff-хелпер;
- `faker` — создаёт domain-specific данные, конфликтует с QDL-типизацией;
- `OR-Tools` / CP-SAT — второй solver; S30 stage 6 уже отдаёт set-cover и
  budget optimization существующему `ClingoEngine`;
- любая вторая formal engine — Clingo уже покрывает graph reasoning.

**Принцип для воркеров S30–S34:**

1. Первая версия — stdlib (dict, set, frozenset, heapq).
2. Библиотека вводится только когда собственный код превышает ~100 строк
   или перестаёт быть очевидно корректным.
3. Каждая новая зависимость — через `pyproject.toml`, с обоснованием
   «что именно она заменяет и почему это дешевле поддерживать».

### 6.8 Graph and automata library consolidation (2026-10-24)

Контекст: раздел 6.7 откладывал `networkx` и `aalpy`. Код-аудит 2026-10-24
показал, что порог «собственный код > ~100 строк или дублирование» уже
пройден. В проекте есть две независимые реализации Tarjan SCC:

- `workflow/execution/deficits.py` — iterative Tarjan SCC + Kahn topological
  order + condensation + longest-path wave layering;
- `application/verification/generators/payload_corpus/compiler.py` —
  recursive Tarjan SCC для grammar dependency cycles.

Это дублирование графовых алгоритмов и ~145 строк hand-rolled кода. Согласно
правилу 6.7, библиотека теперь оправдана.

AALpy не вводится как второй formal engine. Это **passive automata learning
sensor** за adapter-port: он читает QDL-граф с `observed_transition` фактами
и эмиттирует QDL proposal graph. Вердикт по-прежнему выносит только
`StateMachineEngine` + deterministic promotion policy.

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| S39 | **Graph-algorithm consolidation on NetworkX**: заменить обе реализации Tarjan SCC, hand-rolled Kahn topo sort и condensation на `networkx.strongly_connected_components`, `networkx.condensation`, `networkx.topological_sort` и `dag_longest_path`; выделить один общий graph-utility модуль; сохранить текущий deterministic wave-ordering и grammar compilation semantics без изменений | `workflow/execution/deficits.py`, `application/verification/generators/payload_corpus/compiler.py`, новый shared graph utility, `pyproject.toml`, tests | код-аудит 2026-10-24: 2 Tarjan SCC, ~145 строк; правило 6.7 | P2 | S | S30 v1 ✅ | ✅ 2026-10-24 (application/shared/graph_utils.py: NetworkX SCC+condensation+topo+longest-path; оба Tarjan удалены; SLOC −105; property-тест random digraphs; 173 теста) |
| S40 | **Passive learned automata adapter (AALpy)**: ввести `AutomataLearningPort` и AALpy-адаптер за ним; вход — QDL graph с `observed_transition` и declared state facts; выход — QDL proposal graph с `transition` / `forbidden` в `proposal` context; AALpy работает как deterministic proposal sensor, не как formal engine и не как verdict layer; каждый proposed transition обязан ссылаться на observed trace evidence; при нехватке данных адаптер эмиттирует `state_semantics_deficit`, а не догадку | `application/ports/` (`AutomataLearningPort`), `infrastructure/automata/aalpy.py`, `application/verification/formal/state_machine.py`, `proposal_promotion.py`, `pyproject.toml`, tests | раздел 6.6 «Индукция FSM»; S25 открыт; AALpy поддерживает active/passive automata learning, включая DFA/Mealy/Moore и RPNI/EDSM | P1 | L | S25 (scoped by 6.6) | ✅ 2026-10-24 (AutomataLearningPort + AALpyAutomataLearningAdapter (RPNI/EDSM); observed_transition → Moore machine → QDL proposal; state_semantics_deficit при insufficient/conflict; review_learned_transitions через Clingo; 115 тестов; закрывает S25) |

#### Границы

1. NetworkX — только graph primitives: SCC, condensation, topological sort,
   longest-path layering. Он не заменяет Clingo и не становится reasoning engine.
2. AALpy — только proposal sensor за port. Он не пишет accepted facts и не
   выносит verdicts.
3. OR-Tools / CP-SAT не вводим: S30 stage 6 уже отдаёт set-cover и budget
   optimization существующему `ClingoEngine`. Второй solver не нужен.
4. `automata-lib`, `Mata`, `rustworkx`, `pyformlang` не вводим. AALpy и NetworkX
   закрывают текущие потребности; остальные кандидаты — преждевременная
   зависимость.

#### Приёмка S39

- в `pyproject.toml` появляется `networkx`;
- оба самописных Tarjan SCC удаляются;
- `deficits.py` использует `networkx.strongly_connected_components`,
  `condensation`, `topological_sort`, `dag_longest_path`;
- `payload_corpus/compiler.py` использует общий graph utility;
- существующие тесты work-item waves и grammar compilation проходят без
  изменения ожидаемого порядка;
- property-тест на random directed graphs подтверждает, что новая
  реализация даёт те же SCC/waves, что и старая;
- SLOC снижается минимум на 100 строк без потери детерминизма.

#### Приёмка S40

- `AutomataLearningPort` объявлен в `application/ports`;
- AALpy импортируется только внутри infrastructure-адаптера;
- адаптер читает `observed_transition` факты из QDL, а не из имени метода
  или поля;
- выход адаптера — `QdlGraph` в `proposal` context с `transition` / `forbidden`;
- каждый proposed transition несёт provenance на наблюдаемую transition;
- без достаточного evidence адаптер возвращает `state_semantics_deficit`,
  а не accepted fact;
- `StateMachineEngine` остаётся единственным verifier/reasoner;
- promotion идёт через существующий deterministic policy, не через AALpy;
- конфликт между learned transition и declared specification порождает
  mismatch/deficit, а не тихую перезапись;
- тесты проверяют, что state labels берутся только из observed QDL states.

#### Тесты

S39:

- `test_scc_components_match_previous_implementation`
- `test_work_item_waves_preserve_deterministic_order`
- `test_payload_grammar_recursive_components_compile`
- `test_random_digraph_property_waves_are_stable`
- `test_hand_rolled_tarjan_functions_removed`

S40:

- `test_aalpy_adapter_reads_observed_transition_facts`
- `test_learned_transition_is_proposal_not_accepted`
- `test_learned_transition_requires_observed_evidence`
- `test_state_semantics_deficit_when_traces_insufficient`
- `test_conflicting_transition_becomes_mismatch_not_overwrite`
- `test_state_labels_come_from_observed_qdl_states`
- `test_automata_learning_is_deterministic_under_fixed_seed`

### 6.9 Partial-observation witness semantics and derivation closure (2026-10-24)

Контекст: последний live-прогон улучшил результат (5 → 11 findings), но показал
три системных дефекта, не закрытых предыдущими волнами:

- 111/120 target cells остаются `blind`, хотя часть возможностей реально
  исполняется runtime-ом (пример: OOB-эффект получает finding, а его поле в
  coverage остаётся `primitive=unknown`);
- 216 work-item dispatches приходятся на 98 уникальных work items, 55
  предметов повторяются ровно три раза, один — шесть;
- marker-oracle всё ещё может превращать отсутствие свидетеля в `PASS`.

Эти числа — диагностика, не acceptance criteria. Общий математический вывод:
проблема не в недостаточной выразительности QDL, а в отсутствии единой
partial-observation семантики и derivation-based closure.

#### Математическая постановка

Пусть:

```text
W  — QDL witness terms
C  — observation channels
O  — runtime observations
P(e) — positive witnesses эффекта e
N(e) — negative witnesses эффекта e
```

Каждое наблюдение задаёт частичную оценку:

```text
val_o : W ⇀ {0, 1, ⊥}
complete_o : C -> {0, 1}
```

Для эффекта `e`:

```text
T(e,o) ⇔ ∃w ∈ P(e): val_o(w) = 1

F(e,o) ⇔ N(e) ≠ ∅
         ∧ ∀w ∈ N(e):
              complete_o(channel(w)) = 1
              ∧ val_o(w) = 0

U(e,o) ⇔ ¬T(e,o) ∧ ¬F(e,o)
```

Вердикт:

```text
FAIL        ⇔ T(e,o)
PASS        ⇔ F(e,o)
UNSCOREABLE ⇔ U(e,o)
```

Ключевая асимметрия:

```text
positive witness — existential;
negative witness — universal и требует полноты каналов.
```

Композиция соответствует сильной трёхзначной логике Клини:

```text
U ∧ U = U
F ∧ U = F
T ∨ U = T
```

Поэтому `UNSCOREABLE` не может молча становиться `PASS`.

Это согласуется с runtime verification на конечных следах и с oracle problem:
конечное наблюдение не обязано решать свойство, а частичный оракул не имеет
права выдавать отсутствие сигнала за опровержение. Отрицательный вывод требует
локального closed-world assumption по явно полным каналам.

#### Отношение к существующей архитектуре

Новый formal substrate не вводится. Используются уже существующие:

- QDL witness-конструкторы: `field`, `status`, `error`, `latency`,
  `callback`, `trace`;
- роли и типы: `has`, `refers_to`, `exposes`, `is`;
- эффекты и достижимость: `causes`, `reaches`, `reaches_plus`;
- состояние: `initial`, `transition`, `forbidden`;
- Clingo — рекурсивная достижимость и graph reasoning;
- Z3 — типизированные value-constraints, а не graph reachability.

`WitnessGraph`, `WitnessRepository` и второй formal engine запрещены.

#### Задачи

| ID | Задача | Файлы | Источник | P | Eff | Deps | Статус |
|---|---|---|---|---|---|---|---|
| A7 v2 | **Uniform witness semantics**: единый deterministic contract для primitive oracles: positive witness → `FAIL`; complete negative witness → `PASS`; иначе `UNSCOREABLE`. Marker-absence без полного negative scope — `UNSCOREABLE`, не `PASS`. Principal scope mismatch — `UNSCOREABLE` + deficit, не vacuous `PASS`. Sink/witness role taxonomy переносится из кода в QDL/policy, без hardcoded строк | `application/verification/oracles/`, `PrimitiveOracleRouter`, `policy_verdict.py`, `docs/qdl-algebra.md` | e2e 2026-10-24; K3/LTL3; oracle problem; local CWA | P0 | M | — | ✅ 2026-10-24 (PolicyVerdict + WitnessRolePolicy + Kleene 3-valued: FAIL/PASS/UNSCOREABLE; echo→UNSCOREABLE; vacuous PASS удалён; witness_roles.yaml; 159+2207 тестов) |
| S21 v2 | **Algebraic relation deficits**: дефицит — unprovable QDL subgoal, а не action/reason string. `deficit(R,G) :- requirement(R,G), not derivable(R,G)`. Явные подцели вида `unprovable_subgoal(refers_to(...))`, `unprovable_subgoal(reaches(...))`, `unprovable_subgoal(causes(...))`, `unprovable_subgoal(transition(...))`; consultation axis выбирается по predicate class, не по vulnerability class | `workflow/execution/deficits.py`, `semantic_norm_compiler.py`, `application/verification/planning.py`, `formal/consultation.py` | e2e: 98 unique work items на 216 dispatches | P0 | M/L | A7 v2 | ✅ 2026-10-24 (QdlSubgoal + derivable() через Clingo; Deficit=алгебраическая подцель; predicate_class→axis; subgoal-level dedup; 2211 тестов) |
| S23 v2 | **Fixture typing closure**: `fixture_type_deficit` получает axis и consultation; missing-fact alphabet расширяется `refers_to`, `targets`, `causes(create)`; setup выбирается только по typed effects и required state, без alias/suffix fallback | `deficits.py`, `consultation.py`, `binder.py`, `step_setup.py` | e2e: 8 setup unavailable; report-only fixture deficits | P0 | M | S21 v2 | ✅ 2026-10-24 (fixture consultation axis + closed alphabet refers_to/targets/causes(create); promotion exception для fixture-typing facts; 2067+174 тестов) |
| S24 v2 | **Derivation-based coverage**: `supports_primitive` и `field_role` становятся derived views над `has/refers_to/exposes/causes/is`; coverage считается по полям, эффектам и состояниям, не по action-level; `blind` разделяется на semantic/capability/setup/evidence/oracle deficit | `coverage.py`, `norm_coverage.py`, `semantic_norm_compiler.py` | e2e: 111/120 blind при живых возможностях | P0 | M/L | S23 v2 | ✅ 2026-10-24 (derive_field_roles + derive_primitive_supports как derived views; coverage по полям/эффектам/состояниям; blind→5 типов; 2067+174 тестов) |
| S30 v3 | **Wave-level closure**: после merge всей волны пересчитываются все pending deficits на merged graph; `supersedes` применяется к persisted facts; work-item identity строится из unprovable subgoals, а не только action/effect/reason | `deficits.py`, `live_workflow.py`, `proposal_promotion.py` | e2e: 118 extra dispatches; closure per result only | P0 | M/L | S21 v2 | ✅ 2026-10-24 (propagate_wave_results: post-wave merged graph evaluation; supersedes в closure; wave-level не per-result; 2067+174 тестов) |
| S32 v2 | **Parked lead lifecycle**: stable lead key `(action, holder, role)`; повторная консультация только при новом evidence; classification deficit не является security finding, только lead/deficit | `grounding.py`, `proposal_promotion.py`, reporting | e2e: 100 parked alternatives | P1 | M | S30 v3 | ☐ |
| S33 v2 | **Attempt outcome policy**: классифицировать причины повторов; no-evidence — одна попытка; transient schema/token — один retry; rejected promotion — без retry до нового evidence; saturation остаётся последним ограничителем | `deficits.py`, `live_workflow.py` | e2e: 55 items × 3, один × 6 | P1 | M | S30 v3 | ☐ |
| S25 v2 | **State learning runtime proof**: AALpy/RPNI остаётся deterministic proposal sensor; каждый learned transition обязан ссылаться на observed evidence; `StateMachineEngine` остаётся verifier; недостаток данных — `state_semantics_deficit` | `state_machine.py`, automata adapter, `proposal_promotion.py` | e2e: states/transitions unresolved; automata learning limits | P1 | M | S24 v2 | ☐ |

#### Планирование и выбор work items

Work-item selection можно формализовать как budgeted maximum coverage:

```text
maximize |closed_deficits(S)|
subject to cost(S) ≤ budget
           dependencies(S) respected
```

Если `closed_deficits` монотонно субмодулярна, greedy даёт стандартное
приближение. При зависимостях и конфликтах используется существующий
`ClingoEngine`, а не второй solver. Bandit/active-learning приоритеты могут
быть advisory-фичей, но не verdict layer.

#### FSM и process mining

QDL может хранить и проверять `transition` / `forbidden`, но не может
гарантированно индуцировать FSM из конечных positive traces. Automata learning
и process mining всегда дают hypothesis:

```text
observed traces
  -> prefix tree / RPNI / EDSM / AALpy
  -> QDL proposal
  -> deterministic validation
  -> counterexamples
  -> refined hypothesis
```

Полный вывод FSM из конечных наблюдений невозможен без teacher/equivalence
запросов. Поэтому learned model не может автоматически становиться accepted
фактом.

#### Запрещено

- новый `WitnessGraph` / `WitnessRepository`;
- новый базовый предикат `object_ref(t)` вместо derived view;
- hardcoded sink types, path separators и payload lists;
- benchmark-specific method/field names в acceptance;
- LLM verdicts;
- OR-Tools / CP-SAT как второй solver;
- превращение `UNSCOREABLE` в `PASS` через вероятность.

#### Приёмка

- unknown никогда не превращается в `PASS`;
- каждая `PASS`-семантика ссылается на полный negative witness scope;
- coverage согласуется с фактически доступными oracle primitives;
- один promotion может закрыть несколько deficits через post-wave graph;
- повторная консультация невозможна без нового evidence или изменённого graph
  signature;
- classification deficit не попадает в `findings`, только в leads/deficits.

#### Тесты

Witness semantics:

- `test_positive_witness_maps_to_fail`
- `test_complete_negative_witness_maps_to_pass`
- `test_incomplete_negative_channel_maps_to_unscoreable`
- `test_marker_absence_without_complete_negative_scope_is_unscoreable`
- `test_field_exposure_principal_mismatch_is_unscoreable`
- `test_unknown_composition_does_not_become_pass`

Fixture/resource:

- `test_typed_object_ref_requires_has_and_refers_to`
- `test_missing_refers_to_creates_fixture_type_deficit`
- `test_fixture_type_deficit_dispatches_consultation`
- `test_create_effect_provides_resource_state`
- `test_no_setup_creates_fixture_deficit`

Coverage:

- `test_supports_primitive_derived_from_object_ref_role`
- `test_supports_primitive_derived_from_external_net_role`
- `test_supports_primitive_derived_from_exposes`
- `test_one_grounded_field_does_not_hide_sibling_field`
- `test_finding_capability_appears_in_coverage`

Work items:

- `test_fanout_deficits_with_same_subgoal_use_one_work_item`
- `test_wave_closure_recomputes_all_pending_deficits`
- `test_supersedes_is_applied_to_persisted_graph`
- `test_no_evidence_work_item_gets_one_attempt`
- `test_rejected_promotion_is_not_retried_without_new_evidence`

State learning:

- `test_learned_transition_is_proposal_not_accepted`
- `test_learned_transition_requires_observed_evidence`
- `test_insufficient_traces_create_state_semantics_deficit`
- `test_conflicting_transition_becomes_mismatch_not_overwrite`

#### Математические источники

- Bauer, Leucker & Schallhart, *Comparing LTL Semantics for Runtime
  Verification* — https://trustworthy.systems/publications/nicta_full_text/3976.pdf
- Barr et al., *The Oracle Problem in Software Testing: A Survey* —
  https://dl.acm.org/doi/10.1109/TSE.2014.2372785
- Reiter, *On Closed World Data Bases* —
  https://link.springer.com/chapter/10.1007/978-1-4684-3384-5_6
- Lifschitz, *What Is Answer Set Programming?* —
  https://www.cs.utexas.edu/~vl/papers/wiasp.pdf
- Gelfond & Lifschitz, *Classical Negation in Logic Programs and Disjunctive
  Databases* — https://doi.org/10.1007/BF03037169
- Kakas, Kowalski & Toni, *Abductive Logic Programming* —
  https://www.doc.ic.ac.uk/~rak/papers/abdsurv.pdf
- Khuller, Moss & Naor, *The Budgeted Maximum Coverage Problem* —
  https://thibaut.horel.org/submodularity/papers/khuller1999.pdf
- Nemhauser, Wolsey & Fisher, *An Analysis of Approximations for Maximizing
  Submodular Set Functions—I* — https://doi.org/10.1007/BF01588971
- Angluin, *Learning Regular Sets from Queries and Counterexamples* —
  https://doi.org/10.1016/0890-5401(87)90052-6
- Vaandrager, *Model Learning* —
  https://link.springer.com/chapter/10.1007/978-3-642-19345-3_20
- van der Aalst, *Process Mining* —
  https://doi.org/10.1007/978-3-642-19345-3
- Alchourrón, Gärdenfors & Makinson, *On the Logic of Theory Change* —
  https://doi.org/10.2307/2274239

### 6.10 Post-e2e architecture hardening (2026-10-25)

Контекст: прогон 2026-10-24 улучшил стоимость и findings, но вскрыл четыре
архитектурных дефекта: рассинхронизацию HTML coverage-рендера, type confusion
в resource identity, ownership-эффекты из alternatives и evidence-less
dataflows-консультации. Все фиксы закрывают саму причину, а не симптом.

| ID | Задача | Файлы | Источник | P | Eff | Статус |
|---|---|---|---|---|---|---|
| S41 | **HTML coverage renderer migration**: перевести HTML-рендер с legacy `QdlCoverageModel.target/cells` на `fields/effects/field_cells/effect_cells/deficit_counts/state_machine`; не возвращать legacy-поля | `presentation/html/report.py`, tests | e2e: `AttributeError: QdlCoverageModel has no target` | P0 | S | ✅ 2026-10-25 (доступный `<details>` UI, field/effect/state проекции, 10 тестов) |
| S42 | **Stand resource identity from snapshot**: `StandState.resources` строится только из явных `PolicySnapshot.resources`; `method.resource_types` — тип-фильтр, а не источник идентификаторов; отсутствующий тип — typed deficit | `composition/run_provider.py`, `infrastructure/application/verification/formal/policy_projection.py`, `infrastructure/stand/file.py`, benchmark stand fixture | e2e: user получал `order-1001` | P0 | M | ✅ 2026-10-25 (явные stand-ресурсы; user/order/profile/inventory разделены; 45+275 тестов) |
| S43 | **Ownership-effect evidence boundary**: create/remove могут предлагать только `fixture`/`dataflows` и только с evidence; alternatives не может предлагать ownership-эффекты; setup provider выбирается contract → evidence-verified, а не по insertion order | `formal/consultation.py`, `formal/axis_grounding.py`, `formal/proposal_promotion.py`, `workflow/execution/binder.py`, tests | e2e: accepted `causes(ApplyCoupon, create(order))` подменял CreateOrder | P0 | M | ✅ 2026-10-25 (закрытый ownership-гейт + promotion evidence + tiered provider selection; 1022 теста) |
| S44 | **Dataflows evidence gate and alternatives grammar**: без live observation или declared `reaches`/sink факта dataflows паркуется как `evidence_deficit`; alternatives принимает только закрытый causal-effect алфавит и объявленные поля | `workflow/execution/live_workflow.py`, `formal/consultation.py`, `formal/axis_grounding.py`, tests | e2e: 17/24 empty dataflow proposals; invented `read/list/enumerate/export/quot` | P0 | M | ✅ 2026-10-25 (evidence gate + закрытая грамматика; 548 formal + 2045 integration тестов) |
| S45 | **Classification-deficit diagnostics**: classification deficit не security finding; read model разделяет findings и diagnostics с сохранением provenance | `verification/class_catalog.py`, `application/reporting/service.py`, `presentation/json/report.py`, tests | e2e: 2 classification deficits в findings | P0 | S/M | ✅ 2026-10-25 (`ReportBundle.diagnostics`, JSON diagnostics, findings/summary/OWASP только по security findings; 148 тестов) |
| S46 | **Request-field execution coverage**: разделить `request_executed` и `oracle_witness_observed`; поле, фактически присутствовавшее в request, учитывается как executed, но не обязано считаться oracle-covered | `workflow/execution/coverage.py`, `application/reporting/service.py`, `presentation/json/report.py`, `presentation/html/report.py`, `presentation/markdown/report.py`, tests | e2e: 180 evidence_blind полей при живых request-полях | P0 | M | ✅ 2026-10-25 (отдельная runtime-проекция из `TraceStep.request_fields`; JSON/HTML/Markdown показывают Request/Witness; 185 тестов) |

Интеграционная проверка после слияния:

```text
751 targeted tests passed
2098 non-benchmark tests passed
171 benchmark tests passed
4 sandbox-only gRPC port tests passed with escalation
ruff check + ruff format --check: clean
```

### 6.11 Algebraic reformulation of remaining gaps (2026-10-25)

Контекст: старые формулировки S21–S34 частично описывали симптомы
(«добавить ось», «сделать бюджет», «quorum»). Ниже приведена алгебраическая
переформулировка, которая закрывает причину, а не конкретный кейс.

| ID | Алгебраическая постановка | Файлы | Статус |
|---|---|---|---|
| S21R | **Total consultation algebra**: `axis(subgoal) = f(predicate_class, evidence_context)`; функция тотальна над классами QDL-предикатов; отсутствие образа — `consultation_deficit(predicate_class)`, а не отсутствующая фича | `deficits.py`, `consultation.py`, `axis_grounding.py`, `application/verification/planning.py`, tests | ✅ 2026-10-25 (тотальная маршрутизация predicate-class → axis; evidence-routes; import-time closure; `consultation_deficit`; ownership-эффекты выведены из alternatives; 2202 non-benchmark tests) |
| S24R | **Term coverage algebra**: `coverage(term) = semantic × setup × oracle × runtime`; дефицит — по недостающему фактору, а не по path/action | `coverage.py`, `norm_coverage.py`, `semantic_norm_compiler.py`, `reporting/service.py`, tests | ✅ 2026-10-25 (`TermFactors` + term projection; missing-factor lattice semantic → setup → channel → primitive → runtime; 18 lattice/property tests; 2202 non-benchmark tests) |
| S32R | **Lead lifecycle as belief revision**: `lead_key = (action, holder, role, evidence_signature)`; повторная консультация только при новом evidence, иначе сохраняется lead | `grounding.py`, `proposal_promotion.py`, `reporting/service.py`, tests | ✅ 2026-10-25 (`LeadLifecycle` vacuity/expansion; length-prefixed evidence signature; consultation ledger; repeat only with new evidence; report dedupe) |
| S33R | **Consultation outcome automaton**: `outcome ∈ {promoted, parked, rejected, transient_error, missing_evidence, conflict}`; детерминированная политика переходов, не числовые попытки | `consultation_outcomes.py`, `live_workflow.py`, tests | ✅ 2026-10-25 (absorbing outcome automaton; structural classification; no numeric retry; one transition per evidence signature; 21 new tests) |
| S26R | **Fair scheduling algebra**: `maximize information_gain subject to max_min_fairness(deficit_class)`; не ручные квоты | `deficits.py`, `grounding.py`, `live_workflow.py` | ☐ |
| S34R | **Deterministic intersection**: `accepted = ∩ independent_grounded_proposals`; не majority vote и не аппроксимация | `consultation.py`, `axis_grounding.py`, `proposal_promotion.py` | ☐ |
| S22R | **Runtime/docs invariant**: документация — проекция runtime, а не параллельное описание; расхождение = тестовый дефект | `README.md`, `docs/engine-runtime-2026-10-19.md`, `run_provider.py`, `application/verification/planning.py` | ☐ |

Требование к реализациям: без hardcoded имён, без vulnerability dictionary,
без эвристик по именам и без majority-vote quorum.

### 6.12 Probe-carrier closure и classification residuals (2026-10-26)

Разбор прогона `run:662dcd9f29c247a8beffbd45d60334c1` показал разрыв:
`prevents` создаёт логический путь независимо от carrier-поля, а отсутствие
carrier обнаруживается только в marker oracle. Реализован prerequisite
`probe_carrier(Action, Field)` как derived query над существующими
`has`/`reaches_plus` и source declarations; модель не может записать его
напрямую. Формализация находится в `qdl-algebra.md`, §12.

| Обязательство | Реализация и проверка |
|---|---|
| Carrier для marker/OOB | Одна проекция `compile_probe_fields`; executable contexts, current roles, declared inputs, пересечение с `MethodSpec.fields` |
| Closure | `witness_requirement` → `DeficitQueue` → dataflows → proposal `reaches` → deterministic promotion → rebind; content-versioned path |
| Transport coverage | Smoke fallback для действий без channel-ready пути; verdict остаётся `UNSCOREABLE` |
| Prerequisite failure | Отдельный scheduler-переход без расхода canonical execution retries; replay сохраняет эту границу |
| Classification | Residuals берутся из ограничений кандидатов; `Sink` не скрывает `missing_sink_type`; closure учитывает allowed values |
| Promotion typing | Множество source-типов вместо первого `is`; carrier field обязан существовать в source; declaration closure принимается атомарно и не переносит модельные input schemas или sink classifications в accepted через зависимости |
| Request scope | Binding, coverage и witness obligations ограничены действиями выбранных путей; посторонние методы не расходуют budget method-scoped кампании |
| Gate telemetry | Invocation и typed decision имеют одинаковый invocation ID, отрицательное решение учитывается как gate activation |

Сквозная локальная проверка использует реальные workflow, SQLite, promotion,
binder, scheduler, генератор и oracle, заменяя только модель и target.
Проверяются также отказ модели без выдуманного verdict, четыре carrierless
версии с последующим repair/replay и отсутствие solver fan-out при сборе
100 одинаковых obligations. Это локальная приёмка механизма; новый живой
e2e и изменение M1 recall пока не подтверждены. Конкретная причина потери
одного метода в историческом прогоне остаётся неатрибутированной без его
event log и resolved launch configuration.

### 6.13 Независимое ревью execution path и доказательств (2026-10-26)

Повторная проверка рассматривает не число вызовов модели, а сохранение запросов
и свидетельств при переходах QDL → planner → execution → oracle → coverage.
Фикс принимается только вместе с исходным контрпримером и положительным
контролем. Новые словари, параллельные IR и самописные solver не вводятся.
Работы изолированы по владельцам; изменения интегрируются последовательно.

| Пакет | Обязательство | Состояние |
|---|---|---|
| V1 | Reflection и количество успешных вызовов не доказывают `reached`/`completed` | Safety-исправление интегрировано; source/runtime binding для named-flow completion не закрыт |
| V2 | Readback/concurrency witness относится к текущему кандидату; shrinking не заимствует старый witness | Интегрировано; одна physical measurement поддерживает несколько norm-indexed evaluations, без повторных transport checks |
| V3 | Отрицательный witness требует полного scope; coverage связана с конкретными norm/effect и oracle verdict | Интегрировано; canonical norm binding и порядок событий проверены |
| S1 | File policy сохраняет principal/action/resource; отрицание допустимо только в явно полном source scope | Интегрировано, 110 targeted checks passed |
| D1 | Immutable projection и current source revision различаются; namespace prefix трактуется буквально | Интегрировано, 28 targeted checks passed |
| R1 | Posterior и выбор принадлежат River; fractional reward не превращается в `bool(reward)` | Интегрировано, River 0.22.0 и lock; 229 worker checks и 19 integration checks passed |
| P1 | Planner projection сохраняет ответы и цепочки между executable contexts | Интегрировано, включая mixed-context reveal и effects |
| C1 | Retry учитывает только фактически выполненные шаги | Интегрировано; untouched tail сохраняет свой retry budget |
| C2 | Deferred work отличается от ready; новые relevant facts открывают только нужный differential mode | Интегрировано; одна reactive wave перед rebind/execution |
| L1 | Consultation и promotion проверяют один bounded QDL neighbourhood | Интегрировано; unrelated и out-of-bound siblings отвергаются |
| L2 | Provider boundary сохраняет budgets, redaction и ограничения rendered slice | Интегрировано через существующий model adapter; несовместимый GLM tokenizer guard отклонён |
| F1 | Solver учитывает контексты конкретных правил; математические гарантии соответствуют реализации | Интегрировано; T2 ограничена доказанным фрагментом с проверенной контрмоделью |
| P2 | Stateful setup исполняется через существующие QDL setup paths | Интегрировано; create + suffix проверены через существующий resolver; create-only без runtime свидетельства состояния остаётся deficit |
| M1 | Supersession имеет одну current-view; incremental planner эквивалентен fresh | Интегрировано; raw-role lookup и stale append-grounding удалены |
| C3 | У durable reactive commit один lifecycle owner | Интегрировано; offline fixtures переведены на явный owner handoff, 52 checks passed |
| I1 | Enum literals, manifest identity и resource-qualified fields сохраняются при binding | Интегрировано; data literals допускают пустые строки, node references сохраняют nonblank invariant |
| DRY | Один schema/parser/token-budget owner на модельной границе | Интегрировано: −190 production-строк, без новых типов/модулей |

Для V1 отсутствие корректного flow-state контракта не заменяется новой
эвристикой. `UNSCOREABLE` сохраняется как незакрытое доказательное обязательство.
Для S1 полнота — явная metadata источника с exact service/subject/action/resource
scope; отсутствие `may` в partial graph само по себе не доказывает запрет.
Для R1 fractional reward преобразуется в seeded Bernoulli с `P(B=1)=r`:
матожидание сохраняется, но добавляется шум отдельного обновления.

V2: `Check.invariant_id` — generation hint, не единственная допустимая
интерпретация физического измерения. Существующие evaluation maps используют
пару `(observation_id, invariant_id)`; norm reference разрешается через текущий
binding. Readback cache хранит существующий `ReadBackResult` с исходными checks,
а повторная интерпретация использует тот же classifier, trace и step-event
publisher. Check ID, request, identities и marker не меняются. Две нормы не
перезаписывают друг друга; свежий denied/shrink-кандидат не получает чужую пару.
Новый transport, evidence store или assessment IR не добавлен.

DRY: `ModelClient.complete(response_type=...)` задаёт единственную schema.
Адаптер нормализует wire response в `ModelResponse.structured`; consultation,
axis, threat model и generator больше не разбирают `content`. Существующий
`ConsultationBudget` расширяет `ModelBudget` только ограничением делегирования.
Input/output overrun сравнивается в адаптере; недопущенный payload теряет
`structured`, но сохраняет actual usage для provenance. Пустой/неполный raw
usage отвергается до доверия SDK-подстановкам нулей. Native output cap проверен
через настоящий SDK и локальный MockTransport; input cap проверяется по actual
usage после вызова, точный tokenizer для GLM не подменяется чужим.

При независимом ревью S1 обнаружена и исправлена дополнительная регрессия:
policy decision для одного instance не может сопровождать запрос к другому.
Несовместимый requested resource остаётся binding/setup deficit.
Финальная проверка ядра: 3180 passed, 2 full-workflow controls проверены отдельно
и passed. Snapshot всех Python-исходников до/после core run совпал. Расширенный
offline benchmark: 173 passed (четыре loopback gRPC server checks отдельно
проверены с разрешённой эскалацией). Повторные отрицательные контрпримеры не
создают findings; 74 model/consultation checks и Ruff прошли. Это не live e2e.

Эта волна проходит локальную проверку. Улучшение live coverage, M1 recall и
причины исторической регрессии нельзя считать подтверждёнными новым e2e.

### 6.14 Стоимость QDL projections и setup queries (2026-10-26)

Профиль offline readback показал повторную валидацию одинаковых context views,
отдельный solve для каждой пары action/state на каждом пути и повторную grammar
проекцию для alias-ключей. Стоимость находилась преимущественно в binding,
а не в собственно `IncrementalQdlPlanner`.

Выбор контекстов перенесён из двух реализаций в `QdlGraph.select_contexts`.
Для валидированного immutable графа используется закон `ΠC(G) = G`, когда
весь граф уже находится в C; изменённый subset заново проходит проверку
declarations/references. Правила фильтруются целиком.

Существующий query `requires` переработан в `derive_requirements`: Boolean
`derivable` и batch setup используют одни decoded core `Term`, один matcher
и Clingo. Binding материализует relation один раз и переиспользует строки
внутри своей сборки; следующий bind вычисляет её заново. Direct proof остаётся
доступен при solver failure. Intensional rows не принуждаются к persistable
`Fact`: переменная в правиле может связаться с data literal. Grammar source
выбирается один раз, grammar строится по реальным method IDs, не по aliases.
Новых модулей, типов, solver или межсессионного кэша не добавлено.

| Измерение одного и того же offline сценария | До | После |
|---|---:|---:|
| Два одинаковых bind, cProfile | 47.56 s | 5.87 s |
| `ClingoEngine.solve` в этих bind | 528 | 122 |
| Валидации `QdlGraph` | 598 | 36 |
| Grammar projections | 156 | 78 |
| Полный workflow без профилировщика | 82.42 s | 20.60 s |

Полный canonical binding snapshot совпал: 69 paths, 58 norms, setup, grammar,
deficits и identities. В полном workflow совпали physical requests/responses,
findings, verdicts, semantic path descriptors и evidence associations. Для
сравнения fresh runs нормализованы случайные IDs и связанные с provenance
path hashes; исключено фактическое `duration_ms` наблюдений. Остались три
физических вызова и один finding. Это один контрольный workload, не оценка
ускорения live e2e или статистическая performance guarantee.

Независимое ревью проверило projection composition, invalid subsets, aliases,
solver failure, пустой derived literal и signed zero. Вариант LRU по Python
graph equality отклонён: `+0.0` и `-0.0` имеют разное QDL/ASP значение. В
финальном коде cache отсутствует. Regression controls сохранены в существующих
domain/planner/fixture tests. Профили и snapshots: `/tmp/dast-planning-perf-20261026/`.

В четырёх production-файлах +102/−75 строк (нетто +27); три прежние функции
перенесены/переработаны, число функций не выросло. Приёмка в основном дереве:
3196 passed; единственное падение было дрейфом сгенерированной DI-документации,
её обновили текущим renderer, затем 6 architecture checks passed. Все 173
offline benchmark checks прошли за 175.58 s; Ruff check/format чистые.

### 6.15 Ссылочная замкнутость sibling slices: live regression (2026-10-26)

Первый live GLM 5.2 запуск после §6.14 прервался на построении sibling slice:
`causes(A, allowed(C))` оставался в графе, но declaration C отбрасывался,
если C не входил в выбранных участников. Поддерживающая ссылка ошибочно
приравнивалась к разрешению включить action в consultation domain. На
сохранённом валидном source это воспроизведено для 3 из 39 action slices.
Артефакты: `/tmp/cloud-dast-e2e-glm52-20261026-195013/`.

Существующий сборщик references ядра опубликован как `collect_references`
и используется существующим slice closure. Объявление supporting Action
добавляется только при настоящей schema-reference; literal с тем же текстом
не расширяет slice. Множество участников и promotion authority по-прежнему
задаются seed и выбранными siblings, а не всеми declarations среза. Нового
walker, IR, транспорта или слоя promotion нет.

После исправления валидны все 39 slices сохранённого source; 798 связанных
formal/domain/workflow checks passed, Ruff чистый. Независимая проверка
подтвердила отсутствие расширения promotion domain для supporting и
truncated actions. Повторный live запуск использует новый immutable source
snapshot: `/tmp/cloud-dast-e2e-glm52-20261026-201139/`; его итог фиксируется
отдельно после завершения, улучшение recall пока не подтверждено.

Повторный запуск завершился штатно за 1120.42 s (exit 0), сформировал все
отчёты, но приёмку по результативности не проходит: 101 physical check,
16/39 методов, 0 findings. Для предыдущего GLM 5.2 запуска
`/tmp/cloud-dast-e2e-glm52-20261026-125612/` это 138 → 101 проверка,
23 → 16 методов, 4 → 0 findings. Версии source различаются: это наблюдаемая
регрессия результата, не доказательство причины конкретным изменением.

81/101 ответа имеют gRPC NOT_FOUND, 20 — OK. Из 26 событий blocked path:
11 transport/application error, 7 missing_irreversibility_fact, 4 no executable
norm fact, 3 policy result not observable, 1 fixture_unavailable. После
последнего check в 20:20:20Z до evaluating в 20:30:23Z продолжались
консультации, поэтому этот хвост нельзя приписывать ожиданию formal timeout.
В adapter log 97 запросов: 90 completed и 7 LengthFinishReasonError;
report учитывает 647715 tokens успешных запросов, известные usage ошибок —
ещё 98838 tokens. Эти величины не заменяют provider billing. Только concurrency
дал 16 diff pairs, хотя включены все пять режимов. Fields 0/75 covered,
effects 0/8 covered. Отсутствие findings не трактуется как отсутствие багов.
Сводка с причинами и ограничениями сравнения: `analysis.json` повторного запуска.

### 6.16 Причины регрессии live GLM 5.2: counterfactual review (2026-10-26)

Исследование §6.15 выполнено на immutable source, events и отдельных копиях
финальной SQLite. Production-код не менялся, новые LLM-вызовы не выполнялись.
Основные артефакты: `/tmp/cloud-dast-regression-20261026/README.md`,
`resource-selection.json`, `performance-control.json`, `semantic/results.json`;
независимые треки: `/tmp/cloud-dast-policy-oracle-OvoOP0/report.md` и
`/tmp/cloud-dast-scheduler-research-20261026/report.md`.

**Потеря семи методов подтверждена intervention.** Binder передаёт campaign
resource `order-1001` каждому методу. Точный identity/type filter корректно
исключает его для user/invoice/inventory/profile, но выбора уже имеющегося
совместимого экземпляра перед policy query нет. Fixture fallback заканчивается
`missing_service_part_fact`. Изменение только выбора экземпляра до исходного
policy query, без изменения графа/permissions/модели, возвращает ровно семь
исчезнувших методов: ActivateUser, CheckUsername, ExportData, GetInvoice,
GetUser, ReserveInventory, UpdateProfile. Offline paths 18 → 25, methods 16 → 23.
У этих методов было 39 checks и все четыре прежних findings; на оставшихся
методах physical checks 99 → 101. Это доказательство потери исполнения,
не доказательство восстановления security recall.

Правильный binding — join объявленных экземпляров с типом и scope действия,
а не пересечение `{launch_resource}` с совместимыми типами. Использовать
существующие `targets/is/part` и исходный scenario policy query для выбранного
ID. Нельзя вернуть другой instance, сохранив proof запроса к старому ID.

Уточнение 2026-10-27 по замечанию владельца: intervention с готовыми ресурсами
доказывает потерю reachability. Автоматическое создание должно быть обычным
QDL-действием в общей цепочке; отдельные FixturePool/Provisioner не сохраняются
(реализация и ограничения — §6.17). В сохранённых current-source projections
этого запуска нет ни одного causes(A, create(T)), включая accepted sources.
Поэтому цепочка создания не выводилась до исполнения. Недостающие предпосылки
должны проходить существующий цикл deficit → QDL proposal → deterministic
promotion → rebind. Объявленный stand instance и наблюдённый результат обычного
запроса — источники bindings в том же графе, без отдельного fixture lifecycle.

Forensic-проверка 2026-10-27 установила конкретную регрессию: staged S1R
заменил выбор объявленных instances по типу на точный requested ID; родитель
применил этот патч 26 октября в 18:52:37 МСК. На одном live launch graph
замена только настоящего FileScenarioRepository воспроизводит 23 → 16 bound
methods; action IDs дополнительных семи отказов совпадают с ранними/вечерними
runtime logs. На benchmark structural graph обе версии дают 39 bound methods,
поэтому offline-приёмка не проверяла этот launch path. Binder ownership gate
и launch writer в сохранённых before/after версиях не менялись: S1R направил
дополнительные методы в уже неполный fallback. Это подтверждённая регрессия
интеграции, а не только ранее нереализованная возможность. Точный patch,
session attribution и replay: `/tmp/cloud-dast-forensics-20261027/fixtures/`.

**Semantic admission теряет данные до исполнения.** Из реально сохранённого
ответа полностью извлечён 21 факт вида `has(...).`; текущий validator даёт
0 normalized facts. Удаление одной конечной точки даёт 21 salvaged fact,
из них существующий promotion принимает 20; privileged classification
остаётся parked. Это синтаксический дефект нормализации, не снятие gates.

Вторая независимая ошибка — `MAX_SEMANTIC_FACTS=128`: повторная promotion
расходует quota за уже принятые факты и supporting declarations. Контроль
с cap=128 исчерпывает его повторениями одного пакета, после первого merge
не добавляющими ничего в граф. После exhaustion даже norm-only proposal
с нулевой semantic cost паркуется, хотя `max_norms=None`; без exhaustion та
же норма принимается. Следовательно, существующие независимые ограничения
сцеплены общим early return. Нужны canonical delta accounting, нулевая
стоимость повторного принятия и раздельное применение имеющихся лимитов.

Это нарушение уже согласованного unlimited-требования A28, а не новый
разрешённый внутренний budget. Прежняя реализация A28 снимала cap очереди
reactive tasks; S35 обеспечивал идемпотентность runtime projection, S36 —
dedup consumer view. Они не обеспечили идемпотентный расход semantic quota
в PromotionPolicy. Тест invalid_dependency_closure_does_not_consume_semantic_quota
проверял отклонённый пакет, но не повторное принятие валидного. Доказательств,
что именно этот счётчик ранее был исправлен и затем откачен, нет: подтверждена
неполная сквозная реализация/приёмка требования, не конкретный revert.

Историческая проверка уточнила границу последнего утверждения: первое найденное
введение cap/OR gates/result charging — commit
`2d0a716b5c66b6b9b7a2602c163d36ed28d011bc` от 20 октября. В 56 проверенных
promotion versions бюджетное ядро одинаково; исправленного варианта и его
отката в этом корпусе не найдено. Это ограниченный отрицательный результат,
а не доказательство отсутствия временной версии вне сохранённой истории.
Матрица 182 файлов и точные patches: `/tmp/cloud-dast-forensics-20261027/semantic/`.
В live log 226 semantic rejection occurrences (не уникальных фактов).
После последнего check прошли 25 roles consultations с суммой promoted_facts=0.

**Проверка scheduler опровергла первоначальную гипотезу про GetOrder revision.**
Typed resource binding входит в path revision. Исправленная GetOrder revision
выбрана в 20:15:00Z, но остановлена `missing_irreversibility_fact` до probes.
Отдельно подтверждены stale backlog (после typed revision допускается старая
binding), differential cache key без изменившихся typed inputs и lifecycle
разрыв: все шесть точных pending paths воспроизведены с eligible=False,
outcome=None, blocked=False при remaining=0. Backlog должен формироваться из
текущей QDL execution view, measurement identity — из реально исполняемых
prerequisites, исключённые пути должны получать terminal reason существующего
scheduler. AND-chain и запрет перехода после UNSCOREABLE сохраняются.

**Четыре прежних findings не являются безусловным положительным контролем.**
Persisted contract (467 facts) и stand (60 facts) одинаковы в двух запусках;
существующий compiler воспроизводит все четыре synthetic norm ID. Но исходный
open-world stand без completeness не доказывает запрет; текущий oracle оставляет
их FAIL ungrounded. Exact source-backed completeness допускает grounded FAIL,
scope другого action/resource — нет. Старый mutable source не сохранён целиком,
поэтому исторические findings пока не подтверждены и не объявлены окончательно FP.

Дополнительный пробел субстрата: разная scoped `PolicyCompleteness` даёт один
QDL graph/hash, но разные grounded verdict, поскольку repository читает raw
snapshot вне графа. Готовой QDL-семантики scoped policy completeness в ядре нет.
Нельзя подменить её произвольным соглашением на `has`, `prevents` или `evidence`:
нужен отдельно определённый формальный контракт и его trusted source. До этого
отсутствие `may` остаётся unknown.

**Что не объясняет всю регрессию.** Пустые order IDs и NOT_FOUND присутствуют
уже в baseline. Реальный loopback control: пустой ID → NOT_FOUND, существующий
order-1001 → OK; он не создаёт security verdict. До/после performance refactor
на одном реальном final graph (951 facts) совпали 18 paths, 26 norms, deficits,
typed inputs и template/minimal seeds. Это offline binding control, не проверка
эквивалентности асинхронного выполнения. Профиль и модель одинаковы; baseline
запускал mutable source, поэтому точный исторический commit-cause не установлен.

Порядок repair для приёмки: typed instance selection → canonical wire
normalization и idempotent promotion → актуальная execution projection и её
measurement/lifecycle closure. Scoped policy authority требует отдельного
согласования математического контракта; ослабление finding gates не допускается.
Acceptance должна проверять живой execution path, повторное принятие фактов,
изменение bindings и terminal closure, а не только количество findings.

### 6.17 Единое причинное исполнение вместо fixture orchestration (2026-10-27)

Решение владельца: создание ресурса — обычный мутирующий запрос и обычный
шаг QDL-цепочки. Отдельные FixturePool, StepSetupResolver и provisioning
не сохраняются даже как кэш или адаптер. Источник зависимостей — общий граф;
источник конкретных значений — доказанные наблюдения. Это уточнение отменяет
прежние предписания сохранять pool в A25 и исторических разделах выше.

Исследование подтвердило три архитектурных разрыва:

1. Planner выводил make→use из causes/requires, но binder требовал security
   norm для каждого промежуточного действия. Исполнение также связывало
   причинный прогресс исключительно с grounded security FAIL.
2. Типизированный output→input терял направление при проекции в request-only
   coupling; наблюдения сохраняли форму полей, но обычный путь не использовал
   безопасные typed values после rebind.
3. Provisioning разделял общий transport/guardrail с обычным исполнением, но
   имел отдельные планирование, orchestration, регистрацию и бюджетирование.
   Например, прогноз одного create не учитывал list/create/list discovery.

Реализация перерабатывает существующие компоненты:

- Промежуточные действия получают required_effects из QDL edges без фиктивной
  запрещающей нормы; security verdict отделён от доказательства подцели.
- ObservationProjector проецирует trusted typed evidence и исходные
  observation/check/action/scope/identity/time в единственный formal graph.
  Поля входа и выхода привязаны к конкретному наблюдению через существующие
  has/replacement/evidence; старый output не может подменить измеренный input.
- Существующий coupled consumer сохраняет canonical input_field/output_field,
  связывает фактические результаты до guardrail и разрешает durable evidence
  через общий ClingoEngine. Сам coupling — предикат QDL, не отдельный lifecycle.
- Runner выполняет обычные шаги и разряжает уже доказанные подцели только вместе
  с нужными последующим шагам однозначными bindings. Перед проверкой reuse
  существующий checker разрешает coupled-значения текущего Check; historical
  effect обязан совпасть с его typed inputs. Pay(X) не доказывает Pay(Y).
  Исторические доказательства
  не добавляются к новым физическим checks/observations и не создают findings.
- Из активных contracts, composition, binder и deficits удалены SetupRequirement,
  pool/resolver/provisioner и скрытое создание ресурсов. Удалены семь мёртвых
  модулей provisioning/setup/chain и отдельная chain-session extension; causal actions используют общий FuzzSession.

Инварианты приёмки: обычный make→use без fake norm; typed id→widget_id;
новый runner с тем же formal repository выполняет только use при max_checks=1;
отсутствующее/неоднозначное/отозванное доказательство не разрешает binding;
все причинные эффекты обязательны одновременно; обычный успех не создаёт finding;
создание и следующий запрос подчиняются одному request budget и guardrail.

Инвалидация адресует observation-specific link конкретного экземпляра через
supersedes(replacement(...)); она не уничтожает соседний output и не запрещает
новое создание с тем же ID. Исходный timestamp не обновляется при replay:
старое удаление не отзывает более новое наблюдение. ERROR с оставшимся ID не
является positive create evidence. Конфликтующие trace records не доказывают
эффект; одинаковые записи остаются идемпотентными. Проекция получила версию v3;
старые факты без однозначной атрибуции не разрешают reuse.

Статус: базовая унификация реализована, миграция и независимое ревью выполнены.
Весь раздел остаётся открытым: outputless Create → Read и List → Create → List
пока не имеют эквивалента в общем исполнении. Удаление старых provisioning-тестов
не доказывает сохранение discovery/marker coverage. Нельзя считать List причиной
create или превращать отсутствие witness в PASS. Следующий структурный шаг —
разделить доказательство изменения мира и получение наблюдаемого значения,
используя existing QDL terms и обычные запросы; baseline/diff и marker должны
иметь явную корреляцию наблюдений. Отдельный discovery executor не возвращается.
Консервативный отзыв create binding после transition также может потребовать
нового Create: это стоимость текущей модели, а не доказанная оптимальность.

Проверки текущего кода разделены на непересекающиеся срезы: formal/runtime и
extension tests — 1439 passed; architecture/composition/generators/execution —
424 passed; root review regressions — 804 passed; benchmarks — 177 passed;
остальные модели, адаптеры, отчёты и тесты приложения — 783 passed. Всего
3627 passed, без пропущенных тестов; один warning от существующего test-double
закрытия temporary file. Итоговые ограничения и логи сохранены в
`/tmp/cloud-dast-unified-impl-20261027/`. Полный live e2e с LLM для этой
переработки не выполнялся. Историческое исследование сохранено в
`/tmp/cloud-dast-unified-execution-20261027/`.

## 7. Уточнения по итогам критического ревью (дизайн / бизнес-логика / матлогика)

Вторая волна (три adversarial-ревьюера) уточнила задачи выше. Изменения к
формулировкам:

1. **A1/A3 → две политики вместо одной**: `MeasuredStructuralEvidencePolicy`
   (детерминированные структурные наблюдения — canary в ответе) и
   `LLMSemanticPromotionPolicy` (классификации — только с provenance). Один
   общий флаг убьёт полезную measured-exploration либо легализует echo→sink.
   *Реализовано в A15 (2026-10-19): source-only для классификаций + evidence
   exception для фактически наблюдённых response-полей (`evidence_fields` в
   `promote_proposal`); sink-типы — только source.*
2. **A2 (по матревью)**: материализовать derived `may` (или запретить
   `allowed`-нормы без base-`may`/материализованного вывода). `applies_to` —
   в A10.
3. **A4**: не обнулять весь ungrounded-proximity — разделить `confirmed_progress`
   (только grounded FAIL) и bounded `curiosity` (delivered/witness-сигналы,
   не влияют на terminal outcomes/coverage); witness-ступень — только по
   фактически полученному OOB-event/marker-echo, не по отправленному canary.
4. **A5**: delivered-only baseline + отдельный availability-оракул (explicit
   timeout с configured deadline — значимая evidence, не blanket-UNSCOREABLE).
5. **A12**: ввести Result-тип `{value, status, error}` и единый
   `_executable_graph` (сейчас копипаст ×2) — предпосылка для фикса.
6. **B2 (фиксы V1–V8 пересмотрены)**: V2 требует новый `EventSubscriber`-порт
   (у `EventPublisher` нет subscribe); V3–V5 — не перенос `CoverageMatrix`/
   `CampaignMetrics`, а snapshot-события (B12/B13); markdown — тривиально через
   существующий `QdlCoverageMatrixView`; V6 `CloudProvisioner` — сначала поднять
   генерацию seed в caller (иначе infra не может импортировать generators);
   V7 `InvocationRepository` — перенос тривиален, но Dishka-предоставление
   требует переноса сборки `Target` в контейнер.
7. **B5**: length-prefixed join вместо `|`/`:`; полный SHA-256; graph hash;
   campaign/run scope (BL-18); previous outcome при replay (BL-17 → A17).
8. **D1**: реализация — `GuardedTarget`-декоратор в composition (guardrail +
   endpoint policy + token-after-policy в одном объекте), запрет передачи
   голого `Target` (lint-правило).

   *Достроено 2026-10-19 (вопрос владельца о «заткнутой LLM»): паркинг
   отклонённых классификаций под `proposal:*` + логирование
   `classification_parked_without_provenance` + детерминированный детектор
   секретов (`secret_shapes.py`: JWT/PEM/argon2/bcrypt/AKIA по наблюдённым
   значениям, без LLM). Остаток — A20/B17/B18.*

**Не чинить (опровержено критическим ревью):**

- unknown≠unsat в symbolic/Z3 — обрабатывается корректно;
- «frozenset-порядок ломает canonical_json» — в QDL-моделях только tuples;
- ASP-кодирование строк/термов — биективно; стратификация негации корректна;
- MAD-пол latency при n=3 — устойчив к одиночному выбросу (реальные дефекты —
  контаминация ERROR-семплами и неиспользуемый baseline → A18);
- `find_path` default depth — корректен (кроме cross-context edge case → C12-семейство);
- SequenceOracle transition-ветка — корректна (дефект только в completed-ветке → A6).

## 8. Трек E — Тестовый долг (приёмка волн)

Тесты — не отдельная фаза, а приёмка задач A–D. Ключевые adversarial-сценарии,
которые обязаны появиться:

| ID | Сценарий | Закрывает | Волна |
|---|---|---|---|
| E1 | LLM `requires` → permission gap → FAIL: полный конвейер не порождает finding | A1, A2 | 1 |
| E2 | `CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS=false` отключает **все** пути promotion | A3 | 1 |
| E3 | Poisoned endpoint: вызов отклонён до attach токена | D1 | 1 |
| E4 | Identity: per-identity token (no fallback), identity-норма scoreable, possession-scope по активной identity | D2, A8, FE-M4 | 1 |
| E5 | Multi-round бюджет с setup; differential setup+бюджет | A13, B10 | 1–2 |
| E6 | Witness: self-callback, echo marker, filesystem-404, adversarial latency baseline | A5, A7, D4 | 1–2 |
| E7 | Ungrounded FAIL c proximity=1.0 → reward 0; sequence retry; truncated response | A4, A6, A9 | 1 |
| E8 | Tampered cache/event → discard; cross-campaign poisoning не воспроизводится | D5 | 2 |
| E9 | Prompt-injection negative: инструкция в response value не меняет сгенерированный request; секрет не уходит в prompt | D3, FE-H1 | 2 |
| E10 | Import-lint (layer model), DI-structure тест, markdown/ANSI injection | B2, B9, D-11, D-12 | 2–3 |

## 9. Волны и Definition of Done

### Wave 1 — «Корректность вердиктов и доверенные границы» (все P0)

Задачи: A1–A9, A13, A15–A18, D1, D2 + приёмка E1–E5, E7.

Статус на 2026-10-21: все задачи волны закрыты — A1–A9, A13, A15–A18, D1, D2 ✅
(см. текущую таблицу выше; A4 закрыт 2026-10-20). Остаток — приёмка E1–E5, E7.

DoD:
- Ни один P0-путь не порождает ложный FAIL/PASS из подтверждённых сценариев;
- `CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS=false` верифицируемо отключает promotion;
- токен не уходит на непроверенный endpoint; identity не получает чужой токен;
- multi-round бюджет не превышает `max_checks`;
- `pytest -q` и `ruff check .` green; новые adversarial-тесты в CI.

### Wave 2 — «Дизайн-унификация и trust-модель» (P1)

Задачи: A10–A12, A14, A19, B1–B6, B10–B14, B16, B24, C10, D3–D5, D8, S2–S10,
R1–R4, R7, R8 + E6, E8–E10.

DoD:
- в executable-семантике не осталось naming-эвристик (H5, H6 закрыты через B1);
- один promotion policy, один role alphabet, канонические action ID (H1, H2);
- witness-каналы имеют политику аутентичности; персистентность tamper-evident;
- переверификация статусов H9, H11, H15, H19, H20, C1, C2 по коду.

### Wave 3 — «Качество кода и cleanup» (P2)

Задачи: B7–B9, B15, B25, C1–C16, D6, D7, D9, D10, R5, R6, R9, S11.

DoD:
- топ-6 god-методов декомпозированы, ≤15 функций ≥80 строк;
- dead code из C3 удалён без compatibility-обёрток;
- import-lint и DI-тест в CI; lockfile зафиксирован; compose hardened.

## 10. Быстрые победы (можно брать сразу, вне волн)

B8 (S), C2 (S), C4 (S), C5 (S), C6 (S), C9 (S), удаление `reviewer.pyc` (тривиально).

## 11. Сводка

| Трек | P0 | P1 | P2 | Всего |
|---|---:|---:|---:|---:|
| A — логика | 13 | 9 | 2 | 24 |
| B — дизайн | 0 | 16 | 9 | 25 |
| C — качество | 0 | 1 | 15 | 16 |
| D — security-гигиена | 2 | 4 | 4 | 10 |
| S — сенсоры (buy-vs-build) | 0 | 11 | 2 | 13 |
| R — репортинг и ablation-метрики | 0 | 8 | 4 | 12 |
| **Итого задач** | **15** | **48** | **36** | **100** |

Из них 15 задач добавлено/уточнено по итогам критического ревью второй волны
(дизайн `N-*`, бизнес-логика `BL-*`, матлогика) — см. раздел 7.

Правка 2026-10-20 (разбор Hypothesis/Schemathesis/Gramatron/Grammarinator/
ChatAFL): S3/S4 переписаны и подняты P2→P1, добавлены S5–S7 (parse-then-mutate,
AdvisoryResolver, per-class witness-оракулы). Seroval-класс закрыт связкой
S6→S5→S3/S4→S7; фаззинг признан гэпом первого порядка (см. engine-runtime §14).

Правка 2026-10-20 (аудит necessity: smt.py + Neo4j): D9 переведён с «починить
или задокументировать» на удаление — production-потребителей нет, семантика
расходится с движком. Добавлен B24 — SQLite formal-persistence за портом;
Neo4j остаётся только read-адаптером stand-данных (Live* мы не создаём).

Правка 2026-10-20 (решение о сносе агентного слоя): зафиксирован дрейф видения
Layer 5 vs реализации (engine-runtime §16, campaign-automaton); C16 — снос
agent/ с переносом `_DEFICIT_PRIORITY` в B23-benchmark; C14 — River → inline
сэмплер + честный rename; C15 — progress/rich. Итого волна сноса: ~1900 строк,
−2 зависимости (river, rich), −1 сетевой сервис из периметра (B24).

Правка 2026-10-21 (исполнение C16): агентный слой и wiring удалены;
`_DEFICIT_PRIORITY` и evidence tie-break перенесены в
`benchmarks/nsfy_bench/cold_score.py`; Campaign DAG и consultation-протокол
сохранены.

Правка 2026-10-20 (архитектурный разворот по решению владельца): S8 — witness
re-layering (signal-first: сигналы полиморфны, кросс-манифестации
SSTI→XSS/SQLi→OOB/XXE→XSS; интерпретация — в QDL rules, не в диспетчере
оракулов; развязка production↔oracle). B25 — трек local/protocol targets
(EvidenceChannel-порт с eBPF, spec-projector, LocalProcessTarget/SocketTarget);
позиционирование движка — автоматический verification-стейдж SAST.

Тестовые сценарии E1–E10 распределены как приёмка соответствующих задач.

Правка 2026-10-21 (репортинг и ablation-метрики): добавлен трек R (R1–R9,
секция 6.2) — presentation layer с форматами markdown/JSON/SARIF/HTML за единым
`ReportRenderer` protocol, time tracking, ground truth manifest + matcher,
ablation-метрики (precision/recall/F1, time-to-first, findings-per-budget,
повторы + Mann-Whitney U) и ablation runner поверх закрытого B23. Основа:
Klees et al. «Evaluating Fuzz Testing» 2018 (coverage ≠ bugs, повторы
обязательны), Magma (reached/triggered/detected), FuzzBench, CVE-Bench.
Попутно исправлен drift Wave 1: A4 закрыт 2026-10-20, остатка задач нет —
только приёмка E.

Правка 2026-10-21 (снос Neo4j-зависимости): реализована B26 — FileStandSource
(`stand.json` → `PolicySnapshot` → существующий GenericPolicyProjector) как
дефолтный источник stand-данных, утилита экспорта Neo4j → JSON,
`CLOUD_DAST_STAND_SOURCE=file|neo4j`, neo4j-driver → optional-dependencies,
formal_cli → sqlite. Обоснование: Neo4j остаётся только read-адаптером
живых стендов за портом; стенд — launch-fixture (JSON, git-diffable),
formal store — operational (SQLite, B24). Принцип: «то, что ревьюится в
git — текст; то, что живёт в рантайме — SQLite».

Правка 2026-10-21 (волна Corpus learning loop): добавлены S9–S11 после
сверки зафиксированных уроков источников с кодом (из 13 уроков 8 ✅ / 3 ⚠️ /
3 ❌; все три провала — одного класса: разовые находки не накапливаются).
S9 — shrinking (bounded minimization findings до минимального PoC) +
ExampleDatabase (findings-replay: регрессия/фикса за 1 вызов; закрывает
обещанное, но нереализованное в S3); S10 — seed enrichment loop (ChatAFL:
LLM в точке entropy-насыщения предлагает новые продукции как proposal-tier
данные через promotion — пятый гибрид); S11 — grammar representation v2
(CFG-уровень: рекурсивные правила, контекстные зависимости, st.recursive;
закрывает критику «99% SQLi сложнее OR 1=1»). Итог волны: каждая следующая
кампания стартует с мощностью предыдущих.

Реализованы 2026-10-21: S9 (bounded shrinking + JSONL ExampleDatabase +
regression replay), S10 (entropy-driven typed consultation, payload-data
promotion, versioned corpus store/audit trail) и S11 (recursive grammar v2,
context conditions, repeat bounds, v1→v2 migration).

Правка 2026-10-21 (ablation observability): добавлена R10 — positive control
для интерпретации negative ablation-результатов (вопрос владельца: отличить
«компонент не нужен» от «рукожопно реализовали / не подключили / пустой
вход»). Три слоя: component lifecycle телеметрия (invoked/skipped/output/
downstream через существующий event bus), input completeness репорты,
activation proof per arm (fail-fast: INVALID ≠ useless). R9 теперь требует
R10; scorer отказывается интерпретировать INVALID-прогоны как «компонент
бесполезен».

Реализована 2026-10-21: component-lifecycle events, `component_activity`
агрегация и activation proof с отказом от агрегации INVALID-прогонов.

Реализован 2026-10-21: generic `AblationRunner` с фиксированным per-run
budget, R7/R8/R10 integration, exact tie-aware Mann-Whitney U и canonical
JSON-выводом; INVALID-arms исключаются из агрегации и сравнения.

Правка 2026-10-22 (волна Post-e2e findings, секция 6.3): первый полный
e2e-прогон (300 checks, 44 findings, 24/39 методов) вскрыл три скрытых
дефекта и две доводки — A23 (finding fingerprint: identity по
invariant+scenario+sink+field+witness-kind; повторные FAIL = witnesses, не
findings; фаззинг не гасится — решение владельца), R11 (summary-группировка
отчётов по классам/CWE/severity), B27 (валидация synthetic allowed против
ground truth — precision 0.111: баг манифеста или движка), R12 (method_id в
check_completed), A24 (15 методов вне coverage, GetUser второй прогон).
Прогон показал: волна доработок не была регрессией — механика норм, shrink,
differential, R10-телеметрия работают; дефекты были похоронены под
fixture-блокировками и выползли после их починки.

Правка 2026-10-24 (библиотечная консолидация, секция 6.8): добавлены
S39 (NetworkX вместо дублированных Tarjan SCC / Kahn / condensation) и
S40 (passive learned automata на AALpy за `AutomataLearningPort`). В 6.7
соответственно обновлены вердикты по `networkx` и `aalpy`; OR-Tools/CP-SAT
добавлены в список «не вводить», потому что S30 stage 6 уже использует
Clingo для set-cover и budget optimization.
