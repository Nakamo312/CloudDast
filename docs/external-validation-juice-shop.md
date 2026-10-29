# External validation: OWASP Juice Shop

Статус: план первой внешней валидации NSFy.

## Цель и не-цели

**Цель** — измерить, умеет ли дифференциальный DAST находить уязвимости на
чёрном ящике, который мы не проектировали под свою алгебру: локальный OWASP
Juice Shop, generic HTTP/JSON transport, курируемый REST-контракт и внешний
скоринг по `Challenges.solved`.

**Не-цели:**

- не делаем crawler и не доказываем способность найти поверхность атаки;
 Juice Shop не отдаёт полный OpenAPI, поэтому контракт курируем вручную;
- не гоняем DOM/браузерные и OSINT-челленджи;
- не используем SQLite как runtime-оракул во время кампании;
- не кладём challenge keys, payload и подсказки в QDL или LLM-промпт.

## Почему Juice Shop

Плюсы:

- локальный стенд с синтетическими данными — соответствует модели
  full-fidelity retention из RFC §9;
- 116 machine-readable челленджей в `challenges.yml`;
- встроенный ground truth в SQLite (`Challenges.solved`);
- покрытие разных классов: injection, access control, input validation,
  sensitive exposure, XSS, NoSQL, redirect, upload, misconfiguration.

Ограничения:

- это CTF-приложение, а не чистый API-сервис: часть челленджей — головоломки,
  OSINT, DOM/UI или нестабильный DoS;
- официального полного OpenAPI нет; `swagger.yml` содержит только
  `POST /b2b/v2/orders`;
- SPA часто отвечает `200 OK`, поэтому status-only оракул недостаточен;
  нужен полный ответ, shape и read-back state.

Поэтому валидация — не «все 116», а курируемое API-only подмножество.

## Когорта

Из 116 челленджей в первую когорту отобрано **42 API-only**. Фильтр:

1. эффект достижим через REST/HTTP без браузера и OSINT;
2. результат наблюдаем в status, response shape, значении, error, latency,
   redirect, файловых метаданных или read-back state;
3. челлендж не требует дестабилизации стенда или внешних callback-ресурсов;
4. endpoint либо известен, либо может быть подтверждён пробой перед
   фиксацией контракта.

### P0 — первая итерация

Это минимальный набор с высоким сигналом; он должен пройти раньше расширения
когорты.

| Challenge key | Класс | Endpoint candidate | Подтверждение |
|---|---|---|---|
| `passwordHashLeakChallenge` | Sensitive Data Exposure | `GET /rest/user/whoami` | inferred |
| `errorHandlingChallenge` | Security Misconfiguration | `GET /rest/qwertz` | inferred |
| `loginAdminChallenge` | Injection | `POST /rest/user/login` | inferred |
| `loginBenderChallenge` | Injection | `POST /rest/user/login` | inferred |
| `loginJimChallenge` | Injection | `POST /rest/user/login` | inferred |
| `registerAdminChallenge` | Improper Input Validation | `POST /api/Users` | inferred |
| `unionSqlInjectionChallenge` | Injection | `GET /api/Products/search?q=` | inferred |
| `dbSchemaChallenge` | Injection | `GET /api/Products/search?q=` | inferred |
| `forgedFeedbackChallenge` | Broken Access Control | `POST /api/Feedbacks` | inferred |
| `basketAccessChallenge` | Broken Access Control | `GET /api/Baskets/:id` | inferred |
| `basketManipulateChallenge` | Broken Access Control | `POST /api/BasketItems` | inferred |
| `forgedReviewChallenge` | Broken Access Control | `POST /rest/product/:id/reviews` | inferred |
| `adminSectionChallenge` | Broken Access Control | `GET /rest/admin/application-version` | inferred |

Все endpoint candidates здесь — `inferred`: Juice Shop не даёт полного
OpenAPI. Перед фиксацией контракта их нужно подтвердить живыми пробами и
зафиксировать фактические status/shape. Нормализация путей запрещена:
фактические `/api/Users`, `/api/Products/search`, `/api/Baskets` и
`/rest/product/...` сохраняем как есть.

### P1/P2 — расширение после зелёного P0

| Группа | Challenge keys | Классы | Дифф-режим |
|---|---|---|---|
| Login/session | `weakPasswordChallenge`, `ghostLoginChallenge`, `ephemeralAccountantChallenge`, `changePasswordBenderChallenge`, `dataExportChallenge`, `emailLeakChallenge` | auth, disclosure, injection | payload-pairs, timing |
| Users | `passwordRepeatChallenge`, `emptyUserRegistration`, `csrfChallenge`, `freeDeluxeChallenge`, `usernameXssChallenge` | validation, mass assignment, XSS | factor-pairs, payload-pairs |
| Products/reviews | `noSqlCommandChallenge`, `reflectedXssChallenge`, `changeProductChallenge`, `retrieveBlueprintChallenge`, `noSqlOrdersChallenge`, `noSqlReviewsChallenge` | injection, XSS, tampering, disclosure | payload-pairs, read-back |
| Basket/orders | `negativeOrderChallenge`, `deprecatedInterfaceChallenge` | validation, deprecated interface | payload-pairs, read-back |
| Feedback/upload | `persistedXssFeedbackChallenge`, `zeroStarsChallenge`, `feedbackChallenge`, `uploadSizeChallenge`, `uploadTypeChallenge` | XSS, validation, access control | payload-pairs, read-back |
| Other API effects | `redirectCryptoCurrencyChallenge`, `exposedMetricsChallenge`, `chatbotPromptInjectionChallenge`, `chatbotGreedyInjectionChallenge`, `systemPromptExtractionChallenge` | redirect, observability, prompt injection | factor-pairs, payload-pairs |

### Исключения

Не включаем в когорту:

- OSINT и внешние знания: `resetPasswordBjoernOwaspChallenge`,
  `loginAmyChallenge`, `loginRapperChallenge`, `dlpPasswordSprayingChallenge`;
- DOM/UI-only: `scoreBoardChallenge`, `privacyPolicyChallenge`,
  `missingEncodingChallenge`, `xssBonusChallenge`;
- Web3 и крипто-головоломки: `tokenSaleChallenge`, `nftUnlockChallenge`,
  `web3WalletChallenge`, `forgedCouponChallenge`, `jwtForgedChallenge`;
- research/dependency-челленджи без API-наблюдаемости:
  `knownVulnerableComponentChallenge`, `supplyChainAttackChallenge`,
  `vulnerableDockerImageChallenge`, `csafChallenge`;
- нестабильные DoS/XXE/yaml и OOB-кейсы — отдельный режим с изоляцией и
  бюджетом, не первая итерация.

## Контракт первой итерации

Контракт описывает только структуру и наблюдаемость. Он не содержит exploit,
challenge key, подсказку и ожидаемый `solved`.

### Endpoint-группы

| Группа | Endpoint candidates | Наблюдаемые данные |
|---|---|---|
| session | `POST /rest/user/login`, `GET /rest/user/whoami`, `PUT /rest/user/change-password`, `GET /rest/user/data-export` | token/cookie, user shape, email/hash, errors, latency |
| users | `POST /api/Users`, `PUT /api/Users/:id`, `GET /api/SecurityQuestions`, `POST /api/SecurityAnswers` | email, password, role, security answer, status |
| products | `GET /api/Products`, `GET /api/Products/search?q=`, `GET/PUT /api/Products/:id`, `GET/POST /rest/product/:id/reviews`, `PUT /rest/product/reviews/:id` | SQL/NoSQL errors, reflected marker, product state, review ownership |
| basket | `GET /api/Baskets/:id`, `POST /api/BasketItems`, `PUT/DELETE /api/BasketItems/:id` | ownership, product, quantity, state before/after |
| orders | `POST /b2b/v2/orders`, `POST /b2b/v1/orders` | `cid`, order lines, quantity, v1/v2 difference |
| feedback/files | `GET/POST/PUT/DELETE /api/Feedbacks`, `POST /api/Complaints`, `POST /file-upload` | rating, comment, author, content-type, size, parser errors |
| admin/effects | `GET /rest/admin/application-version`, `GET /metrics`, `GET /redirect?to=` | admin shape, metrics labels, `Location` |

### Общий `MethodSpec`

Для каждого endpoint фиксируем:

- `method_id`, `service: juice-shop`;
- HTTP method и path без нормализации регистра;
- роли: `anonymous`, `user`, `admin`;
- request fields: имя, тип, required, repeated;
- response shape и expected status ranges;
- state keys: `userId`, `basketId`, `productId`, `orderId`;
- наблюдаемые поля: status, headers/cookies, full response tree, error reason,
  duration, redirect target, file metadata;
- probe marker и правила его уникальности.

## Транспорт

Нужен generic HTTP/JSON `Target` + `PayloadCodec`, не привязанный к gRPC,
Neo4j или IAM:

1. render request: path/query/body/headers/cookies;
2. execute HTTP;
3. decode JSON, text, redirect и файловые метаданные;
4. построить `Observation.response_tree` из dotted paths ко всем листьям;
5. вычислить `response_digest`;
6. найти marker по всем string-листьям;
7. сохранить полную транзакцию в локальный артефакт прогона.

Это тот же порт `Target`, что используется для gRPC; добавляется только
HTTP-адаптер, а не специальная Juice Shop-логика в движке.

## Скоринг

Стенд должен быть одноразовым или восстанавливаемым:

1. pinned Juice Shop image/tag/digest;
2. зафиксированный seed и env;
3. snapshot SQLite до прогона;
4. кампания NSFy с ограниченным бюджетом запросов;
5. snapshot SQLite после прогона;
6. внешний scorer читает только артефакты, не участвует в исполнении.

Основной запрос:

```sql
SELECT key, name, category, difficulty, solved
FROM Challenges
ORDER BY id;
```

Скоринг считает переходы `solved: false → true`, а не финальное состояние,
чтобы исключить pre-solved челленджи.

### Артефакты прогона

```text
runs/<run_id>/
  environment.json
  config.json
  contract.json
  qdl-graph.json
  events.jsonl
  http-transactions.jsonl
  diff-reports.jsonl
  findings.jsonl
  coverage.json
  metrics.json
  challenges-before.json
  challenges-after.json
  sqlite-before.sqlite
  sqlite-after.sqlite
  benchmark-map.json
```

### Маппинг

`Finding.goal_id` — внутренний идентификатор NSFy. Challenge key живёт только
в scoring-слое:

```json
{
  "loginAdminChallenge": {
    "method_id": "juice-shop:rest:user:login",
    "vulnerability_class": "Injection",
    "cwe": ["CWE-89"],
    "requires": ["probe_marker_seen"],
    "expected_observable": ["response_shape_or_value"]
  }
}
```

Требование к атрибуции: finding считаем покрывшим challenge только если есть
уникальный probe marker или конкретная транзакция, из-за которой `solved`
переключился. Иначе это `unattributed_solved`, а не результат NSFy.

### Метрики

- `eligible_recall`: solved transitions в eligible когорте / размер когорты;
- `p0_recall`: то же только для P0;
- `finding_precision`: findings с валидной атрибуцией / все findings;
- `determinism`: пересечение findings между двумя прогонами;
- `budget`: requests, tokens, wall time;
- `blind_spot_delta`: challenges, решённые baseline-методом, но не NSFy.

E4 сравнение: тот же стенд и бюджет — NSFy, Nuclei, LLM-agent. Отдельно
фиксируем, какие классы находит каждый метод; одна цифра recall недостаточна.

## Защита от самосбывающегося теста

1. QDL-контракт не знает challenge keys и payload.
2. LLM видит shape и diff-размерности, а не содержимое ответа Juice Shop.
3. Challenge descriptions, hints и `challenges.yml` не попадают в промпт.
4. SQLite читается только после завершения кампании.
5. Для каждого прогона — свежий или восстановленный стенд и before/after
   snapshot.
6. Endpoint candidates подтверждаются живыми пробами до freeze контракта;
   несуществующие пути не добавляем «по памяти».
7. Учитываем `disabledEnv` и не включаем челленджи, отключённые в Docker.
8. DOM-only XSS исключаем; в когорту попадают только API-наблюдаемые XSS.
9. DoS/XXE/yaml — отдельные изолированные режимы с жёстким бюджетом.

## Приёмка

| Фаза | Definition of Done |
|---|---|
| J0 | Juice Shop запускается локально, версия/seed/env зафиксированы, SQLite snapshot читается |
| J1 | endpoint probe подтверждает кандидатов P0; contract frozen и захеширован |
| J2 | HTTP/JSON `Target` проходит unit-тесты и e2e на двух endpoint-группах |
| J3 | NSFy выполняет кампанию на P0 с полным retention и diff-режимами §9.1 |
| J4 | scorer выдаёт `p0_recall`, `eligible_recall`, precision, determinism и budget |
| J5 | сравнение с Nuclei и LLM-agent на одинаковых бюджете и стенде |

## Открытые вопросы

1. Как атрибутировать multi-effect payload: один запрос решает несколько
   челленджей. Нужны изоляция состояния и уникальные marker-пары.
2. Точная версия Juice Shop и seed для воспроизводимости между прогонами.
3. Нужно ли добавлять cookie/session lifecycle в `Target`, или достаточно
   bindings в сценарии.
4. Какие P1-челленджи включать после P0: по классам или по endpoint-группам.
