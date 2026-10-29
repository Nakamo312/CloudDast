# NSFy Bench full-mode E2E — 2026-10-15

## Status

Completed after the second full-engine iteration with:

- bounded full-fidelity `EvidenceView`;
- staged semantic grounding;
- deterministic `SemanticNormCompiler`;
- evidence-aware `ThreatIntentCompiler`;
- `DifferentialOracle` for read-back state changes;
- full-response `FieldExposureOracle`;
- transition primitive support;
- generic outcome finding policy;
- differential modes:
  - `factors`
  - `payload`
  - `readback`
  - `timing`
  - `concurrency`.

The CLI exited with code `1` because findings were raised.

## Freshness

The run started from:

```text
contract:nsfy.shop.v1
stand:nsfy.shop.v1
state-machine:nsfy.shop.v1
```

The fresh loader cleared:

```text
accepted:nsfy.shop.v1
accepted-batch:nsfy.shop.v1:*
diff:nsfy.shop.v1:*
```

and preserved the structural state machine.

## Configuration

- Profile: `benchmarks/nsfy-bench/profiles/nsfy-bench-llm.toml`
- Model: `glm-5.3`
- LLM grounding: enabled
- Grounding cache: bypassed
- Proposal promotion: enabled
- Max checks: `300`
- Identity: `attacker`
- Local transport: insecure gRPC
- Differential modes: `factors,payload,readback,timing,concurrency`
- Event log: `/tmp/nsfy-e2e-full-fixed-20261015-180043.jsonl`

## Execution totals

| Metric | Value |
|---|---:|
| Observations | 299 |
| QDL paths evaluated | 78 |
| QDL steps evaluated | 113 |
| Differential pairs | 48 |
| Pairs with variance | 14 |
| Evidence records | 58 |
| Raw findings | 44 |

Measured variance dimensions:

| Dimension | Count |
|---|---:|
| `value` | 8 |
| `error` | 4 |
| `aggregate` | 3 |
| `latency` | 0 |

The aggregate variance confirms that concurrency mode produced measurable
signals. Timing mode was enabled, but no pair produced a robust latency-class
difference in this run.

`DiffPairComputed.mode` was added immediately after this run, so the event log
does not carry per-mode counts. Future full-mode runs will expose the mode on
every differential-pair event.

## Scoring

### M1 semantic score

| Metric | Value |
|---|---:|
| Vulnerable scenarios | 9 |
| Found | 7 |
| Recall | 77.8% |
| Controls | 2 |
| False positives on controls | 0 |
| Raw findings | 44 |
| Precision | 15.9% |

Found:

- `bola-order-read`
- `fla-admin-delete`
- `mass-assign-total`
- `sql-injection-search`
- `ssrf-webhook`
- `ship-unpaid-order`
- `quota-list-unbounded`

Missed:

- `disclose-user-email`
- `path-traversal-doc`

### Full planted-norm score

The full scorer uses all 34 violated norms and 2 controls.

| Metric | Strict | Semantic |
|---|---:|---:|
| Found | 4 | 13 |
| Recall | 11.8% | 38.2% |
| Distinct scored findings | 44 | 45 |
| Precision | 9.1% | 28.9% |

Strict exact matches:

- `norm:bola-order-read`
- `norm:fla-admin-delete`
- `norm:stf-uncancel`
- `norm:stf-dispatch-twice`

Additional semantic matches:

- `norm:mass-assign-total`
- `norm:sql-injection-search`
- `norm:ssrf-webhook`
- `norm:ship-unpaid-order`
- `norm:quota-list-bounded`
- `norm:stf-refund-reuse`
- `norm:stf-deser-rce`
- `norm:stf-user-enum`
- `norm:fuzz-template-injection`

## Product-policy effect

Compared with the first clean full run:

| Metric | Before | After |
|---|---:|---:|
| Raw findings | 47 | 44 |
| Full semantic precision | 15.6% | 28.9% |
| Full strict recall | 4/34 | 4/34 |
| Full semantic recall | 14/34 | 13/34 |
| M1 semantic recall | 7/9 | 7/9 |

The product policy suppresses ordinary generic permission gaps, while specific
effect findings remain eligible. The remaining 44 findings are dominated by
object-reference/BOLA-shaped outcomes; the current object-reference signal is
shape-based and does not yet prove cross-owner access structurally.

## Interpretation

Positive changes:

1. The complete five-mode differential contract is implemented and tested.
2. Concurrency produced real aggregate variance in the live run.
3. The full scorer now separates strict and semantic effect matching.
4. Read-back `changed` norms can now become deterministic findings.
5. Full-response field exposure is no longer limited by `safe_fields`.
6. The fresh loader preserves the structural state machine.

Remaining blockers:

1. `disclose-user-email` is still missed.
2. `path-traversal-doc` is still missed.
3. Most race norms remain unconfirmed; concurrency currently measures
   aggregate variance but has no dedicated aggregate oracle.
4. Timing produced no robust variance on this benchmark run.
5. The object-reference product signal needs structural ownership evidence
   instead of request-shape approximation.
6. Full semantic precision is improved but still low.

## Next external-validation gate

Before Juice Shop:

1. use the newly persisted `DiffPairComputed.mode` in the next run report;
2. add a structural ownership signal to the generic outcome policy;
3. rerun NSFy with per-mode metrics;
4. implement a generic HTTP/JSON target;
5. run the Juice Shop P0 cohort.

## Post-review run — measured canary reach

A follow-up review found two execution bugs that made the first full-mode run
look weaker than the implemented substrate:

1. QDL markers contained `:` and `-`, which SQLite tokenized/truncated in
   syntax errors.  The marker oracle searched for the full identifier and
   returned `PASS` even though the canary had reached the error channel.
2. Measured canary reach depended on the shared LLM variance budget.  Later
   variance deficits could starve earlier injection/reflection signals.

Fixes:

- probe markers are normalized to parser-safe `[A-Za-z0-9_]` tokens;
- payload-pair canary reach is compiled deterministically to
  `prevents(N, reached(Action, Sink))`;
- factor-pair variance still goes through LLM grounding (it is not a payload
  canary);
- measured variance promotion no longer consumes the shared LLM budget;
- `MarkerOracle` also searches `error_reason`;
- strict full scoring is witness-insensitive for `reached`/`external_call`:
  it compares effect kind plus action, while preserving full canonical
  matching when it uniquely identifies a planted norm.

Final post-fix run:

| Metric | Value |
|---|---:|
| Observations | 300 |
| Differential pairs | 44 |
| Probe markers | 5 |
| Raw findings | 51 |
| Finding effects | 48 `allowed`, 2 `external_call`, 1 `reached` |
| Finding classes | 44 BOLA, 4 function-level authz, 2 SSRF, 1 command injection |
| M1 semantic recall | 7/9 |
| Full strict recall | 6/34 |
| Full semantic recall | 13/34 |
| Full strict precision | 12.5% |
| Full semantic precision | 26.5% |

The strict set now includes the real SQL-injection finding on
`SearchOrders` and both real SSRF findings on `SetWebhook`.  The engine still
does not find every planted bug: user-email disclosure, path traversal, most
state/race cases, and several chain-only cases remain missed.  The next
bottleneck is no longer marker visibility; it is action coverage and fixture
construction for state-dependent paths.
