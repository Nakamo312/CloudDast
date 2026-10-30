# Architecture Boundaries

The engine is application-agnostic by construction.  Everything
cloud-specific, transport-specific, or oracle-specific lives behind a port;
the core speaks only the QDL algebra and facts.

## Core (no adapters import-able from here)

- The QDL basis: six primitives, witness/effect constructors, letters,
  corpus rules (``qdl/graph.py``, ``formal/clingo_engine.py``).
- The planner, coverage matrix, campaign loop, fixture pool: facts in,
  facts out.
- Fixture needs are expressed as facts
  (``FixtureRequest``: resource type, state, scope) and handed to the
  provisioner port — never as transport calls.

## Ports

| Port | Purpose | Implementations |
|---|---|---|
| `ProvisionerPort` | create one stand fixture from a fact | `CloudProvisioner` (live transport + provisioner identity); future: local process orchestration, sandbox APIs |
| `Target` / `OobUrlFactory` | execute one probe request, OOB canary URLs | gRPC/HTTP adapters |
| `primitive_router.Oracle` | deterministic verdicts over the six witness channels (П1–П6) | outcome, field, latency, marker, OOB, trace oracles |
| `ModelClient` | LLM proposals (semantic compiler) | GLM/other model adapters |
| `GroundingCache` | persist validated semantic-grounding proposals | `FileGroundingCache` |
| `FormalRepository`, `MethodRepository`, `ScenarioRepository` | graph persistence | Neo4j adapters |

## Adapter symmetry

Testing a locally deployed application or a sandboxed one must not change
the core:

- a **local adapter** implements `ProvisionerPort` with process
  orchestration (docker, compose, nsjail) and the transport port with
  plain HTTP;
- an **eBPF-instrumented sandbox** is an oracle/observation adapter: it can
  ground `causes`/`reached`/`observes` facts from syscall and process
  events, feeding the same algebra — the core never learns that evidence
  came from a kernel probe rather than an HTTP response;
- the **cloud adapter** (current) implements provisioning through the live
  transport under a dedicated provisioner identity, separate from the
  victim and attacker identities used by probes.

## Identity roles

- **provisioner** — service/admin account; creates fixtures (never used by
  probes);
- **victim** — owns or can access the fixture; used for positive-control
  checks;
- **attacker** — the principal under test.

The core only ever sees identities as check fields; which token signs which
call is adapter business.


## Automatic grounding (no manual rituals)

Every campaign start re-grounds the model automatically:

1. **contract** — re-projected from the source graph (idempotent, content-addressed);
2. **stand** — principals, bindings, and resource hierarchy re-projected;
3. **LLM semantic layer** — model-backed grounding is disabled by
   `CLOUD_DAST_SKIP_LLM_GROUNDING=1`. The model proposes
   roles/couplings/causes; `FormalModelOutputValidator` salvages the valid
   subset and the deterministic `promote_proposal` policy persists accepted
   semantic facts. `CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS=1` separately gates
   exploratory formal threat norms in `ScenarioBinder`.

   The parallel grounding layer also writes validated proposals into a
   content-addressed `GroundingCache`. Its key covers the model namespace,
   prompt strategy, instruction, response schema, and the contract+stand slice;
   accepted LLM outputs are deliberately excluded so the next campaign reuses
   the result instead of invalidating itself.

The state machine is grounded from its own source when data exists; the
`transition` effect constructor maps `transition(A, From, To)` facts into
`causes(A, transition(From, To))`, so state-machine threats flow through
the existing tampering letter without new algebra elements.

## Generic adapter boundary (2026-10-19)

`HttpJsonTarget` implements the transport-agnostic `Target` port for HTTP/JSON
and `GenericPolicyProjector` maps a `PolicySnapshot` to the QDL `may`-family.
They are unit-tested adapter implementations, not core engines. The default
live composition still selects `GrpcTarget`; policy production wiring reads
Neo4j into a `PolicySnapshot`, emits it through `GenericPolicyProjector`, and
uses a replaceable `PolicyRulePack` in `ClingoEngine`.

## Data migration (2026-10-11)

The code moved to the QDL algebra months of iterations ago, but the store
kept pre-algebra projections and the old STRIDE/ThreatGraph world:

- **contract re-ingest** — the stored projection embedded legacy predicate
  definitions (e.g. the extension-era `targets`); loading now coerces them,
  and re-ingestion writes current-canonical facts;
- **semantic promotion v2 + persistence** — `promote_proposal` now promotes
  the semantic grounding layer (roles, couplings, causes) alongside norms,
  and the binder persists the promoted graph into `accepted:{service}`;
  the LLM grounding accumulates content-addressed instead of evaporating
  after every run;
- **closed role alphabet** — the semantic compiler is instructed to emit
  exactly the algebra's role atoms (`object_ref`, `sensitive`, …), so the
  corpus rules can match them;
- **legacy marking** — `migration_cli` reports and marks the ~106k
  old-world nodes (`ThreatGraph`, `Goal`, `Path`, `Step`, `Threat`,
  `Invariant`, `Version`, `DfdElement`, `StrideAnnotation`, `Finding`) with
  a reversible `Legacy` label; `--purge-legacy` removes them on explicit
  request.

Letter/corpus derivation over the static store still yields nothing — by
design: the corpus rules are the *violation* layer and need runtime facts
(`executes`, `may`, `owner`).  Goal generation (item 1) adds the
*opportunity* layer over the migrated facts.
