# QDL rearchitecture target

## Goal

Make `qdl` the single canonical language and semantic IR of Cloud DAST.
QDL owns terms, predicate declarations, facts, rules, graph invariants,
surface-language compilation, neutral graph validation, and the Clingo
boundary. It does not own model wire schemas, proposal salvage/admission,
transport schemas, runtime orchestration, derived security projections, or
automata learning/search algorithms.

## Non-negotiable invariants

- `QdlGraph` is the only source of truth for declarative facts and rules.
- `Context.PROPOSAL` never becomes accepted or runtime state without the
  existing promotion policy.
- Clingo remains the only QDL/Datalog/ASP reasoning engine.
- Request and response schemas have one typed owner and are shared by template,
  fuzzing, and symbolic extensions.
- Learned automata emit QDL proposal graphs; they do not emit accepted facts or
  security verdicts.
- Campaign DAG and runtime state are projections over QDL and events, not new
  formal stores.
- SQLite/Neo4j persist QDL projections and provenance; they do not own derived
  attack paths or campaign DAG semantics.
- No compatibility facade may create a second public owner for a QDL symbol.

## Target ownership

```text
core/model       request/response schemas and observed evidence
core/qdl         terms, ontology, graph, parser/compiler, validation,
                 Clingo
core/model       proposal wire models and bounded proposal decoding
core             public extension contracts: binding and field couplings
core/qdl         declarative semantics, state-machine specifications and
                 neutral graph operations
core/runtime     campaign sequencing and candidate orchestration
core/verification field-role policy, norm/oracle compilation, taxonomy,
                  evidence interpretation and findings
automata         learned-automata adapters and learning state
fuzzing          candidate search, mutation, feedback, shrinking
symbolic         constraint generation and solving
infrastructure   repositories, transports, event journal, external adapters
```

The intended QDL kernel is:

```text
qdl/
  graph.py       Atom, Variable, Struct, facts, rules, invariants, constructors
  ontology.py    predicate/constructor schemas and registries
  facts.py       Fact, Rule, QdlGraph and graph invariants
  parser.py      bounded text -> surface syntax tree or parsed term mappings
  syntax.py      surface AST with source spans
  diagnostics.py structured line/column compiler errors
  compiler.py    surface AST -> QdlGraph, without promotion
  renderer.py    QdlGraph -> deterministic QDL text
  validation.py  neutral graph validation and declaration closure
  engine.py      the single Clingo adapter
```

Runtime planning owns campaign intent projections and the runtime/model
packages own evidence-fact constructors. Model-generated proposal wire
schemas, bounded decoding, salvage, and context policy live in
`core/contracts/proposals.py`; they consume `qdl.validation` but are not part
of the language kernel. `qdl/reasoning.py` contains only pure declarative
algebra and plan-value derivation; campaign state and scheduling remain in
`runtime`.

QDL modules have one canonical owner. Compatibility imports may remain only in
the explicitly documented public API modules; no `application` namespace or
formal compatibility package is part of the architecture.

## Surface DSL and compiler boundary

The LLM-facing text format is a controlled document language rather than a
second ontology. Sections select graph context; statements are facts or
bounded Datalog rules; `meta` and `uncertainty` remain side-car information:

```text
meta:
  source: "contract:profiles"
  provenance: "adapter:v1"

contract:
  is(action:read_profile, Action)

accepted:
  prevents(norm:profile_visibility, allowed(action:read_profile))
```

The compiler pipeline is:

```text
surface text -> Lark -> SurfaceDocument -> QdlCompiler -> QdlGraph
                                      -> proposal admission (when needed)
```

`parse_term` and `parse_fact` remain bounded parsing entry points for proposal
decoding. New document consumers should use `QdlCompiler`, which returns
line/column diagnostics and never promotes a proposal on its own. Variables in
the surface language are explicit (`$X`); uppercase names such as `Action` are
ordinary QDL atoms and therefore remain unambiguous type identifiers.

`render_qdl` is the reverse, deterministic projection used to give a model a
stable canonical view. It renders semantic facts and rules only; metadata and
uncertainties are carried separately through `CompilationMetadata`.

All generated ASP query programs use `ClingoEngine.solve_program` or its
engine-owned `program_session` for incremental grounding. Query layers may
append bounded rules to a compiled graph, but they do not construct their own
solver controls. This keeps Clingo as the one declarative execution boundary
while leaving query-specific projections outside the semantic graph.

The deterministic state-machine verifier is owned by `qdl/state_machine.py`.
The learned-machine algorithm and adapter are owned by `packages/automata`;
the verifier consumes its proposal graph and keeps acceptance and security
decisions outside the QDL language kernel.

The remaining compatibility modules are thin exports only; semantic owners are
listed explicitly and the former `application/verification/formal` package is
gone:

```text
qdl/grammar.py         -> model.grammar + extensions.runtime_placeholder
qdl/grammar_facts.py   -> runtime.grammar_facts
qdl/binding.py         -> removed; public extension facade is `cloud_dast.binding`
qdl/couplings.py       -> cloud_dast.couplings
qdl/field_roles.py     -> qdl field-role semantics
qdl/norms.py           -> qdl primitive vocabulary
qdl/norm_view.py       -> removed; consumers use verification norm views directly
qdl/oracle_compiler.py -> removed; compiler is owned by verification
qdl/payload_hints.py   -> runtime.payload_hints
qdl/projection.py      -> qdl projection implementation
qdl/reasoning.py       -> pure QDL algebra and declarative plan values
qdl/roles.py           -> qdl semantic-role vocabulary
qdl/semantic_roles.py  -> removed; roles are owned by qdl/roles.py
qdl/semantics.py      -> removed; compiler is qdl.semantic_norm_compiler
qdl/semantic_norm_compiler.py -> qdl norm compilation
qdl/state_machine.py  -> qdl.state_machine
qdl/state_machine_spec.py -> qdl.state_machine_spec
qdl/threat_compiler.py -> qdl.threat_compiler
```

The removed modules are not compatibility exports: consumers import the
semantic owner directly. `cloud_dast.binding` and `cloud_dast.couplings` are
the deliberate public contract facades for optional extensions. No
transitional application namespace is retained.

## Schema flow

```text
contract adapter or descriptor registry
    -> RequestSchema / ResponseSchema
    -> QDL semantic enrichment
    -> candidate and constraint plugins
    -> Check / Observation
```

The schema is immutable and transport-aware. File/Neo4j contract adapters use
declared fields; descriptor-backed gRPC composition can derive the complete
request and response shape from `DescriptorRegistry` (including nested paths,
repeated fields, enum values, oneofs, and scalar bounds). QDL adds semantic
roles, sinks, effects, and evidence requirements; it does not replace the
transport schema.

The canonical schema owner is `core/model/schemas.py`. `RequestSchema`,
`ResponseSchema`, `MessageSchema`, and `FieldSpec` are defined there; imports
through `model.checks` are compatibility re-exports only. QDL consumes these
contracts but does not define a second schema hierarchy.

## Learned automata flow

```text
runtime observations
    -> automata learner
    -> Context.PROPOSAL QDL graph
    -> proposal validation and review/promotion policy
    -> Context.ACCEPTED QDL graph
```

The existing AALpy adapter is the first implementation of this port and is
registered through the `cloud_dast.extensions` entry point. Its learning
algorithm belongs in `packages/automata`; QDL retains only the canonical
transition vocabulary, graph invariants, proposal admission, and deterministic
verification.

## Migration order

1. Characterize current QDL graph, parser, Clingo, planner, and automata
   behavior with contract tests.
2. Remove duplicate formal facades and establish one owner per symbol.
3. Introduce the typed request/response schema contract.
4. Move learned-automata search and adapters out of `qdl`; keep QDL transition
   facts and neutral validation in the kernel, with proposal admission in the
   model/application boundary and deterministic verification in
   application/verification.
5. Split `graph.py` into ontology and graph facts, and replace handwritten
   textual parsing with a bounded library-backed parser.
6. Move runtime, verification, and reporting projections out of `qdl`.
7. Add explicit runtime checkpoint/replay contracts for campaign state.

Each step must preserve the existing public behavior and pass focused tests
before the next ownership boundary is changed.
