from __future__ import annotations

import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cloud_dast.qdl.engine import (
    ClingoEngine,
    ClingoSolution,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    allowed,
    canonical_json,
    changed,
    duration,
    external_call,
    field,
    has,
    input_field,
    reached,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.semantic_norm_compiler import (
    FormalCompilationError,
    SemanticNormCompiler,
)
from cloud_dast.qdl.state_machine_spec import (
    StateMachineSpecification,
    StateMachineTransition,
)
from cloud_dast.qdl.threat_compiler import (
    _AVAILABILITY_CLASSES,
    _RELEVANT_THREATS,
    _THREAT_ACTION_POSITIONS,
    _THREAT_RESOURCE_POSITIONS,
    ThreatIntentCompiler,
)


def fact(name, args, context=Context.ACCEPTED):
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


def make_threat_graph() -> QdlGraph:
    """A miniature graph where the attacker has elevation on two actions."""
    return QdlGraph(
        facts=(
            # Actions
            fact("is", (Atom(value="action:get"), Atom(value="Action"))),
            fact("is", (Atom(value="action:list"), Atom(value="Action"))),
            fact("is", (Atom(value="action:admin"), Atom(value="Action"))),
            # Targets
            fact(
                "targets",
                (Atom(value="action:get"), Atom(value="resource:lockbox.secret")),
            ),
            fact(
                "targets",
                (Atom(value="action:list"), Atom(value="resource:lockbox.secret")),
            ),
            fact(
                "targets",
                (Atom(value="action:admin"), Atom(value="resource:lockbox.secret")),
            ),
            fact(
                "is",
                (Atom(value="resource:lockbox.secret"), Atom(value="ResourceType")),
            ),
            # Attacker hypothesis
            fact("is", (Atom(value="principal:attacker"), Atom(value="Subject"))),
            fact("attacker", (Atom(value="principal:attacker"),)),
            # Attacker has NO lockbox permissions (no binding facts)
            # so ¬may holds for all actions → elevation threats derive.
        )
    )


def make_same_short_name_graph() -> QdlGraph:
    """Two actions whose IDs share the last dot-separated segment."""
    return QdlGraph(
        facts=(
            # Actions
            fact("is", (Atom(value="action:orders.Get"), Atom(value="Action"))),
            fact("is", (Atom(value="action:payments.Get"), Atom(value="Action"))),
            # Targets
            fact(
                "targets",
                (Atom(value="action:orders.Get"), Atom(value="resource:orders.order")),
            ),
            fact(
                "targets",
                (
                    Atom(value="action:payments.Get"),
                    Atom(value="resource:payments.charge"),
                ),
            ),
            fact(
                "is",
                (Atom(value="resource:orders.order"), Atom(value="ResourceType")),
            ),
            fact(
                "is",
                (Atom(value="resource:payments.charge"), Atom(value="ResourceType")),
            ),
            # Attacker hypothesis: no bindings, so elevation derives for
            # every action that targets a resource.
            fact("is", (Atom(value="principal:attacker"), Atom(value="Subject"))),
            fact("attacker", (Atom(value="principal:attacker"),)),
        )
    )


def make_disclosure_graph(sensitive: bool) -> QdlGraph:
    """One action exposing a universal channel the attacker can observe.

    The graph mirrors the binder's universal exposes: every action exposes
    its status channel.  The attacker has no permission on the target, so
    the algebra derives both a disclosure and an elevation threat; only the
    disclosure threat depends on the exposed field being sensitive.
    """

    action = Atom(value="action:get")
    resource = Atom(value="resource:profile")
    witness = field(resource, Atom(value="email"))
    facts = [
        fact("is", (action, Atom(value="Action"))),
        fact(
            "is",
            (resource, Atom(value="Resource")),
        ),
        fact("targets", (action, resource)),
        fact("is", (witness, Atom(value="Witness"))),
        fact("exposes", (action, witness)),
        fact("is", (Atom(value="principal:attacker"), Atom(value="Subject"))),
        fact("attacker", (Atom(value="principal:attacker"),)),
    ]
    if sensitive:
        facts.append(fact("has", (witness, Atom(value="sensitive"))))
    return QdlGraph(facts=tuple(facts))


def _select_norms(facts, effect_name: str) -> tuple[Fact, ...]:
    return tuple(
        fact
        for fact in facts
        if fact.predicate.name == "prevents"
        and fact.args[0].value.startswith(f"norm:synthetic:{effect_name}:")
    )


def test_compiler_keeps_disclosure_norms_for_sensitive_actions() -> None:
    """A disclosure threat on a sensitive field yields a possession norm."""

    facts = ThreatIntentCompiler().compile(make_disclosure_graph(sensitive=True))

    disclosed = {
        canonical_json(prevents.args[1]) for prevents in _select_norms(facts, "has")
    }
    expected = has(
        Atom(value="principal:attacker"),
        field(Atom(value="resource:profile"), Atom(value="email")),
    )
    assert disclosed == {canonical_json(expected)}


def test_compiler_skips_disclosure_norms_for_public_actions() -> None:
    """Universal channel exposes on a public action are not disclosures."""

    facts = ThreatIntentCompiler().compile(make_disclosure_graph(sensitive=False))

    assert _select_norms(facts, "has") == ()
    # Elevation is an independent threat hypothesis and keeps its own norm.
    denied = {
        prevents.args[1].args[0].value for prevents in _select_norms(facts, "allowed")
    }
    assert denied == {"action:get"}


def test_compiler_keeps_norms_for_actions_with_same_short_name() -> None:
    """Distinct actions must not collide on a shared norm short name."""
    graph = make_same_short_name_graph()
    facts = ThreatIntentCompiler().compile(graph)

    prevents = [f for f in facts if f.predicate.name == "prevents"]
    denied_actions = {p.args[1].args[0].value for p in prevents}
    assert denied_actions == {"action:orders.Get", "action:payments.Get"}

    norm_ids = [p.args[0].value for p in prevents]
    assert len(norm_ids) == len(set(norm_ids))
    for norm_id in norm_ids:
        assert norm_id.startswith("norm:synthetic:")


def test_compiler_produces_prevents_norms_for_elevation() -> None:
    graph = make_threat_graph()
    compiler = ThreatIntentCompiler()
    facts = compiler.compile(graph)

    assert len(facts) >= 2  # at least get + list (admin has no elevation if no ¬may)
    prevents = [f for f in facts if f.predicate.name == "prevents"]
    assert len(prevents) >= 2

    # Each prevents has a norm:synthetic: prefix
    for p in prevents:
        norm_id = p.args[0].value
        assert norm_id.startswith("norm:synthetic:allowed:")

    # Each prevents uses allowed(action): prevents(N, allowed(A)) means
    # the action must be denied (allowed(A) -> expected DENIED).
    for p in prevents:
        effect = p.args[1]
        assert effect.name == "allowed"
        assert effect.args[0].value.startswith("action:")


def test_compiler_norms_are_valid_qdl_facts() -> None:
    """The synthetic facts must form a valid QdlGraph (references checked)."""
    graph = make_threat_graph()
    compiler = ThreatIntentCompiler()
    facts = compiler.compile(graph)
    assert facts  # guard

    # All facts together must validate
    synthetic = QdlGraph(facts=facts)
    assert len(synthetic.facts) == len(facts)


def test_compiler_skips_undeclared_actions() -> None:
    graph = QdlGraph(
        facts=(
            fact("is", (Atom(value="action:real"), Atom(value="Action"))),
            fact("is", (Atom(value="principal:attacker"), Atom(value="Subject"))),
            fact("attacker", (Atom(value="principal:attacker"),)),
        )
    )
    compiler = ThreatIntentCompiler()
    facts = compiler.compile(graph)
    # No targets → no threats → no facts
    assert facts == ()


def test_compiler_is_idempotent() -> None:
    graph = make_threat_graph()
    compiler = ThreatIntentCompiler()
    first = compiler.compile(graph)
    second = compiler.compile(graph)
    assert len(first) == len(second)


def test_solver_failure_is_an_explicit_error(monkeypatch, caplog) -> None:
    def fail_solve(self, graph, **kwargs):
        raise RuntimeError("solver unavailable")

    monkeypatch.setattr(ClingoEngine, "solve", fail_solve)
    compiler = ThreatIntentCompiler()

    with caplog.at_level(
        logging.ERROR,
        logger="cloud_dast.qdl.threat_compiler",
    ):
        with pytest.raises(
            FormalCompilationError,
            match="threat-intent Clingo solve failed",
        ) as exc_info:
            compiler.compile(make_threat_graph())

    assert isinstance(exc_info.value.__cause__, RuntimeError)
    assert "threat_intent_solve_failed" in caplog.text
    assert "solver unavailable" in caplog.text


def test_non_executable_facts_do_not_feed_context_erasing_algebra() -> None:
    action = Atom(value="action:get")
    resource = Atom(value="resource:secret")
    attacker = Atom(value="principal:attacker")
    graph = QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action")), Context.CONTRACT),
            fact("is", (resource, Atom(value="ResourceType")), Context.PROPOSAL),
            fact("targets", (action, resource), Context.PROPOSAL),
            fact("is", (attacker, Atom(value="Subject")), Context.PROPOSAL),
            fact("attacker", (attacker,), Context.PROPOSAL),
            fact("targets", (action, resource), Context.RUNTIME),
            fact("is", (attacker, Atom(value="Subject")), Context.RUNTIME),
            fact("attacker", (attacker,), Context.RUNTIME),
        )
    )

    facts = ThreatIntentCompiler().compile(graph)

    assert facts == ()


def test_threat_and_semantic_compilers_share_one_effect_norm() -> None:
    action = Atom(value="action:admin.delete")
    permission = Atom(value="permission:admin.delete")
    attacker = Atom(value="principal:attacker")
    resource = Atom(value="resource:secret")
    graph = QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action"))),
            fact("is", (permission, Atom(value="Permission"))),
            fact("is", (attacker, Atom(value="Subject"))),
            fact("is", (resource, Atom(value="Resource"))),
            fact("attacker", (attacker,)),
            fact("requires", (action, permission)),
            fact("targets", (action, resource)),
        )
    )

    threat_norms = {
        canonical_json(fact)
        for fact in ThreatIntentCompiler().compile(graph)
        if fact.predicate.name == "prevents"
    }
    semantic_norms = {
        canonical_json(fact)
        for fact in SemanticNormCompiler().compile(graph)
        if fact.predicate.name == "prevents"
    }

    assert threat_norms
    assert threat_norms == semantic_norms


class StaticClingo:
    def __init__(self, *atoms: str) -> None:
        self._atoms = atoms

    def solve(self, graph, algebra=True):
        assert algebra
        return (ClingoSolution(atoms=self._atoms),)


def make_evidence_graph() -> QdlGraph:
    action = Atom(value="action:admin")
    resource = Atom(value="resource:order")
    token = field(resource, Atom(value="token"))
    query = input_field(action, Atom(value="query"))
    url = input_field(action, Atom(value="url"))
    role = input_field(action, Atom(value="role"))
    sink = Atom(value="sink:sql")
    marker = Atom(value="marker:oob")
    observations = tuple(Atom(value=f"observation:{index}") for index in range(3))
    return QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action"))),
            fact("is", (resource, Atom(value="Resource"))),
            fact("is", (token, Atom(value="Field"))),
            fact("is", (query, Atom(value="Field"))),
            fact("is", (url, Atom(value="Field"))),
            fact("is", (role, Atom(value="Field"))),
            fact("is", (sink, Atom(value="interpreter"))),
            fact("is", (marker, Atom(value="external_net"))),
            fact("exposes", (action, token)),
            fact("has", (token, Atom(value="credential"))),
            fact("reaches", (query, sink)),
            fact("reaches", (url, marker)),
            fact("causes", (action, external_call(action, marker))),
            fact("has", (role, Atom(value="privileged"))),
            fact("targets", (action, resource)),
            fact("causes", (action, duration(action, Atom(value=999)))),
            *(
                fact(
                    "is",
                    (observation, Atom(value="Observation")),
                    Context.RUNTIME,
                )
                for observation in observations
            ),
            *(
                fact(
                    "evidence",
                    (
                        observation,
                        duration(action, Atom(value=value)),
                    ),
                    Context.RUNTIME,
                )
                for observation, value in zip(
                    observations,
                    (110, 120, 130),
                    strict=True,
                )
            ),
        )
    )


@pytest.mark.parametrize(
    ("threat_class", "atom", "expected"),
    [
        (
            "elevation",
            'elevation("principal:attacker","action:admin")',
            allowed(Atom(value="action:admin")),
        ),
        (
            "owasp_api5_function_authz",
            'owasp_api5_function_authz("action:admin","principal:attacker")',
            allowed(Atom(value="action:admin")),
        ),
        (
            "disclosure",
            'disclosure("principal:attacker","action:admin",field("resource:order","token"))',
            has(
                Atom(value="attacker"),
                field(Atom(value="resource:order"), Atom(value="token")),
            ),
        ),
        (
            "tampering",
            'tampering("action:admin","principal:attacker")',
            changed(Atom(value="resource:order"), Atom(value="role")),
        ),
        (
            "owasp_a03_injection",
            'owasp_a03_injection("action:admin","principal:attacker","sink:sql")',
            reached(Atom(value="action:admin"), Atom(value="sink:sql")),
        ),
        (
            "owasp_api7_ssrf",
            'owasp_api7_ssrf("action:admin","principal:attacker")',
            external_call(Atom(value="action:admin"), Atom(value="marker:oob")),
        ),
        (
            "denial",
            'denial("principal:user","resource:order")',
            duration(Atom(value="action:admin"), Atom(value=150)),
        ),
    ],
)
def test_threat_mapping_is_evidence_aware(threat_class, atom, expected) -> None:
    compiler = ThreatIntentCompiler(StaticClingo(atom))

    facts = compiler.compile(make_evidence_graph())
    actual = {
        canonical_json(prevents.args[1])
        for prevents in _select_norms(facts, expected.name)
    }

    assert actual == {canonical_json(expected)}


def test_enriched_semantics_produce_distinct_primitives() -> None:
    compiler = ThreatIntentCompiler(
        StaticClingo(
            'elevation("principal:attacker","action:admin")',
            'disclosure("principal:attacker","action:admin",field("resource:order","token"))',
            'tampering("action:admin","principal:attacker")',
            'owasp_a03_injection("action:admin","principal:attacker","sink:sql")',
            'owasp_api7_ssrf("action:admin","principal:attacker")',
            'denial("principal:user","resource:order")',
        )
    )

    facts = compiler.compile(make_evidence_graph())
    primitives = {
        prevents.args[1].name
        for prevents in facts
        if prevents.predicate.name == "prevents"
    }

    assert primitives == {
        "allowed",
        "has",
        "changed",
        "reached",
        "external_call",
        "duration",
    }


def test_missing_effect_evidence_never_falls_back_to_allowed() -> None:
    action = Atom(value="action:admin")
    source = QdlGraph(facts=(fact("is", (action, Atom(value="Action"))),))
    compiler = ThreatIntentCompiler(
        StaticClingo(
            'tampering("action:admin","principal:attacker")',
            'disclosure("principal:attacker","action:admin",status("action:admin"))',
            'spoofing("action:admin",token("action:admin"),"principal:attacker")',
        )
    )

    facts = compiler.compile(source)

    assert facts == ()


def test_unprefixed_action_ids_are_not_dropped() -> None:
    """Unprefixed declared actions keep their threats (DW-F3 regression)."""

    graph = QdlGraph(
        facts=(
            fact("is", (Atom(value="orders.Get"), Atom(value="Action"))),
            fact(
                "is",
                (Atom(value="resource:orders.order"), Atom(value="ResourceType")),
            ),
            fact(
                "targets",
                (Atom(value="orders.Get"), Atom(value="resource:orders.order")),
            ),
            fact("is", (Atom(value="principal:attacker"), Atom(value="Subject"))),
            fact("attacker", (Atom(value="principal:attacker"),)),
        )
    )

    facts = ThreatIntentCompiler().compile(graph)

    denied = {
        prevents.args[1].args[0].value for prevents in _select_norms(facts, "allowed")
    }
    assert denied == {"orders.Get"}


def test_state_machine_actions_compile_into_threat_norms() -> None:
    """Canonical state-machine action IDs survive threat compilation."""

    specification = StateMachineSpecification(
        states=("created", "approved"),
        actions=("approve",),
        initial_states=("created",),
        transitions=(
            StateMachineTransition(
                action="approve", from_state="created", to_state="approved"
            ),
        ),
    )
    attacker_graph = QdlGraph(
        facts=(
            fact("is", (Atom(value="action:approve"), Atom(value="Action"))),
            fact("is", (Atom(value="resource:order"), Atom(value="ResourceType"))),
            fact(
                "targets",
                (Atom(value="action:approve"), Atom(value="resource:order")),
            ),
            fact("is", (Atom(value="principal:attacker"), Atom(value="Subject"))),
            fact("attacker", (Atom(value="principal:attacker"),)),
        )
    )

    facts = ThreatIntentCompiler().compile(
        merge_graphs(specification.to_qdl_graph(), attacker_graph)
    )

    denied = {
        prevents.args[1].args[0].value for prevents in _select_norms(facts, "allowed")
    }
    assert denied == {"action:approve"}


@pytest.mark.parametrize(
    "atom",
    [
        'owasp_a02_crypto("principal:attacker","action:get",field("resource:profile","email"))',
        'owasp_a02_crypto("action:get",field("resource:profile","email"),"principal:attacker")',
    ],
)
def test_a02_crypto_action_position_follows_the_deriving_rule(atom: str) -> None:
    compiler = ThreatIntentCompiler(StaticClingo(atom))

    facts = compiler.compile(make_disclosure_graph(sensitive=True))

    disclosed = {
        canonical_json(prevents.args[1]) for prevents in _select_norms(facts, "has")
    }
    expected = has(
        Atom(value="principal:attacker"),
        field(Atom(value="resource:profile"), Atom(value="email")),
    )
    assert disclosed == {canonical_json(expected)}


def test_denial_resource_is_read_from_the_predicate_position() -> None:
    action = Atom(value="action:admin")
    resource = Atom(value="orders.order")
    observations = tuple(Atom(value=f"observation:{index}") for index in range(3))
    graph = QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action"))),
            fact("is", (resource, Atom(value="ResourceType"))),
            fact("targets", (action, resource)),
            fact("causes", (action, duration(action, Atom(value=999)))),
            *(
                fact("is", (observation, Atom(value="Observation")), Context.RUNTIME)
                for observation in observations
            ),
            *(
                fact(
                    "evidence",
                    (observation, duration(action, Atom(value=value))),
                    Context.RUNTIME,
                )
                for observation, value in zip(
                    observations,
                    (110, 120, 130),
                    strict=True,
                )
            ),
        )
    )
    compiler = ThreatIntentCompiler(
        StaticClingo('denial("principal:user","orders.order")')
    )

    facts = compiler.compile(graph)

    bounds = {
        canonical_json(prevents.args[1])
        for prevents in _select_norms(facts, "duration")
    }
    assert bounds == {canonical_json(duration(action, Atom(value=150)))}


def test_every_relevant_threat_predicate_has_a_positional_signature() -> None:
    """A relevant predicate without a fixed locator position drops threats."""

    for name in _RELEVANT_THREATS:
        if name in _AVAILABILITY_CLASSES:
            assert name in _THREAT_RESOURCE_POSITIONS
        else:
            assert name in _THREAT_ACTION_POSITIONS


def test_threat_slice_closes_structural_term_declarations() -> None:
    """A referenceable Struct term needs its declaration in the slice."""

    action = Atom(value="action:get")
    field_name = Atom(value="resource_id")
    input_term = input_field(action, field_name)
    graph = QdlGraph(
        facts=(
            fact("is", (action, Atom(value="Action"))),
            fact("is", (input_term, Atom(value="InputField"))),
            fact("part", (input_term, action)),
        )
    )

    slice_ = ThreatIntentCompiler.threat_slice(graph)

    assert any(
        item.predicate.name == "is"
        and canonical_json(item.args[0]) == canonical_json(input_term)
        for item in slice_.facts
    )
    QdlGraph(facts=slice_.facts, rules=slice_.rules)


def test_threat_slice_preserves_relevant_rules_and_separates_cache_entries() -> None:
    """Rule-derived threat inputs must remain part of the cache identity."""

    action = Atom(value="action:get")
    permission = Atom(value="permission:read")
    other_permission = Atom(value="permission:write")
    common = (
        fact("is", (action, Atom(value="Action"))),
        fact("is", (permission, Atom(value="Permission"))),
        fact("is", (other_permission, Atom(value="Permission"))),
        fact("targets", (action, permission)),
    )
    first_rule = Rule(
        body=(fact("targets", (action, permission)),),
        head=(fact("requires", (action, permission)),),
    )
    second_rule = Rule(
        body=(fact("targets", (action, permission)),),
        head=(fact("requires", (action, other_permission)),),
    )
    first = QdlGraph(facts=common, rules=(first_rule,))
    second = QdlGraph(facts=common, rules=(second_rule,))

    first_slice = ThreatIntentCompiler.threat_slice(first)
    second_slice = ThreatIntentCompiler.threat_slice(second)

    assert first_slice.rules == (first_rule,)
    assert second_slice.rules == (second_rule,)
    assert first_slice.content_hash != second_slice.content_hash

    compiler = ThreatIntentCompiler(StaticClingo())
    compiler.compile_cached(first)
    compiler.compile_cached(second)
    assert len(compiler._cache) == 2


def _optional_threat_graph(
    include_part: bool,
    include_requires: bool,
    include_targets: bool,
    include_causes: bool,
) -> QdlGraph:
    """Build a valid threat graph from independently optional QDL relations."""

    action = Atom(value="action:get")
    resource = Atom(value="resource:thing")
    input_term = input_field(action, Atom(value="resource_id"))
    effect = changed(resource, Atom(value="state"))
    declarations = (
        fact("is", (action, Atom(value="Action"))),
        fact("is", (resource, Atom(value="ResourceType"))),
        fact("is", (input_term, Atom(value="InputField"))),
        fact("is", (effect, Atom(value="Effect"))),
    )
    optional = (
        *((fact("part", (input_term, action)),) if include_part else ()),
        *((fact("requires", (action, effect)),) if include_requires else ()),
        *((fact("targets", (action, resource)),) if include_targets else ()),
        *((fact("causes", (action, effect)),) if include_causes else ()),
    )
    return QdlGraph(facts=(*declarations, *optional))


@given(
    include_part=st.booleans(),
    include_requires=st.booleans(),
    include_targets=st.booleans(),
    include_causes=st.booleans(),
)
def test_valid_graph_implies_valid_threat_slice(
    include_part: bool,
    include_requires: bool,
    include_targets: bool,
    include_causes: bool,
) -> None:
    """Property: slicing a valid QDL graph cannot create an unknown reference."""

    graph = _optional_threat_graph(
        include_part,
        include_requires,
        include_targets,
        include_causes,
    )

    slice_ = ThreatIntentCompiler.threat_slice(graph)

    QdlGraph(facts=slice_.facts, rules=slice_.rules)
    source_keys = {canonical_json(item) for item in graph.facts}
    assert {canonical_json(item) for item in slice_.facts} <= source_keys
