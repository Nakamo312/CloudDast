"""Security algebra tests: corpus derivability and closure properties.

The synthetic model grounds every letter and every derivable OWASP class at
once.  Negative controls prove soundness: removing the violating fact removes
the derived class.  Closure tests prove termination on cycles, transitivity,
idempotence, and stratification of the full algebra program.
"""

from __future__ import annotations

import clingo

from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Term,
    changed,
    external_call,
    field,
    input_field,
    trace,
)


def atom(value: str) -> Atom:
    return Atom(value=value)


class ModelBuilder:
    """Build a QDL graph with explicit declarations, test-style."""

    def __init__(self) -> None:
        self._facts: list[Fact] = []

    def entity(self, term: Term, type_name: str) -> None:
        self.fact("is", (term, atom(type_name)))

    def fact(self, predicate: str, args: tuple[Term, ...]) -> None:
        self._facts.append(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name(predicate),
                args=args,
            )
        )

    def build(self) -> QdlGraph:
        return QdlGraph(facts=tuple(self._facts))


ATTACKER = atom("subject:attacker")
VICTIM = atom("subject:victim")
AUDITOR = atom("subject:auditor")
ACTION_AUTH = atom("action:auth")
ACTION_GET = atom("action:get")
ACTION_UPDATE = atom("action:update")
ACTION_FLOW = atom("action:flow")
ACTION_ADMIN = atom("action:admin")
ACTION_CALL = atom("action:call")
ACTION_OLD = atom("action:old")
ACTION_CONSUME = atom("action:consume")
ACTION_DEPLOY = atom("action:deploy")
ACTION_BOLA = atom("action:bola")
ACTION_LOGIN = atom("action:login")
RESOURCE_SECRET = atom("resource:secret")
RESOURCE_FOREIGN = atom("resource:foreign")
RESOURCE_SERVICE = atom("resource:service")
RESOURCE_AUTH = atom("resource:auth")
MARKER_EXTERNAL = atom("marker:external-net")
SINK_SQL = atom("sink:sql-engine")
WITNESS_TOKEN = atom("witness:token")
PAYLOAD_FIELD = field(RESOURCE_SECRET, atom("payload"))
FLOW_TRACE = trace(ACTION_FLOW)
BOLA_INPUT = input_field(ACTION_BOLA, atom("secret_id"))
ROLE_INPUT = input_field(ACTION_UPDATE, atom("role"))
QUERY_INPUT = input_field(ACTION_UPDATE, atom("q"))


def _extra_fact(predicate: str, args: tuple[Term, ...]) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name(predicate),
        args=args,
    )


def make_model(*, extra: list[Fact] | None = None) -> QdlGraph:
    """Ground every letter and every derivable OWASP class at once."""

    model = ModelBuilder()
    for term, type_name in (
        (ATTACKER, "Subject"),
        (VICTIM, "Subject"),
        (AUDITOR, "Subject"),
        (ACTION_AUTH, "Action"),
        (ACTION_GET, "Action"),
        (ACTION_UPDATE, "Action"),
        (ACTION_FLOW, "Action"),
        (ACTION_ADMIN, "Action"),
        (ACTION_CALL, "Action"),
        (ACTION_OLD, "Action"),
        (ACTION_CONSUME, "Action"),
        (ACTION_DEPLOY, "Action"),
        (ACTION_BOLA, "Action"),
        (ACTION_LOGIN, "Action"),
        (RESOURCE_SECRET, "Resource"),
        (RESOURCE_FOREIGN, "Resource"),
        (RESOURCE_SERVICE, "Resource"),
        (RESOURCE_AUTH, "Resource"),
        (MARKER_EXTERNAL, "Marker"),
        (SINK_SQL, "Sink"),
        (WITNESS_TOKEN, "Witness"),
        (PAYLOAD_FIELD, "Witness"),
        (FLOW_TRACE, "Witness"),
        (BOLA_INPUT, "Input"),
        (ROLE_INPUT, "Input"),
        (QUERY_INPUT, "Input"),
    ):
        model.entity(term, type_name)

    # Campaign threat hypothesis: the attacker attempts every action.
    model.fact("attacker", (ATTACKER,))

    # S: accepted evidence that does not truly bind.
    model.fact("accepts", (ACTION_AUTH, WITNESS_TOKEN, VICTIM))
    model.fact("has", (WITNESS_TOKEN, atom("weak_binding")))
    model.fact("has", (WITNESS_TOKEN, atom("credential")))

    # T: unauthorized state change.
    model.fact("executes", (ATTACKER, ACTION_UPDATE))
    model.fact("targets", (ACTION_UPDATE, RESOURCE_SECRET))
    model.fact("causes", (ACTION_UPDATE, changed(RESOURCE_SECRET, atom("payload"))))
    model.fact("has", (ROLE_INPUT, atom("privileged")))
    model.fact("has", (QUERY_INPUT, atom("attacker_controlled")))
    model.fact("reaches", (QUERY_INPUT, SINK_SQL))
    model.fact("is", (SINK_SQL, atom("interpreter")))
    # API6 now derives from a real transition effect (spec §2.2), not a role.
    model.fact("is", (atom("state:created"), atom("State")))
    model.fact("is", (atom("state:approved"), atom("State")))
    model.fact(
        "transition", (ACTION_FLOW, atom("state:created"), atom("state:approved"))
    )
    model.fact("has", (ACTION_CONSUME, atom("downstream_trust")))
    model.fact("has", (ACTION_DEPLOY, atom("component")))
    model.fact("has", (ACTION_UPDATE, atom("unverified_source")))

    # R: executed action without an audited trace.
    model.fact("executes", (ATTACKER, ACTION_FLOW))
    model.fact("targets", (ACTION_FLOW, RESOURCE_SECRET))
    model.fact("causes", (ACTION_FLOW, changed(RESOURCE_SECRET, atom("payload"))))
    model.fact("is", (AUDITOR, atom("auditor")))

    # I: unauthorized observation of an exposed witness.
    model.fact("exposes", (ACTION_GET, PAYLOAD_FIELD))
    model.fact("observes", (ATTACKER, PAYLOAD_FIELD))
    model.fact("targets", (ACTION_GET, RESOURCE_SECRET))
    model.fact("has", (PAYLOAD_FIELD, atom("verbose")))
    model.fact("has", (PAYLOAD_FIELD, atom("sensitive")))

    # Credential disclosure through the login action feeds API2.
    model.fact("exposes", (ACTION_LOGIN, WITNESS_TOKEN))
    model.fact("observes", (ATTACKER, WITNESS_TOKEN))
    model.fact("targets", (ACTION_LOGIN, RESOURCE_AUTH))

    # D: availability norm without reachability.
    model.fact("required", (ATTACKER, RESOURCE_SERVICE))
    model.fact("has", (RESOURCE_SERVICE, atom("unbounded")))

    # E: unauthorized executions across the corpus actions.
    for action in (
        ACTION_BOLA,
        ACTION_ADMIN,
        ACTION_CALL,
        ACTION_OLD,
        ACTION_CONSUME,
        ACTION_DEPLOY,
    ):
        model.fact("executes", (ATTACKER, action))
        model.fact("targets", (action, RESOURCE_SECRET))
    model.fact("causes", (ACTION_CONSUME, changed(RESOURCE_SECRET, atom("payload"))))
    model.fact("causes", (ACTION_DEPLOY, changed(RESOURCE_SECRET, atom("payload"))))

    # API1: object-reference input on a foreign-owned resource.
    model.fact("has", (BOLA_INPUT, atom("object_ref")))
    model.fact("targets", (ACTION_BOLA, RESOURCE_FOREIGN))
    model.fact("owner", (RESOURCE_FOREIGN, VICTIM))

    # API5 / API9 structural kinds.
    model.fact("is", (ACTION_ADMIN, atom("function")))
    model.fact("is", (ACTION_OLD, atom("deprecated")))

    # API7 / A10: outbound call into the external network.
    model.fact("causes", (ACTION_CALL, external_call(ACTION_CALL, MARKER_EXTERNAL)))
    model.fact("is", (MARKER_EXTERNAL, atom("external_net")))

    for fact in extra or ():
        model._facts.append(fact)  # noqa: SLF001 - test builder
    return model.build()


def solve_atoms(graph: QdlGraph) -> set[str]:
    solutions = ClingoEngine().solve(graph, algebra=True)
    assert len(solutions) == 1
    return set(solutions[0].atoms)


def derived(atoms: set[str], name: str) -> set[str]:
    return {item for item in atoms if item.startswith(f"{name}(")}


LETTERS = (
    "spoofing",
    "tampering",
    "repudiation",
    "disclosure",
    "denial",
    "elevation",
)

CORPUS = (
    "owasp_api1_bola",
    "owasp_api2_broken_auth",
    "owasp_api3_mass_assignment",
    "owasp_api4_resource_consumption",
    "owasp_api5_function_authz",
    "owasp_api6_business_flows",
    "owasp_api7_ssrf",
    "owasp_api8_misconfig",
    "owasp_api9_inventory",
    "owasp_api10_unsafe_consumption",
    "owasp_a01_access_control",
    "owasp_a02_crypto",
    "owasp_a03_injection",
    "owasp_a05_misconfig",
    "owasp_a06_components",
    "owasp_a07_auth",
    "owasp_a08_integrity",
    "owasp_a09_logging",
    "owasp_a10_ssrf",
)


def test_all_letters_derive() -> None:
    atoms = solve_atoms(make_model())
    for letter in LETTERS:
        assert derived(atoms, letter), f"letter did not derive: {letter}"


def test_full_owasp_corpus_derives() -> None:
    atoms = solve_atoms(make_model())
    for name in CORPUS:
        assert derived(atoms, name), f"corpus class did not derive: {name}"


def test_spoofing_requires_broken_binding() -> None:
    atoms = solve_atoms(
        make_model(extra=[_extra_fact("binds", (WITNESS_TOKEN, VICTIM))])
    )
    assert not derived(atoms, "spoofing")
    # The spoofing disjunct disappears; the credential-disclosure disjunct
    # through action:login legitimately remains.
    assert not {
        item
        for item in derived(atoms, "owasp_api2_broken_auth")
        if '"action:auth"' in item
    }
    assert not derived(atoms, "owasp_a07_auth")


def test_tampering_requires_missing_permission() -> None:
    atoms = solve_atoms(
        make_model(
            extra=[_extra_fact("may", (ATTACKER, ACTION_UPDATE, RESOURCE_SECRET))]
        )
    )
    assert 'tampering("action:update","subject:attacker")' not in atoms
    assert not derived(atoms, "owasp_api3_mass_assignment")
    assert not derived(atoms, "owasp_a03_injection")


def test_repudiation_requires_audit_trail() -> None:
    atoms = solve_atoms(
        make_model(extra=[_extra_fact("observes", (AUDITOR, FLOW_TRACE))])
    )
    assert not {
        item for item in derived(atoms, "repudiation") if '"action:flow"' in item
    }


def test_disclosure_requires_missing_permission() -> None:
    atoms = solve_atoms(
        make_model(extra=[_extra_fact("may", (ATTACKER, ACTION_GET, RESOURCE_SECRET))])
    )
    assert not {item for item in derived(atoms, "disclosure") if '"action:get"' in item}
    assert not derived(atoms, "owasp_api8_misconfig")


def test_denial_requires_unreachable_resource() -> None:
    atoms = solve_atoms(
        make_model(extra=[_extra_fact("reaches", (ATTACKER, RESOURCE_SERVICE))])
    )
    assert not derived(atoms, "denial")
    assert not derived(atoms, "owasp_api4_resource_consumption")


def test_elevation_requires_missing_permission() -> None:
    atoms = solve_atoms(
        make_model(extra=[_extra_fact("may", (ATTACKER, ACTION_GET, RESOURCE_SECRET))])
    )
    assert not {item for item in derived(atoms, "elevation") if '"action:get"' in item}


def test_bola_requires_foreign_owner() -> None:
    graph = make_model()
    facts = tuple(
        fact
        for fact in graph.facts
        if not (
            fact.predicate.name == "owner" and fact.args == (RESOURCE_FOREIGN, VICTIM)
        )
    ) + (_extra_fact("owner", (RESOURCE_FOREIGN, ATTACKER)),)
    atoms = solve_atoms(QdlGraph(facts=facts))
    # The attacker owns the target: no BOLA even though elevation holds.
    assert derived(atoms, "elevation")
    assert not derived(atoms, "owasp_api1_bola")


def test_injection_requires_interpreter_sink() -> None:
    graph = make_model()
    facts = tuple(
        fact
        for fact in graph.facts
        if not (
            fact.predicate.name == "is" and fact.args == (SINK_SQL, atom("interpreter"))
        )
    )
    atoms = solve_atoms(QdlGraph(facts=facts))
    assert not derived(atoms, "owasp_a03_injection")


def make_cycle_graph() -> QdlGraph:
    model = ModelBuilder()
    for name in ("node:a", "node:b", "node:c"):
        model.entity(atom(name), "Node")
    model.fact("reaches", (atom("node:a"), atom("node:b")))
    model.fact("reaches", (atom("node:b"), atom("node:a")))
    model.fact("reaches", (atom("node:b"), atom("node:c")))
    return model.build()


def test_transitive_closure_terminates_on_cycles() -> None:
    solutions = ClingoEngine().solve(make_cycle_graph(), closures="reaches_plus")
    atoms = set(solutions[0].atoms)
    expected = {
        'reaches_plus("contract","node:a","node:b")',
        'reaches_plus("contract","node:a","node:a")',
        'reaches_plus("contract","node:a","node:c")',
        'reaches_plus("contract","node:b","node:a")',
        'reaches_plus("contract","node:b","node:b")',
        'reaches_plus("contract","node:b","node:c")',
    }
    assert expected <= atoms


def test_part_closure_is_reflexive_for_declared_resources() -> None:
    model = ModelBuilder()
    model.entity(atom("resource:direct"), "Resource")

    solution = ClingoEngine().solve(model.build(), closures="part_plus")[0]

    assert solution.contains(
        'part_plus("contract","resource:direct","resource:direct")'
    )


def test_transitive_closure_is_transitive_and_idempotent() -> None:
    engine = ClingoEngine()
    program = engine.compile(make_cycle_graph(), closures="reaches_plus")
    program += (
        "reaches_plus2(C,X,Y) :- reaches_plus(C,X,Y).\n"
        "reaches_plus2(C,X,Z) :- "
        "reaches_plus(C,X,Y), reaches_plus2(C,Y,Z).\n"
    )
    control = clingo.Control()
    control.add("base", [], program)
    control.ground([("base", [])])
    atoms: set[str] = set()
    with control.solve(yield_=True) as handle:
        for solution in handle:
            atoms = {str(symbol) for symbol in solution.symbols(atoms=True)}
            break
    first = {item for item in atoms if item.startswith("reaches_plus(")}
    second = {item for item in atoms if item.startswith("reaches_plus2(")}
    assert first
    first_args = {item[len("reaches_plus") :] for item in first}
    second_args = {item[len("reaches_plus2") :] for item in second}
    assert first_args == second_args


def test_algebra_program_is_stratified_with_recursive_closure() -> None:
    # A grounding that succeeds proves stratification: Clingo rejects
    # programs whose recursion passes through negation.
    cycle = make_cycle_graph()
    model = ModelBuilder()
    model._facts.extend(cycle.facts)  # noqa: SLF001 - test builder
    model.fact("required", (atom("node:a"), atom("node:c")))
    atoms = solve_atoms(model.build())
    assert not derived(atoms, "denial")


def test_find_path_supports_reaches_relation() -> None:
    path = ClingoEngine().find_path(
        make_cycle_graph(),
        "reaches",
        "node:a",
        "node:c",
    )
    assert path == ("node:a", "node:b", "node:c")


def make_iam_model(
    *, permission_resource_type: str = "resource:lockbox.secret"
) -> QdlGraph:
    """A miniature IAM world: one attacker, one authorized victim."""
    model = ModelBuilder()
    model.fact("is", (atom("action:get"), atom("Action")))
    model.fact("is", (atom("action:list"), atom("Action")))
    model.fact("is", (atom("principal:attacker"), atom("Subject")))
    model.fact("is", (atom("principal:victim"), atom("Subject")))
    model.fact("is", (atom("role:user"), atom("Role")))
    model.fact("is", (atom("role:org-admin"), atom("Role")))
    model.fact("is", (atom("organization:o1"), atom("Scope")))
    model.fact("is", (atom("folder:f1"), atom("Scope")))
    model.fact("is", (atom("resource:secret-1"), atom("Resource")))
    model.fact("is", (atom("resource:secret-1"), atom("resource:lockbox.secret")))
    model.fact("is", (atom("permission:p1"), atom("Permission")))
    model.fact("is", (atom("resource:lockbox.secret"), atom("ResourceType")))
    if permission_resource_type != "resource:lockbox.secret":
        model.fact("is", (atom(permission_resource_type), atom("ResourceType")))
    model.fact("requires", (atom("action:get"), atom("permission:p1")))
    model.fact("requires", (atom("action:list"), atom("permission:p1")))
    model.fact("grants", (atom("role:user"), atom("permission:p1")))
    model.fact(
        "applies_to",
        (atom("permission:p1"), atom(permission_resource_type)),
    )
    model.fact("targets", (atom("action:get"), atom("resource:lockbox.secret")))
    model.fact("targets", (atom("action:list"), atom("resource:lockbox.secret")))
    model.fact("part", (atom("resource:secret-1"), atom("folder:f1")))
    # The attacker holds an unrelated org role; the victim holds
    # role:user directly on the folder containing the secret.
    model.fact(
        "binding",
        (
            atom("principal:attacker"),
            atom("role:org-admin"),
            atom("organization:o1"),
        ),
    )
    model.fact(
        "binding",
        (atom("principal:victim"), atom("role:user"), atom("folder:f1")),
    )
    model.fact("attacker", (atom("principal:attacker"),))
    return model.build()


def test_iam_model_derives_may_from_bindings() -> None:
    atoms = solve_atoms(make_iam_model())
    derived_may = {a for a in atoms if a.startswith("may(")}

    assert (
        'may("contract","principal:victim","action:get","resource:secret-1")'
        in derived_may
    )
    assert not any('"principal:attacker"' in a for a in derived_may)


def test_may_requires_permission_to_apply_to_target_resource_type() -> None:
    atoms = solve_atoms(make_iam_model(permission_resource_type="resource:other"))
    derived_may = {a for a in atoms if a.startswith("may(")}

    assert not any('"principal:victim"' in a for a in derived_may)


def test_on_resource_binding_derives_may_without_containment_edge() -> None:
    model = ModelBuilder()
    model.fact("is", (atom("action:get"), atom("Action")))
    model.fact("is", (atom("principal:victim"), atom("Subject")))
    model.fact("is", (atom("role:user"), atom("Role")))
    model.fact("is", (atom("resource:secret-1"), atom("Resource")))
    model.fact("is", (atom("resource:secret-1"), atom("resource:lockbox.secret")))
    model.fact("is", (atom("permission:p1"), atom("Permission")))
    model.fact("is", (atom("resource:lockbox.secret"), atom("ResourceType")))
    model.fact("requires", (atom("action:get"), atom("permission:p1")))
    model.fact("grants", (atom("role:user"), atom("permission:p1")))
    model.fact(
        "applies_to",
        (atom("permission:p1"), atom("resource:lockbox.secret")),
    )
    model.fact("targets", (atom("action:get"), atom("resource:lockbox.secret")))
    model.fact(
        "binding",
        (
            atom("principal:victim"),
            atom("role:user"),
            atom("resource:secret-1"),
        ),
    )
    model.fact("attacker", (atom("principal:victim"),))

    atoms = solve_atoms(model.build())

    assert (
        'may("contract","principal:victim","action:get","resource:secret-1")' in atoms
    )


def test_threat_hypothesis_derives_elevation_for_attacker_only() -> None:
    atoms = solve_atoms(make_iam_model())
    elevations = {a for a in atoms if a.startswith("elevation(")}

    assert 'elevation("principal:attacker","action:get")' in elevations
    assert 'elevation("principal:attacker","action:list")' in elevations
    assert not any('"principal:victim"' in a for a in elevations)


def test_threat_hypothesis_executes_every_action() -> None:
    atoms = solve_atoms(make_iam_model())
    executes = {a for a in atoms if a.startswith("executes(")}

    assert 'executes("contract","principal:attacker","action:get")' in executes
    assert 'executes("contract","principal:attacker","action:list")' in executes
    assert not any('"principal:victim"' in a for a in executes)
