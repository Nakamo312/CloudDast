"""Executable subject, role and resource binding comes only from QDL facts."""

from __future__ import annotations

import pytest

from cloud_dast.contracts.assessment import BindingDeficit
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
    VerificationPlan,
)
from cloud_dast.model import (
    BindingRef,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    PrincipalRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.field_roles import (
    OBJECT_REF_ROLE,
    FieldRolePolicy,
    resolve_field_roles,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    input_field,
)
from cloud_dast.qdl.reasoning import (
    QdlForbiddenPath,
    QdlStatePath,
    compile_probe_fields,
)
from cloud_dast.runtime.execution.binding import bind_forbidden_path
from cloud_dast.runtime.execution.metadata import decorate as _decorate_execution_paths
from cloud_dast.runtime.execution.view import (
    missing_reference_deficits as _missing_reference_deficits,
)
from cloud_dast.runtime.reference_projection import (
    fields_with_role_by_action,
    principal_refs_from_targets,
    refers_to_targets_by_action,
    typed_object_refs,
)
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast_fuzzing import TemplateGenerator

ACTION = "action:svc.set-bindings"


def _fact(
    name: str,
    args: tuple[object, ...],
    *,
    context: Context = Context.ACCEPTED,
) -> Fact:
    schema = next(
        (schema for schema in EXTENSION_PREDICATE_SCHEMAS if schema.name == name),
        None,
    )
    predicate = Predicate.from_schema(schema) if schema else Predicate.from_name(name)
    return Fact(context=context, predicate=predicate, args=args)  # type: ignore[arg-type]


def _field(name: str) -> Struct:
    return input_field(Atom(value=ACTION), Atom(value=name))


def _role_fact(field_name: str, role: str) -> Fact:
    return _fact("has", (_field(field_name), Atom(value=role)))


def _refers_to(field_name: str, target: str) -> Fact:
    return _fact("refers_to", (_field(field_name), Atom(value=target)))


def _build_graph(*facts: Fact, declarations: tuple[Fact, ...] = ()) -> QdlGraph:
    fields = {
        fact.args[0]
        for fact in facts
        if fact.predicate.name in {"has", "refers_to"}
        and isinstance(fact.args[0], Struct)
        and fact.args[0].name == "input_field"
    }
    graph_facts = (
        _fact("is", (Atom(value=ACTION), Atom(value="Action"))),
        # Every bound campaign carries the attacker hypothesis: the
        # binder adds it for the request principal before planning.
        _subject_declaration("attacker"),
        _fact("attacker", (Atom(value="principal:attacker"),)),
        *(_fact("is", (field, Atom(value="InputField"))) for field in fields),
        *declarations,
        *facts,
    )
    seen: set[str] = set()
    unique: list[Fact] = []
    for fact in graph_facts:
        key = fact.model_dump_json()
        if key in seen:
            continue
        seen.add(key)
        unique.append(fact)
    return QdlGraph(facts=tuple(unique))


@pytest.mark.parametrize(
    "case, targets, reason, kind, context",
    (
        (
            "method",
            ("done",),
            "contract_method_missing",
            "method_missing",
            (("state", "start"),),
        ),
        (
            "scenario",
            ("done",),
            "contract_scenario_missing",
            "scenario_missing",
            (("state", "start"),),
        ),
        (
            "transition",
            (),
            "forbidden_transition_missing",
            "forbidden_transition_missing",
            (("from_state", "start"),),
        ),
        (
            "ambiguous",
            ("done", "other"),
            "ambiguous_forbidden_transition",
            "ambiguous_forbidden_transition",
            (("from_state", "start"), ("target_count", "2")),
        ),
        (
            "final",
            ("other",),
            "forbidden_transition_missing",
            "forbidden_transition_missing",
            (
                ("from_state", "start"),
                ("to_state", "other"),
                ("expected_state", "done"),
            ),
        ),
    ),
)
def test_forbidden_binding_preserves_failure_diagnostics(
    case, targets, reason, kind, context
):
    forbidden = QdlForbiddenPath(
        "forbidden",
        "norm",
        QdlStatePath("state-path", Context.ACCEPTED, "start", "done", (ACTION,)),
    )
    diagnostics = []
    result = bind_forbidden_path(
        forbidden,
        transitions={(ACTION, "start"): targets},
        methods_by_action={} if case == "method" else {ACTION: _method()},
        scenarios_by_action={} if case == "scenario" else {ACTION: _scenario()},
        record_deficit=lambda **details: diagnostics.append(details),
    )

    assert result is None
    assert diagnostics == [
        {
            "action": ACTION,
            "reason": reason,
            "kind": kind,
            "context": (
                ("coverage", "forbidden_path"),
                ("path_id", "forbidden"),
                *context,
            ),
        }
    ]


def _typed_refs(graph: QdlGraph) -> dict[str, tuple[tuple[str, str], ...]]:
    return typed_object_refs(
        refers_to_targets_by_action(graph), resolve_field_roles(graph)
    )


def _subject_declaration(principal: str) -> Fact:
    return _fact("is", (Atom(value=f"principal:{principal}"), Atom(value="Subject")))


def _method(*fields: str) -> MethodSpec:
    return MethodSpec(
        method_id="svc.set-bindings",
        service="svc",
        name="SetBindings",
        layer=EndpointLayer.PUBLIC,
        resource_types=frozenset({"svc.binding"}),
        fields=tuple(
            FieldSpec(name=field, type="string", required=True) for field in fields
        ),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario:binding",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            principals=(
                PrincipalRef(principal_id="victim", principal_type="user"),
                PrincipalRef(principal_id="attacker", principal_type="user"),
            ),
            bindings=(
                BindingRef(principal_id="victim", role="viewer"),
                BindingRef(principal_id="attacker", role="editor"),
            ),
            permissions_known=True,
        ),
    )


def _step(method: MethodSpec, scenario: ScenarioPosition) -> QdlExecutionStep:
    invariant = InvariantProjection(
        invariant_id="invariant:binding",
        norm_id="norm:binding",
        statement="binding norm",
        severity=Severity.HIGH,
    )
    return QdlExecutionStep(
        step_id="step:binding",
        goal_id="goal:binding",
        plan=VerificationPlan(
            plan_id="plan:binding",
            invariant_id=invariant.invariant_id,
            method_id=method.method_id,
            scenario_id=scenario.scenario_id,
        ),
        method=method,
        scenario=scenario,
        invariant=invariant,
    )


def _bound_step(graph: QdlGraph, method: MethodSpec) -> QdlExecutionStep:
    scenario = _scenario()
    methods_by_action = {
        method.method_id: method,
        f"action:{method.method_id}": method,
    }
    paths = _decorate_execution_paths(
        [_path(_step(method, scenario))],
        graph,
        methods_by_action,
        probe_fields=compile_probe_fields(graph),
    )
    return paths[0].steps[0]


def _path(step: QdlExecutionStep) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id="path:binding",
        goal_id="goal:binding",
        kind="invariant",
        description="reference binding path",
        steps=(step,),
    )


def _check(step: QdlExecutionStep) -> dict[str, object]:
    check = TemplateGenerator().generate(
        step.plan,
        step.method,
        step.invariant,
        step.scenario,
    )[0]
    return dict(check.request)


def test_subject_and_role_reference_facts_bind_referred_entities() -> None:
    graph = _build_graph(
        _role_fact("subject_id", "subject_ref"),
        _role_fact("role_id", "role_ref"),
        _refers_to("subject_id", "principal:attacker"),
        _refers_to("role_id", "principal:attacker"),
        declarations=(_subject_declaration("attacker"),),
    )
    step = _bound_step(graph, _method("subject_id", "role_id"))

    assert step.plan.subject_params == ("subject_id",)
    assert step.plan.subject_refs == (("subject_id", "attacker"),)
    assert step.plan.role_params == ("role_id",)
    assert step.plan.role_refs == (("role_id", "attacker"),)

    # The refers_to fact selects the subject: the first stand principal
    # ("victim") must not win by position.
    values = _check(step)
    assert values["subject_id"] == "attacker"
    assert values["role_id"] == "editor"


def test_role_fact_without_refers_to_keeps_field_unresolved() -> None:
    graph = _build_graph(_role_fact("subject_id", "subject_ref"))
    step = _bound_step(graph, _method("subject_id"))

    assert step.plan.subject_params == ("subject_id",)
    assert step.plan.subject_refs == ()
    assert _check(step)["subject_id"] is None


def test_role_fact_without_refers_to_reports_binding_deficit() -> None:
    graph = _build_graph(
        _role_fact("subject_id", "subject_ref"),
        _role_fact("role_id", "role_ref"),
    )
    method = _method("subject_id", "role_id")
    step = _bound_step(graph, method)
    view = QdlExecutionView(
        graph_hash="hash",
        paths=(_path(step),),
        invariants={},
    )

    assert _missing_reference_deficits(view) == (
        BindingDeficit(
            action=method.method_id,
            reason="missing_refers_to",
            context=(("field", "subject_id"),),
        ),
        BindingDeficit(
            action=method.method_id,
            reason="missing_refers_to",
            context=(("field", "role_id"),),
        ),
    )


def test_refers_to_without_role_fact_never_binds() -> None:
    graph = _build_graph(
        _refers_to("subject_id", "principal:attacker"),
        declarations=(_subject_declaration("attacker"),),
    )
    step = _bound_step(graph, _method("subject_id"))

    assert step.plan.subject_params == ()
    assert step.plan.subject_refs == ()
    assert _check(step)["subject_id"] is None


def test_principal_reference_is_not_a_resource_type() -> None:
    graph = _build_graph(
        # Canonical typed_object_ref control (S23 / plan 6.6): the resource
        # reference carries both the object_ref role and refers_to, while the
        # principal reference stays in the principal namespace.
        _role_fact("secret_id", "object_ref"),
        _refers_to("subject_id", "principal:attacker"),
        _refers_to("secret_id", "lockbox.secret"),
        declarations=(
            _subject_declaration("attacker"),
            _fact("is", (Atom(value="lockbox.secret"), Atom(value="ResourceType"))),
        ),
    )

    assert _typed_refs(graph) == {
        ACTION: (("secret_id", "lockbox.secret"),),
    }
    assert principal_refs_from_targets(refers_to_targets_by_action(graph)) == {
        ACTION: (("subject_id", "attacker"),),
    }


def test_superseded_object_ref_fact_is_not_executable() -> None:
    holder = _field("target")
    old_node = Struct(name="replacement", args=(holder, Atom(value="object_ref")))
    new_node = Struct(name="replacement", args=(holder, Atom(value="setup_skip")))
    graph = _build_graph(
        _role_fact("target", "object_ref"),
        _role_fact("target", "setup_skip"),
        _fact("supersedes", (new_node, old_node)),
        declarations=(
            _fact("is", (old_node, Atom(value="Node"))),
            _fact("is", (new_node, Atom(value="Node"))),
            _fact("is", (Atom(value="object_ref"), Atom(value="Role"))),
            _fact("is", (Atom(value="setup_skip"), Atom(value="Role"))),
        ),
    )

    assert fields_with_role_by_action(resolve_field_roles(graph), OBJECT_REF_ROLE) == {}


@pytest.mark.parametrize("context", tuple(Context))
def test_typed_references_require_executable_input_roles(context: Context) -> None:
    graph = _build_graph(
        _fact("has", (_field("target"), Atom(value="object_ref")), context=context),
        _refers_to("target", "resource:svc.item"),
        _fact(
            "has",
            (
                Struct(
                    name="output_field", args=(Atom(value=ACTION), Atom(value="output"))
                ),
                Atom(value="object_ref"),
            ),
        ),
        _refers_to("output", "resource:svc.item"),
        _role_fact("principal", "object_ref"),
        _refers_to("principal", "principal:attacker"),
        _refers_to("untyped", "resource:svc.item"),
        declarations=(
            _fact("is", (Atom(value="resource:svc.item"), Atom(value="ResourceType"))),
            _fact(
                "is",
                (
                    Struct(
                        name="output_field",
                        args=(Atom(value=ACTION), Atom(value="output")),
                    ),
                    Atom(value="OutputField"),
                ),
            ),
        ),
    )

    expected = (
        {ACTION: (("target", "svc.item"),)}
        if context in {Context.CONTRACT, Context.ACCEPTED}
        else {}
    )
    assert _typed_refs(graph) == expected


def test_typed_references_exclude_ambiguity_and_sort_fields() -> None:
    graph = _build_graph(
        *(_role_fact(name, "object_ref") for name in ("z", "a", "ambiguous")),
        _refers_to("z", "resource:svc.z"),
        _refers_to("a", "svc.a"),
        _refers_to("ambiguous", "resource:svc.a"),
        _refers_to("ambiguous", "resource:svc.z"),
        declarations=tuple(
            _fact("is", (Atom(value=name), Atom(value="ResourceType")))
            for name in ("resource:svc.z", "svc.a", "resource:svc.a")
        ),
    )

    assert _typed_refs(graph) == {
        ACTION: (("a", "svc.a"), ("z", "svc.z")),
    }


def test_typed_references_preserve_projected_order_and_omit_empty_actions() -> None:
    roles = FieldRolePolicy(
        roles_by_field={
            ("input", ACTION, field): frozenset({OBJECT_REF_ROLE})
            for field in ("z", "a")
        }
    )
    targets = {
        ACTION: (("z", "resource:svc.z"), ("a", "svc.a")),
        "action:empty": (),
        "action:untyped": (("id", "svc.item"),),
    }

    assert typed_object_refs(targets, roles) == {
        ACTION: (("z", "svc.z"), ("a", "svc.a")),
    }
