from __future__ import annotations

import math

import pytest
import z3

import cloud_dast_symbolic.solver as symbolic_module
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.couplings import FieldCoupling
from cloud_dast.model import (
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    input_field,
    output_field,
    reached,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_symbolic.solver import (
    FieldValueConstraint,
    Z3Limits,
    Z3SymbolicGenerator,
    _constraints,
    _model_value,
    _variable,
    solve_request,
    solve_sequence,
)


class StaticBase:
    def __init__(self, request):
        self._request = request

    def generate(self, plan, method, invariant, scenario, *, feedback=None):
        del plan, method, invariant, scenario, feedback
        return (
            Check(
                invariant_id="inv",
                method_id="get",
                scenario_id="scenario",
                request=self._request,
                identities=("attacker",),
            ),
        )


def method(fields):
    return MethodSpec(
        method_id="get",
        service="service",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=fields,
    )


def scenario():
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def invariant(effect=None):
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="norm",
        severity=Severity.HIGH,
        norm_fact=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(Atom(value="norm:inv"), effect),
            )
            if effect is not None
            else None
        ),
    )


def plan(method_spec):
    return VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id=method_spec.method_id,
        scenario_id="scenario",
    )


def _input(action: str, name: str):
    return input_field(Atom(value=action), Atom(value=name))


def same_method_coupling(left: str, right: str, operator: str):
    return FieldCoupling(
        left=_input("get", left),
        right=_input("get", right),
        operator=operator,
    )


def test_z3_limits_reject_non_positive_values() -> None:
    with pytest.raises(ValueError, match="timeout_ms must be positive"):
        Z3Limits(timeout_ms=0)
    with pytest.raises(ValueError, match="max_memory_mb must be positive"):
        Z3Limits(max_memory_mb=0)


def test_symbolic_generator_applies_z3_limits(monkeypatch) -> None:
    solvers = []

    class UnknownSolver:
        def __init__(self):
            self.settings = []
            solvers.append(self)

        def set(self, name, value):
            self.settings.append((name, value))

        def add(self, *constraints):
            del constraints

        def check(self):
            return z3.unknown

    monkeypatch.setattr(symbolic_module.z3, "Solver", UnknownSolver)
    method_spec = method((FieldSpec(name="limit", type="int32", required=True),))
    seed = StaticBase((("limit", 1),)).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]

    candidate = Z3SymbolicGenerator(
        StaticBase((("limit", 1),)),
        limits=Z3Limits(timeout_ms=123, max_memory_mb=456),
    ).build_seed(seed, method_spec, invariant())

    assert candidate.solver_status == "unknown"
    assert solvers[0].settings == [("timeout", 123), ("max_memory", 456)]


def test_constraints_include_integer_type_range() -> None:
    variable = z3.Int("value")
    field = FieldSpec(name="value", type="uint32", required=True)

    constraints = _constraints(variable, field)

    assert [str(constraint) for constraint in constraints] == [
        "value >= 0",
        "value <= 4294967295",
    ]


def test_constraints_include_float_type_range() -> None:
    variable = z3.FP("value", z3.Float32())
    field = FieldSpec(name="value", type="float", required=True)

    constraints = _constraints(variable, field)

    assert [constraint.sexpr() for constraint in constraints] == [
        (variable >= z3.FPVal(-3.4028234663852886e38, z3.Float32())).sexpr(),
        (variable <= z3.FPVal(3.4028234663852886e38, z3.Float32())).sexpr(),
    ]


def test_float_variable_uses_ieee_sort() -> None:
    float_field = FieldSpec(name="single", type="float", required=True)
    double_field = FieldSpec(name="double", type="double", required=True)

    assert _variable("single", float_field).sort() == z3.Float32()
    assert _variable("double", double_field).sort() == z3.Float64()


def test_symbolic_generator_solves_numeric_alternative():
    fields = (
        FieldSpec(name="limit", type="int32", required=True, minimum=1, maximum=10),
    )
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("limit", 1),)))
    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    assert dict(check.request)["limit"] != 1
    assert 1 <= dict(check.request)["limit"] <= 10
    assert check.generator == "symbolic"


def test_symbolic_generator_solves_repeated_numeric_alternative():
    fields = (
        FieldSpec(
            name="limits",
            type="int32",
            required=True,
            repeated=True,
            minimum=1,
            maximum=10,
        ),
    )
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("limits", (1, 1)),)))

    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    values = dict(check.request)["limits"]
    assert isinstance(values, tuple)
    assert len(values) == 2
    assert values != (1, 1)
    assert all(1 <= value <= 10 for value in values)


def test_symbolic_generator_solves_finite_float_alternative():
    fields = (FieldSpec(name="ratio", type="float", required=True),)
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("ratio", 0.0),)))

    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    value = dict(check.request)["ratio"]
    assert isinstance(value, float)
    assert math.isfinite(value)
    assert abs(value) <= 3.4028234663852886e38


def test_symbolic_generator_solves_enum_alternative():
    fields = (
        FieldSpec(
            name="mode",
            type="string",
            required=True,
            enum_values=("read", "write", "admin"),
        ),
    )
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("mode", "read"),)))
    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    assert dict(check.request)["mode"] in {"write", "admin"}


def test_symbolic_generator_solves_boolean_alternative():
    fields = (FieldSpec(name="verbose", type="bool", required=True),)
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("verbose", False),)))
    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    assert dict(check.request)["verbose"] is True


def test_symbolic_generator_uses_fallback_when_distinct_value_is_impossible():
    fields = (
        FieldSpec(name="limit", type="int32", required=True, minimum=1, maximum=1),
    )
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("limit", 1),)))
    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    assert dict(check.request)["limit"] == 1


def test_symbolic_generator_leaves_marker_payload_to_decorator():
    fields = (FieldSpec(name="template", type="string", required=True),)
    method_spec = method(fields)
    effect = reached(Atom(value="get"), Atom(value="marker-42"))
    generator = Z3SymbolicGenerator(StaticBase((("template", "seed"),)))
    check = generator.generate(
        plan(method_spec), method_spec, invariant(effect), scenario()
    )[0]

    assert dict(check.request)["template"] == "seed"


def test_symbolic_generator_marks_non_symbolic_seed():
    fields = (FieldSpec(name="name", type="string", required=True),)
    method_spec = method(fields)
    generator = Z3SymbolicGenerator(StaticBase((("name", "seed"),)))
    check = generator.generate(plan(method_spec), method_spec, invariant(), scenario())[
        0
    ]

    assert dict(check.request)["name"] == "seed"
    assert check.generator == "symbolic"


def test_symbolic_generator_enforces_enum_equality_coupling():
    fields = (
        FieldSpec(
            name="source_mode",
            type="string",
            required=True,
            enum_values=("read", "write"),
        ),
        FieldSpec(
            name="target_mode",
            type="string",
            required=True,
            enum_values=("read", "write"),
        ),
    )
    method_spec = method(fields)
    base = StaticBase((("source_mode", "read"), ("target_mode", "write")))
    generator = Z3SymbolicGenerator(base)
    seed = base.generate(plan(method_spec), method_spec, invariant(), scenario())[0]
    check = generator.build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("source_mode", "target_mode", "eq"),),
    ).check

    values = dict(check.request)
    assert values["source_mode"] == values["target_mode"]


def test_symbolic_generator_enforces_numeric_order_coupling():
    fields = (
        FieldSpec(name="from", type="int32", required=True, minimum=0, maximum=10),
        FieldSpec(name="to", type="int32", required=True, minimum=0, maximum=10),
    )
    method_spec = method(fields)
    seed = StaticBase((("from", 5), ("to", 5))).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]
    candidate = Z3SymbolicGenerator(StaticBase((("from", 5), ("to", 5)))).build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("from", "to", "lt"),),
    )

    values = dict(candidate.check.request)
    assert values["from"] < values["to"]


def test_symbolic_generator_couples_string_fields():
    fields = (
        FieldSpec(name="name", type="string", required=True),
        FieldSpec(name="confirm_name", type="string", required=True),
    )
    method_spec = method(fields)
    seed = StaticBase((("name", "first"), ("confirm_name", "second"))).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]
    candidate = Z3SymbolicGenerator(
        StaticBase((("name", "first"), ("confirm_name", "second")))
    ).build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("name", "confirm_name", "eq"),),
    )

    values = dict(candidate.check.request)
    assert values["name"] == values["confirm_name"]


def test_symbolic_generator_couples_repeated_fields_elementwise():
    fields = (
        FieldSpec(
            name="source_ids",
            type="int32",
            required=True,
            repeated=True,
        ),
        FieldSpec(
            name="target_ids",
            type="int32",
            required=True,
            repeated=True,
        ),
    )
    method_spec = method(fields)
    base = StaticBase((("source_ids", (1, 2)), ("target_ids", (3, 4))))
    seed = base.generate(plan(method_spec), method_spec, invariant(), scenario())[0]

    candidate = Z3SymbolicGenerator(base).build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("source_ids", "target_ids", "eq"),),
    )

    values = dict(candidate.check.request)
    assert values["source_ids"] == values["target_ids"]
    assert candidate.dropped_couplings is False


def test_symbolic_generator_drops_differently_sized_repeated_coupling():
    fields = (
        FieldSpec(name="source_ids", type="int32", required=True, repeated=True),
        FieldSpec(name="target_ids", type="int32", required=True, repeated=True),
    )
    method_spec = method(fields)
    base = StaticBase((("source_ids", (1, 2)), ("target_ids", (3,))))
    seed = base.generate(plan(method_spec), method_spec, invariant(), scenario())[0]

    candidate = Z3SymbolicGenerator(base).build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("source_ids", "target_ids", "eq"),),
    )

    assert candidate.solver_status == "deferred"
    assert candidate.dropped_couplings is True


def test_symbolic_generator_flags_incompatible_coupling():
    fields = (
        FieldSpec(name="count", type="int32", required=True),
        FieldSpec(name="name", type="string", required=True),
    )
    method_spec = method(fields)
    base = StaticBase((("count", 1), ("name", "seed")))
    seed = base.generate(plan(method_spec), method_spec, invariant(), scenario())[0]

    candidate = Z3SymbolicGenerator(base).build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("count", "name", "eq"),),
    )

    assert candidate.solver_status == "deferred"
    assert candidate.dropped_couplings is True


def test_solve_sequence_binds_coupled_values_across_calls():
    from cloud_dast.couplings import FieldCoupling
    from cloud_dast_symbolic import solve_sequence

    add = MethodSpec(
        method_id="add",
        service="service",
        name="Add",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="cName", type="string", required=True),),
    )
    remove = MethodSpec(
        method_id="remove",
        service="service",
        name="Remove",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="cName", type="string", required=True),),
    )
    seeds = (
        Check(
            invariant_id="inv",
            method_id="add",
            scenario_id="scenario",
            request=(("cName", "seed-add"),),
            identities=("attacker",),
        ),
        Check(
            invariant_id="inv",
            method_id="remove",
            scenario_id="scenario",
            request=(("cName", "seed-remove"),),
            identities=("attacker",),
        ),
    )

    solution = solve_sequence(
        seeds,
        {"add": add, "remove": remove},
        (
            FieldCoupling(
                left=_input("action:add", "cName"),
                right=_input("action:remove", "cName"),
                operator="eq",
            ),
        ),
    )

    assert solution.status == "sat"
    add_name = dict(solution.checks[0].request)["cName"]
    remove_name = dict(solution.checks[1].request)["cName"]
    assert add_name == remove_name
    assert add_name not in {"seed-add", "seed-remove"}


def test_solve_sequence_reports_unsat_for_contradiction():
    from cloud_dast.couplings import FieldCoupling
    from cloud_dast_symbolic import solve_sequence

    add = MethodSpec(
        method_id="add",
        service="service",
        name="Add",
        layer=EndpointLayer.PRIVATE,
        fields=(
            FieldSpec(name="from", type="int32", required=True),
            FieldSpec(name="to", type="int32", required=True),
        ),
    )
    seeds = (
        Check(
            invariant_id="inv",
            method_id="add",
            scenario_id="scenario",
            request=(("from", 1), ("to", 2)),
            identities=("attacker",),
        ),
    )

    solution = solve_sequence(
        seeds,
        {"add": add},
        (
            FieldCoupling(
                left=_input("action:add", "from"),
                right=_input("action:add", "to"),
                operator="gt",
            ),
            FieldCoupling(
                left=_input("action:add", "from"),
                right=_input("action:add", "to"),
                operator="lt",
            ),
        ),
    )

    assert solution.status == "unsat"
    assert solution.checks == seeds


def test_prefilter_sequence_enforces_cross_action_coupling():
    from cloud_dast_symbolic import SymbolicPrefilter

    add = MethodSpec(
        method_id="add",
        service="service",
        name="Add",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="cName", type="string", required=True),),
    )
    remove = MethodSpec(
        method_id="remove",
        service="service",
        name="Remove",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="cName", type="string", required=True),),
    )
    coupling = (
        _input("action:add", "cName"),
        _input("action:remove", "cName"),
        "eq",
    )
    add_plan = plan(add).model_copy(update={"couplings": (coupling,)})
    remove_plan = plan(remove).model_copy(update={"couplings": (coupling,)})
    seeds = (
        Check(
            invariant_id="inv",
            method_id="add",
            scenario_id="scenario",
            request=(("cName", "seed-add"),),
            identities=("attacker",),
        ),
        Check(
            invariant_id="inv",
            method_id="remove",
            scenario_id="scenario",
            request=(("cName", "seed-remove"),),
            identities=("attacker",),
        ),
    )

    solution = SymbolicPrefilter().prefilter_sequence(
        seeds,
        ((add_plan, add), (remove_plan, remove)),
    )

    assert solution.status == "sat"
    values = [dict(check.request)["cName"] for check in solution.checks]
    assert values[0] == values[1]
    assert values[0] not in {"seed-add", "seed-remove"}


def test_prefilter_solves_coupled_fields():
    from cloud_dast_symbolic import SymbolicPrefilter

    fields = (
        FieldSpec(name="from", type="int32", required=True, minimum=0, maximum=10),
        FieldSpec(name="to", type="int32", required=True, minimum=0, maximum=10),
    )
    method_spec = method(fields)
    coupled_plan = plan(method_spec).model_copy(
        update={"couplings": ((_input("get", "from"), _input("get", "to"), "eq"),)}
    )
    seed = StaticBase((("from", 1), ("to", 2))).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]

    decision = SymbolicPrefilter().prefilter(seed, coupled_plan, method_spec)

    values = dict(decision.check.request)
    assert decision.status == "solved"
    assert values["from"] == values["to"]


def test_prefilter_skips_contradictory_plan():
    from cloud_dast_symbolic import SymbolicPrefilter

    fields = (
        FieldSpec(name="from", type="int32", required=True),
        FieldSpec(name="to", type="int32", required=True),
    )
    method_spec = method(fields)
    contradictory = plan(method_spec).model_copy(
        update={
            "couplings": (
                (_input("get", "from"), _input("get", "to"), "gt"),
                (_input("get", "from"), _input("get", "to"), "lt"),
            )
        }
    )
    seed = StaticBase((("from", 1), ("to", 2))).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]

    decision = SymbolicPrefilter().prefilter(seed, contradictory, method_spec)

    assert decision.status == "unsat"
    assert decision.check == seed


def test_prefilter_passes_without_symbolic_fields():
    from cloud_dast_symbolic import SymbolicPrefilter

    fields = (FieldSpec(name="secret_id", type="string", required=True),)
    method_spec = method(fields)
    seed = StaticBase((("secret_id", "secret-1"),)).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]

    decision = SymbolicPrefilter().prefilter(seed, plan(method_spec), method_spec)

    assert decision.status == "pass"
    assert decision.check == seed


def test_solve_request_enforces_constraints_and_couplings():
    fields = (
        FieldSpec(name="name", type="string", required=True),
        FieldSpec(name="from", type="int32", required=True, minimum=0, maximum=10),
        FieldSpec(name="to", type="int32", required=True, minimum=0, maximum=10),
    )
    method_spec = method(fields)

    solution = solve_request(
        {"name": "seed", "from": 1, "to": 2},
        method_spec,
        couplings=(same_method_coupling("from", "to", "eq"),),
        constraints=(FieldValueConstraint("name", "ne", "seed"),),
    )

    assert solution.status == "sat"
    assert solution.request["name"] != "seed"
    assert solution.request["from"] == solution.request["to"]


def test_solve_request_preserves_already_satisfying_values():
    fields = (
        FieldSpec(name="name", type="string", required=True),
        FieldSpec(name="from", type="int32", required=True),
        FieldSpec(name="to", type="int32", required=True),
    )
    method_spec = method(fields)
    request = {"name": "alternative", "from": 3, "to": 3}

    solution = solve_request(
        request,
        method_spec,
        couplings=(same_method_coupling("from", "to", "eq"),),
        constraints=(FieldValueConstraint("name", "ne", "seed"),),
    )

    assert solution.status == "sat"
    assert solution.request == request


def test_solve_request_reports_contradictory_constraints():
    fields = (FieldSpec(name="value", type="int32", required=True),)
    method_spec = method(fields)

    solution = solve_request(
        {"value": 1},
        method_spec,
        constraints=(
            FieldValueConstraint("value", "gt", 2),
            FieldValueConstraint("value", "lt", 1),
        ),
    )

    assert solution.status == "unsat"
    assert solution.request == {"value": 1}


def test_solve_request_preserves_repeated_shape_and_constraints():
    fields = (
        FieldSpec(
            name="ids",
            type="int32",
            required=True,
            repeated=True,
            minimum=1,
            maximum=10,
        ),
    )
    method_spec = method(fields)

    solution = solve_request(
        {"ids": (1, 1)},
        method_spec,
        constraints=(FieldValueConstraint("ids", "gt", 2),),
    )

    assert solution.status == "sat"
    assert solution.dropped_couplings is False
    assert solution.request["ids"] == (3, 3)


def test_model_value_converts_ieee_float() -> None:
    field = FieldSpec(name="x", type="float", required=True)
    value = z3.FPVal(0.1, z3.Float32())

    assert _model_value(value, field) == 0.10000000149011612


def test_solve_sequence_flags_dropped_cross_action_coupling() -> None:
    add = MethodSpec(
        method_id="add",
        service="service",
        name="Add",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="count", type="int32", required=True),),
    )
    remove = MethodSpec(
        method_id="remove",
        service="service",
        name="Remove",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="name", type="string", required=True),),
    )
    seed = Check(
        invariant_id="inv",
        method_id="add",
        scenario_id="scenario",
        request=(("count", 1),),
        identities=("attacker",),
    )

    solution = solve_sequence(
        (seed,),
        {"add": add, "remove": remove},
        (
            FieldCoupling(
                left=_input("action:add", "count"),
                right=_input("action:remove", "name"),
                operator="eq",
            ),
        ),
    )

    assert solution.status == "deferred"
    assert solution.dropped_couplings is True


def test_solve_sequence_reports_unknown(monkeypatch) -> None:
    class UnknownSolver:
        def set(self, name, value):
            del name, value

        def add(self, *constraints):
            del constraints

        def check(self):
            return z3.unknown

    monkeypatch.setattr(symbolic_module.z3, "Solver", UnknownSolver)
    method_spec = method((FieldSpec(name="x", type="float", required=True),))
    seed = StaticBase((("x", 0.1),)).generate(
        plan(method_spec), method_spec, invariant(), scenario()
    )[0]

    solution = solve_sequence((seed,), {method_spec.method_id: method_spec})

    assert solution.status == "unknown"
    assert solution.checks == (seed,)


def test_output_coupling_never_aliases_request_field_with_same_name():
    make = method((FieldSpec(name="id", type="int32"),)).model_copy(
        update={"method_id": "make"}
    )
    use = method((FieldSpec(name="widget_id", type="int32"),)).model_copy(
        update={"method_id": "use"}
    )
    source = Check(
        invariant_id="inv",
        method_id="make",
        scenario_id="make-scenario",
        request=(("id", 17),),
        identities=("attacker",),
    )
    destination = source.model_copy(
        update={
            "method_id": "use",
            "scenario_id": "use-scenario",
            "request": (("widget_id", None),),
        }
    )
    coupling = FieldCoupling(
        left=output_field(Atom(value="action:make"), Atom(value="id")),
        right=_input("action:use", "widget_id"),
        operator="eq",
    )
    solution = solve_sequence(
        (source, destination), {"make": make, "use": use}, (coupling,)
    )
    assert solution.status == "deferred"
    assert solution.dropped_couplings is True
    assert dict(solution.checks[1].request)["widget_id"] is None


def test_symbolic_fallback_preserves_couplings_when_distinct_is_impossible():
    fields = (
        FieldSpec(name="a", type="int32", minimum=0, maximum=0),
        FieldSpec(name="b", type="int32", minimum=1, maximum=1),
    )
    method_spec = method(fields)
    base = StaticBase((("a", 0), ("b", 1)))
    seed = base.generate(plan(method_spec), method_spec, invariant(), scenario())[0]
    candidate = Z3SymbolicGenerator(base).build_seed(
        seed,
        method_spec,
        invariant(),
        couplings=(same_method_coupling("a", "b", "eq"),),
    )
    assert candidate.solver_status == "unsat"
    assert candidate.check.request == seed.request


def test_symbolic_seed_defers_observation_bound_numeric_input():
    method_spec = method((FieldSpec(name="id", type="int32"),))
    base = StaticBase((("id", None),))
    coupling = (
        output_field(Atom(value="action:make"), Atom(value="id")),
        _input("get", "id"),
        "eq",
    )
    bound_plan = plan(method_spec).model_copy(update={"couplings": (coupling,)})
    check = Z3SymbolicGenerator(base).generate(
        bound_plan, method_spec, invariant(), scenario()
    )[0]
    assert dict(check.request)["id"] is None


def test_request_solver_defers_unknown_output_and_preserves_mutation():
    method_spec = method((FieldSpec(name="id", type="int32"),))
    coupling = FieldCoupling(
        output_field(Atom(value="get"), Atom(value="id")), _input("get", "id"), "eq"
    )
    for value in (None, 123):
        solution = solve_request({"id": value}, method_spec, (coupling,))
        assert solution.status == "deferred"
        assert solution.dropped_couplings is True
        assert solution.request["id"] == value
