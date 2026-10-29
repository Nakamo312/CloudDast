"""Z3-backed symbolic seed construction for QDL-derived checks."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import z3

from cloud_dast.binding import validate_binding
from cloud_dast.contracts.feedback import ExecutionFeedback
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.couplings import (
    COUPLED_OPERATORS,
    FieldCoupling,
    couplings_for_method,
    couplings_from_plan,
    normalise_action,
)
from cloud_dast.extensions import TestCaseGenerator
from cloud_dast.model import (
    Check,
    FieldSpec,
    JsonValue,
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.model.schemas import (
    float_range,
    integer_range,
    is_float_type,
    is_integer_type,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.norms import NormCompiler


@dataclass(frozen=True, slots=True)
class SymbolicCandidate:
    """One solver-derived candidate, never a finding by itself."""

    check: Check
    solver_status: str
    dropped_couplings: bool = False


@dataclass(frozen=True, slots=True)
class SequenceSolution:
    """Result of solving one whole API call sequence."""

    checks: tuple[Check, ...]
    status: str
    dropped_couplings: bool = False


@dataclass(frozen=True, slots=True)
class FieldValueConstraint:
    """One declarative value constraint attached to a field."""

    field: str
    operator: str
    value: JsonValue


@dataclass(frozen=True, slots=True)
class RequestSolution:
    """Result of solving one request mapping."""

    request: dict[str, JsonValue]
    status: str
    dropped_couplings: bool = False


@dataclass(frozen=True, slots=True)
class Z3Limits:
    """Resource bounds for one in-process Z3 solve."""

    timeout_ms: int = 5_000
    max_memory_mb: int = 512

    def __post_init__(self) -> None:
        if self.timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        if self.max_memory_mb <= 0:
            raise ValueError("max_memory_mb must be positive")


DEFAULT_Z3_LIMITS = Z3Limits()


class Z3SymbolicGenerator:
    """Build a concrete check by solving numeric, boolean, and enum fields."""

    def __init__(
        self,
        base: TestCaseGenerator,
        *,
        limits: Z3Limits = DEFAULT_Z3_LIMITS,
    ) -> None:
        self._base = base
        self._limits = limits

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback: ExecutionFeedback | None = None,
    ) -> tuple[Check, ...]:
        validate_binding(plan, method, invariant, scenario)
        seed = self._base.generate(
            plan,
            method,
            invariant,
            scenario,
            feedback=feedback,
        )[0]
        candidate = self.build_seed(
            seed,
            method,
            invariant,
            couplings=(
                *couplings_for_method(plan.couplings, method.method_id),
                *(
                    coupling
                    for coupling in couplings_from_plan(plan.couplings)
                    if coupling.left.name == "output_field"
                    or coupling.right.name == "output_field"
                ),
            ),
        )
        return (candidate.check,)

    def build_seed(
        self,
        seed: Check,
        method: MethodSpec,
        invariant: InvariantProjection,
        *,
        couplings: Sequence[FieldCoupling] = (),
    ) -> SymbolicCandidate:
        """Return one solver-derived alternative to ``seed``."""

        primitive = None
        if invariant.norm_fact is not None:
            primitive = NormCompiler().compile(invariant.norm_fact).primitive
        if primitive in {"marker", "oob_event"}:
            # Payload decorators own marker and OOB fields.  Symbolic solving
            # should not compete with those deterministic injections.
            return SymbolicCandidate(
                _mark_symbolic(seed),
                "payload-owned",
                dropped_couplings=bool(couplings),
            )

        fields = {field.name: field for field in method.request_schema.fields}
        coupled_names = {
            atom_value(endpoint.args[1])
            for coupling in couplings
            for endpoint in (coupling.left, coupling.right)
            if endpoint.name == "input_field"
        }
        observed_names = {
            atom_value(endpoint.args[1])
            for coupling in couplings
            if coupling.left.name == "output_field"
            or coupling.right.name == "output_field"
            for endpoint in (coupling.left, coupling.right)
            if endpoint.name == "input_field"
            and normalise_action(atom_value(endpoint.args[0]))
            == normalise_action(method.method_id)
        }
        solver = _solver(self._limits)
        variables: dict[str, object] = {}
        constraints: list[object] = []
        dropped_couplings = False

        for name, value in seed.request:
            field = fields.get(name)
            if (
                field is None
                or name in observed_names
                or not (_is_symbolic_field(field) or name in coupled_names)
            ):
                continue
            variable = _variable(name, field, _element_count(value, field))
            variables[name] = variable
            constraints.extend(_constraints(variable, field))
            seed_value = _seed_value(value, field)
            if seed_value is not None:
                distinct = _distinct_constraint(variable, seed_value)
                if distinct is not None:
                    constraints.append(distinct)

        for coupling in couplings:
            if (
                coupling.left.name != "input_field"
                or coupling.right.name != "input_field"
            ):
                dropped_couplings = True
                continue
            left = atom_value(coupling.left.args[1])
            right = atom_value(coupling.right.args[1])
            constraint, coupling_dropped = _coupling_constraint(
                variables.get(left),
                fields.get(left),
                variables.get(right),
                fields.get(right),
                coupling.operator,
            )
            if coupling_dropped:
                dropped_couplings = True
            else:
                constraints.append(constraint)

        if not variables:
            return SymbolicCandidate(
                _mark_symbolic(seed),
                "deferred" if couplings else "no-symbolic-fields",
                dropped_couplings=dropped_couplings or bool(couplings),
            )

        solver.add(*constraints)
        result = solver.check()
        if result == z3.unknown:
            return SymbolicCandidate(
                _mark_symbolic(seed), "unknown", dropped_couplings=dropped_couplings
            )
        if result == z3.sat:
            model = solver.model()
            request = dict(seed.request)
            for name, variable in variables.items():
                request[name] = _model_value(_eval_model(model, variable), fields[name])
            return SymbolicCandidate(
                seed.model_copy(
                    update={
                        "request": tuple(request.items()),
                        "generator": "symbolic",
                    }
                ),
                "deferred" if dropped_couplings else "sat",
                dropped_couplings=dropped_couplings,
            )

        # If a distinct value is impossible, solve the original constraints.
        fallback_solver = _solver(self._limits)
        fallback_constraints: list[object] = []
        for name in variables:
            variable = variables[name]
            fallback_constraints.extend(_constraints(variable, fields[name]))
        for coupling in couplings:
            if (
                coupling.left.name != "input_field"
                or coupling.right.name != "input_field"
            ):
                continue
            left = atom_value(coupling.left.args[1])
            right = atom_value(coupling.right.args[1])
            constraint, dropped = _coupling_constraint(
                variables.get(left),
                fields.get(left),
                variables.get(right),
                fields.get(right),
                coupling.operator,
            )
            if not dropped:
                fallback_constraints.append(constraint)
        fallback_solver.add(*fallback_constraints)
        fallback_result = fallback_solver.check()
        if fallback_result == z3.unknown:
            return SymbolicCandidate(
                _mark_symbolic(seed), "unknown", dropped_couplings=dropped_couplings
            )
        if fallback_result != z3.sat:
            return SymbolicCandidate(
                _mark_symbolic(seed), "unsat", dropped_couplings=dropped_couplings
            )

        model = fallback_solver.model()
        request = dict(seed.request)
        for name, variable in variables.items():
            request[name] = _model_value(_eval_model(model, variable), fields[name])
        return SymbolicCandidate(
            seed.model_copy(
                update={"request": tuple(request.items()), "generator": "symbolic"}
            ),
            "deferred" if dropped_couplings else "sat-fallback",
            dropped_couplings=dropped_couplings,
        )


def _mark_symbolic(seed: Check) -> Check:
    return seed.model_copy(update={"generator": "symbolic"})


def _is_symbolic_field(field: FieldSpec) -> bool:
    return (
        bool(field.enum_values)
        or is_integer_type(field.type)
        or is_float_type(field.type)
        or "bool" in field.type.lower()
    )


def _variable(name: str, field: FieldSpec, size: int = 1) -> object:
    if size < 0:
        raise ValueError("repeated field size must not be negative")
    if not field.repeated:
        return _scalar_variable(name, field)
    return tuple(_scalar_variable(f"{name}[{index}]", field) for index in range(size))


def _scalar_variable(name: str, field: FieldSpec) -> object:
    if field.enum_values:
        return z3.Int(f"enum:{name}")
    if is_integer_type(field.type):
        return z3.Int(f"int:{name}")
    if is_float_type(field.type):
        return z3.FP(f"fp:{name}", _fp_sort(field))
    if _is_string_field(field):
        return z3.String(f"str:{name}")
    return z3.Bool(f"bool:{name}")


def _solver(limits: Z3Limits) -> z3.Solver:
    solver = z3.Solver()
    solver.set("timeout", limits.timeout_ms)
    solver.set("max_memory", limits.max_memory_mb)
    return solver


def _constraints(variable: object, field: FieldSpec) -> list[object]:
    if isinstance(variable, tuple):
        return [
            constraint for item in variable for constraint in _constraints(item, field)
        ]
    constraints: list[object] = []
    if field.enum_values:
        constraints.append(
            z3.Or(*[variable == index for index in range(len(field.enum_values))])
        )
    elif (bounds := integer_range(field.type)) is not None:
        constraints.extend((variable >= bounds[0], variable <= bounds[1]))
    elif (bounds := float_range(field.type)) is not None:
        constraints.extend(
            (
                variable >= _bound_value(bounds[0], field),
                variable <= _bound_value(bounds[1], field),
            )
        )
    if field.minimum is not None:
        constraints.append(variable >= _bound_value(field.minimum, field))
    if field.maximum is not None:
        constraints.append(variable <= _bound_value(field.maximum, field))
    return constraints


def _model_value(value: object, field: FieldSpec) -> JsonValue:
    if isinstance(value, tuple):
        return tuple(_model_value(item, field) for item in value)
    if field.enum_values:
        index = value.as_long()
        return field.enum_values[index]
    if is_integer_type(field.type):
        return value.as_long()
    if is_float_type(field.type):
        if not z3.is_fp_value(value):
            raise ValueError("symbolic model did not contain a floating-point value")
        return _fp_value(value)
    if _is_string_field(field):
        return value.as_string()
    return z3.is_true(value)


def _seed_value(value: object, field: FieldSpec) -> object:
    return _z3_value(value, field)


def _is_string_field(field: FieldSpec) -> bool:
    return not (
        field.enum_values
        or is_integer_type(field.type)
        or is_float_type(field.type)
        or "bool" in field.type.lower()
    )


def _variable_kind(field: FieldSpec) -> str:
    if field.enum_values:
        return "enum"
    if is_integer_type(field.type):
        return "int"
    if is_float_type(field.type):
        return "fp"
    if _is_string_field(field):
        return "string"
    return "bool"


def _coupling_constraint(
    left_variable: object | None,
    left_field: FieldSpec | None,
    right_variable: object | None,
    right_field: FieldSpec | None,
    operator: str,
) -> tuple[object | None, bool]:
    """Render one value coupling and report whether it had to be dropped.

    ``eq``/``ne`` require the same variable kind; ordering operators require
    numeric or enum kinds. Repeated operands apply the relation element-wise,
    and differently sized repeated operands cannot be coupled.
    """

    if left_variable is None or right_variable is None:
        return None, True
    if left_field is None or right_field is None:
        return None, True
    left_items = left_variable if isinstance(left_variable, tuple) else (left_variable,)
    right_items = (
        right_variable if isinstance(right_variable, tuple) else (right_variable,)
    )
    if (
        isinstance(left_variable, tuple)
        and isinstance(right_variable, tuple)
        and len(left_items) != len(right_items)
    ):
        return None, True
    if isinstance(left_variable, tuple) and not isinstance(right_variable, tuple):
        pairs = ((left_item, right_variable) for left_item in left_items)
    elif not isinstance(left_variable, tuple) and isinstance(right_variable, tuple):
        pairs = ((left_variable, right_item) for right_item in right_items)
    else:
        pairs = zip(left_items, right_items, strict=True)

    rendered: list[object] = []
    for left_item, right_item in pairs:
        constraint = _scalar_coupling_constraint(
            left_item,
            right_item,
            _variable_kind(left_field),
            _variable_kind(right_field),
            operator,
        )
        if constraint is None:
            return None, True
        rendered.append(constraint)
    if not rendered:
        return None, True
    if len(rendered) == 1:
        return rendered[0], False
    return z3.And(*rendered), False


def _scalar_coupling_constraint(
    left_variable: object,
    right_variable: object,
    left_kind: str,
    right_kind: str,
    operator: str,
) -> object | None:
    if operator in {"eq", "ne"}:
        if left_kind != right_kind:
            return None
        return (
            left_variable == right_variable
            if operator == "eq"
            else left_variable != right_variable
        )
    ordered = {"int", "fp", "enum"}
    if left_kind not in ordered or right_kind not in ordered:
        return None
    return {
        "lt": left_variable < right_variable,
        "le": left_variable <= right_variable,
        "gt": left_variable > right_variable,
        "ge": left_variable >= right_variable,
    }[operator]


def _element_count(value: object, field: FieldSpec) -> int:
    if not field.repeated:
        return 1
    return len(value) if isinstance(value, tuple) else 1


def _fp_sort(field: FieldSpec) -> z3.FPSort:
    field_type = field.type.lower()
    if field_type == "float":
        return z3.Float32()
    if field_type == "double":
        return z3.Float64()
    raise ValueError(f"unsupported floating-point type: {field.type!r}")


def _bound_value(value: int | float, field: FieldSpec) -> object:
    if is_float_type(field.type):
        return z3.FPVal(value, _fp_sort(field))
    if is_integer_type(field.type):
        return z3.IntVal(value)
    return value


def _fp_value(value: z3.FPNumRef) -> float:
    if value.isNaN() or value.isInf():
        raise ValueError("symbolic model produced a non-finite float")
    sort = value.sort()
    ebits = sort.ebits()
    sbits = sort.sbits()
    bias = 2 ** (ebits - 1) - 1
    significand = value.significand_as_long()
    if value.isNormal():
        significand += 2 ** (sbits - 1)
    result = math.ldexp(significand, value.exponent_as_long() - bias - sbits + 1)
    return -result if value.sign() else result


def _eval_model(model: z3.Model, variable: object) -> object:
    if isinstance(variable, tuple):
        return tuple(model.eval(item, model_completion=True) for item in variable)
    return model.eval(variable, model_completion=True)


def _distinct_constraint(variable: object, seed_value: object) -> object | None:
    if isinstance(variable, tuple):
        if not isinstance(seed_value, tuple) or len(variable) != len(seed_value):
            return None
        differences = [item != seed for item, seed in zip(variable, seed_value)]
        if not differences:
            return None
        return z3.Or(*differences)
    return variable != seed_value


CONSTRAINT_OPERATORS = COUPLED_OPERATORS


def solve_request(
    request: Mapping[str, JsonValue],
    method: MethodSpec,
    couplings: Sequence[FieldCoupling] = (),
    constraints: Sequence[FieldValueConstraint] = (),
) -> RequestSolution:
    """Solve one request's field constraints and couplings with Z3.

    Fields already satisfying every constraint are preserved.  Only fields
    participating in a coupling or an unsatisfied value constraint are
    replaced by the solver model.
    """

    if not couplings and not constraints:
        return RequestSolution(dict(request), "no-constraints")

    deferred = tuple(
        coupling
        for coupling in couplings
        if any(
            endpoint.name != "input_field"
            or normalise_action(atom_value(endpoint.args[0]))
            != normalise_action(method.method_id)
            for endpoint in (coupling.left, coupling.right)
        )
    )
    if deferred:
        observed_names = {
            atom_value(endpoint.args[1])
            for coupling in deferred
            for endpoint in (coupling.left, coupling.right)
            if endpoint.name == "input_field"
            and normalise_action(atom_value(endpoint.args[0]))
            == normalise_action(method.method_id)
        }
        solution = solve_request(
            request,
            method,
            tuple(
                coupling
                for coupling in couplings
                if coupling not in deferred
                and not any(
                    atom_value(endpoint.args[1]) in observed_names
                    for endpoint in (coupling.left, coupling.right)
                )
            ),
            tuple(
                constraint
                for constraint in constraints
                if constraint.field not in observed_names
            ),
        )
        return RequestSolution(
            solution.request,
            solution.status if solution.status in {"unsat", "unknown"} else "deferred",
            dropped_couplings=True,
        )

    fields = {field.name: field for field in method.request_schema.fields}
    coupled_names = {
        name
        for coupling in couplings
        for name in (
            atom_value(coupling.left.args[1]),
            atom_value(coupling.right.args[1]),
        )
    }
    constraint_names = {constraint.field for constraint in constraints}
    relevant_names = coupled_names | constraint_names
    missing_coupling = any(
        atom_value(coupling.left.args[1]) not in request
        or atom_value(coupling.right.args[1]) not in request
        for coupling in couplings
    )
    if not relevant_names or not all(name in request for name in relevant_names):
        return RequestSolution(
            dict(request),
            "deferred" if missing_coupling else "no-constraints",
            dropped_couplings=missing_coupling,
        )

    satisfied, dropped_couplings = _request_is_satisfied(
        request, fields, couplings, constraints, relevant_names
    )
    if satisfied:
        return RequestSolution(
            dict(request),
            "deferred" if dropped_couplings else "sat",
            dropped_couplings=dropped_couplings,
        )

    solver = z3.Solver()
    variables: dict[str, object] = {}
    z3_constraints: list[object] = []
    dropped_couplings = False
    for name in sorted(relevant_names):
        field = fields.get(name)
        if field is None:
            continue
        variable = _variable(name, field, _element_count(request[name], field))
        variables[name] = variable
        z3_constraints.extend(_constraints(variable, field))

    for constraint in constraints:
        variable = variables.get(constraint.field)
        field = fields.get(constraint.field)
        if variable is None or field is None:
            continue
        value_constraint = _value_constraint(
            variable,
            field,
            constraint.operator,
            constraint.value,
        )
        if value_constraint is not None:
            z3_constraints.append(value_constraint)

    for coupling in couplings:
        if coupling.left.name != "input_field" or coupling.right.name != "input_field":
            dropped_couplings = True
            continue
        left = atom_value(coupling.left.args[1])
        right = atom_value(coupling.right.args[1])
        constraint, coupling_dropped = _coupling_constraint(
            variables.get(left),
            fields.get(left),
            variables.get(right),
            fields.get(right),
            coupling.operator,
        )
        if coupling_dropped:
            dropped_couplings = True
        else:
            z3_constraints.append(constraint)

    if not variables:
        return RequestSolution(
            dict(request),
            "deferred" if couplings else "no-constraints",
            dropped_couplings=dropped_couplings or bool(couplings),
        )

    solver.add(*z3_constraints)
    result = solver.check()
    if result == z3.unknown:
        return RequestSolution(
            dict(request), "unknown", dropped_couplings=dropped_couplings
        )
    if result != z3.sat:
        return RequestSolution(
            dict(request), "unsat", dropped_couplings=dropped_couplings
        )

    model = solver.model()
    solved = dict(request)
    for name, variable in variables.items():
        solved[name] = _model_value(_eval_model(model, variable), fields[name])
    return RequestSolution(
        solved,
        "deferred" if dropped_couplings else "sat",
        dropped_couplings=dropped_couplings,
    )


def _request_is_satisfied(
    request: Mapping[str, JsonValue],
    fields: Mapping[str, FieldSpec],
    couplings: Sequence[FieldCoupling],
    constraints: Sequence[FieldValueConstraint],
    relevant_names: set[str],
) -> tuple[bool, bool]:
    solver = z3.Solver()
    variables: dict[str, object] = {}
    checks: list[object] = []
    dropped_couplings = False
    for name in sorted(relevant_names):
        field = fields.get(name)
        if field is None:
            return False, False
        variable = _variable(name, field, _element_count(request[name], field))
        variables[name] = variable
        checks.extend(_constraints(variable, field))
        size = len(variable) if isinstance(variable, tuple) else None
        value = _z3_value(request[name], field, size=size)
        equality = _value_constraint(variable, field, "eq", request[name])
        if value is None or equality is None:
            return False, False
        checks.append(equality)

    for constraint in constraints:
        variable = variables.get(constraint.field)
        field = fields.get(constraint.field)
        if variable is None or field is None:
            continue
        value_constraint = _value_constraint(
            variable,
            field,
            constraint.operator,
            constraint.value,
        )
        if value_constraint is not None:
            checks.append(value_constraint)

    for coupling in couplings:
        if coupling.left.name != "input_field" or coupling.right.name != "input_field":
            dropped_couplings = True
            continue
        left = atom_value(coupling.left.args[1])
        right = atom_value(coupling.right.args[1])
        constraint, coupling_dropped = _coupling_constraint(
            variables.get(left),
            fields.get(left),
            variables.get(right),
            fields.get(right),
            coupling.operator,
        )
        if coupling_dropped:
            dropped_couplings = True
        else:
            checks.append(constraint)

    solver.add(*checks)
    return solver.check() == z3.sat, dropped_couplings


def _value_constraint(
    variable: object,
    field: FieldSpec,
    operator: str,
    value: object,
) -> object | None:
    if operator not in CONSTRAINT_OPERATORS:
        raise ValueError(f"unknown constraint operator: {operator!r}")
    if isinstance(variable, tuple):
        z3_value = _z3_value(value, field, size=len(variable))
        if not isinstance(z3_value, tuple) or len(z3_value) != len(variable):
            return None
        constraints = [
            _scalar_value_constraint(item, field, operator, item_value)
            for item, item_value in zip(variable, z3_value, strict=True)
        ]
        if not constraints:
            return None
        return constraints[0] if len(constraints) == 1 else z3.And(*constraints)
    z3_value = _z3_value(value, field)
    if z3_value is None:
        return None
    return _scalar_value_constraint(variable, field, operator, z3_value)


def _scalar_value_constraint(
    variable: object,
    field: FieldSpec,
    operator: str,
    z3_value: object,
) -> object:
    return {
        "eq": variable == z3_value,
        "ne": variable != z3_value,
        "lt": variable < z3_value,
        "le": variable <= z3_value,
        "gt": variable > z3_value,
        "ge": variable >= z3_value,
    }[operator]


def _z3_value(
    value: object,
    field: FieldSpec,
    *,
    size: int | None = None,
) -> object | None:
    if field.repeated:
        items = (
            value
            if isinstance(value, tuple)
            else (value,) * size
            if size is not None
            else None
        )
        if items is None:
            return None
        values = tuple(_scalar_z3_value(item, field) for item in items)
        if any(item is None for item in values):
            return None
        return values
    return _scalar_z3_value(value, field)


def _scalar_z3_value(value: object, field: FieldSpec) -> object | None:
    if field.enum_values:
        if not isinstance(value, str):
            return None
        try:
            return z3.IntVal(field.enum_values.index(value))
        except ValueError:
            return None
    if is_integer_type(field.type):
        return (
            z3.IntVal(value)
            if isinstance(value, int) and not isinstance(value, bool)
            else None
        )
    if is_float_type(field.type):
        if not isinstance(value, int | float) or isinstance(value, bool):
            return None
        return z3.FPVal(value, _fp_sort(field))
    if "bool" in field.type.lower():
        return z3.BoolVal(value) if isinstance(value, bool) else None
    if _is_string_field(field):
        return z3.StringVal(value) if isinstance(value, str) else None
    return None


def solve_sequence(
    seeds: Sequence[Check],
    methods: Mapping[str, MethodSpec],
    couplings: Sequence[FieldCoupling] = (),
    *,
    limits: Z3Limits = DEFAULT_Z3_LIMITS,
) -> SequenceSolution:
    """Solve request-input constraints and defer observation-bound values.

    One Z3 model binds request values across the requires-chain. Output
    terms never become request variables; a deferred result requires actual
    observations and runtime coupling enforcement before dependent calls.
    Variables are keyed by ``(method_id, field_name)``; a method occurring
    twice in a sequence shares field values across its occurrences.
    """

    coupled_fields = {
        (normalise_action(atom_value(endpoint.args[0])), atom_value(endpoint.args[1]))
        for coupling in couplings
        for endpoint in (coupling.left, coupling.right)
        if endpoint.name == "input_field"
    }
    observed_fields = {
        (normalise_action(atom_value(endpoint.args[0])), atom_value(endpoint.args[1]))
        for coupling in couplings
        if coupling.left.name == "output_field" or coupling.right.name == "output_field"
        for endpoint in (coupling.left, coupling.right)
        if endpoint.name == "input_field"
    }

    fields_by_method: dict[str, dict[str, FieldSpec]] = {}
    variables: dict[tuple[str, str], object] = {}
    constraints: list[object] = []
    dropped_couplings = False

    for seed in seeds:
        method = methods.get(seed.method_id)
        if method is None:
            continue
        fields = fields_by_method.setdefault(
            seed.method_id,
            {field.name: field for field in method.request_schema.fields},
        )
        for name, value in dict(seed.request).items():
            field = fields.get(name)
            if field is None or (seed.method_id, name) in observed_fields:
                continue
            if not (
                _is_symbolic_field(field) or (seed.method_id, name) in coupled_fields
            ):
                continue
            key = (seed.method_id, name)
            if key in variables:
                continue
            variable = _variable(
                f"{seed.method_id}:{name}", field, _element_count(value, field)
            )
            variables[key] = variable
            constraints.extend(_constraints(variable, field))

    for coupling in couplings:
        if coupling.left.name != "input_field" or coupling.right.name != "input_field":
            dropped_couplings = True
            continue
        left_method = normalise_action(atom_value(coupling.left.args[0]))
        right_method = normalise_action(atom_value(coupling.right.args[0]))
        constraint, coupling_dropped = _coupling_constraint(
            variables.get((left_method, atom_value(coupling.left.args[1]))),
            fields_by_method.get(left_method, {}).get(
                atom_value(coupling.left.args[1])
            ),
            variables.get((right_method, atom_value(coupling.right.args[1]))),
            fields_by_method.get(right_method, {}).get(
                atom_value(coupling.right.args[1])
            ),
            coupling.operator,
        )
        if coupling_dropped:
            dropped_couplings = True
        else:
            constraints.append(constraint)

    if not variables:
        return SequenceSolution(
            checks=tuple(seeds),
            status="deferred" if couplings else "no-symbolic-fields",
            dropped_couplings=dropped_couplings or bool(couplings),
        )

    solver = _solver(limits)
    solver.add(*constraints)
    result = solver.check()
    if result == z3.unknown:
        return SequenceSolution(
            checks=tuple(seeds),
            status="unknown",
            dropped_couplings=dropped_couplings,
        )
    if result != z3.sat:
        return SequenceSolution(
            checks=tuple(seeds),
            status="unsat",
            dropped_couplings=dropped_couplings,
        )

    model = solver.model()
    solved: list[Check] = []
    for seed in seeds:
        fields = fields_by_method.get(seed.method_id, {})
        request = dict(seed.request)
        for name in request:
            variable = variables.get((seed.method_id, name))
            field = fields.get(name)
            if variable is None or field is None:
                continue
            request[name] = _model_value(_eval_model(model, variable), field)
        solved.append(
            seed.model_copy(
                update={"request": tuple(request.items()), "generator": "symbolic"}
            )
        )
    return SequenceSolution(
        checks=tuple(solved),
        status="deferred" if dropped_couplings else "sat",
        dropped_couplings=dropped_couplings,
    )


@dataclass(frozen=True, slots=True)
class PrefilterDecision:
    """What to do with one candidate before it reaches the live stand.

    ``solved`` — the solver produced concrete values; execute this check.
    ``pass``  — nothing to solve (no symbolic/coupled fields); execute as is.
    ``unsat`` — the field constraints are contradictory; skip the live call.
    ``unknown`` — the solver could not decide; do not treat this as UNSAT.
    ``deferred`` — some constraints still need runtime observations/binding.
    """

    check: Check
    status: str
    dropped_couplings: bool = False


class SymbolicPrefilter:
    """Solve one candidate symbolically before spending a live API call.

    This is the SymTEE two-stage paradigm adapted to black-box DAST: Z3
    checks the request's field constraints (types, bounds, enums, plan
    input couplings) first. A deferred result leaves observation constraints
    to the runtime binding gate; SAT alone never proves those constraints.
    """

    def prefilter(
        self,
        check: Check,
        plan: VerificationPlan,
        method: MethodSpec,
    ) -> PrefilterDecision:
        couplings = couplings_from_plan(plan.couplings)
        solution = solve_sequence(
            (check,),
            {check.method_id: method},
            couplings,
        )
        if solution.status == "unsat":
            return PrefilterDecision(
                check=check,
                status="unsat",
                dropped_couplings=solution.dropped_couplings,
            )
        if solution.status == "unknown":
            return PrefilterDecision(
                check=check,
                status="unknown",
                dropped_couplings=solution.dropped_couplings,
            )
        if solution.status == "deferred":
            return PrefilterDecision(
                check=solution.checks[0],
                status="deferred",
                dropped_couplings=True,
            )
        if solution.status == "no-symbolic-fields":
            return PrefilterDecision(
                check=check,
                status="pass",
                dropped_couplings=solution.dropped_couplings,
            )
        return PrefilterDecision(
            check=solution.checks[0],
            status="solved",
            dropped_couplings=solution.dropped_couplings,
        )

    def prefilter_sequence(
        self,
        checks: Sequence[Check],
        bindings: Sequence[tuple[VerificationPlan, MethodSpec]],
    ) -> SequenceSolution:
        """Solve one complete QDL path before any of its checks executes.

        Couplings are collected from every step plan and deduplicated, so a
        constraint attached to both of its actions is enforced exactly once
        over the whole call sequence.
        """

        couplings = tuple(
            dict.fromkeys(
                coupling
                for plan, _method in bindings
                for coupling in couplings_from_plan(plan.couplings)
            )
        )
        methods = {method.method_id: method for _plan, method in bindings}
        return solve_sequence(checks, methods, couplings)
