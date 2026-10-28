"""Registration entry point for the optional symbolic extension."""

from __future__ import annotations

from cloud_dast.extensions import ExtensionRegistry
from cloud_dast_symbolic.solver import (
    FieldValueConstraint,
    SymbolicPrefilter,
    Z3SymbolicGenerator,
    solve_request,
)


def solve_grammar_request(request, method, couplings, constraints):
    """Adapt the symbolic solver to the core grammar-solving contract."""

    from cloud_dast.contracts.grammar import GrammarSolution

    solution = solve_request(
        request,
        method,
        couplings,
        tuple(
            FieldValueConstraint(
                field=constraint.field,
                operator=constraint.operator,
                value=constraint.value,
            )
            for constraint in constraints
        ),
    )
    return GrammarSolution(
        request=solution.request,
        status=solution.status,
        dropped_couplings=solution.dropped_couplings,
    )


def register(registry: ExtensionRegistry) -> None:
    """Expose solver implementations through stable core ports."""

    registry.register(
        symbolic_generator_factory=Z3SymbolicGenerator,
        request_solver=solve_grammar_request,
        symbolic_prefilter_factory=SymbolicPrefilter,
    )


__all__ = ["register", "solve_grammar_request"]
