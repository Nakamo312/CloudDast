#!/usr/bin/env python3
"""Machine-check the formal limits of the QDL projection with Clingo.

Four proof obligations about the map ``system behavior -> formal expression``:

O1  The well-typed QDL term language is infinite even over a fixed finite
    atom universe: the ``has(Principal, Value)`` constructor accepts any
    struct in the value position (``ArgumentSchema(name="value")`` has
    ``struct_names=None``), including ``has`` itself, so nesting depth is
    unbounded.  Verified by strict growth of the term count with the depth
    bound; the recursion rule is depth-uniform, so growth never stops.

O2  The finding-eligible norm space over a fixed graph is finite: with
    identifiers and values drawn from the graph and effects from the closed
    causal constructor list, ``prevents(N, E)`` ranges over a finite set.
    ``has`` values and ``transition`` states are graph references, not free
    grammar positions.  This finiteness is what makes coverage, replay, and
    promotion decidable.

O3  The implemented observation projection is non-injective: two raw
    responses that differ in gRPC error details and nested payload content
    project to the identical Observation, because ``_outcome`` collapses
    the status, the transport drops ``details()``, and the codec keeps only
    whitelisted scalar fields.  The kernel of the projection is therefore
    non-empty and its dropped dimensions are nameable.

O4  The input space grows without bound while the expression space is
    finite: by pigeonhole, infinitely many behaviors share expressions,
    so the kernel of the full map is infinite.

Run:  .venv/bin/python scripts/formal_limits_proof.py
"""

from __future__ import annotations

import clingo


def solve(program: str) -> set[str]:
    """Return the stable-model atoms of one Clingo program."""

    control = clingo.Control()
    control.add("base", [], program)
    control.ground([("base", [])])
    symbols: set[str] = set()
    control.solve(
        on_model=lambda model: symbols.update(
            str(symbol) for symbol in model.symbols(shown=True)
        )
    )
    return symbols


def count_atom(atoms: set[str], name: str) -> int:
    """Return the numeric argument of the single ``name(C)`` atom."""

    matches = [atom for atom in atoms if atom.startswith(f"{name}(")]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {name}/1 atom, got {matches}")
    return int(clingo.parse_term(matches[0]).arguments[0].number)


def prove_language_infinite() -> list[int]:
    """O1: term counts per depth bound strictly grow without limit."""

    template = """
#const maxdepth = {maxdepth}.
atom(a; b).
depth(1..maxdepth).

% Witness constructors take atoms only (qdl/graph.py STRUCT_SCHEMAS).
term(field(A, F), 1) :- atom(A), atom(F).
term(status(A), 1) :- atom(A).

% has/2: principal is an atom; the value position is ArgumentSchema(
% name="value") with struct_names=None — ANY struct, including has itself.
term(has(P, A), 2) :- atom(P), atom(A).
term(has(P, S), E) :- atom(P), term(S, D), depth(D), E = D + 1, E <= maxdepth.

total(TOTAL) :- TOTAL = #count {{ T, D : term(T, D) }}.
"""
    counts: list[int] = []
    for maxdepth in range(1, 7):
        atoms = solve(template.format(maxdepth=maxdepth))
        counts.append(count_atom(atoms, "total"))
    strictly_growing = all(
        later > earlier for earlier, later in zip(counts, counts[1:])
    )
    if not strictly_growing:
        raise AssertionError(f"term counts must strictly grow: {counts}")
    return counts


def prove_grounded_norms_finite() -> tuple[int, int]:
    """O2: count the grounded effect and prevents-norm spaces of a toy graph."""

    program = """
% A fixed toy service graph: finite identifiers only.
action(a1; a2; a3).
field_name(f1; f2; f3; f4).
resource(r1; r2).
sink(s1; s2).
marker(m1; m2).
normid(n1; n2; n3).
principal(p1; p2).
state(s1; s2; s3).
num(100; 500; 1000).

% Graph-declared possession witnesses and control states.  The grounding
% policy admits only these finite carriers; it does not admit free nesting.
witness(field(R, F)) :- resource(R), field_name(F).
witness(has(P, field(R, F))) :- principal(P), resource(R), field_name(F).

% The closed causal-effect constructors over graph identifiers
% (CAUSAL_EFFECT_CONSTRUCTORS in qdl/graph.py).
eff(allowed(A)) :- action(A).
eff(denied(A)) :- action(A).
eff(reached(A, S)) :- action(A), sink(S).
eff(external_call(A, M)) :- action(A), marker(M).
eff(changed(R, F)) :- resource(R), field_name(F).
eff(completed(A)) :- action(A).
eff(identity(P1, P2)) :- principal(P1), principal(P2).
eff(create(R)) :- resource(R).
eff(remove(R)) :- resource(R).
eff(duration(A, N)) :- action(A), num(N).
eff(has(P, W)) :- principal(P), witness(W).
eff(transition(S, T)) :- state(S), state(T).

has_effect_included :- eff(has(P, W)), principal(P), witness(W).
nested_has_effect_included :-
    eff(has(P, has(Q, W))), principal(P), principal(Q), witness(W).
transition_effect_included :-
    eff(transition(S, T)), state(S), state(T).
grounding_policy_complete :-
    has_effect_included,
    nested_has_effect_included,
    transition_effect_included.

effect_count(C) :- C = #count { E : eff(E) }.
norm_count(C) :- C = #count { prevents(N, E) : normid(N), eff(E) }.
"""
    atoms = solve(program)
    if "grounding_policy_complete" not in atoms:
        raise AssertionError("has, nested has, and transition were not grounded")
    effect_count = count_atom(atoms, "effect_count")
    norm_count = count_atom(atoms, "norm_count")
    if norm_count != 3 * effect_count:
        raise AssertionError(
            "grounded norm space must be norm identifiers x effects: "
            f"{norm_count} != 3 * {effect_count}"
        )
    return effect_count, norm_count


def prove_projection_kernel_nonempty() -> set[str]:
    """O3: derive the kernel witness of the implemented observation projection."""

    program = """
world(w1; w2).

% What the transport actually receives from the two raw responses.
grpc_status(w1, invalid_argument).
grpc_status(w2, invalid_argument).
grpc_details(w1, sql_error_with_probe_marker).
grpc_details(w2, plain_invalid_input).
nested_payload(w1, secret_env_canary).
nested_payload(w2, empty).
safe_field(w1, rows, 0).
safe_field(w2, rows, 0).

% ==== Mirror of infrastructure/runtime/grpc.py :: _outcome ====
% Everything except OK / PERMISSION_DENIED / UNAUTHENTICATED /
% NOT_FOUND / UNKNOWN / UNIMPLEMENTED collapses to unknown.
obs_outcome(W, unknown) :- grpc_status(W, S),
    S != ok, S != permission_denied, S != unauthenticated,
    S != not_found, S != unknown, S != unimplemented.

% ==== Mirror of infrastructure/runtime/grpcio_transport.py ====
% The summary is a constant; exc.details() is never read.
obs_summary(W, constant_status_line) :- grpc_status(W, invalid_argument).

% ==== Mirror of infrastructure/runtime/protobuf.py ====
% Only whitelisted scalar safe fields survive decoding.
obs_field(W, F, V) :- safe_field(W, F, V).

% By construction no rule derives any obs_ fact from grpc_details
% or nested_payload: those dimensions are dropped, not merely unobserved.
dropped_channel(details) :- grpc_details(W, _).
dropped_channel(nested_payload) :- nested_payload(W, _).

same_observation(w1, w2) :-
    obs_outcome(w1, O), obs_outcome(w2, O),
    obs_summary(w1, S), obs_summary(w2, S),
    obs_field(w1, F, V), obs_field(w2, F, V).
worlds_differ(w1, w2) :-
    grpc_details(w1, D1), grpc_details(w2, D2), D1 != D2.

% Kernel witness: distinguishable worlds, indistinguishable observation.
kernel_nonempty :- same_observation(w1, w2), worlds_differ(w1, w2).
"""
    atoms = solve(program)
    if "kernel_nonempty" not in atoms:
        raise AssertionError("projection kernel witness was not derived")
    return atoms


def prove_input_space_unbounded(norm_count: int) -> list[tuple[int, int]]:
    """O4: input-string counts grow past the finite norm space."""

    rows: list[tuple[int, int]] = []
    for length in range(1, 13):
        bits = ", ".join(f"B{i}" for i in range(1, length + 1))
        body = ", ".join(f"bit(B{i})" for i in range(1, length + 1))
        program = (
            f"bit(0; 1).\n"
            f"string(s({length}, {bits})) :- {body}.\n"
            f"input_count(C) :- C = #count {{ S : string(S) }}.\n"
        )
        atoms = solve(program)
        count = count_atom(atoms, "input_count")
        rows.append((length, count))
        if count > norm_count:
            break
    return rows


def main() -> int:
    print("QDL formal limits — machine-checked with Clingo")
    print("=" * 60)

    counts = prove_language_infinite()
    print("\n[O1] Term language over a fixed 2-atom universe is infinite")
    print("     has-value accepts any struct (struct_names=None), incl. has;")
    print("     term counts by depth bound:", counts)
    print("     strictly growing + depth-uniform rule => no finite bound.")

    effect_count, norm_count = prove_grounded_norms_finite()
    print("\n[O2] Grounded norm space over a fixed graph is finite")
    print(
        f"     toy graph: |effects| = {effect_count}, |prevents norms| = {norm_count}"
    )
    print("     has values (incl. one nested has) and transition states")
    print("     are graph references;")
    print("     finiteness comes from that grounding policy, not the grammar.")

    kernel_atoms = prove_projection_kernel_nonempty()
    print("\n[O3] Implemented observation projection is non-injective")
    for atom in sorted(kernel_atoms):
        print(f"     derived: {atom}")
    print("     w1 carries an SQL-error marker and a nested canary, w2 does not;")
    print("     both project to (unknown, constant summary, {rows: 0}).")

    rows = prove_input_space_unbounded(norm_count)
    print("\n[O4] Input space is unbounded, expression space is finite")
    print("     binary inputs by length:", rows)
    length, count = rows[-1]
    print(
        f"     at length {length}: |inputs| = {count} > |norms| = {norm_count};"
        " by pigeonhole the full map has an infinite kernel."
    )

    print("\nConclusion")
    print("-" * 60)
    print("The language is countably infinite; the graph-grounded norm space")
    print("is finite per graph; the behavior space is unbounded; and the")
    print("implemented projection already collapses received signal")
    print("(details, nested payloads). Blindness is therefore structural,")
    print("but its dimensions are nameable and hence shrinkable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
