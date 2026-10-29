"""Clingo query rules used by the pure QDL planner."""

from __future__ import annotations

from cloud_dast.couplings import COUPLED_OPERATORS
from cloud_dast.qdl.graph import CAUSAL_EFFECT_CONSTRUCTORS, STRUCT_SCHEMAS, Context

_EFFECT_EDGE_RULE = (
    "_qdl_effect_edge(C,A,B,Effect) :- "
    "current_effect(P,A,Effect), requires(R,B,Effect), _qdl_context(P,R,C)."
)
_REVEAL_EDGE_RULE = (
    "_qdl_reveal_edge(C,A,B,T,W) :- "
    "current_effect(P,A,create(T)), exposes(E,B,W), "
    'current_has(H,W,"object_ref"), refers_to(R,W,T), '
    "_qdl_context(P,E,PE), _qdl_context(PE,H,PEH), _qdl_context(PEH,R,C), "
    "_qdl_action(C,A), _qdl_action(C,B)."
)

# Query-local context composition: trusted premises share a type universe,
# while any accepted dependency makes the derived path accepted. Other contexts
# remain isolated. These are ASP query atoms, never persisted QDL predicates.
_CONTEXT_RULES = tuple(
    f'_qdl_context("{left}","{right}","{result}").'
    for left, right, result in (
        *((context, context, context) for context in Context),
        (Context.CONTRACT, Context.ACCEPTED, Context.ACCEPTED),
        (Context.ACCEPTED, Context.CONTRACT, Context.ACCEPTED),
    )
)
_CHAIN_RULES = (
    # Replace the context-local chain query in this execution projection.
    # current_effect still resolves supersession in the producer's context;
    # composing contexts here never rewrites persisted causes/requires facts.
    "chain_plus(C,A,B) :- _qdl_effect_edge(C,A,B,_).",
    "chain_plus(C,A,B) :- chain_plus(P,A,Middle), "
    "_qdl_effect_edge(R,Middle,B,_), _qdl_context(P,R,C).",
)

# Query-local conjunction composition. Prefixes contain distinct action
# occurrences and grow only to qdl_max_depth producers plus the final consumer.
# The ordinary walks below still carry cyclic/partial diagnostic routes.
# A requirement is one ground term: alternative producers satisfy the same
# term (OR), while every different requirement must be available (AND).
# Availability here is prospective in the plan, never observed runtime proof.
_AND_WALK_RULES = """
_qdl_premise(U,P) :- _qdl_context(U,P,U).
_qdl_dependency(P,A,B,effect(E)) :- _qdl_effect_edge(P,A,B,E).
_qdl_dependency(P,A,B,value(A,B)) :- _qdl_value_edge(P,A,B).
_qdl_requirement(U,A,effect(E)) :- requires(P,A,E), is(D,E,"Effect"),
    _qdl_premise(U,P), _qdl_premise(U,D).
_qdl_requirement(U,B,value(A,B)) :- _qdl_value_edge(P,A,B), _qdl_premise(U,P).
_qdl_join_goal(U,G) :- _qdl_dependency(P,A,G,E), _qdl_dependency(R,B,G,F),
    _qdl_premise(U,P), _qdl_premise(U,R), A != B, E != F, _qdl_action(U,G).
_qdl_join_goal(U,G) :- _qdl_join_goal(U,A), _qdl_dependency(P,A,G,_),
    _qdl_premise(U,P), _qdl_action(U,G).
_qdl_relevant(U,G,G) :- _qdl_join_goal(U,G).
_qdl_relevant(U,G,A) :- _qdl_relevant(U,G,B), _qdl_dependency(P,A,B,_),
    _qdl_premise(U,P), _qdl_action(U,A).
_qdl_prefix(U,G,nil,0) :- _qdl_join_goal(U,G).
_qdl_list(W) :- _qdl_prefix(_,_,W,_).
_qdl_list(W) :- _qdl_complete_walk(_,_,W,_).
_qdl_contains(cons(A,W),A) :- _qdl_list(cons(A,W)).
_qdl_contains(cons(A,W),B) :- _qdl_list(cons(A,W)), _qdl_contains(W,B).
_qdl_available(U,W,effect(E)) :- _qdl_list(W), _qdl_contains(W,A),
    current_effect(P,A,E), _qdl_premise(U,P).
_qdl_available(U,W,value(A,B)) :- _qdl_list(W), _qdl_contains(W,A),
    _qdl_value_edge(P,A,B), _qdl_premise(U,P).
_qdl_missing(U,G,W,A) :- _qdl_prefix(U,G,W,_), _qdl_relevant(U,G,A),
    _qdl_requirement(U,A,E), not _qdl_available(U,W,E).
_qdl_prefix(U,G,cons(A,W),N+1) :- _qdl_prefix(U,G,W,N),
    _qdl_relevant(U,G,A), A != G, not _qdl_contains(W,A),
    not _qdl_missing(U,G,W,A), N < qdl_max_depth.
_qdl_complete_walk(U,G,cons(G,W),N) :- _qdl_prefix(U,G,W,N), N > 0,
    not _qdl_missing(U,G,W,G).
_qdl_before(cons(B,W),A,B) :- _qdl_list(cons(B,W)), _qdl_contains(W,A).
_qdl_before(cons(B,W),A,D) :- _qdl_list(cons(B,W)), _qdl_before(W,A,D).
_qdl_support(U,W,A,B,E,P) :- _qdl_complete_walk(U,_,W,_),
    _qdl_before(W,A,B), _qdl_dependency(P,A,B,E), _qdl_premise(U,P).
_qdl_competing(U,W,A,B,E) :- _qdl_support(U,W,A,B,E,_),
    _qdl_support(U,W,D,B,E,_), A != D.
_qdl_useful(U,W,A) :- _qdl_support(U,W,A,B,E,_),
    not _qdl_competing(U,W,A,B,E).
_qdl_redundant(U,W) :- _qdl_complete_walk(U,G,W,_), _qdl_contains(W,A),
    A != G, not _qdl_useful(U,W,A).
_qdl_accepted_support(U,W) :- _qdl_support(U,W,_,_,_,"accepted").
_qdl_walk_context(U,W,U) :- _qdl_complete_walk(U,_,W,_), U != "accepted".
_qdl_walk_context("accepted",W,"accepted") :-
    _qdl_complete_walk("accepted",_,W,_), _qdl_accepted_support("accepted",W).
_qdl_walk_context("accepted",W,"contract") :-
    _qdl_complete_walk("accepted",_,W,_), not _qdl_accepted_support("accepted",W).
_qdl_and_walk(C,W,N) :- _qdl_complete_walk(U,_,W,N),
    not _qdl_redundant(U,W), _qdl_walk_context(U,W,C).

% Ordinary walks store the source outside their reverse-cons tail. Lower them
% to full occurrence lists before checking nominal support, including repeats.
_qdl_walk_tail(A,W) :- _qdl_walk(_,A,_,W,_).
_qdl_walk_tail(A,T) :- _qdl_walk_tail(A,cons(_,T)).
_qdl_add_source(A,nil,cons(A,nil)) :- _qdl_walk_tail(A,nil).
_qdl_add_source(A,cons(B,T),cons(B,F)) :- _qdl_walk_tail(A,cons(B,T)),
    _qdl_add_source(A,T,F).
_qdl_full_walk(C,F,N) :- _qdl_walk(C,A,_,W,N), _qdl_add_source(A,W,F).
_qdl_full_walk(C,W,N) :- _qdl_and_walk(C,W,N).
_qdl_list(W) :- _qdl_full_walk(_,W,_).
_qdl_list(T) :- _qdl_list(cons(_,T)).
_qdl_step_prefix(cons(A,T),A,T) :- _qdl_list(cons(A,T)).
_qdl_step_prefix(cons(A,T),B,P) :- _qdl_list(cons(A,T)), _qdl_step_prefix(T,B,P).
_qdl_support_scope("contract","accepted").
_qdl_support_scope("accepted","accepted").
_qdl_support_scope(C,C) :- _qdl_context(C,C,C), C != "contract", C != "accepted".
_qdl_path_missing(C,W) :- _qdl_full_walk(C,W,_), _qdl_support_scope(C,U),
    _qdl_step_prefix(W,A,P), _qdl_requirement(U,A,E), not _qdl_available(U,P,E).
_qdl_supported_walk(C,W) :- _qdl_full_walk(C,W,_), not _qdl_path_missing(C,W).
"""

# Bounded walk derivation over chain edges.  The walk is a rule, not a
# per-pair procedure: every newly grounded fact flows into the next solve
# and new/changed walks appear as new model atoms with content-addressed
# path identities.
_WALK_RULES: tuple[str, ...] = (
    *_CONTEXT_RULES,
    '_qdl_action(C,A) :- is(D,A,"Action"), _qdl_context(C,D,_).',
    _EFFECT_EDGE_RULE,
    _REVEAL_EDGE_RULE,
    # Output/input dependencies follow the exposed value's producer. Input/input
    # constraints belong to joint generation and impose no invocation order.
    # These edges neither establish a value nor prove a causal effect.
    *(
        f'_qdl_coupling_operator("{operator}").'
        for operator in sorted(COUPLED_OPERATORS)
    ),
    "_qdl_value_edge(C,A,B) :- "
    "coupled(P,output_field(A,F),input_field(B,G),Op), "
    "exposes(E,A,output_field(A,F)), _qdl_coupling_operator(Op), "
    "_qdl_context(P,E,C), _qdl_action(C,A), _qdl_action(C,B), A != B.",
    "_qdl_value_edge(C,A,B) :- "
    "coupled(P,input_field(B,G),output_field(A,F),Op), "
    "exposes(E,A,output_field(A,F)), _qdl_coupling_operator(Op), "
    "_qdl_context(P,E,C), _qdl_action(C,A), _qdl_action(C,B), A != B.",
    "_qdl_edge(C,A,B) :- _qdl_effect_edge(C,A,B,_).",
    "_qdl_edge(C,A,B) :- _qdl_reveal_edge(C,A,B,_,_), A != B.",
    "_qdl_edge(C,A,B) :- _qdl_value_edge(C,A,B).",
    "_qdl_walk(C,A,B,cons(B,nil),1) :- _qdl_edge(C,A,B), "
    "_qdl_action(C,A), _qdl_action(C,B).",
    "_qdl_walk(C,A,B,cons(B,Walk),Depth+1) :- "
    "_qdl_walk(P,A,Middle,Walk,Depth), _qdl_edge(R,Middle,B), "
    "_qdl_action(R,B), _qdl_context(P,R,C), Depth < qdl_max_depth.",
    # Kernel constructor terms remain causal even without an explicit Effect
    # classification. Permission requirements never become achieved effects.
    *(
        f"_qdl_requirement(U,A,effect({pattern})) :- "
        f"requires(P,A,{pattern}), _qdl_premise(U,P)."
        for schema in STRUCT_SCHEMAS
        if schema.name in CAUSAL_EFFECT_CONSTRUCTORS
        for arity in range(len(schema.arguments), len(schema.all_arguments) + 1)
        for pattern in (
            f"{schema.name}({','.join(f'X{index}' for index in range(arity))})",
        )
    ),
    _AND_WALK_RULES,
)
