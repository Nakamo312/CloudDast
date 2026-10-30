from __future__ import annotations

import pytest

from cloud_dast.model import (
    AccessOutcome,
    Observation,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.verification.evidence import (
    build_evidence_view,
)
from cloud_dast.verification.slices import (
    SiblingAction,
    SliceBudget,
    build_sibling_action_slice,
    build_slice,
    estimate_tokens,
)


def _fact(predicate: str, *args: object) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _build_graph() -> QdlGraph:
    """Three isolated actions plus a two-hop chain under ``action:get-0``."""

    facts = []
    for index in range(3):
        action = Atom(value=f"action:get-{index}")
        permission = Atom(value=f"permission:get-{index}")
        facts.extend(
            (
                _fact("is", action, Atom(value="Action")),
                _fact("is", permission, Atom(value="Permission")),
                _fact("requires", action, permission),
            )
        )
    action = Atom(value="action:get-0")
    resource = Atom(value="resource:user-0")
    owner = Atom(value="principal:admin")
    facts.extend(
        (
            _fact("is", resource, Atom(value="Resource")),
            _fact("is", owner, Atom(value="Principal")),
            _fact("targets", action, resource),
            _fact("owner", resource, owner),
        )
    )
    return QdlGraph(facts=tuple(facts))


def _evidence(summary: str) -> object:
    return build_evidence_view(
        observation=Observation(
            check_id="check-1",
            scenario_id="scenario",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary=summary,
        )
    )


def _action_values(graph: QdlGraph) -> set[str]:
    return {
        fact.args[0].value
        for fact in graph.facts
        if fact.predicate.name == "is"
        and len(fact.args) == 2
        and fact.args[1].value == "Action"
    }


def _has_owner_fact(graph: QdlGraph) -> bool:
    return any(fact.predicate.name == "owner" for fact in graph.facts)


def test_build_slice_never_includes_unrelated_actions() -> None:
    result = build_slice(_build_graph(), actions=("action:get-0",))

    assert _action_values(result.graph) == {"action:get-0"}
    assert not any(
        "get-1" in canonical_json(fact) or "get-2" in canonical_json(fact)
        for fact in result.graph.facts
    )


def test_build_slice_is_bounded_by_depth() -> None:
    graph = _build_graph()

    shallow = build_slice(
        graph,
        actions=("action:get-0",),
        budget=SliceBudget(max_depth=1),
    )
    deep = build_slice(
        graph,
        actions=("action:get-0",),
        budget=SliceBudget(max_depth=2),
    )

    assert not _has_owner_fact(shallow.graph)
    assert shallow.depth == 1
    assert _has_owner_fact(deep.graph)
    assert deep.depth == 2


def test_build_slice_is_bounded_by_tokens() -> None:
    graph = _build_graph()
    full = build_slice(graph, actions=("action:get-0",))
    budget = SliceBudget(max_tokens=full.token_estimate // 2, max_depth=1)

    result = build_slice(graph, actions=("action:get-0",), budget=budget)

    assert result.truncated
    assert result.token_estimate <= budget.max_tokens
    assert len(result.graph.facts) < len(full.graph.facts)


def test_build_slice_is_deterministic_and_stably_ordered() -> None:
    graph = _build_graph()

    first = build_slice(graph, actions=("action:get-0",))
    second = build_slice(graph, actions=("get-0",))
    third = build_slice(
        QdlGraph(facts=tuple(reversed(graph.facts))),
        actions=("action:get-0",),
    )

    assert first.slice_hash == second.slice_hash == third.slice_hash
    assert first.graph == second.graph == third.graph
    assert [canonical_json(fact) for fact in first.graph.facts] == sorted(
        canonical_json(fact) for fact in first.graph.facts
    )


def test_build_slice_includes_runtime_evidence_in_hash_and_context() -> None:
    graph = _build_graph()
    evidence = _evidence("first response")

    with_evidence = build_slice(graph, actions=("action:get-0",), evidence=evidence)
    same_evidence = build_slice(graph, actions=("action:get-0",), evidence=evidence)
    changed = build_slice(
        graph,
        actions=("action:get-0",),
        evidence=_evidence("second response"),
    )

    assert with_evidence.slice_hash == same_evidence.slice_hash
    assert with_evidence.slice_hash != changed.slice_hash
    assert with_evidence.context()["evidence"] == evidence.to_dict()
    assert "first response" in str(with_evidence.context())
    assert "evidence" not in build_slice(graph, actions=("action:get-0",)).context()


def test_build_slice_evidence_shares_the_token_budget() -> None:
    graph = _build_graph()
    evidence = _evidence("first response")
    evidence_tokens = estimate_tokens(
        {"graph": QdlGraph().model_dump(mode="json"), "evidence": evidence.to_dict()}
    )
    budget = SliceBudget(max_tokens=evidence_tokens + 1, max_depth=1)

    result = build_slice(
        graph, actions=("action:get-0",), evidence=evidence, budget=budget
    )

    # Evidence is never dropped; the graph shrinks to nothing instead.
    assert result.graph.facts == ()
    assert result.truncated
    assert (
        result.token_estimate == estimate_tokens(result.context()) <= budget.max_tokens
    )
    with pytest.raises(ValueError, match="evidence exceeds token budget"):
        build_slice(
            graph,
            actions=("action:get-0",),
            evidence=evidence,
            budget=SliceBudget(max_tokens=evidence_tokens - 1),
        )


def test_build_slice_rejects_invalid_budget() -> None:
    with pytest.raises(ValueError, match="max_tokens"):
        SliceBudget(max_tokens=0)
    with pytest.raises(ValueError, match="max_depth"):
        SliceBudget(max_depth=0)
    with pytest.raises(ValueError, match="bytes_per_token"):
        SliceBudget(bytes_per_token=0)


def _sibling_graph() -> QdlGraph:
    """One seed action, four relation siblings, and two outsiders.

    ``action:patch`` shares the seed's effect, ``action:admin`` its
    permission, ``action:read`` its target term, and ``action:audit`` only
    its resource type.  ``action:logout`` shares nothing, and
    ``action:nested`` is only mentioned inside the shared effect struct.
    """

    def action(name: str) -> Atom:
        return Atom(value=f"action:{name}")

    seed = action("update")
    effect = Struct(
        name="changed",
        args=(Atom(value="resource:secret"), Atom(value="total")),
    )
    nested_effect = Struct(
        name="changed",
        args=(action("nested"), Atom(value="note")),
    )
    permission = Atom(value="permission:manage")
    secret = Atom(value="resource:secret")
    one = Atom(value="resource:one")
    other = Atom(value="resource:other")
    secret_type = Atom(value="lockbox.secret")
    disk_type = Atom(value="compute.disk")
    facts = [
        *(
            _fact("is", atom_, Atom(value="Action"))
            for atom_ in (
                seed,
                action("patch"),
                action("admin"),
                action("read"),
                action("audit"),
                action("logout"),
                action("nested"),
            )
        ),
        _fact("is", effect, Atom(value="Effect")),
        _fact("is", nested_effect, Atom(value="Effect")),
        _fact("is", permission, Atom(value="Permission")),
        _fact("is", secret, Atom(value="Resource")),
        _fact("is", one, Atom(value="Resource")),
        _fact("is", other, Atom(value="Resource")),
        _fact("is", secret_type, Atom(value="ResourceType")),
        _fact("is", disk_type, Atom(value="ResourceType")),
        _fact("is", secret, secret_type),
        _fact("is", one, secret_type),
        _fact("is", other, disk_type),
        _fact("causes", seed, effect),
        _fact("causes", action("patch"), effect),
        _fact("causes", action("logout"), nested_effect),
        _fact("requires", seed, permission),
        _fact("requires", action("admin"), permission),
        _fact("targets", seed, secret),
        _fact("targets", action("read"), secret),
        _fact("targets", action("audit"), one),
        _fact("targets", action("logout"), other),
    ]
    return QdlGraph(facts=tuple(facts))


def _declared_actions(graph: QdlGraph) -> set[str]:
    return {
        fact.args[0].value
        for fact in graph.facts
        if fact.predicate.name == "is"
        and len(fact.args) == 2
        and fact.args[1].value == "Action"
    }


def test_sibling_slice_selects_only_qdl_related_actions() -> None:
    result = build_sibling_action_slice(_sibling_graph(), action="action:update")

    assert result.action == "action:update"
    assert [(sibling.action, sibling.relations) for sibling in result.siblings] == [
        ("action:admin", ("requires",)),
        ("action:audit", ("resource_type",)),
        ("action:patch", ("causes",)),
        ("action:read", ("targets",)),
    ]
    assert "action:logout" not in _declared_actions(result.graph)
    # The nested action belongs only to an outsider's unselected effect.
    assert "action:nested" not in _declared_actions(result.graph)
    # This fixture needs no extra supporting action declarations.
    assert _declared_actions(result.graph) == {
        "action:update",
        "action:admin",
        "action:audit",
        "action:patch",
        "action:read",
    }


@pytest.mark.parametrize("reference", [False, True])
def test_sibling_slice_closes_references_without_expanding_participants(reference):
    seed, sibling, support, overflow = (
        Atom(value=f"action:{name}") for name in ("a", "b", "c", "d")
    )
    resource = Atom(value="resource:item")
    effect = (
        Struct(name="allowed", args=(support,))
        if reference
        else Struct(name="changed", args=(resource, support))
    )
    graph = QdlGraph(
        facts=(
            *(
                _fact("is", action, Atom(value="Action"))
                for action in (seed, sibling, support, overflow)
            ),
            _fact("is", resource, Atom(value="Resource")),
            _fact("is", effect, Atom(value="Effect")),
            *(_fact("causes", action, effect) for action in (seed, sibling, overflow)),
        )
    )
    result = build_sibling_action_slice(graph, action=seed.value, max_siblings=1)
    assert result.truncated
    assert [entry.action for entry in result.siblings] == [sibling.value]
    expected = {seed.value, sibling.value}
    if reference:
        expected.add(support.value)
    assert _declared_actions(result.graph) == expected
    assert support.value not in {
        result.action,
        *(entry.action for entry in result.siblings),
    }
    assert QdlGraph.model_validate_json(result.graph.model_dump_json()) == result.graph
    assert _fact("causes", seed, effect) in result.graph.facts
    assert _fact("causes", sibling, effect) in result.graph.facts


def test_sibling_slice_justifications_are_verifiable() -> None:
    graph = _sibling_graph()
    result = build_sibling_action_slice(graph, action="action:update")

    sibling_by_action = {sibling.action: sibling for sibling in result.siblings}
    shared_effect = canonical_json(
        next(
            fact.args[1]
            for fact in graph.facts
            if fact.predicate.name == "causes" and fact.args[0].value == "action:update"
        )
    )
    assert sibling_by_action["action:patch"].shared_terms == (shared_effect,)
    assert sibling_by_action["action:admin"].shared_terms == (
        canonical_json(Atom(value="permission:manage")),
    )
    assert sibling_by_action["action:read"].shared_terms == (
        canonical_json(Atom(value="resource:secret")),
    )
    assert sibling_by_action["action:audit"].shared_terms == (
        canonical_json(Atom(value="lockbox.secret")),
    )
    # The resource-type chain is self-contained in the slice graph.
    graph_json = [canonical_json(fact) for fact in result.graph.facts]
    assert (
        canonical_json(
            _fact("targets", Atom(value="action:audit"), Atom(value="resource:one"))
        )
        in graph_json
    )
    assert (
        canonical_json(
            _fact(
                "is",
                Atom(value="resource:one"),
                Atom(value="lockbox.secret"),
            )
        )
        in graph_json
    )
    assert (
        canonical_json(
            _fact("is", Atom(value="lockbox.secret"), Atom(value="ResourceType"))
        )
        in graph_json
    )


def test_sibling_slice_is_deterministic_and_alias_stable() -> None:
    graph = _sibling_graph()

    first = build_sibling_action_slice(graph, action="action:update")
    alias = build_sibling_action_slice(graph, action="update")
    reordered = build_sibling_action_slice(
        QdlGraph(facts=tuple(reversed(graph.facts))),
        action="action:update",
    )

    assert first == alias == reordered
    assert first.slice_hash
    assert [canonical_json(fact) for fact in first.graph.facts] == sorted(
        canonical_json(fact) for fact in first.graph.facts
    )


def test_sibling_slice_shared_target_does_not_duplicate_resource_type() -> None:
    seed = Atom(value="action:get")
    sibling = Atom(value="action:list")
    resource_type = Atom(value="resource:lockbox.secret")
    graph = QdlGraph(
        facts=(
            _fact("is", seed, Atom(value="Action")),
            _fact("is", sibling, Atom(value="Action")),
            _fact("is", resource_type, Atom(value="ResourceType")),
            _fact("targets", seed, resource_type),
            _fact("targets", sibling, resource_type),
        )
    )

    result = build_sibling_action_slice(graph, action="action:get")

    assert result.siblings == (
        SiblingAction(
            action="action:list",
            relations=("targets",),
            shared_terms=(canonical_json(resource_type),),
        ),
    )


def test_sibling_slice_undeclared_seed_returns_empty_slice() -> None:
    result = build_sibling_action_slice(_sibling_graph(), action="action:unknown")

    assert result.action == ""
    assert result.siblings == ()
    assert result.graph.facts == ()
    assert not result.truncated
    assert result.slice_hash


def test_sibling_slice_caps_siblings_deterministically() -> None:
    graph = _sibling_graph()

    result = build_sibling_action_slice(
        graph,
        action="action:update",
        max_siblings=2,
    )

    assert result.truncated
    assert [sibling.action for sibling in result.siblings] == [
        "action:admin",
        "action:audit",
    ]
    # This truncated fixture needs no extra reference declarations.
    assert _declared_actions(result.graph) == {
        "action:update",
        "action:admin",
        "action:audit",
    }


def test_sibling_slice_rejects_invalid_max_siblings() -> None:
    with pytest.raises(ValueError, match="max_siblings"):
        build_sibling_action_slice(
            _sibling_graph(),
            action="action:update",
            max_siblings=0,
        )
