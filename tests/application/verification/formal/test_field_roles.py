"""Accepted QDL field roles drive redaction and replay decisions."""

from __future__ import annotations

import json

from cloud_dast.contracts.finding_examples import is_replayable_check
from cloud_dast.infrastructure.jsonl import redact_json_payload
from cloud_dast.model import Check
from cloud_dast.qdl.field_roles import (
    FieldRoleDeficit,
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
    output_field,
)

ACTION = "action:get"


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _role_graph(*facts: Fact | tuple[Fact, Fact]) -> QdlGraph:
    action = Atom(value=ACTION)
    unique: dict[str, Fact] = {}
    for item in facts:
        for fact in item if isinstance(item, tuple) else (item,):
            unique.setdefault(fact.content_hash, fact)
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            *unique.values(),
        )
    )


def _input_role(
    field_name: str,
    role: str,
    *,
    context: Context = Context.ACCEPTED,
) -> tuple[Fact, Fact]:
    field = input_field(Atom(value=ACTION), Atom(value=field_name))
    return (
        _fact("is", (field, Atom(value="InputField")), context),
        _fact("has", (field, Atom(value=role)), context),
    )


def _output_role(
    field_name: str,
    role: str,
    *,
    context: Context = Context.ACCEPTED,
) -> tuple[Fact, Fact]:
    field = output_field(Atom(value=ACTION), Atom(value=field_name))
    return (
        _fact("is", (field, Atom(value="OutputField")), context),
        _fact("has", (field, Atom(value=role)), context),
    )


def test_object_ref_fact_retains_field_for_replay() -> None:
    policy = resolve_field_roles(_role_graph(_input_role("order_id", "object_ref")))

    assert policy.retains("get", "order_id", direction="input")
    assert policy.retains("action:get", "order_id", direction="input")
    assert policy.retained_fields("get") == frozenset({"order_id"})


def test_replay_safe_role_retains_output_field() -> None:
    policy = resolve_field_roles(_role_graph(_output_role("order.id", "replay_safe")))

    assert policy.retains("get", "order.id", direction="output")
    assert policy.retained_fields("get", direction="output") == frozenset({"order.id"})


def test_field_without_fact_is_redacted_and_reported_as_deficit() -> None:
    policy = resolve_field_roles(_role_graph(_input_role("order_id", "object_ref")))

    assert not policy.retains("get", "session_id", direction="input")
    assert policy.deficits(
        "get",
        ("order_id", "session_id"),
        direction="input",
    ) == (
        FieldRoleDeficit(
            action="get",
            direction="input",
            field="session_id",
        ),
    )


def test_credential_and_sensitive_roles_force_redaction_without_deficit() -> None:
    policy = resolve_field_roles(
        _role_graph(
            _input_role("api_key", "credential"),
            _input_role("order_id", "object_ref"),
            _input_role("order_id", "sensitive"),
        )
    )

    assert not policy.retains("get", "api_key", direction="input")
    assert not policy.retains("get", "order_id", direction="input")
    assert (
        policy.deficits(
            "get",
            ("api_key", "order_id"),
            direction="input",
        )
        == ()
    )


def test_proposal_context_role_facts_are_not_accepted() -> None:
    policy = resolve_field_roles(
        _role_graph(_input_role("order_id", "object_ref", context=Context.PROPOSAL))
    )

    assert not policy.retains("get", "order_id", direction="input")
    assert policy.deficits("get", ("order_id",), direction="input")


def test_superseded_role_is_not_current() -> None:
    old = _input_role("order_id", "setup_value")
    new = _input_role("order_id", "setup_skip")
    holder = old[0].args[0]
    old_node = Struct(name="replacement", args=(holder, Atom(value="setup_value")))
    new_node = Struct(name="replacement", args=(holder, Atom(value="setup_skip")))
    graph = _role_graph(
        *old,
        *new,
        _fact("is", (Atom(value="setup_value"), Atom(value="Role"))),
        _fact("is", (Atom(value="setup_skip"), Atom(value="Role"))),
        _fact("is", (old_node, Atom(value="Node"))),
        _fact("is", (new_node, Atom(value="Node"))),
        _fact("supersedes", (new_node, old_node)),
    )

    policy = resolve_field_roles(graph)

    assert policy.roles("get", "order_id", direction="input") == frozenset(
        {"setup_skip"}
    )
    assert not policy.retains("get", "order_id", direction="input")


def test_unknown_action_retains_nothing_and_reports_deficit() -> None:
    policy = resolve_field_roles(_role_graph(_input_role("order_id", "object_ref")))

    assert not policy.retains("delete", "order_id", direction="input")
    assert policy.retained_fields("delete") == frozenset()
    assert policy.deficits("delete", ("order_id",), direction="input")


def test_empty_policy_redacts_every_field() -> None:
    policy = FieldRolePolicy()

    assert not policy.retains("get", "order_id", direction="input")
    assert policy.retained_fields("get") == frozenset()
    assert policy.deficits("get", ("order_id",), direction="input")


def test_accepted_object_ref_restores_order_id_for_replay() -> None:
    """S12 acceptance: graph facts, not names, decide replay retention."""

    policy = resolve_field_roles(_role_graph(_input_role("order_id", "object_ref")))
    replayable = policy.retained_fields("get")
    check = Check(
        invariant_id="invariant",
        method_id="get",
        scenario_id="scenario",
        request=(
            ("order_id", "order-victim"),
            ("session_id", "session-secret"),
        ),
        identities=("attacker",),
    )

    assert not is_replayable_check(check, replayable_fields=replayable)
    assert is_replayable_check(
        check.model_copy(update={"request": (("order_id", "order-victim"),)}),
        replayable_fields=replayable,
    )
    payload = json.dumps(
        {
            "request": [
                ["order_id", "order-victim"],
                ["session_id", "session-secret"],
            ]
        }
    ).encode("utf-8")
    redacted = json.loads(redact_json_payload(payload, retained_fields=replayable))
    assert redacted["request"][0] == ["order_id", "order-victim"]
    assert redacted["request"][1][1].startswith("redacted:sha256:")
