import pytest

from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.runtime.identity_projection import IdentityView, derive_identities


def _fact(context: Context, predicate: str, *args: str) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=tuple(Atom(value=value) for value in args),
    )


def test_identity_projection_uses_only_executable_qdl_contexts() -> None:
    graph = QdlGraph(
        facts=(
            _fact(Context.CONTRACT, "is", "principal:attacker", "Subject"),
            _fact(Context.CONTRACT, "attacker", "principal:attacker"),
            _fact(Context.CONTRACT, "is", "action:read", "Action"),
            _fact(Context.CONTRACT, "is", "resource:item", "Resource"),
            _fact(
                Context.CONTRACT,
                "may",
                "principal:owner",
                "action:read",
                "resource:item",
            ),
            _fact(Context.CONTRACT, "is", "principal:owner", "Subject"),
            _fact(Context.CONTRACT, "owner", "resource:item", "principal:owner"),
            _fact(Context.CONTRACT, "targets", "action:read", "resource:item"),
            _fact(Context.PROPOSAL, "is", "principal:proposal", "Subject"),
            _fact(Context.PROPOSAL, "attacker", "principal:proposal"),
            _fact(Context.RUNTIME, "is", "principal:runtime", "Subject"),
            _fact(Context.RUNTIME, "attacker", "principal:runtime"),
        )
    )

    identities = derive_identities(graph)

    assert identities.subjects_for("read") == ("attacker", "owner")
    assert "proposal" not in identities.attackers
    assert "runtime" not in identities.attackers


def _project(context: Context, rows: tuple[tuple[object, ...], ...]) -> IdentityView:
    # Construct directly to cover legacy arities and malformed persisted terms,
    # including forms that current QDL admission rejects before projection.
    facts = tuple(
        Fact.model_construct(
            context=context,
            predicate=Predicate.from_name(name),
            args=tuple(Atom(value=value) for value in args),
        )
        for name, *args in rows
    )
    return derive_identities(QdlGraph.model_construct(facts=facts))


@pytest.mark.parametrize("context", list(Context))
def test_identity_policy_preserves_full_view(context: Context) -> None:
    identities = _project(
        context,
        (
            ("attacker", "principal:z"),
            ("attacker", "subject:a"),
            ("attacker", "a"),
            ("attacker", "undeclared"),
            ("may", "principal:m", "action:read", "resource:item"),
            ("may", "policy:rule", "subject:a", "read", "resource:other"),
            ("may", "undeclared", "action:read", "resource:item"),
            ("owner", "resource:unrelated", "subject:o"),
            ("owner", "resource:item", "undeclared"),
            ("targets", "action:read", "resource:item"),
            ("targets", "action:write", "resource:other"),
            ("is", "principal:z", "Subject"),
            ("is", "a", "Subject"),
            ("is", "subject:m", "Subject"),
            ("is", "principal:o", "Subject"),
        ),
    )

    if context not in (Context.CONTRACT, Context.ACCEPTED):
        assert identities == IdentityView()
        return
    assert identities == IdentityView(
        attackers=("a", "z"),
        by_action={"read": ("a", "m", "o"), "write": ("o",)},
    )
    assert identities.subjects_for("action:read") == ("a", "z", "m", "o")
    assert identities.subjects_for("missing") == ("a", "z")


@pytest.mark.parametrize("value", ["", "principal:", "subject:", 0, False])
def test_identity_policy_ignores_empty_or_non_string_subjects(value: object) -> None:
    assert _project(
        Context.CONTRACT,
        (
            ("is", value, "Subject"),
            ("attacker", value),
            ("may", value, "action:read", "resource:item"),
            ("may", "rule", value, "action:read", "resource:item"),
            ("owner", "resource:item", value),
            ("targets", "action:read", "resource:item"),
        ),
    ) == IdentityView(by_action={"read": ()})


@pytest.mark.parametrize("value", ["", "action:", 0, False])
def test_identity_policy_ignores_empty_or_non_string_actions(value: object) -> None:
    assert (
        _project(
            Context.ACCEPTED,
            (
                ("is", "owner", "Subject"),
                ("owner", "resource:item", "owner"),
                ("may", "owner", value, "resource:item"),
                ("may", "rule", "owner", value, "resource:item"),
                ("targets", value, "resource:item"),
            ),
        )
        == IdentityView()
    )


def test_identity_policy_ignores_other_types_and_wrong_arities() -> None:
    assert (
        _project(
            Context.CONTRACT,
            (
                ("is", "not_subject", "Action"),
                ("attacker", "not_subject"),
                ("is", "subject", "Subject"),
                ("is", "extra", "Subject", "extra"),
                ("attacker",),
                ("attacker", "subject", "extra"),
                ("owner", "subject"),
                ("owner", "resource:item", "subject", "extra"),
                ("may", "subject", "action:read"),
                ("may", "rule", "subject", "action:read", "item", "extra"),
                ("targets", "action:read"),
                ("targets", "action:read", "resource:item", "extra"),
            ),
        )
        == IdentityView()
    )


def test_identity_policy_keeps_target_without_declared_owners() -> None:
    assert _project(
        Context.CONTRACT,
        (("targets", "action:read", "resource:item"),),
    ) == IdentityView(by_action={"read": ()})


def test_identity_policy_joins_declarations_across_executable_contexts() -> None:
    graph = QdlGraph(
        facts=(
            _fact(Context.ACCEPTED, "is", "principal:owner", "Subject"),
            _fact(Context.CONTRACT, "is", "action:read", "Action"),
            _fact(Context.CONTRACT, "is", "resource:item", "Resource"),
            _fact(Context.CONTRACT, "is", "resource:other", "Resource"),
            _fact(Context.CONTRACT, "attacker", "principal:owner"),
            _fact(Context.CONTRACT, "owner", "resource:item", "principal:owner"),
            _fact(Context.ACCEPTED, "targets", "action:read", "resource:other"),
            _fact(Context.PROPOSAL, "is", "principal:excluded", "Subject"),
            _fact(Context.CONTRACT, "attacker", "principal:excluded"),
        ),
    )

    assert derive_identities(graph) == IdentityView(
        attackers=("owner",), by_action={"read": ("owner",)}
    )
