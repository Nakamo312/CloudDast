from __future__ import annotations

from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import Context
from cloud_dast.qdl.policy_projection import (
    GenericPolicyProjector,
    PolicyApplication,
    PolicyBinding,
    PolicyContainment,
    PolicyGrant,
    PolicyOwnership,
    PolicyPermission,
    PolicyRequirement,
    PolicyResource,
    PolicySnapshot,
    PolicyTarget,
)


def fact_tuples(graph) -> set[tuple[object, ...]]:
    return {
        (fact.predicate.name, *(argument.value for argument in fact.args))
        for fact in graph.facts
    }


def permitted_atoms(snapshot: PolicySnapshot) -> set[str]:
    graph = GenericPolicyProjector(snapshot).project("billing")
    solution = ClingoEngine().solve(graph, algebra=True)[0]
    return {
        atom
        for atom in solution.atoms
        if atom.startswith('may("accepted","principal:alice","action:approve"')
    }


def test_policy_projection_emits_may_family_facts() -> None:
    snapshot = PolicySnapshot(
        permissions=(PolicyPermission("alice", "approve", "invoice-1"),),
        bindings=(PolicyBinding("alice", "approver", "tenant-a"),),
        grants=(PolicyGrant("approver", "invoice.approve"),),
        requirements=(PolicyRequirement("approve", "invoice.approve"),),
        applications=(PolicyApplication("invoice.approve", "invoice"),),
        targets=(PolicyTarget("approve", "invoice"),),
        ownerships=(PolicyOwnership("invoice-1", "alice"),),
        resources=(PolicyResource("invoice-1", "invoice"),),
        containments=(PolicyContainment("invoice-1", "tenant-a"),),
    )

    graph = GenericPolicyProjector(snapshot).project("billing")
    facts = fact_tuples(graph)

    assert ("may", "principal:alice", "action:approve", "resource:invoice-1") in facts
    assert ("binding", "principal:alice", "role:approver", "scope:tenant-a") in facts
    assert ("grants", "role:approver", "permission:invoice.approve") in facts
    assert ("requires", "action:approve", "permission:invoice.approve") in facts
    assert ("applies_to", "permission:invoice.approve", "resource:invoice") in facts
    assert ("targets", "action:approve", "resource:invoice") in facts
    assert ("owner", "resource:invoice-1", "principal:alice") in facts
    assert ("is", "principal:alice", "Subject") in facts
    assert ("is", "action:approve", "Action") in facts
    assert ("is", "resource:invoice-1", "Resource") in facts
    assert ("is", "resource:invoice-1", "resource:invoice") in facts
    assert ("is", "resource:invoice", "ResourceType") in facts
    assert ("part", "resource:invoice-1", "scope:tenant-a") in facts
    assert all(fact.context is Context.ACCEPTED for fact in graph.facts)


def test_policy_projection_accepts_arbitrary_identifiers() -> None:
    snapshot = PolicySnapshot(
        permissions=(
            PolicyPermission(
                "team:payments",
                "workflow:release",
                "environment:production",
            ),
        )
    )

    facts = fact_tuples(GenericPolicyProjector(snapshot).project("custom"))

    assert (
        "may",
        "principal:team:payments",
        "action:workflow:release",
        "resource:environment:production",
    ) in facts


def test_policy_projection_deduplicates_facts() -> None:
    permission = PolicyPermission("alice", "approve", "invoice-1")
    snapshot = PolicySnapshot(permissions=(permission, permission))

    graph = GenericPolicyProjector(snapshot).project("billing")
    may_facts = [fact for fact in graph.facts if fact.predicate.name == "may"]

    assert len(may_facts) == 1


def test_resource_scope_is_not_renamed_to_a_generic_scope() -> None:
    snapshot = PolicySnapshot(
        bindings=(PolicyBinding("alice", "approver", "invoice-1"),),
        resources=(PolicyResource("invoice-1", "invoice"),),
    )

    facts = fact_tuples(GenericPolicyProjector(snapshot).project("billing"))

    assert (
        "binding",
        "principal:alice",
        "role:approver",
        "resource:invoice-1",
    ) in facts
    assert ("is", "resource:invoice-1", "Scope") in facts


def test_rbac_policy_derives_the_common_may_interface() -> None:
    snapshot = PolicySnapshot(
        bindings=(PolicyBinding("alice", "approver", "invoice-1"),),
        grants=(PolicyGrant("approver", "invoice.approve"),),
        requirements=(PolicyRequirement("approve", "invoice.approve"),),
        applications=(PolicyApplication("invoice.approve", "invoice"),),
        targets=(PolicyTarget("approve", "invoice"),),
        resources=(PolicyResource("invoice-1", "invoice"),),
    )

    assert permitted_atoms(snapshot) == {
        'may("accepted","principal:alice","action:approve","resource:invoice-1")'
    }


def test_dac_policy_derives_the_common_may_interface() -> None:
    snapshot = PolicySnapshot(
        requirements=(PolicyRequirement("approve", "invoice.approve"),),
        applications=(PolicyApplication("invoice.approve", "invoice"),),
        targets=(PolicyTarget("approve", "invoice"),),
        ownerships=(PolicyOwnership("invoice-1", "alice"),),
        resources=(PolicyResource("invoice-1", "invoice"),),
    )

    assert permitted_atoms(snapshot) == {
        'may("accepted","principal:alice","action:approve","resource:invoice-1")'
    }


def test_mac_policy_normalizes_to_the_common_may_interface() -> None:
    snapshot = PolicySnapshot(
        permissions=(PolicyPermission("alice", "approve", "invoice-1"),),
    )

    assert permitted_atoms(snapshot) == {
        'may("accepted","principal:alice","action:approve","resource:invoice-1")'
    }
