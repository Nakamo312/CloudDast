from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import commit_branch

"""Learning F1: bounded sibling requests and promotion share their scope."""

import json
from pathlib import Path

import pytest

import cloud_dast
from cloud_dast.ports import ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.runtime.grounding.axis import Grounder
from cloud_dast.verification.promotion import PromotionPolicy


def fact(name, *args, context=Context.CONTRACT):
    return Fact(context=context, predicate=Predicate.from_name(name), args=args)


A, B, C = (Atom(value=f"action:{name}") for name in ("blocked", "sibling", "other"))
RESOURCE = Atom(value="resource:object")
EFFECT = changed(RESOURCE, Atom(value="state"))


class Repository:
    def __init__(self, source):
        self.graphs = {"contract:svc": source}
        self.saved = []

    def load(self, key):
        return self.graphs.get(key, QdlGraph())

    def load_merged(self, prefix):
        return merge_graphs(
            *(g for k, g in self.graphs.items() if k.startswith(prefix))
        )

    def save(self, key, graph, **kwargs):
        self.graphs[key] = graph
        self.saved.append((key, graph))


class Client:
    def __init__(self, proposal):
        self.payload = {
            "context": "proposal",
            "facts": [f.model_dump(mode="json") for f in proposal.facts],
            "rules": [],
        }
        self.requests = []

    def complete(self, request, **kwargs):
        self.requests.append(request)
        return ModelResponse(structured=self.payload, content=json.dumps(self.payload))


def branch_service(action, *, sibling_context=Context.CONTRACT):
    # An unrelated action is declared in the same service. Only B targets R.
    source = QdlGraph(
        facts=(
            *(fact("is", a, Atom(value="Action")) for a in (A, B, C)),
            fact("is", RESOURCE, Atom(value="Resource")),
            fact("targets", A, RESOURCE),
            fact("targets", B, RESOURCE, context=sibling_context),
        )
    )
    proposal = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action"), context=Context.PROPOSAL),
            fact("is", RESOURCE, Atom(value="Resource"), context=Context.PROPOSAL),
            fact("is", EFFECT, Atom(value="Effect"), context=Context.PROPOSAL),
            fact("causes", action, EFFECT, context=Context.PROPOSAL),
        )
    )
    client = Client(proposal)
    repository = Repository(source)
    service = AutoGroundingService(
        repository,
        axis_grounding=Grounder(
            consultation=ConsultationDispatcher(client),
            grounding_dispatcher=Dispatcher(client),
            max_workers=1,
        ),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    return service, repository, client


@pytest.mark.parametrize("blocked", ["action:blocked", "blocked"])
@pytest.mark.parametrize("actor", [A, B])
def test_bounded_branch_accepts_and_persists_once(actor, blocked):
    assert (
        Path(cloud_dast.__file__)
        .resolve()
        .is_relative_to(Path(__file__).resolve().parents[1])
    )
    service, repository, client = branch_service(actor)
    promoted = commit_branch(service, "svc", blocked)
    assert promoted is not None
    expected = fact("causes", actor, EFFECT, context=Context.ACCEPTED)
    assert expected in promoted.facts
    accepted = [g for key, g in repository.saved if key.startswith("accepted-batch:")]
    assert sum(expected in graph.facts for graph in accepted) == 1
    commit_branch(service, "svc", blocked)
    # Repeated results use the existing content-addressed revision, rather
    # than creating a second accepted source or a duplicate persisted fact.
    accepted_sources = {
        key: graph
        for key, graph in repository.saved
        if key.startswith("accepted-batch:")
    }
    assert len(accepted_sources) == 1
    assert repository.load_merged("accepted-batch:").facts.count(expected) == 1
    assert [s["action"] for s in client.requests[0].context["sibling_actions"]] == [
        B.value
    ]


def test_unrelated_service_action_is_rejected():
    service, repository, client = branch_service(C)
    assert commit_branch(service, "svc", A.value) is None
    assert not any(key.startswith("accepted-batch:") for key, _ in repository.saved)
    assert [s["action"] for s in client.requests[0].context["sibling_actions"]] == [
        B.value
    ]


def test_current_accepted_relation_justifies_sibling():
    service, repository, _ = branch_service(B, sibling_context=Context.ACCEPTED)
    assert commit_branch(service, "svc", A.value) is not None
    assert fact("causes", B, EFFECT, context=Context.ACCEPTED) in (
        repository.load_merged("accepted-batch:").facts
    )


def test_sibling_outside_bounded_request_is_rejected():
    from cloud_dast.verification.slices import DEFAULT_MAX_SIBLINGS

    service, repository, client = branch_service(B)
    earlier_siblings = tuple(
        Atom(value=f"action:before-{i:02}") for i in range(DEFAULT_MAX_SIBLINGS)
    )
    repository.graphs["contract:svc"] = merge_graphs(
        repository.graphs["contract:svc"],
        QdlGraph(
            facts=(
                fact("is", RESOURCE, Atom(value="Resource")),
                *(
                    f
                    for action in earlier_siblings
                    for f in (
                        fact("is", action, Atom(value="Action")),
                        fact("targets", action, RESOURCE),
                    )
                ),
            )
        ),
    )
    assert commit_branch(service, "svc", A.value) is None
    requested = client.requests[0].context["sibling_actions"]
    assert len(requested) == DEFAULT_MAX_SIBLINGS
    assert B.value not in [s["action"] for s in requested]
    assert not any(key.startswith("accepted-batch:") for key, _ in repository.saved)
