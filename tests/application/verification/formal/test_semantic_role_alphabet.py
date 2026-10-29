from __future__ import annotations

import json
import re

import pytest

from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.roles import (
    ENGINE_ROLES,
    SEMANTIC_ROLE_NAMES,
    SEMANTIC_ROLES,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    privileged_change_effects,
)
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.verification.taxonomy import DEFAULT_CATALOG
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from cloud_dast_llm.threat_model import FormalThreatModeler
from tests.support.threat_model import project_stride

ACTION = "action:get"


class RecordingClient:
    def __init__(self, *payloads: dict) -> None:
        self.payloads = payloads
        self.requests: list[ModelRequest] = []

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append(request)
        if len(self.requests) > len(self.payloads):
            raise AssertionError("model client was called more times than expected")
        return ModelResponse(
            structured=self.payloads[len(self.requests) - 1],
            content=json.dumps(self.payloads[len(self.requests) - 1]),
            model_id="test-model",
        )


def _source_graph() -> QdlGraph:
    action = Atom(value=ACTION)
    return QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
        )
    )


def _term(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _input_field_term(field_name: str) -> dict:
    return {
        "kind": "struct",
        "name": "input_field",
        "args": [_term(ACTION), _term(field_name)],
    }


def _fact(predicate: str, *args: dict) -> dict:
    return {
        "context": "proposal",
        "predicate": predicate,
        "args": list(args),
    }


def _axis_payload(roles: tuple[str, ...]) -> dict:
    facts = [_fact("is", _term(ACTION), _term("Action"))]
    for index, role in enumerate(roles):
        field = _input_field_term(f"field:{index}")
        facts.extend(
            (
                _fact("is", field, _term("Field")),
                _fact("has", field, _term(role)),
            )
        )
    return {"context": "proposal", "facts": facts, "rules": []}


def _threat_payload(role: str) -> dict:
    field = _input_field_term("query")
    return {
        "context": "proposal",
        "facts": [
            _fact("is", _term(ACTION), _term("Action")),
            _fact("is", _term("norm:no-get"), _term("Norm")),
            _fact(
                "prevents",
                _term("norm:no-get"),
                {
                    "kind": "struct",
                    "name": "allowed",
                    "args": [_term(ACTION)],
                },
            ),
            _fact("is", field, _term("Field")),
            _fact("has", field, _term(role)),
        ],
        "rules": [],
    }


def test_semantic_role_alphabet_excludes_engine_roles() -> None:
    assert SEMANTIC_ROLES
    assert {role.name for role in SEMANTIC_ROLES} == SEMANTIC_ROLE_NAMES
    assert not SEMANTIC_ROLE_NAMES & ENGINE_ROLES


def test_prompts_and_catalog_derive_from_semantic_role_alphabet() -> None:
    axis_client = RecordingClient(_axis_payload(("object_ref",)))
    Bootstrap(
        consultation=ConsultationDispatcher(axis_client),
        grounding_dispatcher=Dispatcher(axis_client),
        batch_size=1,
        max_workers=1,
    ).ground(_source_graph())
    axis_request = next(
        request
        for request in axis_client.requests
        if request.task == "formal_grounding_roles"
    )

    threat_client = RecordingClient(_threat_payload("object_ref"))
    FormalThreatModeler(threat_client).propose(_source_graph())
    threat_request = threat_client.requests[0]

    for instruction in (axis_request.instruction, threat_request.instruction):
        assert all(role in instruction for role in SEMANTIC_ROLE_NAMES)
        assert not ENGINE_ROLES.intersection(re.findall(r"\b[a-z_]+\b", instruction))

    catalog_roles = {
        role
        for entry in DEFAULT_CATALOG.entries
        for role in (*entry.input_roles, *entry.witness_roles)
    }
    assert catalog_roles <= SEMANTIC_ROLE_NAMES


def test_axis_grounding_rejects_unknown_and_engine_roles(caplog) -> None:
    client = RecordingClient(
        _axis_payload(("object_ref", "mystery_role", "probe_target", "setup_skip"))
    )
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    with caplog.at_level(
        "WARNING",
        logger="cloud_dast.runtime.grounding.parallel",
    ):
        result = service.ground_reactive("roles", (ACTION,), _source_graph())
    assert result.graph is not None
    roles = {
        atom_value(fact.args[1])
        for fact in result.graph.facts
        if fact.predicate.name == "has"
    }
    assert roles == {"object_ref"}
    assert result.issue_count >= 3
    assert "axis_grounding_role_rejected" in caplog.text
    assert "mystery_role:unknown" in caplog.text
    assert "probe_target:engine" in caplog.text
    assert "setup_skip:engine" in caplog.text


@pytest.mark.parametrize("role", ["payload", "mutable_input"])
def test_mutable_payload_roles_pass_the_semantic_boundary(role: str) -> None:
    """Payload-pair mutability is groundable, not engine-internal."""

    assert role in SEMANTIC_ROLE_NAMES
    assert role not in ENGINE_ROLES

    client = RecordingClient(_axis_payload((role,)))
    service = Followup(
        consultation=ConsultationDispatcher(client),
        grounding_dispatcher=Dispatcher(client),
        batch_size=1,
        max_workers=1,
    )

    result = service.ground_reactive("roles", (ACTION,), _source_graph())

    assert result.graph is not None
    assert {
        atom_value(fact.args[1])
        for fact in result.graph.facts
        if fact.predicate.name == "has"
    } == {role}
    assert result.issue_count == 0


@pytest.mark.parametrize("role", ["mystery_role", "probe_target", "setup_skip"])
def test_threat_modeler_rejects_non_semantic_roles(role: str) -> None:
    payload = _threat_payload(role)
    client = RecordingClient(payload, payload)

    result = FormalThreatModeler(client).propose(_source_graph())

    assert not result.valid
    assert result.attempts == 2
    issues = (*result.initial_issues, *result.repair_issues, *result.issues)
    assert any(
        issue.code == "semantic_role" and role in issue.message for issue in issues
    )
    assert result.proposal is None or not any(
        fact.predicate.name == "has" and atom_value(fact.args[1]) == role
        for fact in result.proposal.facts
    )


def test_stride_projection_derives_categories_from_alphabet() -> None:
    action = Atom(value=ACTION)
    privileged = input_field(action, Atom(value="role"))
    probe = input_field(action, Atom(value="marker"))
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(privileged, Atom(value="Field")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(probe, Atom(value="Field")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(privileged, Atom(value="privileged")),
            ),
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("has"),
                args=(probe, Atom(value="probe_target")),
            ),
        )
    )

    views = project_stride(graph)

    assert {view.role: view.categories for view in views} == {
        "privileged": ("T",),
        "probe_target": (),
    }


@pytest.mark.parametrize("role", ["mystery_role", "probe_target", "setup_skip"])
def test_semantic_compiler_ignores_non_semantic_roles(role: str) -> None:
    action = Atom(value=ACTION)
    resource = Atom(value="resource:order")
    field = input_field(action, Atom(value="total"))
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(resource, Atom(value="Resource")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(field, Atom(value="Field")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("targets"),
                args=(action, resource),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("has"),
                args=(field, Atom(value=role)),
            ),
        )
    )

    assert privileged_change_effects(graph) == ()
