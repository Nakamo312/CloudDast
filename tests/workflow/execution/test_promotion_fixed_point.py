"""S27 — the promotion fixed-point proof.

One end-to-end reactive cycle through the production engine:

    deficit -> consultation (mock LLM) -> deterministic promotion
    -> append-only SQLite accepted-batch -> ScenarioBinder rebind
    -> new executable path -> mock target -> oracle verdict
    -> deficit closed.

Every stage is the real component: ``DeficitQueue``, the typed
consultation protocol, ``PromotionPolicy``, ``SqliteFormalRepository``,
``ScenarioBinder`` and the QDL planner, the ``BoundPathRunner`` executor
and the deterministic primitive oracle.  The only doubles are the model
client (the LLM boundary) and the live target.
"""

from __future__ import annotations

import json
import sqlite3

from cloud_dast.composition.execution import assemble_runner
from cloud_dast.consultation import (
    ConsultationBudget,
)
from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.infrastructure.events import EventBus
from cloud_dast.infrastructure.sqlite import SqliteFormalRepository
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    StandState,
    VerdictStatus,
)
from cloud_dast.model.events import (
    DomainEvent,
    QdlPathEvaluated,
    QdlStepEvaluated,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    changed,
    input_field,
)
from cloud_dast.runtime.binding import ScenarioBinder
from cloud_dast.runtime.deficits import (
    consultation_request,
    grounding_result_closes_deficit,
)
from cloud_dast.runtime.deficits import (
    coverage_gaps as coverage_deficits,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap
from cloud_dast.runtime.planning import IncrementalQdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from cloud_dast.verification.promotion import PromotionPolicy
from cloud_dast_fuzzing import (
    GoalPayloadGenerator,
    TemplateGenerator,
)
from cloud_dast_fuzzing.strategies.selector import (
    GeneratorSelector,
)
from cloud_dast_llm.axis_grounding import Dispatcher
from cloud_dast_llm.consultation import ConsultationDispatcher
from tests.grounding_owner import make_grounding
from tests.support.guardrails import AllowAllGuardrail

SERVICE = "orders.v1.OrderService"
CANCEL = f"{SERVICE}.Cancel"
ACTION = f"action:{CANCEL}"
ORDER_FIELD = "order_id"
ORDER_ID = input_field(Atom(value=ACTION), Atom(value=ORDER_FIELD))
ORDER_RESOURCE = Atom(value="resource:order")
ROLE_FACT = Fact(
    context=Context.ACCEPTED,
    predicate=Predicate.from_name("has"),
    args=(ORDER_ID, Atom(value="object_ref")),
)


class EventLog:
    """In-memory event store used by the runner and its subscribers."""

    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


class MethodRepo:
    def __init__(self, methods: tuple[MethodSpec, ...]) -> None:
        self.methods = methods

    def list_methods(self, service: str):
        return self.methods


class ScenarioRepo:
    def __init__(self, scenario: ScenarioPosition) -> None:
        self.scenario = scenario

    def get_scenario(self, principal_id, resource_id, method=None, **kwargs):
        return self.scenario


class RolesConsultationModelClient:
    """Mock LLM that answers the roles consultation deterministically."""

    def __init__(self, action: str, field_name: str) -> None:
        self.action = action
        self.field_name = field_name
        self.requests: list[ModelRequest] = []

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append(request)
        payload = (
            self._roles_payload()
            if request.task == "formal_grounding_roles"
            else {"context": "proposal", "facts": [], "rules": []}
        )
        return ModelResponse(
            structured=payload,
            content=json.dumps(payload),
            model_id="mock-roles-model",
            input_tokens=64,
            cached_input_tokens=8,
            output_tokens=32,
        )

    def _roles_payload(self) -> dict:
        action = _wire_atom(self.action)
        field = {
            "kind": "struct",
            "name": "input_field",
            "args": [action, _wire_atom(self.field_name)],
        }
        return {
            "context": "proposal",
            "facts": [
                {
                    "context": "proposal",
                    "predicate": "is",
                    "args": [action, _wire_atom("Action")],
                },
                {
                    "context": "proposal",
                    "predicate": "is",
                    "args": [field, _wire_atom("InputField")],
                },
                {
                    "context": "proposal",
                    "predicate": "has",
                    "args": [field, _wire_atom("object_ref")],
                },
            ],
            "rules": [],
        }


def _wire_atom(value: str) -> dict:
    return {"kind": "atom", "value": value, "literal_type": "string"}


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    predicate_object = (
        Predicate.from_schema(
            next(
                schema
                for schema in EXTENSION_PREDICATE_SCHEMAS
                if schema.name == predicate
            )
        )
        if predicate == "refers_to"
        else Predicate.from_name(predicate)
    )
    return Fact(
        context=context,
        predicate=predicate_object,
        args=args,  # type: ignore[arg-type]
    )


def _cancel_method() -> MethodSpec:
    return MethodSpec(
        method_id=CANCEL,
        service=SERVICE,
        name="Cancel",
        layer=EndpointLayer.PRIVATE,
        permissions=frozenset({"orders.cancel"}),
        resource_types=frozenset({"order"}),
        fields=(FieldSpec(name=ORDER_FIELD, type="string", required=True),),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="cancel-foreign-order",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.CROSS_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="created",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service="orders",
                    resource_type="order",
                    resource_id="order-live",
                ),
            ),
            principals=(PrincipalRef(principal_id="attacker", principal_type="user"),),
            effective_permissions=frozenset(),
            permissions_known=True,
        ),
    )


def _contract() -> QdlGraph:
    """A cancellable order action whose input role is deliberately missing.

    The contract carries the typed reference (``refers_to``) and an explicit
    non-removing mutation effect, but no ``has(input_field, object_ref)``
    fact: S13 semantics mean the binder cannot substitute the live order,
    which is exactly the reactive gap the cycle must close.  Structural
    facts stay in the contract context; the executable norm is accepted
    semantics, exactly as the contract projection persists it.
    """

    action = Atom(value=ACTION)
    norm = Atom(value="norm:cancel-foreign-order")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (ORDER_RESOURCE, Atom(value="Resource"))),
            _fact("targets", (action, ORDER_RESOURCE)),
            _fact("is", (ORDER_ID, Atom(value="InputField"))),
            _fact("refers_to", (ORDER_ID, ORDER_RESOURCE)),
            _fact(
                "causes",
                (action, changed(ORDER_RESOURCE, Atom(value="state"))),
            ),
            _fact("is", (norm, Atom(value="Norm")), Context.ACCEPTED),
            _fact("prevents", (norm, allowed(action)), Context.ACCEPTED),
        )
    )


def _saved_source_ids(database_path, prefix: str) -> tuple[str, ...]:
    connection = sqlite3.connect(database_path)
    try:
        rows = connection.execute(
            "SELECT source_id FROM qdl_projection WHERE source_id LIKE ?",
            (prefix + "%",),
        ).fetchall()
    finally:
        connection.close()
    return tuple(row[0] for row in rows)


def test_promotion_fixed_point_closes_deficit_and_scores_new_path(
    tmp_path,
) -> None:
    database_path = tmp_path / "formal.sqlite3"
    with SqliteFormalRepository(database_path) as repository:
        repository.save(
            f"contract:{SERVICE}",
            _contract(),
            provenance={"source_kind": "test"},
            adapter_version="contract-projection-v1",
            mapping_report={"mapped": 8, "unmapped": 0},
        )
        method = _cancel_method()
        binder = ScenarioBinder(
            MethodRepo((method,)),
            ScenarioRepo(_scenario()),
            repository,
            qdl_planner=IncrementalQdlPlanner(),
        )
        request = LiveRequest(
            service=SERVICE,
            principal_id="attacker",
            resource_id="order-live",
        )

        # Stage 1 — the contract-only binding carries the unbound reference.
        initial = binder.bind(request, formal_proposal=False)
        assert initial.execution.paths
        initial_path_ids = {path.path_id for path in initial.execution.paths}
        initial_steps = [
            step for path in initial.execution.paths for step in path.steps
        ]
        assert initial_steps
        assert all(step.plan.resource_params == () for step in initial_steps)

        # Stage 2 — the real queue detects and dispatches the deficit.
        queue = DeficitQueue(max_tasks=1)
        detected = coverage_deficits(initial)
        deficit = next(
            item
            for item in detected
            if item.predicate_class == "has" and item.action == CANCEL
        )
        assert queue.add((deficit,)) == 1
        dispatched = queue.pop_next()
        assert dispatched is not None
        assert dispatched.consultation_id == deficit.consultation_id

        # Stage 3 — the deficit becomes one typed consultation request.
        consultation = consultation_request(
            dispatched,
            graph=initial.graph,
            budget=ConsultationBudget(
                max_input_tokens=1024,
                max_output_tokens=512,
            ),
        )
        assert consultation is not None
        assert consultation.kind == "roles"
        assert consultation.deficit_id == deficit.consultation_id
        assert consultation.action == CANCEL

        # Stage 4 — mock-LLM consultation, deterministic promotion, SQLite.
        model = RolesConsultationModelClient(ACTION, ORDER_FIELD)
        grounder_options_1 = GrounderOptions(
            consultation=ConsultationDispatcher(model),
            grounding_dispatcher=Dispatcher(model),
            batch_size=1,
            max_workers=1,
        )
        grounding = make_grounding(
            repository,
            ingest_contract=None,
            project_stand=None,
            startup=Bootstrap(options=grounder_options_1),
            reactive=Followup(options=grounder_options_1),
            promotion_policy=PromotionPolicy(enabled=True),
        )
        result = grounding.consultation.run(SERVICE, consultation)
        assert len(model.requests) == 1
        assert model.requests[0].task == "formal_grounding_roles"
        assert result.outcome.status == "proposal"
        assert result.outcome.provenance.deficit_id == deficit.consultation_id
        assert result.outcome.provenance.kind == "roles"
        assert result.promoted is not None
        assert result.promoted.facts

        # (a) The role fact survives in the append-only accepted batch.
        accepted = repository.load_merged(f"accepted-batch:{SERVICE}:")
        assert any(
            fact.context is Context.ACCEPTED
            and fact.predicate.name == "has"
            and fact.args == ROLE_FACT.args
            for fact in accepted.facts
        )
        # S28: the promotion is addressed by a per-revision source id.
        source_ids = _saved_source_ids(
            database_path,
            f"accepted-batch:{SERVICE}:consultation:{deficit.consultation_id}",
        )
        assert source_ids
        assert all(len(source_id.rsplit(":", 1)[-1]) == 64 for source_id in source_ids)

        # Stage 5 — the rebind absorbs the promoted fact and builds a new path.
        rebound = binder.bind(request, formal_proposal=False)
        new_paths = [
            path
            for path in rebound.execution.paths
            if path.path_id not in initial_path_ids
        ]
        assert new_paths
        new_steps = [step for path in new_paths for step in path.steps]
        assert new_steps
        assert all(step.plan.resource_params == (ORDER_FIELD,) for step in new_steps)
        assert all(
            step.plan.resource_types == ((ORDER_FIELD, "order"),) for step in new_steps
        )
        # The fixed point itself: one promotion exhausts the gap — the
        # rebound graph no longer reports the missing role for the action.
        assert not [
            item
            for item in coverage_deficits(rebound)
            if item.predicate_class == "has" and item.action == CANCEL
        ]

        # Stage 6 — the new path executes against the mock target and is scored.
        events = EventLog()
        bus = EventBus()
        for event_type in (QdlStepEvaluated, QdlPathEvaluated):
            bus.subscribe(event_type, events.append)
        executed_checks = []

        def target(check):
            executed_checks.append(check)
            return Observation(
                check_id=check.check_id,
                scenario_id=check.scenario_id,
                observed_outcome=AccessOutcome.ALLOWED,
                response_summary="foreign order cancelled",
                transport_status=HttpStatus(code=200),
            )

        checker = Checker(
            target,
            GoalPayloadGenerator(GeneratorSelector({"template": TemplateGenerator()})),
            AllowAllGuardrail(),
            bus,
        )
        runner = assemble_runner(
            checker,
            bus,
            events,
            grounded_oracle=GroundedOutcomeOracle(),
            primitive_oracle=PrimitiveOracleRouter(),
            formal_repository=repository,
        )
        execution = runner.execute_plan(request, rebound.plan, rebound.execution)

        cancel_checks = [
            check for check in executed_checks if check.method_id == CANCEL
        ]
        assert cancel_checks
        # The promoted role + contract refers_to substitute the live order.
        assert any(
            dict(check.request).get(ORDER_FIELD) == "order-live"
            for check in cancel_checks
        )

        # (c) The executed path receives a deterministic, grounded verdict:
        # the attacker holds no cancel permission, yet the target allowed
        # the request — the promoted object reference made this violation
        # reachable and the oracle scores it.
        assert execution.policy_verdicts
        assert all(
            verdict.status is VerdictStatus.FAIL
            for verdict in execution.policy_verdicts.values()
        )
        assert all(
            verdict.deterministic and verdict.grounded
            for verdict in execution.policy_verdicts.values()
        )
        new_path_ids = {path.path_id for path in new_paths}
        step_events = [
            event
            for event in events.events
            if isinstance(event, QdlStepEvaluated) and event.path_id in new_path_ids
        ]
        assert step_events
        assert all(event.verdict is VerdictStatus.FAIL for event in step_events)
        path_events = [
            event
            for event in events.events
            if isinstance(event, QdlPathEvaluated) and event.path_id in new_path_ids
        ]
        assert path_events
        assert all(event.outcome == "completed" for event in path_events)

        # Stage 7 — (d) the deficit closes on its semantic witness.
        assert grounding_result_closes_deficit(dispatched, result.promoted)
        assert queue.record_success(dispatched, gap_closed=True)
        assert queue.closed_count == 1
        assert not queue.dispatchable
