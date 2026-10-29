"""Bind canonical QDL to executable scenarios and execution views."""

from __future__ import annotations

from collections.abc import Mapping

from cloud_dast.config import DEFAULT_MAX_PROMOTED_NORMS
from cloud_dast.contracts.assessment import BindingDeficit
from cloud_dast.contracts.execution import LiveRequest, ScenarioBinding
from cloud_dast.contracts.plan import QdlExecutionView
from cloud_dast.model import (
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.model.events import (
    action_aliases,
)
from cloud_dast.ports import (
    FormalGrounder,
    FormalRepository,
    MethodRepository,
    ScenarioRepository,
)
from cloud_dast.proposals import ThreatModelProposer
from cloud_dast.qdl.graph import (
    Context,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.projection import (
    campaign_view,
)
from cloud_dast.qdl.reasoning import QdlPlan
from cloud_dast.qdl.threat_compiler import (
    ThreatIntentCompiler,
)
from cloud_dast.runtime.campaign.graph import (
    Assembler,
)
from cloud_dast.runtime.execution.projection import (
    record_binding_deficit as _record_binding_deficit,
)
from cloud_dast.runtime.execution.view import build as _build_execution_view
from cloud_dast.runtime.execution.view import method_for_action as _method_for_action
from cloud_dast.runtime.execution.view import (
    missing_reference_deficits as _missing_reference_deficits,
)
from cloud_dast.runtime.execution.view import (
    ordered_plan_actions as _ordered_plan_actions,
)
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from cloud_dast.runtime.planning import QdlPlanner, declared_action_ids
from cloud_dast.runtime.reference_projection import (
    refers_to_targets_by_action as _refers_to_targets_by_action,
)
from cloud_dast.runtime.resource_projection import (
    target_resources as _target_resources,
)
from cloud_dast.verification.action_runtime import build_action_runtime_ledger
from cloud_dast.verification.invariant_projection import (
    resolve_actions,
)


# A violated primitive says what the tenant actually loses, so the finding
# severity follows the witness channel instead of defaulting to CRITICAL.
class ScenarioBinder:
    """Resolve QDL-derived actions into executable live scenario bindings."""

    def __init__(
        self,
        methods: MethodRepository,
        scenarios: ScenarioRepository,
        formal_repository: FormalRepository,
        qdl_planner: QdlPlanner,
        formal_threat_modeler: ThreatModelProposer | None = None,
        *,
        promote_formal_proposals: bool = False,
        max_promoted_norms: int | None = DEFAULT_MAX_PROMOTED_NORMS,
        threat_compiler: ThreatIntentCompiler | None = None,
        promotion_policy: PromotionPolicy | None = None,
    ) -> None:
        self._methods = methods
        self._scenarios = scenarios
        if formal_repository is None:
            raise ValueError("formal_repository is required for live planning")
        self._qdl_planner = qdl_planner
        selected_promotion_policy = promotion_policy or PromotionPolicy(
            enabled=promote_formal_proposals,
            max_norms=max_promoted_norms,
        )
        self._graph_assembler = Assembler(
            formal_repository,
            formal_threat_modeler,
            selected_promotion_policy,
        )
        self._threat_compiler = threat_compiler

    @property
    def formal_threat_modeler(self) -> ThreatModelProposer | None:
        """The optional model-backed formal proposal service."""

        return self._graph_assembler.formal_threat_modeler

    def bind(
        self,
        request: LiveRequest,
        *,
        formal_proposal: bool = True,
    ) -> ScenarioBinding:
        """Load QDL sources, plan executable views, and bind live scenarios."""

        methods = self._methods.list_methods(request.service)
        if not methods:
            raise LookupError("service has no methods")
        methods_by_id = {item.method_id: item for item in methods}

        graph = self._graph_assembler.load(
            request.service,
            formal_proposal=formal_proposal,
        )
        graph = campaign_view(
            graph,
            request.principal_id,
            request.service,
            self._threat_compiler,
        )
        plan = self._qdl_planner.plan(graph)
        method = self._select_method(request.method_id, methods_by_id, plan)
        binding_deficits: list[BindingDeficit] = []
        scenario = self._resolve_scenario(
            request,
            method,
        )
        norm_actions = resolve_actions(plan, graph)
        scenarios_by_method = self._resolve_scenarios(
            request,
            plan,
            methods_by_id,
            graph=graph,
            selected_method=method,
            selected_scenario=scenario,
            deficits=binding_deficits,
            norm_actions=norm_actions,
        )
        execution = _build_execution_view(
            plan,
            graph,
            methods=methods,
            scenarios_by_method=scenarios_by_method,
            norm_actions=norm_actions,
            binding_deficits=binding_deficits,
        )
        binding_deficits.extend(_missing_reference_deficits(execution))
        binding_deficits.extend(_identity_deficits(execution))
        action_runtime = build_action_runtime_ledger(
            graph,
            paths=execution.paths,
            planned_paths=plan.bound_paths,
            binding_deficits=binding_deficits,
        )
        return ScenarioBinding(
            scenario=scenario,
            graph=graph,
            plan=plan,
            execution=execution,
            invariants=execution.invariants,
            methods=methods,
            deficits=tuple(dict.fromkeys(binding_deficits)),
            action_runtime=action_runtime,
        )

    @property
    def formal_grounder(self) -> FormalGrounder | None:
        """Expose the existing assembler's preparation and admission capabilities."""

        return self._graph_assembler if self.formal_threat_modeler is not None else None

    @staticmethod
    def _select_method(
        method_id: str | None,
        methods_by_id: Mapping[str, MethodSpec],
        plan: QdlPlan,
    ) -> MethodSpec:
        if method_id is not None:
            method = methods_by_id.get(method_id)
            if method is None:
                raise LookupError(f"method not found: {method_id}")
            return method

        for action in _ordered_plan_actions(plan):
            method = _method_for_action(action, methods_by_id)
            if method is not None:
                return method
        if not methods_by_id:
            raise LookupError("service has no methods")
        return next(iter(methods_by_id.values()))

    def _resolve_scenario(
        self,
        request: LiveRequest,
        method: MethodSpec,
    ) -> ScenarioPosition:
        scenario = self._scenarios.get_scenario(
            request.principal_id,
            request.resource_id,
            method=method,
        )
        if scenario is None:
            raise LookupError(
                f"scenario not found for principal={request.principal_id!r}, "
                f"resource={request.resource_id!r}"
            )
        return scenario

    def _resolve_scenarios(
        self,
        request: LiveRequest,
        plan: QdlPlan,
        methods_by_id: Mapping[str, MethodSpec],
        *,
        graph: QdlGraph,
        selected_method: MethodSpec,
        selected_scenario: ScenarioPosition,
        deficits: list[BindingDeficit],
        norm_actions: Mapping[Struct, tuple[str, ...]],
    ) -> dict[str, ScenarioPosition]:
        scenarios = {selected_method.method_id: selected_scenario}
        actions = _ordered_plan_actions(plan)
        references = _refers_to_targets_by_action(graph)
        # Invariant norms bind their own actions even when no attack path
        # exists yet; their scenarios must resolve so every accepted norm
        # gets an executable invariant path.
        for qdl_invariant in plan.invariants:
            related = norm_actions[qdl_invariant.effect]
            actions += related
            if not related and qdl_invariant.effect.name == "changed":
                resource = atom_value(qdl_invariant.effect.args[0])
                for method in methods_by_id.values():
                    aliases = action_aliases(method.method_id)
                    if resource not in _target_resources(
                        graph, method.method_id
                    ) and not any(
                        target == resource
                        for alias in aliases
                        for _, target in references.get(alias, ())
                    ):
                        continue
                    _record_binding_deficit(
                        deficits,
                        action=method.method_id,
                        reason="missing_causal_effect",
                        kind="invariant_missing",
                        context=(
                            ("requirement", canonical_json(qdl_invariant.effect)),
                        ),
                    )
        actions += tuple(sorted(declared_action_ids(graph, Context.CONTRACT)))
        for action in actions:
            method = _method_for_action(action, methods_by_id)
            if method is None or method.method_id in scenarios:
                if method is None:
                    _record_binding_deficit(
                        deficits,
                        action=action,
                        reason="contract_method_missing",
                        kind="method_missing",
                        context=(("coverage", "contract_action"),),
                    )
                continue
            scenario = self._scenarios.get_scenario(
                request.principal_id,
                request.resource_id,
                method=method,
            )
            if scenario is None:
                _record_binding_deficit(
                    deficits,
                    action=action,
                    reason="contract_scenario_missing",
                    kind="scenario_missing",
                    context=(("coverage", "contract_action"),),
                )
                continue
            scenarios[method.method_id] = scenario
        return scenarios


def identity_deficit(
    action: str,
    *,
    scenario_id: str | None = None,
) -> BindingDeficit:
    """Return the typed deficit for an action with no valid identity."""

    context = [] if scenario_id is None else [("scenario_id", scenario_id)]
    return BindingDeficit(
        action=action,
        reason="identity_deficit",
        context=tuple(context),
    )


def _identity_deficits(execution: QdlExecutionView) -> tuple[BindingDeficit, ...]:
    """Report bound actions whose QDL graph derives no valid identity.

    An empty grounded ``identity_terms`` projection means the binder derived
    no ``valid_identity(action, subject)`` term at all.  The gap is reported
    for grounding; generators must not guess an identity in its place.
    """

    deficits: list[BindingDeficit] = []
    seen: set[tuple[str, str]] = set()
    for path in execution.paths:
        for step in path.steps:
            if step.plan.identity_terms is None or step.plan.identity_terms:
                continue
            key = (step.method.method_id, step.scenario.scenario_id)
            if key in seen:
                continue
            seen.add(key)
            deficits.append(
                identity_deficit(
                    step.method.method_id,
                    scenario_id=step.scenario.scenario_id,
                )
            )
    return tuple(deficits)
