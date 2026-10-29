"""Fitness checks for the current core source boundary."""

import ast
import inspect
import tomllib
from pathlib import Path

import pytest

from cloud_dast.contracts import dag as dag_contract
from cloud_dast.contracts import execution as execution_results
from cloud_dast.contracts.payload_proposals import SeedEnrichmentModelWireOutput
from cloud_dast.contracts.proposals import FormalModelOutputValidator
from cloud_dast.extensions import (
    FuzzSession as FuzzSessionContract,
)
from cloud_dast.extensions import (
    FuzzSessionFactory,
    FuzzSessionRequest,
    PayloadCorpusSource,
)
from cloud_dast.extensions import (
    TestCaseGenerator as GeneratorContract,
)
from cloud_dast.qdl.extension_schemas import EXTENSION_PREDICATE_SCHEMAS
from cloud_dast.runtime import (
    differential,
    reference_projection,
    resource_projection,
)
from cloud_dast.runtime.campaign.state import RuntimeState
from cloud_dast.runtime.candidates import session as step_candidates
from cloud_dast.runtime.deficits import Deficit as RuntimeDeficit
from cloud_dast.runtime.execution import binding as path_binding
from cloud_dast.runtime.execution import (
    metadata as execution_metadata,
)
from cloud_dast.runtime.execution import view as execution_view
from cloud_dast.verification import (
    action_runtime,
    coverage_models,
    finding_evaluator,
    invariant_projection,
    norm_coverage,
)
from cloud_dast.verification import findings as finding_projection
from cloud_dast.verification.differential import contracts
from cloud_dast_fuzzing import FuzzSession
from cloud_dast_fuzzing.corpus import PayloadCorpusCompiler, PayloadCorpusStore
from cloud_dast_llm.consultation import ConsultationDispatcher
from cloud_dast_llm.generator import LlmGenerator
from cloud_dast_llm.proposals import LlmGeneratedChecks
from cloud_dast_llm.threat_model import FormalThreatModeler
from cloud_dast_symbolic import Z3SymbolicGenerator

SOURCE_ROOT = Path(__file__).parents[2] / "packages/core/src/cloud_dast"


def _imported_modules(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text())
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
    return tuple(modules)


def _module_owns_class(module: object, name: str) -> bool:
    """Return whether a module defines a class rather than re-exporting it."""

    value = getattr(module, name, None)
    return inspect.isclass(value) and getattr(value, "__module__", "") == getattr(
        module, "__name__", ""
    )


def _module_owns_symbol(module: object, name: str) -> bool:
    """Return whether a module defines a symbol rather than re-exporting it."""

    value = getattr(module, name, None)
    if value is None:
        return False
    return getattr(value, "__module__", None) == getattr(module, "__name__", "")


def _module_defines_method(module: object, name: str) -> bool:
    """Return whether one of a module's classes owns a method name."""

    return any(
        inspect.isclass(value)
        and getattr(value, "__module__", "") == getattr(module, "__name__", "")
        and hasattr(value, name)
        for value in vars(module).values()
    )


def test_differential_contracts_do_not_depend_on_workflow() -> None:
    modules = _imported_modules(Path(contracts.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)


def test_action_runtime_projection_is_verification_owned() -> None:
    modules = _imported_modules(Path(action_runtime.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert action_runtime.__name__ == "cloud_dast.verification.action_runtime"
    assert not (SOURCE_ROOT / "application/verification/runtime_ledger.py").exists()


def test_deficit_algebra_is_runtime_owned() -> None:
    modules = _imported_modules(Path(inspect.getfile(RuntimeDeficit)))
    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert RuntimeDeficit.__module__ == "cloud_dast.runtime.deficits.model"
    from cloud_dast.runtime import deficits
    from cloud_dast.runtime.deficits import model as deficit_model

    assert deficits.Deficit is deficit_model.Deficit
    assert deficit_model.DeficitKey is deficits.DeficitKey
    assert not (SOURCE_ROOT / "application/verification/deficits.py").exists()


def test_deficits_use_one_semantic_namespace() -> None:
    from cloud_dast.runtime import deficits
    from cloud_dast.runtime.deficits import (
        classification,
        closure,
        collection,
        coverage,
        detection,
        dispatch,
        model,
        propagation,
        queue,
        queue_state,
        routing,
    )

    package = Path(deficits.__file__).parent
    for old_name in (
        "deficits.py",
        "deficit_closure.py",
        "deficit_collection.py",
        "deficit_dispatch.py",
        "deficit_model.py",
        "deficit_queue.py",
        "deficit_queue_state.py",
    ):
        assert not (package.parent / old_name).exists()

    assert detection.Deficit.__module__ == "cloud_dast.runtime.deficits.model"
    assert collection.DeficitCollector.__module__ == (
        "cloud_dast.runtime.deficits.collection"
    )
    assert dispatch.select_wave_groups.__module__ == (
        "cloud_dast.runtime.deficits.dispatch"
    )
    assert model.Deficit.__module__ == "cloud_dast.runtime.deficits.model"
    assert queue.DeficitQueue.__module__ == "cloud_dast.runtime.deficits.queue"
    assert queue_state.WorkGroup.__module__ == (
        "cloud_dast.runtime.deficits.queue_state"
    )
    assert propagation.propagate_item.__module__ == (
        "cloud_dast.runtime.deficits.propagation"
    )
    assert propagation.propagate_wave.__module__ == (
        "cloud_dast.runtime.deficits.propagation"
    )
    assert closure.grounded_output_paths.__module__ == (
        "cloud_dast.runtime.deficits.closure"
    )
    assert routing.axis_for_subgoal.__module__ == (
        "cloud_dast.runtime.deficits.routing"
    )
    assert routing.consultation_request.__module__ == (
        "cloud_dast.runtime.deficits.routing"
    )
    assert classification.CLASSIFICATION_DEFICIT_KIND == "classification_deficit"
    assert classification.gap_for_invariant.__module__ == (
        "cloud_dast.runtime.deficits.classification"
    )
    assert classification.gaps_for_observations.__module__ == (
        "cloud_dast.runtime.deficits.classification"
    )
    assert coverage.gaps.__module__ == ("cloud_dast.runtime.deficits.coverage")
    assert coverage.reference_deficits.__module__ == (
        "cloud_dast.runtime.deficits.coverage"
    )
    assert not _module_owns_symbol(detection, "axis_for_subgoal")
    assert not _module_owns_symbol(detection, "classification_deficit")


def test_qdl_invariant_projection_is_application_owned() -> None:
    from cloud_dast.runtime import binding

    modules = _imported_modules(Path(invariant_projection.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    for symbol in (
        "_InvariantIndex",
        "_build_invariant_index",
        "_exposes_by_witness",
        "_actions_by_effect",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_qdl_reference_projection_is_application_owned() -> None:
    from cloud_dast.runtime import binding

    modules = _imported_modules(Path(reference_projection.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    for symbol in (
        "_resource_params_by_action",
        "_refers_to_targets_by_action",
        "typed_object_refs_by_action",
        "FixturePool",
        "ProvisionerPort",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_qdl_resource_projection_is_application_owned() -> None:
    from cloud_dast.runtime import binding

    modules = _imported_modules(Path(resource_projection.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    for symbol in (
        "_target_resources",
        "_target_resource_type",
        "required_setup_states",
        "ProvisionerPort",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_execution_path_metadata_is_runtime_owned() -> None:
    from cloud_dast.runtime import binding

    modules = _imported_modules(Path(execution_metadata.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert execution_metadata.__name__ == "cloud_dast.runtime.execution.metadata"

    for symbol in (
        "_apply_resource_params",
        "_apply_subject_role_params",
        "_apply_irreversibility",
        "_apply_probe_fields",
        "_apply_sink_types",
        "_apply_grammar_facts",
        "_version_executable_inputs",
        "_executable_versioned_path_id",
        "_apply_plan_couplings",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_qdl_path_binding_is_runtime_owned() -> None:
    from cloud_dast.runtime import binding

    modules = _imported_modules(Path(path_binding.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert path_binding.__name__ == "cloud_dast.runtime.execution.binding"

    for symbol in (
        "_path_key",
        "_bind_attack_path",
        "_bind_forbidden_path",
        "_select_edge_invariant",
        "_invariant_path",
        "_build_step",
        "_transition_targets",
        "_forbidden_statement",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_execution_view_assembly_is_runtime_owned() -> None:
    from cloud_dast.runtime import binding

    modules = _imported_modules(Path(execution_view.__file__))
    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert execution_view.__name__ == "cloud_dast.runtime.execution.view"

    for symbol in (
        "_build_execution_view",
        "_bind_execution_paths",
        "_decorate_execution_paths",
        "_apply_setup_methods",
        "_missing_reference_deficits",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_finding_shrinking_is_separate_from_live_path_execution() -> None:
    from cloud_dast.runtime import finding_shrinking
    from cloud_dast.runtime.execution import runner as execution

    modules = _imported_modules(Path(finding_shrinking.__file__))
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in modules
        for prefix in (
            "cloud_dast.runtime.execution.runner",
            "cloud_dast_fuzzing",
        )
    )
    assert not _module_owns_class(execution, "FindingShrinkCoordinator")

    assert not _module_defines_method(execution, "_shrink_finding")
    assert not _module_defines_method(execution, "save_finding_example")


def test_observation_recording_is_separate_from_live_transport() -> None:
    from cloud_dast.runtime import observation_recording
    from cloud_dast.runtime.execution import runner as execution

    modules = _imported_modules(Path(observation_recording.__file__))
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in modules
        for prefix in (
            "cloud_dast.runtime.execution.runner",
            "cloud_dast.composition.execution",
            "cloud_dast.ports",
            "cloud_dast.infrastructure",
        )
    )
    assert not _module_owns_class(execution, "Coordinator")

    for symbol in (
        "_classify_and_record_observation",
        "_record_step_feedback",
        "_finalize_step_observation",
    ):
        assert not _module_defines_method(execution, symbol)


def test_observation_effects_are_separate_from_path_orchestration() -> None:
    from cloud_dast.runtime import observation_effects
    from cloud_dast.runtime.execution import runner as execution

    modules = _imported_modules(Path(observation_effects.__file__))
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in modules
        for prefix in (
            "cloud_dast.runtime.execution.runner",
            "cloud_dast.composition.execution",
            "cloud_dast.ports",
            "cloud_dast.infrastructure",
        )
    )
    assert not _module_owns_class(execution, "Publisher")

    for symbol in (
        "_publish_component_result",
        "_publish_observation_effects",
        "_publish_runtime_facts",
        "_publish_step_event",
    ):
        assert not _module_defines_method(execution, symbol)


def test_readback_reevaluation_is_separate_from_live_execution() -> None:
    from cloud_dast.runtime import readback_reevaluation
    from cloud_dast.runtime.execution import runner as execution

    modules = _imported_modules(Path(readback_reevaluation.__file__))
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in modules
        for prefix in (
            "cloud_dast.runtime.execution.runner",
            "cloud_dast.ports",
            "cloud_dast.infrastructure",
        )
    )
    assert not _module_owns_class(execution, "Reevaluation")
    assert not _module_defines_method(execution, "reevaluate_readbacks")


def test_path_prefilter_is_separate_from_live_path_execution() -> None:
    from cloud_dast.runtime.execution import prefilter as path_prefilter
    from cloud_dast.runtime.execution import runner as execution

    modules = _imported_modules(Path(path_prefilter.__file__))
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in modules
        for prefix in (
            "cloud_dast.runtime.execution.runner",
            "cloud_dast.composition.execution",
            "cloud_dast.ports",
            "cloud_dast.infrastructure",
        )
    )
    assert not _module_owns_class(execution, "SymbolicPathPrefilter")
    assert not _module_defines_method(execution, "_prefilter_path")
    assert not _module_defines_method(execution, "prefilter_sequence")


def test_execution_package_has_one_runner_api_and_owned_modules() -> None:
    from cloud_dast.composition import execution as composition_execution
    from cloud_dast.runtime import execution
    from cloud_dast.runtime.execution import (
        binding as path_binding,
    )
    from cloud_dast.runtime.execution import (
        calls,
        paths,
        runner,
        state,
        terminal,
    )

    assert execution.__all__ == ["BoundPathRunner"]
    assert composition_execution.assemble_runner.__module__ == (
        "cloud_dast.composition.execution"
    )
    assert composition_execution.BoundPathRunnerOptions.__module__ == (
        "cloud_dast.composition.execution"
    )
    assert execution.BoundPathRunner is runner.BoundPathRunner
    assert runner.BoundPathRunner.__module__ == ("cloud_dast.runtime.execution.runner")
    assert calls.execute.__module__ == "cloud_dast.runtime.execution.calls"
    assert paths.Executor.__module__ == "cloud_dast.runtime.execution.paths"
    assert path_binding.__name__ == "cloud_dast.runtime.execution.binding"
    assert terminal.PathTerminalizer.__module__ == (
        "cloud_dast.runtime.execution.terminal"
    )
    assert state.CampaignAccumulator.__module__ == (
        "cloud_dast.runtime.execution.state"
    )
    assert not (SOURCE_ROOT / "runtime/execution.py").exists()


def test_path_evidence_is_separate_from_live_execution_composition() -> None:
    from cloud_dast.runtime.execution import evidence as path_evidence
    from cloud_dast.runtime.execution import runner as execution

    assert path_evidence.PathSignature.__module__ == (
        "cloud_dast.runtime.execution.evidence"
    )
    assert not _module_owns_class(execution, "PathSignature")


def test_evidence_reuse_is_separate_from_live_path_orchestration() -> None:
    from cloud_dast.runtime import evidence_reuse
    from cloud_dast.runtime.execution import runner as execution

    modules = _imported_modules(Path(evidence_reuse.__file__))
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in modules
        for prefix in (
            "cloud_dast.runtime.execution.runner",
            "cloud_dast.composition.execution",
            "cloud_dast.ports",
            "cloud_dast.infrastructure",
        )
    )
    assert not _module_owns_class(execution, "Reuse")
    for symbol in (
        "_resume_observed_step",
        "_reuse_proved_effects",
        "read_observed_outputs",
    ):
        assert not _module_defines_method(execution, symbol)


def test_campaign_dag_models_are_not_owned_by_projection_builder() -> None:
    from cloud_dast.runtime.campaign import dag as campaign_dag_projection

    assert dag_contract.CampaignDag.__module__ == ("cloud_dast.contracts.dag")
    assert campaign_dag_projection.build_campaign_dag.__module__ == (
        "cloud_dast.runtime.campaign.dag"
    )

    builder = campaign_dag_projection
    for symbol in (
        "CampaignNodeKind",
        "CampaignEdgeKind",
        "CampaignNodeRef",
        "CampaignDag",
    ):
        assert not _module_owns_symbol(builder, symbol)


def test_campaign_event_index_is_separate_from_dag_projection() -> None:
    from cloud_dast.runtime.campaign import dag as campaign_dag_projection
    from cloud_dast.runtime.campaign import events as campaign_events

    assert campaign_events.EventIndex.__module__ == (
        "cloud_dast.runtime.campaign.events"
    )
    assert not _module_defines_method(campaign_dag_projection, "_collect_events")


@pytest.mark.parametrize(
    "first_import",
    (
        "cloud_dast.runtime.campaign.dag",
        "cloud_dast.runtime.campaign.events",
        "cloud_dast.contracts.dag",
        "cloud_dast.runtime.campaign.replay",
    ),
)
def test_campaign_projection_imports_cold_and_projects(first_import: str) -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
import importlib
importlib.import_module({first_import!r})
from cloud_dast.contracts.dag import CampaignDag
from cloud_dast.model.events import FactVerified, IntentProposed
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.intents import intent_graph
from cloud_dast.runtime.campaign.dag import build_campaign_dag
from cloud_dast.runtime.campaign.replay import EventGraph
from cloud_dast.verification.evidence_facts import verified_fact

events = (FactVerified(fact=verified_fact("ready")),
          IntentProposed(intent=intent_graph("use", prerequisites=("ready",))))
projected = build_campaign_dag(QdlGraph(), events)
assert {{node.kind for node in projected.nodes}} == {{"hypothesis", "verdict"}}
assert {{edge.kind for edge in projected.edges}} == {{"depends_on", "supports"}}
assert {{(edge.source.node_id, edge.target.node_id) for edge in projected.edges}} == {{
    ("hypothesis:proposal:use", "verdict:runtime:ready"),
    ("verdict:runtime:ready", "hypothesis:proposal:use"),
}}
assert CampaignDag.model_validate_json(projected.model_dump_json()) == projected
replayed = EventGraph.replay(events).project_dag(events)
assert replayed.nodes == projected.nodes
assert replayed.edges == projected.edges
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_campaign_projection_preserves_qdl_and_event_edge_evidence() -> None:
    from cloud_dast.model import VerdictStatus
    from cloud_dast.model.events import QdlPathEvaluated, QdlStepEvaluated
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
    from cloud_dast.runtime.campaign.dag import (
        DEPENDS_ON,
        PATH_TYPE,
        STEP_TYPE,
        build_campaign_dag,
    )

    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="path"), Atom(value=PATH_TYPE)),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="step"), Atom(value=STEP_TYPE)),
            ),
            Fact(
                context=Context.RUNTIME,
                predicate=DEPENDS_ON,
                args=(Atom(value="step"), Atom(value="path")),
            ),
        )
    )
    events = (
        QdlPathEvaluated(
            path_id="path",
            outcome="blocked",
            attempted_steps=1,
            step_count=1,
            probe_count=1,
            reason="blocked",
        ),
        QdlStepEvaluated(
            path_id="path",
            step_id="step",
            step_index=0,
            verdict=VerdictStatus.FAIL,
            phase="blocked",
            reason="blocked",
        ),
    )
    projected = build_campaign_dag(graph, events)
    edges = [edge for edge in projected.edges if edge.kind == "depends_on"]
    assert len(edges) == 2
    assert len({edge.edge_id for edge in edges}) == 2
    assert all(
        edge.source.node_id == "step:runtime:step"
        and edge.target.node_id == "path:runtime:path"
        for edge in edges
    )
    assert {edge.payload for edge in edges} == {
        (("source", "qdl"),),
        (("source", "event"),),
    }


def test_grounding_projection_is_pure_and_not_owned_by_service() -> None:
    from cloud_dast.qdl import graph_ops
    from cloud_dast.runtime.grounding import projection as grounding_projection
    from cloud_dast.runtime.grounding import runtime as grounding_runtime

    modules = _imported_modules(Path(grounding_projection.__file__))
    assert not any(
        module.startswith(prefix)
        for module in modules
        for prefix in (
            "cloud_dast.consultation",
            "cloud_dast.ports",
            "cloud_dast.runtime.grounding",
        )
    )
    assert grounding_runtime.append_supersession is graph_ops.append_supersession
    assert not hasattr(grounding_runtime, "_timing_thresholds")

    for symbol in (
        "_accepted_fact_groups",
        "_current_replacement_facts",
        "_supersession_node_declarations",
        "_treatment_contains_canary",
    ):
        assert not _module_defines_method(grounding_runtime, symbol)


def test_axis_filtering_imports_without_grounding_owners() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.grounding.axes.filtering import _filter_grounding_graph
assert not set(['cloud_dast.runtime.grounding.startup', 'cloud_dast.runtime.grounding.reactive', 'cloud_dast.runtime.grounding.axes.scheduler', 'cloud_dast.runtime.grounding.axes.cache']).intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_finding_projection_is_verification_owned() -> None:
    modules = _imported_modules(Path(finding_projection.__file__))
    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert not (SOURCE_ROOT / "application/verification/finding_projection.py").exists()
    assert finding_projection.__name__ == "cloud_dast.verification.findings"


def test_vulnerability_taxonomy_is_verification_owned() -> None:
    from cloud_dast.verification.taxonomy import (
        DEFAULT_CATALOG,
        ClassCatalog,
    )

    assert ClassCatalog.__module__ == "cloud_dast.verification.taxonomy.catalog"
    assert DEFAULT_CATALOG.__class__.__module__ == (
        "cloud_dast.verification.taxonomy.catalog"
    )
    assert (SOURCE_ROOT / "verification/taxonomy/classes.yaml").exists()
    assert not (SOURCE_ROOT / "application/verification/class_catalog.py").exists()
    assert not (SOURCE_ROOT / "application/verification/classes.yaml").exists()


def test_finding_evaluation_and_result_contracts_are_application_owned() -> None:
    for module in (execution_results, finding_evaluator):
        assert not any(
            dependency.startswith("cloud_dast.workflow")
            for dependency in _imported_modules(Path(module.__file__))
        )

    assert not (SOURCE_ROOT / "workflow/execution/finding_evaluator.py").exists()


def test_identity_attachment_is_runtime_owned() -> None:
    from cloud_dast.runtime import binding, identity_projection

    modules = _imported_modules(Path(identity_projection.__file__))
    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert identity_projection.__name__ == "cloud_dast.runtime.identity_projection"

    for symbol in ("_apply_identity_terms", "_identity_terms_for_step"):
        assert not _module_owns_symbol(binding, symbol)


def test_setup_reference_and_service_projections_are_application_owned() -> None:
    from cloud_dast.runtime import binding

    for symbol in (
        "_principal_refs_by_action",
        "_principal_refs_from_targets",
        "_services",
        "_service_for_resource_type",
    ):
        assert not _module_owns_symbol(binding, symbol)


def test_coverage_models_are_verification_owned() -> None:
    modules = _imported_modules(Path(coverage_models.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)
    assert coverage_models.__name__ == "cloud_dast.verification.coverage_models"
    assert not (SOURCE_ROOT / "application/verification/coverage_models.py").exists()


def test_norm_coverage_read_model_is_verification_owned() -> None:
    modules = _imported_modules(Path(norm_coverage.__file__))

    assert not any(module.startswith("cloud_dast.workflow") for module in modules)

    api_modules = _imported_modules(SOURCE_ROOT / "api.py")
    assert "cloud_dast_reporting.norm_coverage" not in api_modules
    assert norm_coverage.__name__ == "cloud_dast.verification.norm_coverage"


def test_generator_and_fuzz_session_boundary_is_single_and_public() -> None:
    generator_parameters = inspect.signature(GeneratorContract.generate).parameters

    assert "feedback" in generator_parameters
    assert not hasattr(GeneratorContract, "generate_with_feedback")
    assert GeneratorContract.__module__ == "cloud_dast.extensions"
    assert FuzzSession.__module__ == "cloud_dast_fuzzing.session"
    assert FuzzSessionContract.__module__ == "cloud_dast.extensions"
    assert FuzzSessionFactory.__module__ == "cloud_dast.extensions"
    request_parameters = inspect.signature(FuzzSessionFactory.__call__).parameters
    assert tuple(request_parameters)[:2] == ("self", "request")
    assert FuzzSessionRequest.__module__ == "cloud_dast.extensions"


def test_fuzzing_extension_uses_public_core_ports() -> None:
    from cloud_dast.ports import EventStore, FindingExampleStore, Guardrail

    assert EventStore.__module__ == "cloud_dast.ports"
    assert FindingExampleStore.__module__ == "cloud_dast.ports"
    assert Guardrail.__module__ == "cloud_dast.ports"
    modules = _imported_modules(Path(inspect.getfile(FuzzSession)))
    assert not any(module.startswith("cloud_dast.application") for module in modules)
    assert not any(module.startswith("cloud_dast.workflow") for module in modules)


def test_payload_corpus_is_consumed_through_a_core_contract() -> None:
    """Corpus state may move to fuzzing without moving its read port."""

    assert PayloadCorpusSource.__module__ == "cloud_dast.extensions"


def test_payload_corpus_implementation_is_fuzzing_owned() -> None:
    assert PayloadCorpusCompiler.__module__ == "cloud_dast_fuzzing.corpus.compiler"
    assert PayloadCorpusStore.__module__ == "cloud_dast_fuzzing.corpus.store"
    assert (
        not (SOURCE_ROOT / "application/verification/generators/payload_corpus")
        .joinpath("compiler.py")
        .exists()
    )


def test_witness_signals_are_core_owned_and_history_uses_the_public_contract() -> None:
    from cloud_dast.verification.witness import WitnessSignal, extract_witness_signals
    from cloud_dast_fuzzing import history

    assert WitnessSignal.__module__ == "cloud_dast.verification.witness"
    assert extract_witness_signals.__module__ == "cloud_dast.verification.witness"
    history_modules = _imported_modules(Path(history.__file__))
    assert "cloud_dast.verification.oracles" not in history_modules
    assert "cloud_dast.verification.witness" in history_modules
    legacy_witness = SOURCE_ROOT / "application/verification/oracles/witness.py"
    assert not legacy_witness.exists()


def test_deterministic_oracles_are_verification_owned() -> None:
    from cloud_dast.verification.oracles import (
        GroundedOutcomeOracle,
        PrimitiveOracleRouter,
    )

    assert GroundedOutcomeOracle.__module__ == (
        "cloud_dast.verification.oracles.grounded"
    )
    assert PrimitiveOracleRouter.__module__ == (
        "cloud_dast.verification.oracles.primitive_router"
    )
    legacy = SOURCE_ROOT / "application/verification/oracles"
    assert not any(legacy.glob("*.py"))
    for module in (SOURCE_ROOT / "verification/oracles").glob("*.py"):
        assert not any(
            dependency.startswith("cloud_dast.application.verification.oracles")
            for dependency in _imported_modules(module)
        )


def test_grammar_facts_have_single_contract_and_runtime_owners() -> None:
    from cloud_dast.contracts.grammar import (
        GrammarConstraint,
        GrammarFacts,
        GrammarFieldRule,
    )
    from cloud_dast.runtime.grammar_facts import (
        compile,
    )

    assert GrammarConstraint.__module__ == "cloud_dast.contracts.grammar"
    assert GrammarFacts.__module__ == "cloud_dast.contracts.grammar"
    assert GrammarFieldRule.__module__ == "cloud_dast.contracts.grammar"
    assert compile.__module__ == "cloud_dast.runtime.grammar_facts"
    from cloud_dast.runtime import grammar_facts

    projection_modules = _imported_modules(Path(inspect.getfile(compile)))
    assert "cloud_dast.contracts.grammar" in projection_modules
    assert not _module_owns_symbol(grammar_facts, "GrammarFacts")
    assert not _module_owns_symbol(grammar_facts, "GrammarFieldRule")
    assert not (
        SOURCE_ROOT / "application/verification/formal/grammar_facts.py"
    ).exists()
    assert not (SOURCE_ROOT / "qdl/grammar.py").exists()
    assert not (SOURCE_ROOT / "qdl/grammar_facts.py").exists()


def test_optional_algorithm_extensions_use_only_core_public_surfaces() -> None:
    pytest.importorskip("aalpy")
    from cloud_dast_automata.learning import AALpyAutomataLearningAdapter

    forbidden = (
        "cloud_dast.application",
        "cloud_dast.composition",
        "cloud_dast.infrastructure",
        "cloud_dast.presentation",
        "cloud_dast.workflow",
    )
    for implementation in (AALpyAutomataLearningAdapter, Z3SymbolicGenerator):
        modules = _imported_modules(Path(inspect.getfile(implementation)))
        assert not any(module.startswith(forbidden) for module in modules)

    assert not (SOURCE_ROOT / "application/verification/formal/symbolic.py").exists()
    assert not (SOURCE_ROOT / "infrastructure/automata/aalpy.py").exists()
    with (SOURCE_ROOT.parent.parent / "pyproject.toml").open("rb") as metadata_file:
        core_metadata = tomllib.load(metadata_file)
    assert all(
        not dependency.startswith("aalpy")
        for dependency in core_metadata["project"]["dependencies"]
    )


def test_fuzzing_strategies_use_only_core_public_surfaces() -> None:
    from cloud_dast_fuzzing.strategies import FuzzingGenerator, GrammarGenerator

    forbidden = (
        "cloud_dast.application",
        "cloud_dast.composition",
        "cloud_dast.infrastructure",
        "cloud_dast.presentation",
        "cloud_dast.runtime",
        "cloud_dast.workflow",
    )
    for implementation in (FuzzingGenerator, GrammarGenerator):
        modules = _imported_modules(Path(inspect.getfile(implementation)))
        assert not any(module.startswith(forbidden) for module in modules)
    assert FuzzingGenerator.__module__ == "cloud_dast_fuzzing.strategies.fuzzing"
    assert GrammarGenerator.__module__ == "cloud_dast_fuzzing.strategies.grammar"
    assert not (
        SOURCE_ROOT / "application/verification/generators/grammar_compiler.py"
    ).exists()
    assert not (SOURCE_ROOT / "application/verification/generators/fuzzing.py").exists()


def test_llm_concrete_strategy_and_proposals_are_extension_owned() -> None:
    assert LlmGenerator.__module__ == "cloud_dast_llm.generator"
    assert LlmGeneratedChecks.__module__ == "cloud_dast_llm.proposals"
    assert not (SOURCE_ROOT / "application/verification/generators/llm.py").exists()
    modules = _imported_modules(Path(inspect.getfile(LlmGenerator)))
    assert not any(
        module.startswith(
            (
                "cloud_dast.application.verification",
                "cloud_dast.infrastructure",
                "cloud_dast.runtime",
                "cloud_dast.composition",
                "cloud_dast.workflow",
            )
        )
        for module in modules
    )
    provider_modules = _imported_modules(SOURCE_ROOT / "composition/run_provider.py")
    assert "cloud_dast_llm.generator" not in provider_modules
    from cloud_dast_llm import plugin

    plugin_modules = _imported_modules(Path(plugin.__file__))
    assert "cloud_dast_llm.generator" in plugin_modules
    assert "cloud_dast_llm.threat_model" in plugin_modules


def test_llm_consultation_lifecycle_is_extension_owned() -> None:
    assert ConsultationDispatcher.__module__ == "cloud_dast_llm.consultation"
    assert (
        SeedEnrichmentModelWireOutput.__module__
        == "cloud_dast.contracts.payload_proposals"
    )
    consultation_modules = _imported_modules(
        Path(inspect.getfile(ConsultationDispatcher))
    )
    assert not any(
        module.startswith("cloud_dast_fuzzing") for module in consultation_modules
    )
    assert not (
        SOURCE_ROOT / "application/verification/formal/consultation.py"
    ).exists()
    from cloud_dast import consultation

    assert consultation.ConsultationDispatcher.__module__ == "cloud_dast.consultation"


def test_proposal_boundary_has_single_schema_and_validator_owner() -> None:
    assert FormalModelOutputValidator.__module__ == "cloud_dast.contracts.proposals"
    assert EXTENSION_PREDICATE_SCHEMAS.__class__ is tuple
    assert EXTENSION_PREDICATE_SCHEMAS[0].__class__.__module__ == (
        "cloud_dast.qdl.ontology"
    )
    from cloud_dast.qdl import ontology

    assert ontology.PredicateSchema.__module__ == "cloud_dast.qdl.ontology"
    assert not (
        SOURCE_ROOT / "application/verification/formal/model_output.py"
    ).exists()
    assert not (SOURCE_ROOT / "application/verification/formal/validator.py").exists()


def test_message_schemas_have_single_model_owner() -> None:
    from cloud_dast.model import FieldSpec, MessageSchema, RequestSchema, ResponseSchema

    for schema_type in (FieldSpec, MessageSchema, RequestSchema, ResponseSchema):
        assert schema_type.__module__ == "cloud_dast.model.schemas"
    assert (SOURCE_ROOT / "model/schemas.py").exists()


def test_qdl_surface_language_has_one_compiler_and_renderer_owner() -> None:
    from cloud_dast.qdl.compiler import QdlCompiler
    from cloud_dast.qdl.diagnostics import Diagnostic
    from cloud_dast.qdl.renderer import render_qdl
    from cloud_dast.qdl.syntax import SurfaceDocument

    assert QdlCompiler.__module__ == "cloud_dast.qdl.compiler"
    assert Diagnostic.__module__ == "cloud_dast.qdl.diagnostics"
    assert SurfaceDocument.__module__ == "cloud_dast.qdl.syntax"
    assert render_qdl.__module__ == "cloud_dast.qdl.renderer"
    from cloud_dast.qdl import compiler, parser

    assert "lark" in _imported_modules(Path(parser.__file__))
    assert not _module_owns_class(parser, "SurfaceDocument")
    assert not _module_owns_class(compiler, "QdlGraph")


def test_repository_ports_have_single_core_owner() -> None:
    from cloud_dast.ports import (
        ContractGraphRepository,
        FormalRepository,
        GraphNode,
        MethodRepository,
        ServiceGraphSlice,
    )

    assert ContractGraphRepository.__module__ == "cloud_dast.ports"
    assert FormalRepository.__module__ == "cloud_dast.ports"
    assert MethodRepository.__module__ == "cloud_dast.ports"
    assert GraphNode.__module__ == "cloud_dast.ports"
    assert ServiceGraphSlice.__module__ == "cloud_dast.ports"


def test_ordinary_requests_need_no_provisioning_port() -> None:
    from cloud_dast import ports

    assert not hasattr(ports, "ProvisionerPort")
    assert not hasattr(ports, "FixtureRequest")
    assert not (SOURCE_ROOT / "application/ports/provisioning.py").exists()
    assert not (SOURCE_ROOT / "runtime/setup.py").exists()
    assert not (SOURCE_ROOT / "runtime/provisioning.py").exists()
    assert not (SOURCE_ROOT / "infrastructure/runtime/provisioning.py").exists()


def test_evidence_model_and_channel_have_single_core_owners() -> None:
    from cloud_dast.ports import EvidenceChannel, EvidenceEvent

    assert EvidenceEvent.__module__ == "cloud_dast.ports"
    assert EvidenceChannel.__module__ == "cloud_dast.ports"
    assert not (SOURCE_ROOT / "application/ports/evidence.py").exists()

    production_modules = tuple(
        dependency
        for root in (SOURCE_ROOT / "runtime", SOURCE_ROOT / "infrastructure")
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert "cloud_dast.application.ports.evidence" not in production_modules


def test_grounding_cache_and_metrics_have_single_core_owners() -> None:
    from cloud_dast.ports import CampaignMetricsRecorder, GroundingCache

    assert GroundingCache.__module__ == "cloud_dast.ports"
    assert CampaignMetricsRecorder.__module__ == "cloud_dast.ports"
    assert not (SOURCE_ROOT / "application/ports/grounding_cache.py").exists()
    assert not (SOURCE_ROOT / "application/ports/metrics.py").exists()

    production_modules = tuple(
        dependency
        for root in (SOURCE_ROOT / "runtime", SOURCE_ROOT / "infrastructure")
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert "cloud_dast.application.ports.grounding_cache" not in production_modules
    assert "cloud_dast.application.ports.metrics" not in production_modules


def test_metric_read_models_are_contract_owned() -> None:
    from cloud_dast.contracts import metrics as metric_contracts

    assert metric_contracts.CampaignMetricsSnapshot.__module__ == (
        "cloud_dast.contracts.metrics"
    )
    assert metric_contracts.TokenUsageSnapshot.__module__ == (
        "cloud_dast.contracts.metrics"
    )
    assert not (SOURCE_ROOT / "runtime/metrics_models.py").exists()
    reporting_service = (
        SOURCE_ROOT.parents[3]
        / "packages/reporting/src/cloud_dast_reporting/service.py"
    )
    assert "cloud_dast.runtime.metrics_models" not in reporting_service.read_text()


def test_grounding_runtime_ports_have_single_core_owner() -> None:
    from cloud_dast.ports import GroundingBatch, GroundingHandle, GroundingRunner

    for contract in (GroundingBatch, GroundingHandle, GroundingRunner):
        assert contract.__module__ == "cloud_dast.ports"
    assert not (SOURCE_ROOT / "application/ports/grounding.py").exists()

    production_modules = tuple(
        dependency
        for root in (SOURCE_ROOT / "runtime", SOURCE_ROOT / "infrastructure")
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert "cloud_dast.application.ports.grounding" not in production_modules


def test_grounding_source_loading_has_one_owner() -> None:
    from cloud_dast.runtime.grounding import lifecycle, runtime, source, variance

    assert source.Loader.__module__ == "cloud_dast.runtime.grounding.source"
    assert not _module_defines_method(runtime, "load")
    assert not _module_defines_method(lifecycle, "_load_source")
    assert not _module_defines_method(variance, "_load_source")
    assert "cloud_dast.qdl.graph_ops" not in _imported_modules(Path(lifecycle.__file__))
    assert "cloud_dast.qdl.graph_ops" not in _imported_modules(Path(variance.__file__))


def test_grounding_consultation_flow_is_not_owned_by_service_facade() -> None:
    from cloud_dast.runtime.grounding import consultation, runtime

    assert consultation.DispatchFlow.__module__ == (
        "cloud_dast.runtime.grounding.consultation"
    )
    for method in ("_rejected_consultation", "_save_consultation"):
        assert not _module_defines_method(runtime, method)
    assert not _module_defines_method(runtime, "_publish_consultation_suppressed")


def test_grounding_service_uses_one_options_owner() -> None:
    from cloud_dast.composition.grounding import ServiceOptions

    assert ServiceOptions.__module__ == "cloud_dast.composition.grounding"


def test_grounding_call_inputs_have_one_contract_owner() -> None:
    from cloud_dast.runtime.grounding import inputs, reactive, variance

    for name in ("ReactiveCall", "BranchCall", "PairInput"):
        assert getattr(inputs, name).__module__ == (
            "cloud_dast.runtime.grounding.inputs"
        )
    assert not _module_owns_class(reactive, "ReactiveCall")
    assert not _module_owns_class(reactive, "BranchCall")
    assert not _module_owns_class(variance, "PairInput")


def test_approval_audit_model_and_port_have_single_core_owners() -> None:
    from cloud_dast.model.events import ApprovalAuditRecord
    from cloud_dast.ports import ApprovalAuditLog

    assert ApprovalAuditRecord.__module__ == "cloud_dast.model.events"
    assert ApprovalAuditLog.__module__ == "cloud_dast.ports"
    assert not (SOURCE_ROOT / "application/ports/approvals.py").exists()

    production_modules = tuple(
        dependency
        for root in (SOURCE_ROOT / "runtime", SOURCE_ROOT / "infrastructure")
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert "cloud_dast.application.ports.approvals" not in production_modules


def test_production_code_does_not_depend_on_application_port_facade() -> None:
    production_modules = tuple(
        dependency
        for path in SOURCE_ROOT.rglob("*.py")
        if "/application/ports/" not in str(path)
        for dependency in _imported_modules(path)
    )
    assert not any(
        dependency.startswith("cloud_dast.application.ports")
        for dependency in production_modules
    )


def test_observation_projection_has_verification_owner() -> None:
    from cloud_dast.verification.projection import ObservationProjector
    from cloud_dast.verification.projection import (
        ObservationProjector as LegacyObservationProjector,
    )

    assert LegacyObservationProjector is ObservationProjector
    assert ObservationProjector.__module__ == "cloud_dast.verification.projection"
    modules = tuple(
        dependency
        for root in (
            SOURCE_ROOT / "runtime",
            SOURCE_ROOT / "verification",
            SOURCE_ROOT / "composition",
        )
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert not any(module.startswith("cloud_dast.application") for module in modules)


def test_contract_projection_has_verification_owner() -> None:
    from cloud_dast.verification.contract_projection import ContractProjector
    from cloud_dast.verification.contract_projection import (
        ContractProjector as LegacyContractProjector,
    )

    assert LegacyContractProjector is ContractProjector
    assert ContractProjector.__module__ == "cloud_dast.verification.contract_projection"
    modules = tuple(
        dependency
        for root in (
            SOURCE_ROOT / "runtime",
            SOURCE_ROOT / "verification",
            SOURCE_ROOT / "composition",
        )
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert not any(module.startswith("cloud_dast.application") for module in modules)


def test_formal_projection_owns_planner_view() -> None:
    from cloud_dast.qdl.projection import planner_view

    assert planner_view.__module__ == ("cloud_dast.qdl.projection")
    assert (SOURCE_ROOT / "qdl/projection.py").exists()


def test_differential_evidence_has_verification_owner() -> None:
    from cloud_dast.verification.differential import (
        DiffReport,
        compare_observations,
        project_diff,
    )

    assert DiffReport.__module__ == "cloud_dast.verification.differential.report"
    assert compare_observations.__module__ == (
        "cloud_dast.verification.differential.comparator"
    )
    assert project_diff.__module__ == "cloud_dast.verification.differential.projection"
    assert not (
        SOURCE_ROOT / "application/verification/differential"
    ).exists() or not any(
        path.suffix == ".py"
        for path in (SOURCE_ROOT / "application/verification/differential").iterdir()
    )
    modules = tuple(
        dependency
        for path in (SOURCE_ROOT / "verification/differential").glob("*.py")
        for dependency in _imported_modules(path)
    )
    assert not any(module.startswith("cloud_dast.application") for module in modules)


def test_state_machine_engine_has_qdl_owner() -> None:
    from cloud_dast.qdl.state_machine import (
        StateMachineEngine,
    )

    assert StateMachineEngine.__module__ == ("cloud_dast.qdl.state_machine")
    assert (SOURCE_ROOT / "qdl/state_machine.py").exists()


def test_qdl_graph_state_has_facts_owner_and_stable_facade() -> None:
    from cloud_dast.qdl.facts import Fact, QdlGraph, Rule
    from cloud_dast.qdl.graph import (
        Fact as GraphFact,
    )
    from cloud_dast.qdl.graph import (
        QdlGraph as Graph,
    )
    from cloud_dast.qdl.graph import (
        Rule as GraphRule,
    )

    assert Fact.__module__ == "cloud_dast.qdl.facts"
    assert QdlGraph.__module__ == "cloud_dast.qdl.facts"
    assert Rule.__module__ == "cloud_dast.qdl.facts"
    assert GraphFact is Fact
    assert Graph is QdlGraph
    assert GraphRule is Rule
    from cloud_dast.qdl import graph

    assert not _module_owns_class(graph, "Fact")
    assert not _module_owns_class(graph, "Rule")
    assert not _module_owns_class(graph, "QdlGraph")


def test_state_machine_spec_and_ingestion_have_split_owners() -> None:
    from cloud_dast.qdl.state_machine_spec import (
        StateMachineSpecification,
    )
    from cloud_dast.verification.state_machine_ingestion import (
        StateMachineIngestionService,
    )

    assert StateMachineSpecification.__module__ == ("cloud_dast.qdl.state_machine_spec")
    assert (
        StateMachineIngestionService.__module__
        == "cloud_dast.verification.state_machine_ingestion"
    )
    ingestion_modules = _imported_modules(
        SOURCE_ROOT / "verification/state_machine_ingestion.py"
    )
    assert (SOURCE_ROOT / "qdl/state_machine_spec.py").exists()
    assert "cloud_dast.qdl.state_machine_spec" in ingestion_modules
    assert not (
        SOURCE_ROOT / "application/verification/formal/state_machine_ingestion.py"
    ).exists()


def test_threat_compiler_has_qdl_owner() -> None:
    from cloud_dast.qdl.threat_compiler import (
        ThreatIntentCompiler,
    )

    assert ThreatIntentCompiler.__module__ == ("cloud_dast.qdl.threat_compiler")
    assert (SOURCE_ROOT / "qdl/threat_compiler.py").exists()


def test_threat_modeler_belongs_to_llm_extension() -> None:
    from cloud_dast.extensions import ExtensionRegistry
    from cloud_dast.proposals import FormalThreatModelResult, ThreatModelProposer
    from cloud_dast_llm.plugin import register

    assert FormalThreatModeler.__module__ == "cloud_dast_llm.threat_model"
    assert FormalThreatModelResult.__module__ == "cloud_dast.proposals"
    assert getattr(ThreatModelProposer, "__module__", "") == "cloud_dast.proposals"
    registry = ExtensionRegistry()
    register(registry)
    assert registry.threat_modeler_factory is FormalThreatModeler
    production_modules = tuple(
        dependency
        for root in (
            SOURCE_ROOT / "runtime",
            SOURCE_ROOT / "composition",
            SOURCE_ROOT / "verification",
        )
        for path in root.rglob("*.py")
        for dependency in _imported_modules(path)
    )
    assert not any(
        dependency.startswith("cloud_dast_llm") for dependency in production_modules
    )


def test_qdl_reasoning_and_engine_have_single_owners() -> None:
    from cloud_dast.qdl.engine import ClingoEngine as QdlEngine
    from cloud_dast.qdl.semantic_norm_compiler import (
        SemanticNormCompiler as QdlCompiler,
    )

    assert QdlEngine.__module__ == "cloud_dast.qdl.engine"
    assert QdlCompiler.__module__ == ("cloud_dast.qdl.semantic_norm_compiler")


def test_qdl_and_verification_projection_owners_are_single() -> None:
    from cloud_dast.binding import scenario_scope
    from cloud_dast.qdl.couplings import FieldCoupling
    from cloud_dast.qdl.field_roles import FieldRolePolicy
    from cloud_dast.qdl.roles import SemanticRole
    from cloud_dast.verification.evidence import EvidenceView
    from cloud_dast.verification.norm_view import NormView
    from cloud_dast.verification.norms import NormCompiler
    from cloud_dast.verification.slices import BoundedSlice

    assert FieldRolePolicy.__module__ == "cloud_dast.qdl.field_roles"
    assert scenario_scope.__module__ == "cloud_dast.binding"
    assert FieldCoupling.__module__ == "cloud_dast.couplings"
    assert NormCompiler.__module__ == "cloud_dast.verification.norms"
    assert SemanticRole.__module__ == "cloud_dast.qdl.roles"
    assert NormView.__module__ == "cloud_dast.verification.norm_view"
    assert EvidenceView.__module__ == "cloud_dast.verification.evidence"
    assert BoundedSlice.__module__ == "cloud_dast.verification.slices"
    for old_path in (
        "application/verification/formal/field_roles.py",
        "application/verification/formal/evidence_view.py",
        "application/verification/formal/slices.py",
        "application/verification/oracles/norm_view.py",
    ):
        assert not (SOURCE_ROOT / old_path).exists()
    assert (SOURCE_ROOT / "verification/norm_view.py").exists()
    assert not (SOURCE_ROOT / "qdl/norm_view.py").exists()


def test_qdl_has_no_backwards_application_facades() -> None:
    """QDL must not point back into the transitional application namespace."""

    for path in (SOURCE_ROOT / "qdl").rglob("*.py"):
        assert not any(
            dependency.startswith("cloud_dast.application")
            for dependency in _imported_modules(path)
        ), path


def test_campaign_runtime_does_not_own_per_step_fuzz_state() -> None:
    runtime_fields = set(RuntimeState.__annotations__)

    assert not runtime_fields & {"fuzz_session", "generators", "strategy_state"}


def test_campaign_runtime_state_has_explicit_lifecycle_slices() -> None:
    from cloud_dast.runtime.campaign.state import (
        DifferentialState,
        ExecutionState,
        GroundingState,
    )

    assert ExecutionState.__module__ == "cloud_dast.runtime.campaign.state"
    assert DifferentialState.__module__ == "cloud_dast.runtime.campaign.state"
    assert GroundingState.__module__ == "cloud_dast.runtime.campaign.state"
    assert set(RuntimeState.__annotations__) == {
        "request",
        "binding",
        "scope",
        "execution",
        "differential",
        "grounding",
    }


def test_grounding_promotion_has_one_runtime_owner() -> None:
    from cloud_dast.runtime import grounding
    from cloud_dast.runtime.grounding import promotion as grounding_promotion
    from cloud_dast.runtime.grounding.promotion import ProposalPromoter

    assert ProposalPromoter.__module__ == ("cloud_dast.runtime.grounding.promotion")
    for method in (
        "_park_promotion_outputs",
        "_save_parked_proposal",
        "_park_secret_shapes",
        "_publish_promotion_activity",
        "_save_promoted_graph",
    ):
        assert not _module_defines_method(grounding, method)
    assert Path(grounding_promotion.__file__).exists()


def test_grounding_lifecycle_has_one_runtime_owner() -> None:
    from cloud_dast.runtime import grounding
    from cloud_dast.runtime.grounding import lifecycle as grounding_lifecycle
    from cloud_dast.runtime.grounding.lifecycle import RunCoordinator

    assert RunCoordinator.__module__ == "cloud_dast.runtime.grounding.lifecycle"
    for method in (
        "_run_grounded_worker",
        "_start_formal",
        "_promote_axis_batch",
        "_publish_formal_result",
        "_project_stand_if_configured",
    ):
        assert not _module_defines_method(grounding, method)
    assert Path(grounding_lifecycle.__file__).exists()


def test_grounding_uses_one_semantic_namespace() -> None:
    from cloud_dast.runtime import grounding
    from cloud_dast.runtime.grounding import (
        evidence,
        lifecycle,
        projection,
        promotion,
        results,
        runtime,
        state,
        variance,
    )

    package = Path(grounding.__file__).parent
    for old_name in (
        "grounding.py",
        "grounding_lifecycle.py",
        "grounding_projection.py",
        "grounding_promotion.py",
        "grounding_results.py",
        "grounding_state.py",
    ):
        assert not (package.parent / old_name).exists()

    assert runtime.BatchFlow.__module__ == ("cloud_dast.runtime.grounding.runtime")
    assert lifecycle.RunCoordinator.__module__ == (
        "cloud_dast.runtime.grounding.lifecycle"
    )
    assert promotion.ProposalPromoter.__module__ == (
        "cloud_dast.runtime.grounding.promotion"
    )
    assert results.AxisResult.__module__ == "cloud_dast.runtime.grounding.results"
    assert state.LeadLifecycle.__module__ == "cloud_dast.runtime.grounding.state"
    from cloud_dast.qdl.graph_ops import append_supersession

    assert append_supersession.__module__ == "cloud_dast.qdl.graph_ops"
    assert not _module_owns_symbol(projection, "append_supersession")
    assert evidence.MeasuredEvidencePolicy.__module__ == (
        "cloud_dast.runtime.grounding.evidence"
    )
    assert variance.DifferentialFlow.__module__ == (
        "cloud_dast.runtime.grounding.variance"
    )
    assert not _module_owns_class(runtime, "MeasuredEvidencePolicy")
    assert not _module_owns_class(runtime, "DifferentialFlow")


def test_per_step_candidate_lifecycle_has_one_runtime_owner() -> None:
    assert step_candidates.StepCandidateRunner.__module__ == (
        "cloud_dast.runtime.candidates.session"
    )
    from cloud_dast.runtime import execution

    assert not _module_owns_class(execution, "StepCandidateRunner")
    for method in ("_next_unprefiltered", "_next_prefiltered", "_path_candidates"):
        assert not _module_defines_method(execution, method)
    assert hasattr(step_candidates.StepCandidateRunner, "preview_path")


def test_differential_probe_execution_has_one_runtime_owner() -> None:
    modules = _imported_modules(Path(differential.__file__))

    assert differential.ProbeExecutor.__module__ == (
        "cloud_dast.runtime.differential.executor"
    )
    assert not any(module.startswith("cloud_dast.infrastructure") for module in modules)
    from cloud_dast.runtime import execution

    for method in (
        "_prepare_differential_steps",
        "_execute_concurrency_batch",
        "_pair_partial_result",
    ):
        assert not _module_defines_method(execution, method)


def test_differential_step_context_has_one_owner() -> None:
    from cloud_dast.runtime.differential import context, probes

    assert context.ProbeContext.__module__ == (
        "cloud_dast.runtime.differential.context"
    )
    assert "ProbeContext" not in probes.__dict__
    assert "evaluate_step_modes" in probes.ProbeRunner.__dict__


def test_differential_executor_and_probe_coordinator_are_distinct() -> None:
    from cloud_dast.runtime.differential import executor, probes

    assert executor.ProbeExecutor.__module__ == (
        "cloud_dast.runtime.differential.executor"
    )
    assert probes.ProbeRunner.__module__ == ("cloud_dast.runtime.differential.probes")
    assert executor.ProbeExecutor is not probes.ProbeRunner
    assert "executor" in probes.ProbeCallbacks.__dataclass_fields__
    assert "runner" not in probes.ProbeCallbacks.__dataclass_fields__
    assert not (SOURCE_ROOT / "runtime/differential/facade.py").exists()
    for method in (
        "execute_step_pair",
        "execute_readback",
        "execute_concurrency_step",
    ):
        assert hasattr(executor.ProbeExecutor, method)
        assert not hasattr(probes.ProbeRunner, method)
    for method in (
        "evaluate_step_modes",
        "_evaluate_pair",
        "_evaluate_readback_pair",
        "_evaluate_timing_pair",
        "_evaluate_concurrency_pair",
    ):
        assert hasattr(probes.ProbeRunner, method)
        assert not hasattr(executor.ProbeExecutor, method)


def test_timing_mode_has_one_runtime_owner() -> None:
    from cloud_dast.runtime.differential import probes, timing

    assert timing.LatencyProbe.__module__ == ("cloud_dast.runtime.differential.timing")
    for method in (
        "_evaluate_timing_pair",
        "_measure_timing_pairs",
        "_measure_timing_pair",
    ):
        assert method in timing.LatencyProbe.__dict__
        assert method not in probes.ProbeRunner.__dict__


def test_concurrency_mode_has_one_runtime_owner() -> None:
    from cloud_dast.runtime.differential import concurrency, probes

    assert concurrency.ParallelProbe.__module__ == (
        "cloud_dast.runtime.differential.concurrency"
    )
    for method in (
        "_evaluate_concurrency_pair",
        "_record_concurrency_result",
        "_execute_concurrency_measurement",
    ):
        assert method in concurrency.ParallelProbe.__dict__
        assert method not in probes.ProbeRunner.__dict__


def test_consultation_outcome_automaton_is_runtime_owned() -> None:
    from cloud_dast.runtime.consultation import outcomes

    assert Path(outcomes.__file__).parent == SOURCE_ROOT / "runtime/consultation"
    assert not (
        SOURCE_ROOT / "application/verification/formal/consultation_outcomes.py"
    ).exists()


def test_live_execution_owners_are_in_runtime_not_workflow() -> None:
    from cloud_dast.runtime import (
        binding,
        budget,
        campaign,
        deficits,
        execution,
        metrics,
        recovery,
        scheduler,
    )
    from cloud_dast.runtime.differential import evidence as differential_evidence
    from cloud_dast.runtime.execution import scenarios

    modules = (
        recovery,
        binding,
        budget,
        campaign,
        deficits,
        differential_evidence,
        execution,
        metrics,
        scenarios,
        scheduler,
    )
    runtime_roots = {
        SOURCE_ROOT / "runtime",
        SOURCE_ROOT / "runtime/campaign",
        SOURCE_ROOT / "runtime/differential",
        SOURCE_ROOT / "runtime/deficits",
        SOURCE_ROOT / "runtime/execution",
        SOURCE_ROOT / "runtime/scheduler",
    }
    for module in modules:
        assert Path(module.__file__).parent in runtime_roots

    assert campaign.LiveWorkflow.__module__ == "cloud_dast.runtime.campaign.runtime"
    assert RuntimeState.__module__ == "cloud_dast.runtime.campaign.state"
    assert recovery.Coordinator.__module__ == "cloud_dast.runtime.recovery"
    assert Path(recovery.__file__) == SOURCE_ROOT / "runtime/recovery.py"
    assert (SOURCE_ROOT / "runtime/campaign/__init__.py").exists()
    for old_module in (
        "campaign.py",
        "campaign_initialization.py",
        "campaign_finalization.py",
        "campaign_round.py",
        "campaign_state.py",
        "campaign_replay.py",
        "campaign_graph.py",
    ):
        assert not (SOURCE_ROOT / "runtime" / old_module).exists()
    assert not (SOURCE_ROOT / "workflow/execution/live_workflow.py").exists()
    assert not (SOURCE_ROOT / "runtime/backtracking.py").exists()

    assert binding.ScenarioBinder.__module__ == "cloud_dast.runtime.binding"

    for old_name in (
        "backtracking",
        "binder",
        "budget",
        "deficits",
        "differential_evidence",
        "metrics",
        "path_runner",
        "provisioning",
        "runner",
        "scheduler",
        "step_setup",
    ):
        assert not (SOURCE_ROOT / f"workflow/execution/{old_name}.py").exists()

    moved_modules = {
        f"cloud_dast.workflow.execution.{name}"
        for name in (
            "backtracking",
            "binder",
            "budget",
            "deficits",
            "differential_evidence",
            "metrics",
            "path_runner",
            "provisioning",
            "runner",
            "scheduler",
            "step_setup",
        )
    }
    for module in modules:
        assert not any(
            dependency in moved_modules
            for dependency in _imported_modules(Path(module.__file__))
        )
        assert not any(
            dependency.startswith("cloud_dast.workflow")
            for dependency in _imported_modules(Path(module.__file__))
        )


def test_public_campaign_contracts_have_one_inward_owner() -> None:
    from cloud_dast import api
    from cloud_dast.contracts.execution import LiveRequest, LiveResult, ScenarioBinding
    from cloud_dast.contracts.plan import (
        QdlExecutionPath,
        QdlExecutionStep,
        QdlExecutionView,
    )

    assert api.LiveRequest is LiveRequest
    assert api.LiveResult is LiveResult
    assert api.ScenarioBinding is ScenarioBinding
    assert api.QdlExecutionPath is QdlExecutionPath
    assert api.QdlExecutionStep is QdlExecutionStep
    assert api.QdlExecutionView is QdlExecutionView


def test_public_contracts_import_without_runtime_or_verification() -> None:
    import subprocess
    import sys

    script = f"""
import sys
from typing import get_type_hints
sys.path[:0] = {sys.path!r}
from cloud_dast import api
from cloud_dast.contracts.assessment import CoverageMatrix, NormCoverageRow
from cloud_dast.contracts.plan import InvariantProjection
for contract in (api.LiveRequest, api.LiveResult, api.ScenarioBinding,
                 api.QdlExecutionStep, api.QdlExecutionPath, api.QdlExecutionView,
                 CoverageMatrix, NormCoverageRow, InvariantProjection):
    get_type_hints(contract)
assert not any(name == prefix or name.startswith(prefix + ".")
               for name in sys.modules
               for prefix in ("cloud_dast.runtime", "cloud_dast.verification",
                              "cloud_dast.infrastructure", "cloud_dast.composition"))
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_proposal_promotion_contract_is_public_and_single_owned() -> None:
    from cloud_dast.proposals import (
        ProposalPromoter,
        ProposalPromotionRequest,
        ProposalPromotionResult,
    )

    assert ProposalPromotionRequest.__module__ == "cloud_dast.proposals"
    assert ProposalPromotionResult.__module__ == "cloud_dast.proposals"
    assert ProposalPromoter.__module__ == "cloud_dast.proposals"
    assert not (
        SOURCE_ROOT / "application/verification/formal/promotion_contracts.py"
    ).exists()
    assert not (
        SOURCE_ROOT / "application/verification/formal/proposal_promotion.py"
    ).exists()


def test_causal_paths_have_no_parallel_setup_executor() -> None:
    from cloud_dast.extensions import ExtensionRegistry
    from cloud_dast.runtime.candidates import session as step_candidates
    from cloud_dast.runtime.execution import runner as execution

    imported = _imported_modules(Path(execution.__file__))
    assert not any(
        module
        in {
            "cloud_dast.runtime.setup",
            "cloud_dast.runtime.provisioning",
            "cloud_dast.runtime.chain",
        }
        for module in imported
    )
    assert not hasattr(ExtensionRegistry(), "chain_session_factory")
    assert hasattr(step_candidates, "StepCandidateRunner")
    assert not (SOURCE_ROOT / "runtime/setup.py").exists()
    assert not (SOURCE_ROOT / "runtime/provisioning.py").exists()
    assert not (SOURCE_ROOT / "runtime/chain.py").exists()


def test_observation_evaluation_is_verification_owned() -> None:
    from cloud_dast.runtime.execution import runner as execution
    from cloud_dast.verification import evaluation
    from cloud_dast.verification.differential.contracts import (
        DifferentialEvidenceView,
    )

    assert evaluation.ObservationEvaluator.__module__ == (
        "cloud_dast.verification.evaluation"
    )
    assert evaluation.ObservationEvaluation.__module__ == (
        "cloud_dast.verification.evaluation"
    )
    assert DifferentialEvidenceView.__module__ == (
        "cloud_dast.verification.differential.contracts"
    )
    evaluation_modules = _imported_modules(Path(evaluation.__file__))
    assert not any(
        module.startswith("cloud_dast.runtime") for module in evaluation_modules
    )
    for method in (
        "_classify",
        "_concurrency_verdict",
        "_trace_for_step",
        "_readback_trace_for_measurement",
        "_concurrency_trace",
        "_unscoreable",
    ):
        assert not _module_defines_method(execution, method)


def test_campaign_round_owns_scheduler_loop() -> None:
    from cloud_dast.runtime.campaign import round as campaign_round
    from cloud_dast.runtime.campaign.replay import RoundReplay
    from cloud_dast.runtime.execution import runner as execution
    from cloud_dast.runtime.execution.state import (
        CampaignAccumulator,
        CampaignRoundState,
    )

    assert campaign_round.Runner.__module__ == ("cloud_dast.runtime.campaign.round")
    assert CampaignRoundState.__module__ == "cloud_dast.runtime.execution.state"
    assert CampaignAccumulator.__module__ == "cloud_dast.runtime.execution.state"
    assert RoundReplay.__module__ == "cloud_dast.runtime.campaign.replay"
    round_fields = set(CampaignRoundState.__annotations__)
    assert not round_fields & {
        "verified_fact_ids",
        "evaluated_outcomes",
        "evaluated_signatures",
    }
    assert not _module_owns_class(campaign_round, "CampaignRoundState")
    assert not _module_owns_class(campaign_round, "CampaignAccumulator")
    assert not _module_defines_method(execution, "_replay_round_state")


def test_path_terminalization_is_runtime_owned() -> None:
    from cloud_dast.runtime.execution import runner as execution
    from cloud_dast.runtime.execution import terminal as path_terminal

    assert path_terminal.PathTerminalizer.__module__ == (
        "cloud_dast.runtime.execution.terminal"
    )
    assert path_terminal.PathAttempt.__module__ == (
        "cloud_dast.runtime.execution.terminal"
    )
    for method in (
        "_finish_path_attempt",
        "_publish_path_evaluated",
        "_restore_intent_state",
        "_publish_scheduler_terminal_events",
        "_publish_missing_terminal_path_events",
    ):
        assert not _module_defines_method(execution, method)


def test_evidence_projection_is_not_owned_by_path_runner() -> None:
    from cloud_dast.runtime import evidence_projection
    from cloud_dast.runtime.execution import runner as execution

    assert evidence_projection.Projection.__module__ == (
        "cloud_dast.runtime.evidence_projection"
    )
    assert not _module_defines_method(execution, "_observed_graph")
    assert not _module_defines_method(execution, "_persist_observation")


def test_grounding_state_is_not_owned_by_grounding_orchestration() -> None:
    from cloud_dast.runtime import grounding
    from cloud_dast.runtime.grounding import state as grounding_state

    assert grounding_state.LeadLifecycle.__module__ == (
        "cloud_dast.runtime.grounding.state"
    )
    assert grounding_state.ConsultationLedger.__module__ == (
        "cloud_dast.runtime.grounding.state"
    )
    assert not _module_owns_class(grounding, "LeadLifecycle")
    assert not _module_owns_class(grounding, "ConsultationLedger")


def test_planning_projections_have_separate_owners() -> None:
    from cloud_dast.runtime import planning
    from cloud_dast.runtime.planning import (
        attacks,
        core,
        invariants,
        rules,
        states,
        symbols,
    )

    assert planning.QdlPlanner is core.QdlPlanner
    assert core.QdlPlanner.__module__ == "cloud_dast.runtime.planning.core"
    assert attacks.declared_action_ids.__module__ == (
        "cloud_dast.runtime.planning.attacks"
    )
    assert states.find_state_paths.__module__ == ("cloud_dast.runtime.planning.states")
    assert invariants.compile_invariants.__module__ == (
        "cloud_dast.runtime.planning.invariants"
    )
    assert symbols._path_id.__module__ == "cloud_dast.runtime.planning.symbols"
    assert rules.__name__ == "cloud_dast.runtime.planning.rules"
    assert rules._WALK_RULES
    assert not (SOURCE_ROOT / "runtime/planning.py").exists()
    assert not _module_owns_class(attacks, "QdlPlanner")
    assert not _module_owns_class(states, "QdlPlanner")
    assert not _module_owns_class(invariants, "QdlPlanner")


def test_executable_path_assembly_is_not_owned_by_view_facade() -> None:
    from cloud_dast.runtime.execution import projection as path_projection
    from cloud_dast.runtime.execution import view as execution_view

    assert path_projection.bind_execution_paths.__module__ == (
        "cloud_dast.runtime.execution.projection"
    )
    assert execution_view.bind_execution_paths is path_projection.bind_execution_paths
    assert not _module_defines_method(execution_view, "bind_execution_paths")
    assert not _module_defines_method(execution_view, "bind_contract_smoke_paths")


def test_scheduler_scoring_is_not_owned_by_scheduler_state() -> None:
    from cloud_dast.runtime import prioritization, scheduler

    assert prioritization.InterestPrioritizer.__module__ == (
        "cloud_dast.runtime.prioritization"
    )
    assert prioritization.ColdScore.__module__ == ("cloud_dast.runtime.prioritization")
    assert not hasattr(scheduler, "InterestPrioritizer")
    assert not _module_owns_class(scheduler, "InterestPrioritizer")
    assert not _module_owns_class(scheduler, "ColdScore")


def test_scheduler_state_and_ranking_import_without_coordination() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.scheduler.model import State
from cloud_dast.runtime.scheduler.selection import rank_path, pending_outcomes
state = State()
assert not state.selections and not state.outcomes
assert not any(name == prefix or name.startswith(prefix + ".")
               for name in sys.modules
               for prefix in ("cloud_dast.runtime.scheduler.core",
                              "cloud_dast.runtime.scheduler.prewarm",
                              "cloud_dast.runtime.scheduler.registry",
                              "cloud_dast.runtime.campaign",
                              "cloud_dast.runtime.execution"))
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_deficit_queue_state_is_not_owned_by_queue_policy() -> None:
    from cloud_dast.runtime.deficits import queue as deficit_queue
    from cloud_dast.runtime.deficits import queue_state as deficit_queue_state

    assert deficit_queue_state.QueueEntry.__module__ == (
        "cloud_dast.runtime.deficits.queue_state"
    )
    assert deficit_queue_state.WorkItemState.__module__ == (
        "cloud_dast.runtime.deficits.queue_state"
    )
    assert deficit_queue_state.WorkGroup.__module__ == (
        "cloud_dast.runtime.deficits.queue_state"
    )
    for symbol in (
        "QueueEntry",
        "WorkItemState",
        "WorkGroup",
        "DispatchState",
    ):
        assert not _module_owns_class(deficit_queue, symbol)


def test_partial_differential_results_are_not_owned_by_checker() -> None:
    from cloud_dast.runtime.differential import results as differential_results
    from cloud_dast.runtime.execution import scenarios as runner

    assert differential_results.PartialExecutionResult.__module__ == (
        "cloud_dast.runtime.differential.results"
    )
    assert differential_results.PartialExecutionError.__module__ == (
        "cloud_dast.runtime.differential.results"
    )
    for symbol in (
        "PartialExecutionResult",
        "PairPartialResult",
        "ReadBackPartialResult",
        "ConcurrencyPartialResult",
        "PartialExecutionError",
    ):
        assert not _module_owns_class(runner, symbol)


def test_coupling_solver_is_not_owned_by_scenario_checker() -> None:
    from cloud_dast.runtime.coupling import constraints as coupling_solver
    from cloud_dast.runtime.execution import scenarios as runner

    assert coupling_solver.solve_coupled_request.__module__ == (
        "cloud_dast.runtime.coupling.constraints"
    )
    from cloud_dast.qdl.field_roles import declared_output_refs
    from cloud_dast.verification.projection import read_live_outputs

    assert declared_output_refs.__module__ == "cloud_dast.qdl.field_roles"
    assert read_live_outputs.__module__ == "cloud_dast.verification.projection"
    for symbol in (
        "_typed_output_fields",
        "_solve_coupled_request",
        "_field_accepts",
        "_coupled_values_hold",
    ):
        assert not _module_owns_symbol(runner, symbol)


def test_coupling_resolution_is_not_owned_by_scenario_checker() -> None:
    from cloud_dast.runtime.coupling import resolve as coupling_resolution
    from cloud_dast.runtime.execution import scenarios as runner

    assert coupling_resolution.Binder.__module__ == (
        "cloud_dast.runtime.coupling.resolve"
    )
    assert coupling_resolution.Context.__module__ == (
        "cloud_dast.runtime.coupling.resolve"
    )
    for symbol in (
        "_resolve_values",
        "_coupled_rows",
        "_occurrence_values",
        "_read_live_outputs",
        "_causal_ready",
    ):
        assert not _module_owns_symbol(runner, symbol)


def test_startup_imports_without_reactive_owner() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.grounding.startup import Bootstrap
assert not set(['cloud_dast.runtime.grounding.reactive']).intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_reactive_imports_without_startup_cache_or_scheduler() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.grounding.reactive import Followup
assert not set(['cloud_dast.runtime.grounding.startup', 'cloud_dast.runtime.grounding.axes.scheduler', 'cloud_dast.runtime.grounding.axes.cache']).intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_grounding_scheduler_imports_without_stage_or_campaign_owners() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.grounding.axes.scheduler import AxisTaskScheduler
assert not {{
    "cloud_dast.runtime.grounding.axis",
    "cloud_dast.runtime.grounding.startup",
    "cloud_dast.runtime.grounding.reactive",
    "cloud_dast.runtime.grounding.lifecycle",
    "cloud_dast.runtime.campaign.runtime",
}}.intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_axis_result_projection_has_one_runtime_owner() -> None:
    from cloud_dast.runtime.grounding.axes import projection as axis_result_projection

    assert axis_result_projection.build_axis_result.__module__ == (
        "cloud_dast.runtime.grounding.axes.projection"
    )
    assert axis_result_projection.intersect_axis_batch_proposals.__module__ == (
        "cloud_dast.runtime.grounding.axes.projection"
    )
    projection_modules = _imported_modules(Path(axis_result_projection.__file__))
    assert "cloud_dast.runtime.grounding.axis" not in projection_modules
    assert "cloud_dast.runtime.campaign" not in projection_modules
    assert "cloud_dast.runtime.scheduler" not in projection_modules


def test_axis_model_transport_has_extension_boundary() -> None:
    from cloud_dast.extensions import ExtensionRegistry
    from cloud_dast_llm.axis_grounding import Dispatcher
    from cloud_dast_llm.plugin import register

    assert Dispatcher.__module__ == "cloud_dast_llm.axis_grounding"
    registry = ExtensionRegistry()
    register(registry)
    assert registry.axis_grounding_factory is Dispatcher


def test_axis_slicing_is_not_owned_by_axis_service() -> None:
    from cloud_dast.runtime.grounding.axes import slicing as axis_slicing

    assert axis_slicing.build_axis_slice.__module__ == (
        "cloud_dast.runtime.grounding.axes.slicing"
    )
    assert axis_slicing.policy_permission_graph.__module__ == (
        "cloud_dast.runtime.grounding.axes.slicing"
    )
    slicing_modules = _imported_modules(Path(axis_slicing.__file__))
    assert "cloud_dast.runtime.grounding.axis" not in slicing_modules
    assert "cloud_dast.runtime.campaign" not in slicing_modules


def test_axis_scheduling_is_not_owned_by_axis_service() -> None:
    from cloud_dast.runtime.grounding.axes import scheduler as axis_scheduler

    assert axis_scheduler.AxisTaskScheduler.__module__ == (
        "cloud_dast.runtime.grounding.axes.scheduler"
    )
    scheduler_modules = _imported_modules(Path(axis_scheduler.__file__))
    assert "cloud_dast.runtime.grounding.axis" not in scheduler_modules
    assert "cloud_dast.runtime.campaign" not in scheduler_modules


def test_axis_cache_lifecycle_is_not_owned_by_axis_service() -> None:
    from cloud_dast.runtime.grounding.axes import cache as axis_cache

    assert axis_cache.AxisResultCache.__module__ == (
        "cloud_dast.runtime.grounding.axes.cache"
    )
    cache_modules = _imported_modules(Path(axis_cache.__file__))
    assert "cloud_dast.runtime.grounding.axis" not in cache_modules
    assert "cloud_dast.runtime.campaign" not in cache_modules


def test_reactive_consultation_lifecycle_has_one_runtime_owner() -> None:
    from cloud_dast.runtime.grounding import reactive

    assert reactive.Followup.dispatch_consultation.__module__ == (
        "cloud_dast.runtime.grounding.reactive"
    )
    modules = _imported_modules(Path(reactive.__file__))
    assert "cloud_dast.runtime.grounding.axis" not in modules
    assert "cloud_dast.runtime.campaign" not in modules


def test_differential_campaign_has_one_runtime_owner() -> None:
    from cloud_dast.runtime import campaign
    from cloud_dast.runtime.differential import (
        campaign as differential_campaign,
    )
    from cloud_dast.runtime.differential import (
        outcomes as differential_outcomes,
    )
    from cloud_dast.runtime.differential import (
        probes as differential_probes,
    )
    from cloud_dast.runtime.differential import (
        specs as differential_specs,
    )

    assert differential_campaign.Runner.__module__ == (
        "cloud_dast.runtime.differential.campaign"
    )
    assert differential_outcomes.OutcomeRecorder.__module__ == (
        "cloud_dast.runtime.differential.outcomes"
    )
    assert differential.ProbeRunner.__module__ == (
        "cloud_dast.runtime.differential.probes"
    )
    assert differential_specs.SpecResolver.__module__ == (
        "cloud_dast.runtime.differential.specs"
    )
    assert (SOURCE_ROOT / "runtime/differential/__init__.py").exists()
    for old_module in (
        "differential.py",
        "differential_campaign.py",
        "differential_evidence.py",
        "differential_outcomes.py",
        "differential_probes.py",
        "differential_results.py",
        "differential_specs.py",
    ):
        assert not (SOURCE_ROOT / "runtime" / old_module).exists()
    for method in (
        "_run_differential_round",
        "_evaluate_step_modes",
        "_evaluate_pair",
        "_evaluate_readback_pair",
        "_evaluate_timing_pair",
        "_evaluate_concurrency_pair",
    ):
        assert not _module_defines_method(campaign, method)
    assert "cloud_dast.runtime.grounding" not in _imported_modules(
        Path(differential_campaign.__file__)
    )
    for method in (
        "_record_diff_report",
        "_persist_diff_runtime_facts",
        "_observation_for_report",
        "_check_for_report",
    ):
        assert not _module_defines_method(differential_campaign, method)
    outcome_modules = _imported_modules(Path(differential_outcomes.__file__))
    assert "cloud_dast.runtime.execution" not in outcome_modules
    assert "cloud_dast.runtime.scheduler" not in outcome_modules
    assert "cloud_dast.runtime.differential.campaign" not in outcome_modules
    probe_modules = _imported_modules(Path(differential_probes.__file__))
    assert "cloud_dast.runtime.differential.campaign" not in probe_modules
    assert "cloud_dast.runtime.scheduler" not in probe_modules
    spec_modules = _imported_modules(Path(differential_specs.__file__))
    assert "cloud_dast.runtime.execution" not in spec_modules
    assert "cloud_dast.runtime.differential.campaign" not in spec_modules
    assert "cloud_dast.runtime.differential.probes" not in spec_modules


def test_campaign_finalization_has_one_runtime_owner() -> None:
    from cloud_dast.runtime import campaign
    from cloud_dast.runtime.campaign import finalization as campaign_finalization

    assert campaign_finalization.Finalizer.__module__ == (
        "cloud_dast.runtime.campaign.finalization"
    )
    finalization_modules = _imported_modules(Path(campaign_finalization.__file__))
    for method in ("_live_result", "_close_grounding_lifecycle"):
        assert not _module_defines_method(campaign, method)
    assert "cloud_dast.runtime.campaign.runtime" not in finalization_modules
    assert "cloud_dast.runtime.scheduler" not in finalization_modules


def test_campaign_initialization_has_one_runtime_owner() -> None:
    from cloud_dast.runtime import campaign
    from cloud_dast.runtime.campaign import initialization as campaign_initialization

    assert campaign_initialization.Bootstrap.__module__ == (
        "cloud_dast.runtime.campaign.initialization"
    )
    for method in (
        "_start_grounding",
        "_prepare_initial_binding",
        "_prepare_campaign",
        "_require_grounding_runner",
    ):
        assert not _module_defines_method(campaign, method)
    assert "cloud_dast.runtime.campaign.runtime" not in _imported_modules(
        Path(campaign_initialization.__file__)
    )


def test_consultation_worker_imports_without_queue_or_commit_owners() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.consultation.calls import Invoker, PlannedItem
assert not {{
    "cloud_dast.runtime.consultation.wave",
    "cloud_dast.runtime.consultation.commit",
    "cloud_dast.runtime.consultation.context",
    "cloud_dast.runtime.deficits.queue",
    "cloud_dast.runtime.evidence_gate",
    "cloud_dast.runtime.campaign.runtime",
}}.intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_consultation_outcomes_import_without_coordination() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.consultation.outcomes import AttemptKey, OutcomePolicy, classify

policy = OutcomePolicy()
key = AttemptKey("svc", "work", ("obs",))
assert policy.record(key, classify(evidence_required=True)) == "parked"
assert not policy.should_dispatch(key)
assert policy.record(key, "promoted") == "parked"
for module in sys.modules:
    assert not module.startswith((
        "cloud_dast.runtime.campaign", "cloud_dast.runtime.execution",
        "cloud_dast.runtime.candidates", "cloud_dast.runtime.deficits",
        "cloud_dast.runtime.grounding", "cloud_dast.runtime.scheduler",
    )), module
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_deficit_closure_has_one_runtime_owner() -> None:
    from cloud_dast.runtime import deficits
    from cloud_dast.runtime.deficits import closure as deficit_closure
    from cloud_dast.runtime.deficits import queue as deficit_queue

    assert deficit_closure.grounding_result_closes_deficit.__module__ == (
        "cloud_dast.runtime.deficits.closure"
    )
    assert deficit_closure.grounded_output_paths.__module__ == (
        "cloud_dast.runtime.deficits.closure"
    )
    for function in (
        "grounding_result_closes_deficit",
        "_apply_supersedes",
        "_variance_result_closes",
        "interpreted_signal_kinds",
        "grounded_output_paths",
    ):
        assert not _module_owns_symbol(deficits, function)
    assert not hasattr(deficit_queue, "grounding_result_closes_deficit")
    assert not _module_owns_symbol(deficit_queue, "_deficit_is_stale")


def test_deficit_dispatch_is_pure_policy_owned() -> None:
    from cloud_dast.runtime.deficits import dispatch as deficit_dispatch
    from cloud_dast.runtime.deficits import queue as deficit_queue

    assert deficit_dispatch.select_wave_groups.__module__ == (
        "cloud_dast.runtime.deficits.dispatch"
    )
    assert deficit_dispatch.select_next_group.__module__ == (
        "cloud_dast.runtime.deficits.dispatch"
    )
    dispatch_modules = _imported_modules(Path(deficit_dispatch.__file__))
    for function in (
        "_select_wave_groups",
        "_select_next_group",
        "_fair_model_order",
        "_priority",
        "_interest_score",
    ):
        assert not _module_owns_symbol(deficit_queue, function)
    assert deficit_dispatch.select_wave_groups.__module__ == deficit_dispatch.__name__
    assert deficit_dispatch.select_next_group.__module__ == deficit_dispatch.__name__
    assert not any("grounding" in module.lower() for module in dispatch_modules)


def test_generator_catalog_is_the_single_qdl_extension_boundary() -> None:
    from cloud_dast_fuzzing.strategies import catalog

    assert not any(
        module.startswith("cloud_dast.workflow")
        for module in _imported_modules(Path(catalog.__file__))
    )
    from cloud_dast.composition import run_provider
    from cloud_dast.composition.run_provider import RunProvider

    assert hasattr(RunProvider, "generator_catalog")
    assert not hasattr(run_provider, "wrapped_generators")
    assert not hasattr(run_provider, "GoalPayloadGenerator")


def test_application_namespace_is_removed() -> None:
    root = SOURCE_ROOT / "application"
    assert not root.exists() or not any(root.rglob("*.py"))
    production_root = SOURCE_ROOT.parents[3] / "packages"
    production_modules = tuple(
        dependency
        for path in production_root.glob("**/*.py")
        for dependency in _imported_modules(path)
    )
    assert not any(
        dependency.startswith("cloud_dast.application")
        for dependency in production_modules
    )


def test_coverage_builder_is_verification_owned() -> None:
    from cloud_dast.verification import coverage

    assert Path(coverage.__file__).parent == SOURCE_ROOT / "verification"
    assert not (SOURCE_ROOT / "application/verification/coverage.py").exists()
    assert not (SOURCE_ROOT / "workflow/execution/coverage.py").exists()


def test_api_contracts_do_not_own_differential_decisions() -> None:
    from cloud_dast import api

    for symbol in (
        "DifferentialSpec",
        "PayloadPairSpec",
        "ReadBackSpec",
        "ReadBackResult",
        "ConcurrencyResult",
        "select_read_method",
    ):
        assert not _module_owns_symbol(api, symbol)


def test_observation_owners_import_without_candidate_engine() -> None:
    import subprocess
    import sys

    script = f"""
import sys
sys.path[:0] = {sys.path!r}
from cloud_dast.runtime.observation_recording import Coordinator
from cloud_dast.runtime.observation_effects import Publisher
from cloud_dast.runtime.execution.terminal import PathAttempt
from cloud_dast.runtime.execution.contracts import PrefilterResult

assert not {{
    "cloud_dast.runtime.execution.runner",
    "cloud_dast.composition.execution",
    "cloud_dast.runtime.campaign.runtime",
}}.intersection(sys.modules)
assert not any(name.startswith("cloud_dast.runtime.candidates") for name in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
