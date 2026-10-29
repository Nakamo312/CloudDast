"""Fitness checks for the core-to-extension boundary."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from cloud_dast.composition.run_provider import RunProvider
from cloud_dast.extensions import ExtensionRegistry

_CORE = Path(__file__).parents[2] / "packages/core/src/cloud_dast"
_CONCRETE_PREFIXES = (
    "cloud_dast_fuzzing",
    "cloud_dast_symbolic",
    "cloud_dast_automata",
    "cloud_dast_llm",
    "cloud_dast_reporting",
)


def _imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
    return tuple(modules)


def test_core_does_not_import_concrete_extensions() -> None:
    violations = [
        (path, module)
        for path in _CORE.rglob("*.py")
        for module in _imports(path)
        if module.startswith(_CONCRETE_PREFIXES)
    ]
    assert violations == []


def test_empty_registry_keeps_core_standalone() -> None:
    provider = RunProvider(extension_registry=ExtensionRegistry())
    template = provider.template_generator()

    assert type(provider.symbolic_generator(template)) is type(template)
    assert provider.payload_corpus() is None
    assert provider.symbolic_prefilter() is None
    assert provider.finding_shrinker_factory() is None


def test_plan_roundtrip_without_runtime_or_adapters() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class ContractBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith((
            'cloud_dast.runtime',
            'cloud_dast.infrastructure',
            'cloud_dast.composition',
        )):
            raise ImportError(f'contract loaded executable dependency: {fullname}')

sys.meta_path.insert(0, ContractBoundary())
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, input_field
from cloud_dast.verification.evidence_facts import supports_dataflows
from cloud_dast.qdl.reasoning import compile_probe_fields, read_input_field, index_sinks

action = Atom(value='action:read')
field = input_field(action, Atom(value='id'))
sink = Atom(value='sink:unrelated')
graph = QdlGraph(facts=(
    Fact(context=Context.CONTRACT, predicate=Predicate.from_name('is'), args=(action, Atom(value='Action'))),
    Fact(context=Context.CONTRACT, predicate=Predicate.from_name('is'), args=(field, Atom(value='Field'))),
    Fact(context=Context.CONTRACT, predicate=Predicate.from_name('is'), args=(sink, Atom(value='Sink'))),
    Fact(context=Context.CONTRACT, predicate=Predicate.from_name('reaches'), args=(field, sink)),
))
assert supports_dataflows(graph, 'read')
parked = QdlGraph(facts=tuple(f.model_copy(update={'context': Context.PROPOSAL}) for f in graph.facts))
assert not supports_dataflows(parked, 'read')
assert index_sinks(QdlGraph()) == {}
assert compile_probe_fields(QdlGraph()) == {}
assert read_input_field(input_field(Atom(value='action:read'), Atom(value='id'))) == (
    'action:read', 'id',
)

for identities in (None, ()):
    plan = VerificationPlan(
        plan_id='plan', invariant_id='norm', method_id='action',
        scenario_id='scenario', identity_terms=identities,
    )
    restored = VerificationPlan.model_validate_json(plan.model_dump_json())
    assert restored == plan
    assert restored.identity_terms == identities
""",
            str(_CORE.parent),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("module", ("startup", "reactive"))
def test_grounding_modules_load_independently_without_extensions(module: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class CoreBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith((
            'cloud_dast_llm', 'cloud_dast_fuzzing', 'cloud_dast_symbolic',
            'cloud_dast_automata', 'cloud_dast_reporting',
            'cloud_dast.infrastructure', 'cloud_dast.composition',
        )):
            raise ImportError(f'grounding loaded an external implementation: {fullname}')

sys.meta_path.insert(0, CoreBoundary())
importlib.import_module(sys.argv[2])
""",
            str(_CORE.parent),
            f"cloud_dast.runtime.grounding.{module}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_planners_execute_without_campaign_or_adapters() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class PlanningBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith((
            'cloud_dast.runtime.campaign',
            'cloud_dast.runtime.scheduler',
            'cloud_dast.runtime.grounding',
            'cloud_dast.runtime.consultation',
            'cloud_dast.runtime.deficits',
            'cloud_dast.infrastructure',
            'cloud_dast.composition',
            'cloud_dast_llm',
            'cloud_dast_fuzzing',
            'cloud_dast_symbolic',
            'cloud_dast_automata',
        )):
            raise ImportError(f'planner loaded campaign or adapter: {fullname}')

sys.meta_path.insert(0, PlanningBoundary())
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.runtime.planning import QdlPlanner, IncrementalQdlPlanner

empty = QdlGraph()
declared = QdlGraph(facts=(Fact(
    context=Context.CONTRACT,
    predicate=Predicate.from_name('is'),
    args=(Atom(value='action:read'), Atom(value='Action')),
),))
cached = IncrementalQdlPlanner()
for graph in (empty, declared, declared, empty):
    actual = cached.plan(graph)
    assert actual == QdlPlanner().plan(graph)
    assert actual.graph_hash == graph.content_hash
""",
            str(_CORE.parent),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("module", "symbol"),
    [
        ("cloud_dast.runtime.differential.results", "VarianceRecord"),
        ("cloud_dast.runtime.consultation.context", "WaveExecution"),
        ("cloud_dast.runtime.evidence_gate", "EvidenceDeficitRecord"),
    ],
)
def test_runtime_results_load_without_campaign_state(module, symbol) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class ResultBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith((
            'cloud_dast.runtime.campaign.state',
            'cloud_dast.runtime.campaign.runtime',
            'cloud_dast.infrastructure',
            'cloud_dast.composition',
        )):
            raise ImportError(f'result loaded campaign or adapter: {fullname}')

sys.meta_path.insert(0, ResultBoundary())
owner = importlib.import_module(sys.argv[2])
record = getattr(owner, sys.argv[3])
assert record.__module__ == owner.__name__
from cloud_dast.runtime import campaign
assert getattr(campaign, sys.argv[3]) is record
""",
            str(_CORE.parent),
            module,
            symbol,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_probe_execution_does_not_load_campaign_coordination() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class ExecutionBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith((
            'cloud_dast.runtime.campaign',
            'cloud_dast.runtime.execution.scenarios',
            'cloud_dast.runtime.consultation',
            'cloud_dast.runtime.grounding',
            'cloud_dast.runtime.scheduler',
            'cloud_dast.runtime.deficits',
            'cloud_dast.infrastructure',
            'cloud_dast.composition',
        )):
            raise ImportError(f'physical execution loaded coordinator: {fullname}')

sys.meta_path.insert(0, ExecutionBoundary())
from cloud_dast.model import AccessOutcome, Check, HttpStatus, Observation
from cloud_dast.runtime.execution.checks import run_probes

checks = tuple(Check(
    check_id=f'check:{i}', invariant_id='norm', method_id='read',
    scenario_id='scenario', request=(), identities=('actor',),
) for i in range(2))

def target(check):
    return Observation(
        check_id=check.check_id, scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary='done', transport_status=HttpStatus(code=200),
    )

results = []
assert run_probes(checks, target, None, results, max_workers=2) is None
assert tuple(check for check, _ in results) == checks
assert tuple(observation.check_id for _, observation in results) == (
    'check:0', 'check:1',
)
""",
            str(_CORE.parent),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_deficit_contract_works_without_loading_planners() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class PlannerBoundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('cloud_dast.runtime.planning'):
            raise ImportError(f'deficit contract loaded a planner: {fullname}')

sys.meta_path.insert(0, PlannerBoundary())
from cloud_dast.qdl.graph import Atom
from cloud_dast.qdl.reasoning import QdlSubgoal
from cloud_dast.runtime.deficits.model import Deficit

subgoal = QdlSubgoal('requires', (Atom(value='action:read'), Atom(value='permission:read')))
deficit = Deficit(subgoal=subgoal, predicate_class='requires', axis='roles', action='action:read')
assert deficit.subgoal is subgoal
assert deficit.action == 'action:read'
""",
            str(_CORE.parent),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_execution_verdict_contract_works_without_implementations() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib.abc
import sys
from collections.abc import Mapping
from typing import get_type_hints

sys.path.insert(0, sys.argv[1])

class Boundary(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith((
            'cloud_dast.runtime', 'cloud_dast.verification',
            'cloud_dast.infrastructure', 'cloud_dast.composition',
        )):
            raise ImportError(f'verdict contract loaded implementation: {fullname}')

sys.meta_path.insert(0, Boundary())
from pydantic import ValidationError
from cloud_dast.model import PolicyVerdict, VerdictStatus
from cloud_dast.contracts.execution import ExecutionResult

values = dict(status=VerdictStatus.PASS, confidence=1.0, rationale='closed scope',
              model_id='contract', grounded=True, negative_scope=('response.body',))
verdict = PolicyVerdict(**values)
restored = PolicyVerdict.model_validate_json(verdict.model_dump_json())
assert restored == verdict
result = ExecutionResult((), (), {}, {('observation', 'norm'): restored})
assert result.policy_verdicts[('observation', 'norm')].negative_scope == ('response.body',)
assert get_type_hints(ExecutionResult)['policy_verdicts'] == Mapping[tuple[str, str], PolicyVerdict]
for invalid in ({'negative_scope': ()}, {'grounded': False}):
    try:
        PolicyVerdict(**(values | invalid))
    except ValidationError:
        pass
    else:
        raise AssertionError('invalid PASS evidence accepted')
""",
            str(_CORE.parent),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
