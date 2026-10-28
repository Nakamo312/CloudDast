from __future__ import annotations

from dataclasses import dataclass

from benchmarks.cve_bench.contract import (
    GenericContractManifest,
    GenericContractSource,
    build_contract,
)
from benchmarks.cve_bench.profile import (
    CveBenchProfileRequest,
    build_profile,
)
from benchmarks.cve_bench.repositories import (
    CveBenchRepositoryBundle,
    InMemoryFormalRepository,
)

from cloud_dast.model import EndpointLayer
from cloud_dast.ports import (
    ContractGraphRepository,
    InvocationRepository,
    MethodRepository,
    ScenarioRepository,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph


@dataclass(frozen=True)
class SyntheticTask:
    task_id: str
    service: str
    identity: str | None = None
    principal_id: str | None = None
    resource_id: str | None = None
    environment: str | None = None


def generated_run():
    manifest = GenericContractManifest.model_validate(
        {
            "service": "repositories.v1",
            "endpoint": "http://127.0.0.1:9200",
            "methods": [
                {
                    "method_id": "http:repositories.v1.readRecord",
                    "name": "readRecord",
                    "http_method": "GET",
                    "path_template": "/records/{record_id}",
                    "fields": [
                        {"name": "record_id", "type": "string", "required": True}
                    ],
                    "permissions": ["record.read"],
                    "resource_types": ["record"],
                    "body_fields": [],
                },
                {
                    "method_id": "http:repositories.v1.writeRecord",
                    "name": "writeRecord",
                    "http_method": "POST",
                    "path_template": "/records/{record_id}",
                    "fields": [
                        {"name": "record_id", "type": "string", "required": True},
                        {"name": "label", "type": "string"},
                    ],
                    "permissions": ["record.write"],
                    "resource_types": ["record"],
                    "body_fields": ["label"],
                },
            ],
        }
    )
    task = SyntheticTask(
        task_id="repository-task",
        service="repositories.v1",
        identity="attacker",
        resource_id="record-42",
    )
    contract = build_contract(task, GenericContractSource(manifest))
    profile = build_profile(
        contract,
        CveBenchProfileRequest(
            identity="attacker",
            resource_id="record-42",
            resource_type="record",
            authorized_method_ids=("http:repositories.v1.readRecord",),
        ),
    )
    return contract, profile


def test_repositories_are_seeded_from_generated_contract_and_profile() -> None:
    contract, profile = generated_run()
    bundle = CveBenchRepositoryBundle.from_contract(contract, profile.snapshot)

    methods: MethodRepository = bundle.methods
    invocations: InvocationRepository = bundle.invocations
    graphs: ContractGraphRepository = bundle.contract_graphs
    scenarios: ScenarioRepository = bundle.scenarios

    method = methods.get_method("http:repositories.v1.readRecord")
    assert method is not None
    assert method.service == "repositories.v1"
    assert method.layer is EndpointLayer.PUBLIC
    assert methods.list_methods("repositories.v1") == contract.methods
    assert methods.get_method("http:missing") is None

    invocation = invocations.get_invocation("http:repositories.v1.readRecord")
    assert invocation is not None
    assert invocation.endpoint == "http://127.0.0.1:9200"
    assert invocation.http_method == "GET"
    assert invocations.get_invocation("http:missing") is None

    assert graphs.load_slice("repositories.v1") == contract.graph
    assert graphs.load_slice("missing.v1").nodes == ()

    scenario = scenarios.get_scenario(
        "attacker",
        "record-42",
        method,
    )
    assert scenario is not None
    assert scenario.profile.endpoint_layer is EndpointLayer.PUBLIC
    assert scenario.stand.permissions_known is True
    assert scenario.stand.effective_permissions == frozenset({"record.read"})
    assert scenario.stand.resources[0].resource_id == "record-42"
    assert scenario.stand.resources[0].resource_type == "record"


def test_scenario_repository_preserves_unauthorized_positions() -> None:
    contract, profile = generated_run()
    bundle = CveBenchRepositoryBundle.from_contract(contract, profile.snapshot)
    method = bundle.methods.get_method("http:repositories.v1.writeRecord")
    assert method is not None

    scenario = bundle.scenarios.get_scenario(
        "attacker",
        "record-42",
        method,
    )

    assert scenario is not None
    assert scenario.stand.permissions_known is True
    assert scenario.stand.effective_permissions == frozenset()


def test_scenario_repository_resolves_method_ids_without_method_objects() -> None:
    contract, profile = generated_run()
    bundle = CveBenchRepositoryBundle.from_contract(contract, profile.snapshot)

    scenario = bundle.scenarios.get_scenario(
        "attacker",
        "record-42",
        method_id="http:repositories.v1.readRecord",
    )

    assert scenario is not None
    assert scenario.stand.effective_permissions == frozenset({"record.read"})
    assert bundle.scenarios.get_scenario("unknown", "record-42") is None


def test_formal_repository_merges_sources_under_a_prefix() -> None:
    repository = InMemoryFormalRepository()
    first = QdlGraph(facts=(_declaration("first"),))
    second = QdlGraph(facts=(_declaration("second"),))
    repository.save(
        "prefix:first",
        first,
        provenance={},
        adapter_version="test",
        mapping_report={},
    )
    repository.save(
        "prefix:second",
        second,
        provenance={},
        adapter_version="test",
        mapping_report={},
    )
    repository.save(
        "other:third",
        QdlGraph(facts=(_declaration("third"),)),
        provenance={},
        adapter_version="test",
        mapping_report={},
    )

    merged = repository.load_merged("prefix:")

    assert {fact.args[0].value for fact in merged.facts} == {"first", "second"}


def _declaration(value: str) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("is"),
        args=(
            Atom(value=value, literal_type="string"),
            Atom(value="Entity", literal_type="string"),
        ),
    )
