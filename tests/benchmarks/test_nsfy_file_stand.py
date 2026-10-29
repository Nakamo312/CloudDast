from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from benchmarks.nsfy_bench.contract import (
    BUY_GIFT_CARD,
    CREATE_API_KEY,
    CREATE_ORDER,
    CREATE_REFUND,
    CREATE_TRANSFER,
    IMPORT_PICKLE,
    INPUT_OUTPUT_TYPES,
    REQUEST_PAYOUT,
    SERVICE,
    action_id,
    methods,
)
from benchmarks.nsfy_bench.norms import AUTHORIZED_ATTACKER_METHODS, policy_facts

from cloud_dast.composition.app_provider import (
    ContractEndpointRecord,
    load_contract_manifest,
)
from cloud_dast.composition.guardrails import AllowlistGuardrail
from cloud_dast.composition.profile import apply_profile_environment, load_profile
from cloud_dast.composition.run_provider import (
    FileScenarioRepository,
    select_scenario_repository,
)
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.infrastructure.stand import FileStandSource
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    Observation,
    ResourceRef,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, denied
from cloud_dast.verification.oracles import GroundedOutcomeOracle

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STAND_PATH = PROJECT_ROOT / "benchmarks" / "nsfy-bench" / "stand.json"
PROFILE_PATH = (
    PROJECT_ROOT / "benchmarks" / "nsfy-bench" / "profiles" / "nsfy-bench-llm.toml"
)
CONTRACT_PATH = PROJECT_ROOT / "benchmarks" / "nsfy-bench" / "contract.json"
PROVISIONING_METHODS = (
    CREATE_ORDER,
    CREATE_TRANSFER,
    BUY_GIFT_CARD,
    CREATE_API_KEY,
    REQUEST_PAYOUT,
    CREATE_REFUND,
)


def test_committed_contract_fixture_matches_the_benchmark_contract() -> None:
    manifest = load_contract_manifest(CONTRACT_PATH)

    assert manifest.service == SERVICE
    assert manifest.endpoints == (
        ContractEndpointRecord(address="127.0.0.1:50051", environment="bench"),
    )
    assert [record.method_id for record in manifest.methods] == [
        method.method_id for method in methods()
    ]
    for record, method in zip(manifest.methods, methods(), strict=True):
        assert record.service == method.service
        assert record.name == method.name
        assert record.layer == method.layer
        assert record.permissions == method.permissions
        assert record.resource_types == method.resource_types
        assert record.fields == method.fields
        assert record.input_type == INPUT_OUTPUT_TYPES[method.method_id][0]
        assert record.output_type == INPUT_OUTPUT_TYPES[method.method_id][1]


def test_llm_profile_uses_the_file_stand_without_neo4j() -> None:
    with PROFILE_PATH.open("rb") as stream:
        profile = tomllib.load(stream)

    assert "neo4j" not in profile
    assert profile["stand"] == {
        "source": "file",
        "file": "benchmarks/nsfy-bench/stand.json",
    }
    assert profile["runtime"]["setup_identity"] == "victim"


def test_llm_profile_exports_victim_setup_identity() -> None:
    environment: dict[str, str] = {}

    apply_profile_environment(load_profile(PROFILE_PATH), environment)

    assert environment["CLOUD_DAST_SETUP_IDENTITY"] == "victim"


def test_file_stand_projects_direct_may_permissions() -> None:
    graph = FileStandSource(STAND_PATH).project(SERVICE)
    facts = {
        (fact.predicate.name, *(argument.value for argument in fact.args))
        for fact in graph.facts
    }

    assert (
        "may",
        "principal:attacker",
        f"action:{CREATE_API_KEY}",
        "resource:api_key",
    ) in facts
    assert (
        "may",
        "principal:provisioner",
        f"action:{CREATE_TRANSFER}",
        "resource:transfer",
    ) in facts


def test_file_stand_matches_the_benchmark_attacker_policy_facts() -> None:
    stand_facts = FileStandSource(STAND_PATH).project(SERVICE).facts
    stand_may = {
        tuple(argument.value for argument in fact.args)
        for fact in stand_facts
        if fact.predicate.name == "may" and fact.args[0].value == "principal:attacker"
    }
    benchmark_may = {
        tuple(argument.value for argument in fact.args)
        for fact in policy_facts()
        if fact.predicate.name == "may"
    }

    assert stand_may == benchmark_may


def test_scenario_repository_selects_the_file_stand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(STAND_PATH))

    repository = select_scenario_repository(None)

    assert isinstance(repository, FileScenarioRepository)


def test_file_stand_resources_keep_user_and_order_identities_separate() -> None:
    repository = FileScenarioRepository(STAND_PATH)

    order = repository.get_scenario(
        "attacker",
        "order-1001",
        _method("grpc:nsfy.shop.v1.OrderService.GetOrder"),
    )
    user = repository.get_scenario(
        "attacker",
        "order-1001",
        _method("grpc:nsfy.shop.v1.UserService.GetUser"),
    )

    assert order is not None and user is not None
    assert order.stand.resources == (
        ResourceRef(
            service=SERVICE,
            resource_type="order",
            resource_id="order-1001",
        ),
    )
    assert user.stand.resources == ()
    assert not user.stand.permissions_known
    selected_user = repository.get_scenario(
        "attacker", "victim", _method("grpc:nsfy.shop.v1.UserService.GetUser")
    )
    assert selected_user.stand.resources == (
        ResourceRef(service=SERVICE, resource_type="user", resource_id="victim"),
    )


def _instance_stand(tmp_path, method) -> Path:
    """Give the positive control an explicit instance-level permission fixture."""
    payload = json.loads(STAND_PATH.read_text())
    (resource_type,) = method.resource_types
    payload["resources"].append(
        {
            "resource": "resource-under-test",
            "resource_type": resource_type,
            "service": method.service,
        }
    )
    for permission in payload["permissions"]:
        if (
            permission["action"] == method.method_id
            and permission["resource"] == resource_type
        ):
            permission["resource"] = "resource-under-test"
    path = tmp_path / "instance-stand.json"
    path.write_text(json.dumps(payload))
    return path


@pytest.mark.parametrize("method_id", AUTHORIZED_ATTACKER_METHODS)
def test_authorized_attacker_methods_have_effective_permissions(
    tmp_path, method_id: str
) -> None:
    method = _method(method_id)
    scenario = FileScenarioRepository(_instance_stand(tmp_path, method)).get_scenario(
        "attacker",
        "resource-under-test",
        method,
    )

    assert scenario is not None
    assert method.permissions <= scenario.stand.effective_permissions
    assert scenario.stand.permissions_known is True


@pytest.mark.parametrize("method_id", PROVISIONING_METHODS)
def test_provisioning_identity_can_create_fixtures(tmp_path, method_id: str) -> None:
    method = _method(method_id)
    scenario = FileScenarioRepository(_instance_stand(tmp_path, method)).get_scenario(
        "provisioner",
        "resource-under-test",
        method,
    )

    assert scenario is not None
    assert method.permissions <= scenario.stand.effective_permissions
    assert scenario.stand.permissions_known is True


@pytest.mark.parametrize("method_id", [CREATE_API_KEY, IMPORT_PICKLE])
def test_grounded_oracle_passes_for_allowed_authorized_methods(
    tmp_path, method_id: str
) -> None:
    method = _method(method_id)
    scenario = FileScenarioRepository(_instance_stand(tmp_path, method)).get_scenario(
        "attacker",
        "resource-under-test",
        method,
    )
    assert scenario is not None

    observation = Observation(
        check_id="check:allowed",
        scenario_id=scenario.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="method allowed",
        transport_status=HttpStatus(code=200),
    )
    verdict = GroundedOutcomeOracle().evaluate_outcome(
        _allowed_invariant(method_id),
        observation,
        method,
        scenario,
    )

    assert verdict.status is VerdictStatus.PASS
    assert verdict.grounded is True


def test_guardrail_allows_campaign_and_provisioning_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_SERVICES", SERVICE)
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_METHODS", "*")
    monkeypatch.setenv("CLOUD_DAST_ALLOWED_IDENTITIES", "attacker,provisioner")
    guardrail = AllowlistGuardrail.from_environment(_BenchmarkMethodRepository())

    for identity in ("attacker", "provisioner"):
        for method in methods():
            check = Check(
                invariant_id="guardrail",
                method_id=method.method_id,
                scenario_id="scenario",
                request=(),
                identities=(identity,),
            )

            assert guardrail.allows(check)


def _method(method_id: str):
    return next(method for method in methods() if method.method_id == method_id)


def _allowed_invariant(method_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=f"allowed:{method_id}",
        norm_id=f"norm:allowed:{method_id}",
        statement="method must not be denied",
        severity=Severity.LOW,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:allowed:{method_id}"),
                denied(action_id(method_id)),
            ),
        ),
    )


class _BenchmarkMethodRepository:
    def get_method(self, method_id: str):
        return next(
            (method for method in methods() if method.method_id == method_id),
            None,
        )

    def list_methods(self, service: str):
        return methods() if service == SERVICE else ()
