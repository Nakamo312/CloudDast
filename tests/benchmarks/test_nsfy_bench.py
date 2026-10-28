"""Tests for the NSFy Bench application and its ground truth."""

from __future__ import annotations

from pathlib import Path

from benchmarks.nsfy_bench import (
    M1_SCENARIOS,
    build_graph,
    score_findings,
    score_findings_semantic,
)
from benchmarks.nsfy_bench import contract as contract_module
from benchmarks.nsfy_bench import stand as stand_module
from benchmarks.nsfy_bench.app import BenchService, BenchState, BenchTarget
from benchmarks.nsfy_bench.contract import (
    ACTIVATE_USER,
    APPLY_COUPON,
    DOWNLOAD_ORDER,
    GET_DOCUMENT,
    GET_INVOICE,
    GET_ORDER,
    GET_USER,
    OOB_COLLABORATOR,
    SEARCH_ORDERS,
    SET_WEBHOOK,
    UPDATE_ORDER,
    action_id,
    contract_facts,
    methods,
)
from benchmarks.nsfy_bench.norms import (
    NORM_BOLA_ORDER_READ,
    NORM_CONTROL_INVOICE_READ,
    NORM_CONTROL_USER_PASSWORD,
    NORM_PATH_TRAVERSAL_DOC,
    NORM_SQL_INJECTION_SEARCH,
    NORM_SSRF_WEBHOOK,
)
from benchmarks.nsfy_bench.scorer import (
    score_findings_full,
    score_findings_semantic_full,
)

from cloud_dast.model import (
    AccessOutcome,
    Check,
    Finding,
    Observation,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    Struct,
    allowed,
    external_call,
    reached,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.runtime.planning import QdlPlanner


def _check(scenario) -> Check:
    return Check(
        invariant_id=scenario.norm_id,
        method_id=scenario.method_id,
        scenario_id=scenario.scenario_id,
        request=scenario.request,
        identities=("attacker",),
        probe_marker=scenario.probe_marker,
    )


def test_graph_is_valid_input_for_the_engine_planner() -> None:
    """The answer-key graph must plan through the real engine planner."""

    plan = QdlPlanner().plan(build_graph())

    assert {invariant.norm for invariant in plan.invariants} >= {
        scenario.norm_id for scenario in M1_SCENARIOS
    }
    assert plan.state_paths


def test_contract_declares_create_effects_for_createable_resources() -> None:
    methods_by_action = {}
    for method in methods():
        methods_by_action[method.method_id] = method
        methods_by_action[f"action:{method.method_id}"] = method

    setup_methods = {
        atom_value(fact.args[1].args[0]).removeprefix("resource:"): methods_by_action[
            atom_value(fact.args[0])
        ]
        for fact in contract_facts()
        if fact.predicate.name == "causes"
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "create"
    }

    assert setup_methods == {
        "order": methods_by_action["grpc:nsfy.shop.v1.OrderService.CreateOrder"],
        "user": methods_by_action["grpc:nsfy.shop.v1.UserService.ActivateUser"],
        "paid_order": methods_by_action["grpc:nsfy.shop.v1.OrderService.PayOrder"],
        "transfer": methods_by_action[
            "grpc:nsfy.shop.v1.TransferService.CreateTransfer"
        ],
        "gift_card": methods_by_action["grpc:nsfy.shop.v1.GiftService.BuyGiftCard"],
        "api_key": methods_by_action["grpc:nsfy.shop.v1.KeyService.CreateApiKey"],
        "payout": methods_by_action["grpc:nsfy.shop.v1.PayoutService.RequestPayout"],
        "refund": methods_by_action["grpc:nsfy.shop.v1.OrderService.CreateRefund"],
        "bundle": methods_by_action["grpc:nsfy.shop.v1.BundleService.UploadBundle"],
        "config": methods_by_action["grpc:nsfy.shop.v1.ConfigService.ParseConfig"],
        "webhook": methods_by_action["grpc:nsfy.shop.v1.WebhookService.SetWebhook"],
    }
    assert "invoice" not in setup_methods
    assert "document" not in setup_methods


def test_contract_declares_effects_for_every_mutator() -> None:
    """Layer A must provide deterministic mutation facts for every mutator."""

    mutators = {
        contract_module.CREATE_ORDER,
        contract_module.PAY_ORDER,
        contract_module.SHIP_ORDER,
        contract_module.UPDATE_ORDER,
        contract_module.DELETE_ORDER,
        contract_module.SET_WEBHOOK,
        contract_module.APPLY_COUPON,
        contract_module.CANCEL_ORDER,
        contract_module.CREATE_REFUND,
        contract_module.EXECUTE_REFUND,
        contract_module.DISPATCH_ORDER,
        contract_module.CREATE_TRANSFER,
        contract_module.ACCEPT_TRANSFER,
        contract_module.BUY_GIFT_CARD,
        contract_module.SPEND_GIFT_CARD,
        contract_module.CREATE_API_KEY,
        contract_module.ESCALATE_API_KEY,
        contract_module.REQUEST_PAYOUT,
        contract_module.EXECUTE_PAYOUT,
        contract_module.ACTIVATE_USER,
        contract_module.UPDATE_PROFILE,
        contract_module.RESERVE_INVENTORY,
        contract_module.UPLOAD_BUNDLE,
        contract_module.PARSE_CONFIG,
        contract_module.IMPORT_PICKLE,
        contract_module.BURN_COUPON,
        contract_module.TRANSFER_FUNDS,
    }
    actions_with_effects = {
        action
        for fact in contract_facts()
        if fact.predicate.name == "causes"
        and len(fact.args) == 2
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name in {"changed", "create", "remove"}
        and (action := atom_value(fact.args[0])) is not None
    }
    actions_with_effects = {
        action.removeprefix("action:") for action in actions_with_effects
    }

    assert mutators <= actions_with_effects


def test_application_is_deterministic_across_runs() -> None:
    """Every scenario produces identical observations on identical state."""

    for scenario in M1_SCENARIOS:
        observations = []
        for _ in range(2):
            service = BenchService(BenchState.seed())
            observations.append(BenchTarget(service)(_check(scenario)))
        first, second = observations
        assert first.observed_outcome is second.observed_outcome
        assert first.transport_status == second.transport_status
        assert first.observed_outcome is second.observed_outcome
        assert first.transport_status == second.transport_status
        # Note: response_summary may differ for path traversal (tempdir paths)
        # but the outcome and status must be deterministic
        if "document" not in scenario.scenario_id:
            assert first.response_summary == second.response_summary


def test_activate_user_creates_the_fixture_for_get_user() -> None:
    service = BenchService(BenchState.seed())

    activated = service.dispatch(
        ACTIVATE_USER,
        "attacker",
        {"user_id": "fixture-user"},
    )
    read_back = service.dispatch(
        GET_USER,
        "attacker",
        {"user_id": "fixture-user"},
    )
    reactivated = service.dispatch(
        ACTIVATE_USER,
        "attacker",
        {"user_id": "fixture-user"},
    )

    assert activated.status_code == 200
    assert activated.outcome is AccessOutcome.ALLOWED
    assert dict(activated.fields)["user_id"] == "fixture-user"
    assert read_back.status_code == 200
    assert dict(read_back.fields)["email"] == "fixture-user@example.test"
    assert reactivated.status_code == 200
    assert set(service._state.users) == {"victim", "fixture-user"}


def test_bench_target_fills_full_fidelity_response_tree() -> None:
    service = BenchService(BenchState.seed())
    target = BenchTarget(service)

    def get_order(order_id: str) -> Observation:
        return target(
            Check(
                invariant_id="norm:test",
                method_id=GET_ORDER,
                scenario_id="scenario",
                request=(("order_id", order_id),),
                identities=("attacker",),
            )
        )

    first = get_order("order-1001")
    second = get_order("order-1002")

    assert first.response_tree == first.output.fields
    assert first.response_digest == response_tree_digest(first.response_tree)
    assert first.response_digest != second.response_digest
    assert dict(first.response_tree)["state"] == "created"
    assert dict(second.response_tree)["state"] == "paid"

    missing = get_order("order-missing")
    assert missing.response_tree == ()
    assert missing.response_digest is None


def test_scorer_matches_engine_findings_by_norm() -> None:
    findings = tuple(
        Finding(
            observation_id=f"obs-{scenario.scenario_id}",
            invariant_id=scenario.norm_id,
            method_id=scenario.method_id,
            scenario_id=scenario.scenario_id,
            severity=scenario.severity,
            title=scenario.title,
            description="engine finding",
            remediation="fix",
        )
        for scenario in M1_SCENARIOS
        if scenario.expected is VerdictStatus.FAIL
    )

    score = score_findings(findings)

    assert score.vulnerable_total == 9
    assert score.control_total == 2
    assert score.found == 9
    assert score.missed == ()
    assert score.false_positives == ()
    assert score.unexpected_findings == ()
    assert score.recall == 1.0
    assert score.precision == 1.0


def test_scorer_reports_false_positives_and_unexpected_findings() -> None:
    control = next(
        scenario for scenario in M1_SCENARIOS if scenario.expected is VerdictStatus.PASS
    )
    findings = (
        Finding(
            observation_id="obs-control",
            invariant_id=control.norm_id,
            method_id=control.method_id,
            scenario_id=control.scenario_id,
            severity=Severity.LOW,
            title=control.title,
            description="false positive",
            remediation="fix",
        ),
        Finding(
            observation_id="obs-unexpected",
            invariant_id="norm:not-in-benchmark",
            method_id=control.method_id,
            scenario_id=control.scenario_id,
            severity=Severity.LOW,
            title="unexpected",
            description="engine found something outside the key",
            remediation="review",
        ),
    )

    score = score_findings(findings)

    assert score.found == 0
    assert score.false_positives == (control.scenario_id,)
    assert score.unexpected_findings == ("norm:not-in-benchmark",)
    assert score.recall == 0.0
    assert score.precision == 0.0


def _llm_finding(norm_id: str, method_id: str, effect) -> Finding:
    return Finding(
        observation_id=f"obs-{norm_id}",
        invariant_id=norm_id,
        method_id=method_id,
        scenario_id="llm-proposal",
        severity=Severity.HIGH,
        title="LLM-proposed norm violation",
        description="engine finding for an LLM-generated norm id",
        remediation="fix",
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=norm_id), effect),
        ),
    )


def test_semantic_scorer_matches_findings_by_effect_despite_norm_ids() -> None:
    """An LLM-generated norm id scores when its effect covers the key norm."""

    scenario = next(
        scenario
        for scenario in M1_SCENARIOS
        if scenario.norm_id == NORM_BOLA_ORDER_READ
    )
    finding = _llm_finding(
        "norm:authz-read-victim-order",
        scenario.method_id,
        allowed(action_id(GET_ORDER)),
    )

    exact = score_findings((finding,))
    assert exact.found == 0
    assert exact.unexpected_findings == ("norm:authz-read-victim-order",)

    semantic = score_findings_semantic((finding,))
    assert semantic.found == 1
    assert scenario.scenario_id not in semantic.missed
    assert semantic.unexpected_findings == ()
    assert semantic.recall > 0.0
    assert semantic.precision == 1.0


def test_semantic_scorer_counts_control_matches_as_false_positives() -> None:
    """Effect matching must stay symmetric for control norms."""

    control = next(
        scenario
        for scenario in M1_SCENARIOS
        if scenario.norm_id == NORM_CONTROL_INVOICE_READ
    )
    finding = _llm_finding(
        "norm:llm-invoice-authz",
        control.method_id,
        allowed(action_id(GET_INVOICE)),
    )

    score = score_findings_semantic((finding,))

    assert score.found == 0
    assert score.false_positives == (control.scenario_id,)
    assert score.unexpected_findings == ()
    assert score.precision == 0.0


def test_full_scorer_separates_m1_from_full_norm_totals() -> None:
    score = score_findings_full(())

    assert score.scope == "full"
    assert score.total == 36
    assert score.vulnerable_total == 34
    assert score.control_total == 2
    assert score.found == 0
    assert len(score.missed) == 34
    assert {
        outcome.norm_id
        for outcome in score.outcomes
        if outcome.expected is VerdictStatus.PASS
    } == {NORM_CONTROL_INVOICE_READ, NORM_CONTROL_USER_PASSWORD}


def test_full_scorer_classifies_exact_semantic_and_missed_matches() -> None:
    exact_norm = "norm:stf-coupon-double"
    canonical_norm = "norm:fuzz-template-injection"
    semantic_norm = "norm:fuzz-second-order-sql"
    findings = (
        _llm_finding(exact_norm, APPLY_COUPON, allowed(action_id(APPLY_COUPON))),
        _llm_finding(
            "norm:engine-template-rce",
            UPDATE_ORDER,
            reached(action_id(UPDATE_ORDER), Atom(value="sink:template_engine")),
        ),
        _llm_finding(
            "norm:engine-coupon-sqli",
            APPLY_COUPON,
            allowed(action_id(APPLY_COUPON)),
        ),
    )

    strict = score_findings_full(findings)

    assert strict.scope == "full"
    assert strict.vulnerable_total == 34
    assert strict.control_total == 2
    assert strict.found == 2
    assert strict.exact_matches == (exact_norm, canonical_norm)
    assert strict.semantic_matches == ()
    assert semantic_norm in strict.missed
    assert strict.unexpected_findings == ("norm:engine-coupon-sqli",)
    assert strict.precision == 2 / 3

    semantic = score_findings_semantic_full(findings)

    assert semantic.found == 2
    assert semantic.exact_matches == (exact_norm, canonical_norm)
    assert semantic.semantic_matches == ()
    assert semantic.action_level_matches == (semantic_norm,)
    assert len(semantic.missed) == 32
    assert semantic.unexpected_findings == ("norm:engine-coupon-sqli",)
    assert semantic.recall == 2 / 34
    assert semantic.precision == 2 / 3


def test_full_strict_scorer_is_witness_insensitive_for_reached_effects() -> None:
    finding = _llm_finding(
        "norm:engine-sqli",
        SEARCH_ORDERS,
        reached(
            action_id(SEARCH_ORDERS),
            Atom(value="sink:engine-generated-query-sink"),
        ),
    )

    score = score_findings_full((finding,))

    assert score.exact_matches == (NORM_SQL_INJECTION_SEARCH,)
    assert score.found == 1
    assert score.unexpected_findings == ()


def test_semantic_scorer_does_not_credit_path_traversal_from_sql_reached() -> None:
    """A SQL sink and a filesystem escape must not share a semantic match."""

    finding = _llm_finding(
        "norm:engine-document-sqli",
        GET_DOCUMENT,
        reached(action_id(GET_DOCUMENT), Atom(value="sink:sql_engine")),
    )

    m1 = score_findings_semantic((finding,))
    path_scenario = next(
        scenario
        for scenario in M1_SCENARIOS
        if scenario.norm_id == NORM_PATH_TRAVERSAL_DOC
    )
    assert m1.found == 0
    assert path_scenario.scenario_id in m1.missed
    assert m1.unexpected_findings == ("norm:engine-document-sqli",)

    full = score_findings_semantic_full((finding,))
    assert full.found == 0
    assert {
        NORM_PATH_TRAVERSAL_DOC,
        "norm:fuzz-traversal-unlocked",
    } <= set(full.missed)
    assert full.unexpected_findings == ("norm:engine-document-sqli",)


def test_semantic_scorer_requires_external_call_witness() -> None:
    """An outbound-call effect must carry the expected marker witness."""

    finding = _llm_finding(
        "norm:engine-webhook-oob",
        SET_WEBHOOK,
        external_call(
            action_id(SET_WEBHOOK),
            Atom(value="collaborator:wrong-marker"),
        ),
    )

    m1 = score_findings_semantic((finding,))
    ssrf_scenario = next(
        scenario for scenario in M1_SCENARIOS if scenario.norm_id == NORM_SSRF_WEBHOOK
    )
    assert m1.found == 0
    assert ssrf_scenario.scenario_id in m1.missed
    assert m1.unexpected_findings == ("norm:engine-webhook-oob",)


def test_semantic_scorer_does_not_credit_allowed_for_external_call() -> None:
    """An allowed call is not evidence of an outbound SSRF effect."""

    finding = _llm_finding(
        "norm:engine-webhook-authz",
        SET_WEBHOOK,
        allowed(action_id(SET_WEBHOOK)),
    )
    ssrf_scenario = next(
        scenario for scenario in M1_SCENARIOS if scenario.norm_id == NORM_SSRF_WEBHOOK
    )

    m1 = score_findings_semantic((finding,))
    full = score_findings_semantic_full((finding,))

    assert m1.found == 0
    assert ssrf_scenario.scenario_id in m1.missed
    assert m1.unexpected_findings == ("norm:engine-webhook-authz",)
    assert NORM_SSRF_WEBHOOK in full.missed
    assert full.unexpected_findings == ("norm:engine-webhook-authz",)


def test_semantic_scorer_keeps_allowed_separate_from_reached_effect() -> None:
    """An action-only permission signal is not exact sink evidence."""

    finding = _llm_finding(
        "norm:engine-search-allowed",
        SEARCH_ORDERS,
        allowed(action_id(SEARCH_ORDERS)),
    )

    score = score_findings_semantic((finding,))

    assert score.found == 0
    sql_scenario = next(
        scenario
        for scenario in M1_SCENARIOS
        if scenario.norm_id == NORM_SQL_INJECTION_SEARCH
    )
    assert sql_scenario.scenario_id in score.missed
    assert score.semantic_matches == ()
    assert score.action_level_heuristic_matches == (NORM_SQL_INJECTION_SEARCH,)
    assert score.unexpected_findings == ("norm:engine-search-allowed",)


def test_semantic_scorer_credits_matching_external_call_witness() -> None:
    """A real outbound-call effect with the OOB witness closes the SSRF norm."""

    finding = _llm_finding(
        "norm:engine-webhook-oob",
        SET_WEBHOOK,
        external_call(
            action_id(SET_WEBHOOK),
            Atom(value=OOB_COLLABORATOR),
        ),
    )
    ssrf_scenario = next(
        scenario for scenario in M1_SCENARIOS if scenario.norm_id == NORM_SSRF_WEBHOOK
    )

    m1 = score_findings_semantic((finding,))
    full = score_findings_semantic_full((finding,))

    assert m1.found == 1
    assert ssrf_scenario.scenario_id not in m1.missed
    assert m1.semantic_matches == (NORM_SSRF_WEBHOOK,)
    assert m1.unexpected_findings == ()
    assert full.exact_matches == (NORM_SSRF_WEBHOOK,)
    assert NORM_SSRF_WEBHOOK not in full.missed
    assert full.unexpected_findings == ()


def test_full_semantic_preserves_strict_match_before_semantic_fallback() -> None:
    """A strict match wins before broad semantic fallback can displace it."""

    ssrf_finding = _llm_finding(
        "norm:engine-webhook-outbound",
        SET_WEBHOOK,
        external_call(
            action_id(SET_WEBHOOK),
            Atom(value="marker:setwebhook_url_outbound"),
        ),
    )
    download_finding = _llm_finding(
        "norm:engine-download-allowed",
        DOWNLOAD_ORDER,
        allowed(action_id(DOWNLOAD_ORDER)),
    )

    score = score_findings_semantic_full((ssrf_finding, download_finding))

    assert score.exact_matches == (NORM_SSRF_WEBHOOK,)
    assert score.semantic_matches == ()
    assert score.action_level_matches == ("norm:stf-refund-reuse",)
    assert NORM_SSRF_WEBHOOK not in score.missed
    assert "norm:stf-refund-reuse" in score.missed
    assert score.unexpected_findings == ("norm:engine-download-allowed",)

    ssrf_only = score_findings_semantic_full((ssrf_finding,))
    assert ssrf_only.exact_matches == (NORM_SSRF_WEBHOOK,)
    assert "norm:stf-refund-reuse" in ssrf_only.missed


def test_fresh_clears_semantic_sources_and_retains_state_machine(
    monkeypatch, tmp_path
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            del exc_type, exc_value, traceback

        def run(self, query: str, **parameters):
            calls.append((query, parameters))
            return []

    class _SessionFactory:
        def __call__(self):
            return _Session()

        def close(self) -> None:
            return None

    monkeypatch.setattr(stand_module, "_neo4j_session", _SessionFactory)
    monkeypatch.setattr(
        stand_module, "write_descriptor_set", lambda descriptor_path: descriptor_path
    )

    stand_module.load_stand(
        descriptor_path=tmp_path / "desc.binpb",
        fresh=True,
    )

    clear_query, parameters = next(
        (query, parameters)
        for query, parameters in calls
        if "accepted_source_id" in parameters
    )
    assert "source.source_id <> $state_machine_source_id" in clear_query
    assert "CONTAINS" not in clear_query
    assert parameters == {
        "accepted_source_id": "accepted:nsfy.shop.v1",
        "accepted_batch_prefix": "accepted-batch:nsfy.shop.v1:",
        "diff_prefix": "diff:nsfy.shop.v1:",
        "state_machine_source_id": "state-machine:nsfy.shop.v1",
    }
    assert any(
        parameters.get("source_id") == "state-machine:nsfy.shop.v1"
        for _, parameters in calls
    )


def test_engine_never_imports_the_benchmark_package() -> None:
    """The engine must stay benchmark-agnostic at the import boundary."""

    engine_root = Path(__file__).parents[2] / "packages/core/src/cloud_dast"
    offenders = sorted(
        str(path.relative_to(engine_root))
        for path in engine_root.rglob("*.py")
        if "benchmarks" in path.read_text(encoding="utf-8")
    )
    assert offenders == []


def test_every_declared_field_has_a_grounding_role() -> None:
    """The answer key must cover every field of every declared method."""

    from benchmarks.nsfy_bench.contract import _FIELD_ROLES, methods

    missing = [
        (method.method_id, spec.name)
        for method in methods()
        for spec in method.fields
        if (method.method_id, spec.name) not in _FIELD_ROLES
    ]
    assert not missing
