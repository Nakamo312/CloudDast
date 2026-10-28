from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest
from benchmarks.cve_bench.contract import (
    ContractMissing,
    ContractSourceError,
    GenericContractManifest,
    GenericContractSource,
    OpenApiContractSource,
    build_contract,
    build_contract_runtime,
    load_contract_source,
)
from benchmarks.cve_bench.runtime import CveBenchContractSource, CveBenchTaskRun

from cloud_dast.infrastructure.runtime.http_json import HttpJsonTarget
from cloud_dast.model import EndpointLayer


@dataclass(frozen=True)
class SyntheticTask:
    task_id: str
    service: str
    identity: str | None = None
    principal_id: str | None = None
    resource_id: str | None = None
    environment: str | None = None


def task() -> SyntheticTask:
    return SyntheticTask(
        task_id="synthetic-task",
        service="synthetic.v1",
        identity="attacker",
        resource_id="record-17",
        environment="test",
    )


def openapi_document() -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic API"},
        "servers": [
            {
                "url": "https://{host}/v1",
                "variables": {"host": {"default": "api.example.test"}},
            }
        ],
        "paths": {
            "/records/{record_id}": {
                "parameters": [
                    {
                        "name": "record_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "get": {
                    "operationId": "getRecord",
                    "parameters": [
                        {
                            "name": "include",
                            "in": "query",
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Record"}
                                }
                            }
                        }
                    },
                },
                "post": {
                    "operationId": "updateRecord",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/RecordInput"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Record"}
                                }
                            }
                        }
                    },
                },
            }
        },
        "components": {
            "schemas": {
                "Record": {
                    "type": "object",
                    "properties": {
                        "record_id": {"type": "string"},
                        "owner": {"type": "string"},
                    },
                    "required": ["record_id"],
                },
                "RecordInput": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "settings": {
                            "type": "object",
                            "properties": {
                                "mode": {
                                    "type": "string",
                                    "enum": ["read", "write"],
                                }
                            },
                            "required": ["mode"],
                        },
                    },
                    "required": ["label"],
                },
            }
        },
    }


def generic_manifest() -> GenericContractManifest:
    return GenericContractManifest.model_validate(
        {
            "service": "generic.v1",
            "endpoint": "http://127.0.0.1:9000",
            "methods": [
                {
                    "method_id": "http:generic.v1.listRecords",
                    "name": "listRecords",
                    "http_method": "GET",
                    "path_template": "/records",
                    "fields": [{"name": "limit", "type": "int32", "required": True}],
                    "permissions": ["record.read"],
                    "resource_types": ["record"],
                    "query_fields": ["limit"],
                    "body_fields": [],
                }
            ],
        }
    )


def test_missing_contract_source_returns_a_typed_result() -> None:
    result = build_contract(task(), None)

    assert isinstance(result, ContractMissing)
    assert result.task_id == "synthetic-task"
    assert "contract source is required" in result.reason


def test_openapi_source_builds_engine_native_contract() -> None:
    result = build_contract(task(), OpenApiContractSource(openapi_document()))

    assert not isinstance(result, ContractMissing)
    assert result.service == "synthetic.v1"
    assert result.source_kind == "openapi"
    assert result.specification.service == "synthetic.v1"
    assert tuple(action.action_id for action in result.specification.actions) == (
        "http:synthetic.v1.getRecord",
        "http:synthetic.v1.updateRecord",
    )
    assert result.graph.service == "synthetic.v1"
    assert {
        node.properties.get("method_id")
        for node in result.graph.nodes
        if "Method" in node.labels
    } == {
        "http:synthetic.v1.getRecord",
        "http:synthetic.v1.updateRecord",
    }

    methods = {method.method_id: method for method in result.methods}
    get_method = methods["http:synthetic.v1.getRecord"]
    update_method = methods["http:synthetic.v1.updateRecord"]
    assert get_method.service == "synthetic.v1"
    assert get_method.name == "getRecord"
    assert get_method.layer is EndpointLayer.PUBLIC
    assert {field.name for field in get_method.fields} == {"record_id", "include"}
    assert {field.name for field in update_method.fields} == {
        "record_id",
        "label",
        "settings",
        "settings.mode",
    }

    invocations = {
        invocation.method_id: invocation for invocation in result.invocations
    }
    get_invocation = invocations["http:synthetic.v1.getRecord"]
    update_invocation = invocations["http:synthetic.v1.updateRecord"]
    assert get_invocation.endpoint == "https://api.example.test/v1"
    assert get_invocation.transport == "http-json"
    assert get_invocation.http_method == "GET"
    assert get_invocation.path_template == "/records/{record_id}"
    assert get_invocation.query_fields == ("include",)
    assert get_invocation.body_fields == ()
    assert get_invocation.output_type == "Record"
    assert update_invocation.http_method == "POST"
    assert update_invocation.input_type == "RecordInput"
    assert update_invocation.body_fields == ("label", "settings")


def test_generic_manifest_builds_engine_native_contract() -> None:
    result = build_contract(
        SyntheticTask(task_id="generic-task", service="generic.v1"),
        GenericContractSource(generic_manifest()),
    )

    assert not isinstance(result, ContractMissing)
    assert result.source_kind == "generic-manifest"
    assert result.specification.actions[0].action_id == "http:generic.v1.listRecords"
    assert result.methods[0].permissions == frozenset({"record.read"})
    assert result.methods[0].resource_types == frozenset({"record"})
    assert result.invocations[0].endpoint == "http://127.0.0.1:9000"
    assert result.invocations[0].http_method == "GET"
    assert result.invocations[0].path_template == "/records"
    assert result.invocations[0].query_fields == ("limit",)


def test_contract_sources_are_loaded_from_temporary_files(tmp_path) -> None:
    openapi_path = tmp_path / "openapi.json"
    manifest_path = tmp_path / "manifest.json"
    openapi_path.write_text(
        json.dumps(openapi_document()),
        encoding="utf-8",
    )
    manifest_path.write_text(
        generic_manifest().model_dump_json(indent=2),
        encoding="utf-8",
    )

    openapi_source = load_contract_source(openapi_path)
    manifest_source = load_contract_source(manifest_path)

    assert isinstance(openapi_source, OpenApiContractSource)
    assert isinstance(manifest_source, GenericContractSource)
    assert build_contract(task(), openapi_source).service == "synthetic.v1"
    assert (
        build_contract(
            SyntheticTask(task_id="generic-task", service="generic.v1"),
            manifest_source,
        ).service
        == "generic.v1"
    )


def test_task_and_contract_service_must_match() -> None:
    source = GenericContractSource(generic_manifest())

    with pytest.raises(ContractSourceError, match="does not match contract service"):
        build_contract(task(), source)


def test_runtime_contract_factory_builds_neo4j_free_ports(tmp_path) -> None:
    manifest_path = tmp_path / "runtime-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "service": "runtime-source.v1",
                "endpoint": "http://127.0.0.1:9300",
                "methods": [
                    {
                        "method_id": "http:runtime-source.v1.readRecord",
                        "name": "readRecord",
                        "http_method": "GET",
                        "path_template": "/records/{record_id}",
                        "fields": [
                            {
                                "name": "record_id",
                                "type": "string",
                                "required": True,
                            }
                        ],
                        "resource_types": ["record"],
                        "body_fields": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    task_run = CveBenchTaskRun(
        task_id="runtime-task",
        variant="zero_day",
        service="runtime-task",
        principal_id="attacker",
        resource_id="record-99",
        method_id=None,
        max_checks=None,
        contract_source=CveBenchContractSource(
            kind="manifest",
            path=manifest_path,
        ),
        target_url="http://127.0.0.1:9300",
    )

    runtime = build_contract_runtime(task_run)

    assert runtime.methods.list_methods("runtime-task")
    assert runtime.methods.list_methods("runtime-source.v1") == ()
    assert (
        runtime.invocations.get_invocation("http:runtime-source.v1.readRecord")
        is not None
    )
    assert runtime.contract_graph.load_slice("runtime-task").nodes
    assert (
        runtime.scenarios.get_scenario(
            "attacker",
            "record-99",
            method_id="http:runtime-source.v1.readRecord",
        )
        is not None
    )
    assert runtime.formal.load("runtime-task:zero_day").facts
    assert runtime.stand.project("runtime-task").facts
    assert isinstance(runtime.target, HttpJsonTarget)
