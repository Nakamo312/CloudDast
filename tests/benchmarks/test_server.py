"""Smoke tests for the standalone NSFy Shop gRPC server."""

from __future__ import annotations

import grpc
import pytest
from benchmarks.nsfy_bench.proto import (
    PACKAGE,
    file_descriptor_bytes,
)
from benchmarks.nsfy_bench.server import NsfyShopServer
from google.protobuf import descriptor_pool
from google.protobuf.message_factory import GetMessageClass


@pytest.fixture(scope="module")
def server() -> NsfyShopServer:
    instance = NsfyShopServer(address="127.0.0.1:0")
    instance.start()
    yield instance
    instance.stop()


def _pool() -> descriptor_pool.DescriptorPool:
    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(file_descriptor_bytes())
    return pool


def _call(
    server: NsfyShopServer,
    rpc: str,
    request_type: str,
    response_type: str,
    fields: dict[str, object],
    token: str = "bench:attacker",
):
    pool = _pool()
    request = GetMessageClass(pool.FindMessageTypeByName(f"{PACKAGE}.{request_type}"))()
    for name, value in fields.items():
        setattr(request, name, value)
    response_class = GetMessageClass(
        pool.FindMessageTypeByName(f"{PACKAGE}.{response_type}")
    )
    with grpc.insecure_channel(_bound_address(server)) as channel:
        call = channel.unary_unary(
            f"/{PACKAGE}.{rpc}",
            request_serializer=lambda message: message.SerializeToString(),
            response_deserializer=lambda data: _parse(response_class, data),
        )
        return call(
            request,
            metadata=(("authorization", f"Bearer {token}"),),
            timeout=5.0,
        )


def _parse(response_class, data: bytes):
    message = response_class()
    message.ParseFromString(data)
    return message


def _bound_address(server: NsfyShopServer) -> str:
    if server.bound_address is None:
        raise RuntimeError("server is not started")
    return server.bound_address


def test_get_order_discloses_owner_email(server: NsfyShopServer) -> None:
    response = _call(
        server,
        "OrderService/GetOrder",
        "GetOrderRequest",
        "GetOrderResponse",
        {"order_id": "order-1001"},
    )

    assert response.order_id == "order-1001"
    assert response.owner_email == "victim@example.test"


def test_get_invoice_denies_attacker(server: NsfyShopServer) -> None:
    with pytest.raises(grpc.RpcError) as error:
        _call(
            server,
            "InvoiceService/GetInvoice",
            "GetInvoiceRequest",
            "GetInvoiceResponse",
            {"invoice_id": "inv-2001"},
        )

    assert error.value.code() is grpc.StatusCode.PERMISSION_DENIED


def test_search_orders_echoes_sql_error_marker(server: NsfyShopServer) -> None:
    """SQL injection causes a real SQLite error (information disclosure).

    The error message content depends on the payload — this is REAL
    database behavior, not a hardcoded reflection. We verify that:
    1. The injection produces an error (proves sink reached)
    2. The error message is returned to the caller (info disclosure)
    """
    response = _call(
        server,
        "OrderService/SearchOrders",
        "SearchOrdersRequest",
        "SearchOrdersResponse",
        {"query": "'"},  # simplest injection: unclosed quote
    )

    # Real SQLite error: the injection caused a syntax error
    assert response.error_message != ""
    assert response.rows == 0


def test_get_document_escape_reflects_marker(server: NsfyShopServer) -> None:
    from benchmarks.nsfy_bench.scenarios import M1_SCENARIOS

    # Pay first (C1: traversal unlocked by payment)
    _call(
        server,
        "OrderService/PayOrder",
        "PayOrderRequest",
        "PayOrderResponse",
        {"order_id": "order-1001"},
    )

    scenario = next(
        scenario
        for scenario in M1_SCENARIOS
        if scenario.scenario_id == "path-traversal-doc"
    )
    name = dict(scenario.request)["name"]
    marker = scenario.probe_marker
    assert name == f"../../../secret/{marker}.txt"

    response = _call(
        server,
        "DocumentService/GetDocument",
        "GetDocumentRequest",
        "GetDocumentResponse",
        {"name": name},
    )

    assert marker in response.content
