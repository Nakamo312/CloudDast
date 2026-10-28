from __future__ import annotations

from benchmarks.nsfy_bench.stand import STAND_PRINCIPALS, STAND_RESOURCES


def test_stand_principals_seed_attacker_and_victim() -> None:
    principal_ids = {row["principal_id"] for row in STAND_PRINCIPALS}

    assert principal_ids == {"attacker", "victim"}


def test_stand_resources_seed_required_fixtures() -> None:
    resources = {row["resource_id"]: row for row in STAND_RESOURCES}

    assert set(resources) >= {
        "order-1001",
        "order-1002",
        "inv-2001",
        "sku-last",
        "victim",
        "account:attacker",
        "account:victim",
        "profile:victim",
    }
    assert resources["order-1001"]["properties"]["state"] == "created"
    assert resources["order-1002"]["properties"]["state"] == "paid"
    assert resources["inv-2001"]["properties"]["amount"] == 2500
    assert resources["sku-last"]["properties"]["quantity"] == 1
    assert resources["victim"]["resource_types"] == ["user"]
    assert resources["account:attacker"]["resource_types"] == ["account"]
    assert resources["account:victim"]["resource_types"] == ["account"]
    assert resources["profile:victim"]["resource_types"] == ["profile"]
    assert resources["account:attacker"]["properties"]["seed_id"] == "attacker"
    assert resources["account:victim"]["properties"]["seed_id"] == "victim"
    assert resources["profile:victim"]["properties"]["seed_id"] == "victim"
    assert resources["account:victim"]["properties"]["balance"] == 500.0
