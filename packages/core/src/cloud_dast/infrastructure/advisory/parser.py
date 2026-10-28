"""Deterministic parsers for the allowlisted advisory corpus formats."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from cloud_dast.infrastructure.advisory.models import (
    AdvisoryRecord,
    AdvisorySource,
)

_COMPARATOR_PATTERN = re.compile(r"^(<=|>=|<|>|==|=)\s*([^\s,]+)$")


def parse_advisory_payload(
    source: AdvisorySource,
    payload: str | bytes | Sequence[Mapping[str, Any]] | Mapping[str, Any],
) -> tuple[AdvisoryRecord, ...]:
    """Normalize one OSV, GHSA, or NVD response into advisory records."""

    if isinstance(payload, str | bytes):
        try:
            decoded = payload.decode("utf-8") if isinstance(payload, bytes) else payload
            payload = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{source.kind} advisory payload must be JSON") from error

    if source.kind == "osv":
        return _parse_osv(source, payload)
    if source.kind == "ghsa":
        return _parse_ghsa(source, payload)
    return _parse_nvd(source, payload)


def _parse_osv(
    source: AdvisorySource,
    payload: object,
) -> tuple[AdvisoryRecord, ...]:
    records = _payload_records(payload)
    parsed: list[AdvisoryRecord] = []
    for record in records:
        advisory_id = _required_string(record, "id", source.kind)
        packages = []
        for affected in _required_sequence(record, "affected", source.kind):
            package = affected.get("package")
            if not isinstance(package, Mapping):
                raise ValueError(f"{advisory_id}: affected package is missing")
            ecosystem = _required_string(package, "ecosystem", source.kind)
            name = _required_string(package, "name", source.kind)
            ranges = _osv_ranges(affected)
            packages.append(
                {
                    "ecosystem": ecosystem,
                    "name": name,
                    "ranges": ranges,
                }
            )
        parsed.append(
            AdvisoryRecord(
                source_kind=source.kind,
                advisory_id=advisory_id,
                packages=tuple(packages),  # type: ignore[arg-type]
            )
        )
    return tuple(parsed)


def _osv_ranges(affected: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    ranges: list[dict[str, str]] = []
    for raw_range in affected.get("ranges", ()):
        if not isinstance(raw_range, Mapping):
            raise ValueError("OSV range must be an object")
        events = raw_range.get("events", ())
        if not isinstance(events, Sequence) or isinstance(events, str | bytes):
            raise ValueError("OSV range events must be a sequence")
        current: dict[str, str] = {}
        for event in events:
            if not isinstance(event, Mapping):
                raise ValueError("OSV range event must be an object")
            introduced = _optional_event_value(event, "introduced")
            if introduced is not None:
                if current:
                    ranges.append(current)
                current = {"introduced": introduced}
                continue
            for key in ("fixed", "last_affected", "limit"):
                value = _optional_event_value(event, key)
                if value is None:
                    continue
                if not current:
                    current = {"introduced": "0"}
                current[key] = value
                ranges.append(current)
                current = {}
                break
        if current:
            ranges.append(current)
    for version in affected.get("versions", ()):
        if not isinstance(version, str) or not version.strip():
            raise ValueError("OSV affected version must be a non-empty string")
        ranges.append({"exact": version.strip()})
    if not ranges:
        raise ValueError("OSV affected package requires ranges or versions")
    return tuple(ranges)


def _optional_event_value(event: Mapping[str, Any], key: str) -> str | None:
    value = event.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"OSV {key} event must be a non-empty string")
    return value.strip()


def _parse_ghsa(
    source: AdvisorySource,
    payload: object,
) -> tuple[AdvisoryRecord, ...]:
    records = _payload_records(payload)
    parsed: list[AdvisoryRecord] = []
    for record in records:
        advisory_id = _first_string(
            record,
            ("ghsa_id", "advisory_id", "cve_id"),
            source.kind,
        )
        packages = []
        for vulnerability in _required_sequence(
            record,
            "vulnerabilities",
            source.kind,
        ):
            package = vulnerability.get("package")
            if not isinstance(package, Mapping):
                raise ValueError(f"{advisory_id}: vulnerability package is missing")
            ecosystem = _required_string(package, "ecosystem", source.kind)
            name = _required_string(package, "name", source.kind)
            raw_range = vulnerability.get("vulnerable_version_range", "")
            if not isinstance(raw_range, str):
                raise ValueError(f"{advisory_id}: vulnerable range must be a string")
            bounds = _parse_range_expression(raw_range)
            patched = vulnerability.get("first_patched_version")
            if isinstance(patched, Mapping):
                identifier = patched.get("identifier")
                if isinstance(identifier, str) and identifier.strip():
                    bounds.setdefault("fixed", identifier.strip())
            packages.append(
                {
                    "ecosystem": ecosystem,
                    "name": name,
                    "ranges": (bounds,),
                }
            )
        parsed.append(
            AdvisoryRecord(
                source_kind=source.kind,
                advisory_id=advisory_id,
                packages=tuple(packages),  # type: ignore[arg-type]
            )
        )
    return tuple(parsed)


def _parse_nvd(
    source: AdvisorySource,
    payload: object,
) -> tuple[AdvisoryRecord, ...]:
    if not isinstance(payload, Mapping):
        raise ValueError("NVD advisory payload must be an object")
    parsed: list[AdvisoryRecord] = []
    for vulnerability in _required_sequence(payload, "vulnerabilities", source.kind):
        cve = vulnerability.get("cve")
        if not isinstance(cve, Mapping):
            raise ValueError("NVD vulnerability requires a CVE object")
        advisory_id = _required_string(cve, "id", source.kind)
        packages = []
        for configuration in cve.get("configurations", ()):
            if not isinstance(configuration, Mapping):
                raise ValueError("NVD configuration must be an object")
            for node in _required_sequence(configuration, "nodes", source.kind):
                for cpe_match in _required_sequence(node, "cpeMatch", source.kind):
                    package = _nvd_package(cpe_match)
                    packages.append(package)
        parsed.append(
            AdvisoryRecord(
                source_kind=source.kind,
                advisory_id=advisory_id,
                packages=tuple(packages),  # type: ignore[arg-type]
            )
        )
    return tuple(parsed)


def _nvd_package(cpe_match: Mapping[str, Any]) -> dict[str, object]:
    criteria = cpe_match.get("criteria")
    if not isinstance(criteria, str):
        raise ValueError("NVD CPE match requires criteria")
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        raise ValueError(f"invalid CPE criteria: {criteria}")
    part, vendor, product, version = parts[2:6]
    if not part or not vendor or not product:
        raise ValueError(f"invalid CPE package: {criteria}")

    bounds: dict[str, str] = {}
    for source_key, target_key in (
        ("versionStartIncluding", "introduced"),
        ("versionStartExcluding", "introduced_exclusive"),
        ("versionEndExcluding", "fixed"),
        ("versionEndIncluding", "last_affected"),
    ):
        value = cpe_match.get(source_key)
        if isinstance(value, str) and value.strip():
            bounds[target_key] = value.strip()
    if not bounds:
        if version == "*":
            bounds["introduced"] = "0"
        else:
            bounds["exact"] = version

    return {
        "ecosystem": "cpe",
        "name": f"{part}:{vendor}:{product}",
        "ranges": (bounds,),
    }


def _parse_range_expression(raw: str) -> dict[str, str]:
    bounds: dict[str, str] = {}
    for clause in raw.split(","):
        normalized = clause.strip()
        if not normalized:
            continue
        match = _COMPARATOR_PATTERN.fullmatch(normalized)
        if match is None:
            raise ValueError(f"invalid GHSA version range: {raw}")
        operator, version = match.groups()
        key = {
            "<=": "last_affected",
            ">=": "introduced",
            "<": "fixed",
            ">": "introduced_exclusive",
            "=": "exact",
            "==": "exact",
        }[operator]
        bounds[key] = version
    if not bounds:
        raise ValueError(f"GHSA version range is empty: {raw}")
    return bounds


def _payload_records(payload: object) -> tuple[Mapping[str, Any], ...]:
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes):
        records = payload
    elif isinstance(payload, Mapping):
        records = (payload,)
    else:
        raise ValueError("advisory payload must be an object or array")
    if not all(isinstance(record, Mapping) for record in records):
        raise ValueError("advisory payload records must be objects")
    return tuple(records)  # type: ignore[return-value]


def _required_sequence(
    payload: Mapping[str, Any],
    key: str,
    source_kind: str,
) -> tuple[Mapping[str, Any], ...]:
    value = payload.get(key)
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise ValueError(f"{source_kind} payload requires {key} as an array")
    if not all(isinstance(item, Mapping) for item in value):
        raise ValueError(f"{source_kind} {key} entries must be objects")
    return tuple(value)  # type: ignore[return-value]


def _required_string(
    payload: Mapping[str, Any],
    key: str,
    source_kind: str,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source_kind} advisory requires non-empty {key}")
    return value.strip()


def _first_string(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
    source_kind: str,
) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise ValueError(f"{source_kind} advisory requires one of {', '.join(keys)}")
