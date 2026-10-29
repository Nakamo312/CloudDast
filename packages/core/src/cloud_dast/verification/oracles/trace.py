"""Shared trace type for deterministic primitive oracles."""

from __future__ import annotations

from cloud_dast.model import Observation

type ObservationTrace = tuple[Observation, ...]

__all__ = ["ObservationTrace"]
