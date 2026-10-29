from __future__ import annotations

from cloud_dast.extensions import ExtensionRegistry
from cloud_dast_automata.learning import AALpyAutomataLearningAdapter
from cloud_dast_automata.plugin import register


def test_register_exposes_automata_learning_port() -> None:
    registry = ExtensionRegistry()

    register(registry)

    assert registry.automata_learning_factory is AALpyAutomataLearningAdapter


def test_discovery_finds_automata_extension() -> None:
    registry = ExtensionRegistry.discover()

    assert registry.automata_learning_factory is AALpyAutomataLearningAdapter
