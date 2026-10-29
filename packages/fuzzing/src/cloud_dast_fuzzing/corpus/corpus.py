"""Versioned payload-corpus loading and schema migration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cloud_dast.contracts.payloads import (
    PayloadAlternative,
    PayloadCorpus,
    PayloadNode,
    PayloadProduction,
    PayloadTerminal,
    PayloadTerminalAlternative,
    _root_node_name,
    _template_elements,
)

DEFAULT_PAYLOAD_CORPUS_PATH = Path(__file__).with_name("payloads.yaml")


def load_payload_corpus(path: Path | str | None = None) -> PayloadCorpus:
    """Load and validate the versioned engine corpus."""

    corpus_path = Path(path) if path is not None else DEFAULT_PAYLOAD_CORPUS_PATH
    raw: Any = yaml.safe_load(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") not in {1, 2}:
        raise ValueError(f"invalid payload-corpus schema: {corpus_path}")
    corpus = PayloadCorpus.model_validate(raw)
    if corpus.schema_version == 1:
        return migrate_payload_corpus(corpus)
    return corpus


def migrate_payload_corpus(corpus: PayloadCorpus) -> PayloadCorpus:
    """Mechanically migrate a schema-v1 template corpus to schema v2."""

    if corpus.schema_version == 2:
        return corpus
    productions = tuple(
        _migrate_production(production) for production in corpus.productions
    )
    return PayloadCorpus(
        schema_version=2,
        corpus_version=corpus.corpus_version,
        productions=productions,
    )


def _migrate_production(production: PayloadProduction) -> PayloadProduction:
    if production.root is not None:
        return production
    slot_nodes = tuple(
        PayloadNode(
            name=slot.name,
            alternatives=(
                PayloadAlternative(
                    elements=(
                        PayloadTerminal(
                            alternatives=tuple(
                                PayloadTerminalAlternative(value=value)
                                for value in slot.alternatives
                            ),
                        ),
                    ),
                ),
            ),
        )
        for slot in production.slots
    )
    slot_by_name = {slot.name: slot for slot in production.slots}
    elements = _template_elements(production.template or "", slot_by_name)
    root_name = _root_node_name(slot_by_name)
    root_node = PayloadNode(
        name=root_name,
        alternatives=(PayloadAlternative(elements=elements),),
    )
    return PayloadProduction(
        production_id=production.production_id,
        sink_types=production.sink_types,
        dialects=production.dialects,
        root=root_name,
        nodes=(root_node, *slot_nodes),
        default=production.default,
    )


DEFAULT_PAYLOAD_CORPUS = load_payload_corpus()

__all__ = [
    "DEFAULT_PAYLOAD_CORPUS",
    "DEFAULT_PAYLOAD_CORPUS_PATH",
    "load_payload_corpus",
    "migrate_payload_corpus",
]
