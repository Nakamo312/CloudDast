"""QDL-grounded vulnerability classes and interpretation rules."""

from cloud_dast.verification.taxonomy.catalog import (
    CLASSIFICATION_DEFICIT,
    DEFAULT_CATALOG,
    ClassCatalog,
    ClassEntry,
    ClassificationFacts,
    FindingClassification,
    is_classification_deficit,
    load_entries,
)

__all__ = [
    "CLASSIFICATION_DEFICIT",
    "DEFAULT_CATALOG",
    "ClassCatalog",
    "ClassEntry",
    "ClassificationFacts",
    "FindingClassification",
    "is_classification_deficit",
    "load_entries",
]
