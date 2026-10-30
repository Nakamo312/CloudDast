"""Business services that classify verification observations."""

from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles.classification_lead import (
    ClassificationLead,
    ClassificationLeadOracle,
    evaluate_classification_leads,
)
from cloud_dast.verification.oracles.differential import (
    DifferentialOracle,
)
from cloud_dast.verification.oracles.field_exposure import (
    FieldExposureOracle,
)
from cloud_dast.verification.oracles.grounded import (
    GroundedOutcomeOracle,
)
from cloud_dast.verification.oracles.latency import (
    LatencyBaseline,
    LatencyOracle,
    collect_delivered_durations,
)
from cloud_dast.verification.oracles.marker import MarkerOracle
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from cloud_dast.verification.oracles.roles import WitnessRolePolicy
from cloud_dast.verification.oracles.sequence import SequenceOracle
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.oracles.witness import WitnessSignalOracle
from cloud_dast.verification.witness import (
    KnownContentWitness,
    ObservationPair,
)

__all__ = [
    "ClassificationLead",
    "ClassificationLeadOracle",
    "DifferentialOracle",
    "FieldExposureOracle",
    "GroundedOutcomeOracle",
    "LatencyBaseline",
    "LatencyOracle",
    "collect_delivered_durations",
    "MarkerOracle",
    "NormView",
    "ObservationTrace",
    "ObservationPair",
    "PrimitiveOracleRouter",
    "SequenceOracle",
    "KnownContentWitness",
    "WitnessSignalOracle",
    "WitnessRolePolicy",
    "evaluate_classification_leads",
]
