"""Named runtime defaults shared by Cloud DAST layers."""

from typing import Final

OOB_PROBE_TIMEOUT_SECONDS: Final = 1.0
"""Default wait for an asynchronous out-of-band probe callback."""

QDL_MAX_DEPTH: Final = 8
"""Default bounded-walk depth for QDL planning and state-machine reasoning."""

RESPONSE_TREE_MAX_DEPTH: Final = 64
"""Maximum nested response levels retained in a full-fidelity tree."""

RESPONSE_TREE_MAX_LEAVES: Final = 4096
"""Maximum scalar response leaves retained in a full-fidelity tree."""

MAX_SEMANTIC_FACTS: Final = 128
"""Default campaign-wide cap for promoted semantic facts."""

DEFAULT_MAX_PROMOTED_NORMS: Final = 32
"""Default campaign-wide cap for promoted formal norms."""
