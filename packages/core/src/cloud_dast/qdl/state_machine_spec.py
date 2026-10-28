"""QDL state-machine specification and canonical graph ingestion."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cloud_dast.model.events import canonical_action_id
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.qdl.state_machine import state_machine_graph


class StateMachineTransition(BaseModel):
    """One declarative transition in a state-machine specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str = Field(min_length=1)
    from_state: str = Field(min_length=1)
    to_state: str = Field(min_length=1)

    @field_validator("action")
    @classmethod
    def canonicalize_action(cls, value: str) -> str:
        """Canonicalize the action identifier once, at the ingestion boundary."""

        return canonical_action_id(value)


class StateMachineForbiddenState(BaseModel):
    """One state that a norm forbids reaching."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    norm: str = Field(min_length=1)
    state: str = Field(min_length=1)


class StateMachineSpecification(BaseModel):
    """A declarative state-machine specification compiled into QDL facts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    states: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    norms: tuple[str, ...] = ()
    initial_states: tuple[str, ...] = ()
    transitions: tuple[StateMachineTransition, ...] = ()
    forbidden_states: tuple[StateMachineForbiddenState, ...] = ()
    observed_transitions: tuple[StateMachineTransition, ...] = ()

    @field_validator("actions")
    @classmethod
    def canonicalize_actions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Canonicalize declared actions and drop alias duplicates."""

        return tuple(dict.fromkeys(canonical_action_id(item) for item in value))

    @field_validator("transitions", "observed_transitions")
    @classmethod
    def deduplicate_transitions(
        cls,
        value: tuple[StateMachineTransition, ...],
    ) -> tuple[StateMachineTransition, ...]:
        """Drop transitions that canonicalize to the same QDL fact."""

        return tuple(dict.fromkeys(value))

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if not self.initial_states:
            raise ValueError("state machine requires at least one initial state")
        if not self.transitions:
            raise ValueError("state machine requires at least one transition")
        return self

    def to_qdl_graph(self) -> QdlGraph:
        """Compile the specification to a closed QDL graph."""

        return state_machine_graph(
            states=self.states,
            actions=self.actions,
            norms=self.norms,
            initial_states=self.initial_states,
            transitions=tuple(
                (item.action, item.from_state, item.to_state)
                for item in self.transitions
            ),
            forbidden_states=tuple(
                (item.norm, item.state) for item in self.forbidden_states
            ),
            observed_transitions=tuple(
                (item.action, item.from_state, item.to_state)
                for item in self.observed_transitions
            ),
        )
