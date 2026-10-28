"""Facts, rules, and the immutable QDL graph container.

The term and predicate language is defined by :mod:`cloud_dast.qdl.graph`;
this module owns the extensional/intensional graph state and its invariants.
The import direction is intentionally one-way so ``qdl.graph`` remains the
stable public compatibility surface.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Self

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from cloud_dast.qdl.graph import (
    RECURSIVE_PREDICATES,
    Atom,
    Context,
    Predicate,
    Struct,
    Term,
    _collect_declarations,
    _collect_variables,
    _contains_variable,
    _find_disallowed_cycle,
    _predicate_dependencies,
    _reject_duplicates,
    _validate_references,
    _validate_term,
    _walk_terms,
    canonical_json,
    hash_content,
)


class Fact(BaseModel):
    """A contextual predicate application.

    Variables are allowed in rule literals. Facts stored in a ``QdlGraph``
    must be ground.
    """

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    context: Context
    predicate: Predicate
    args: tuple[Term, ...] = ()

    @model_validator(mode="after")
    def validate_args(self) -> Self:
        expected = self.predicate.arity
        if len(self.args) != expected:
            raise ValueError(
                f"{self.predicate.name} expects {expected} arguments, "
                f"got {len(self.args)}"
            )
        for term, argument in zip(
            self.args, self.predicate.definition.arguments, strict=True
        ):
            _validate_term(term, argument, path=argument.name)
        return self

    @property
    def content_hash(self) -> str:
        return hash_content(self)


class Rule(BaseModel):
    """A safe Datalog rule of the form ``body -> head`` in one context."""

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    body: tuple[Fact, ...]
    head: tuple[Fact, ...]

    @model_validator(mode="after")
    def validate_safety(self) -> Self:
        if not self.body:
            raise ValueError("rule body must not be empty")
        if not self.head:
            raise ValueError("rule head must not be empty")
        if len(self.head) != 1:
            raise ValueError(
                "rule head must contain exactly one literal; "
                "multi-head rules are not supported"
            )
        contexts = {literal.context for literal in (*self.body, *self.head)}
        if len(contexts) != 1:
            rendered = ", ".join(
                context.value
                for context in sorted(contexts, key=lambda item: item.value)
            )
            raise ValueError(
                "rule literals must share one context; cross-context promotion "
                f"is not allowed (contexts: {rendered})"
            )

        bound = {
            variable
            for literal in self.body
            for term in literal.args
            for variable in _collect_variables(term)
        }
        for literal in self.head:
            for term in literal.args:
                for variable in _collect_variables(term):
                    if variable not in bound:
                        raise ValueError(
                            f"rule head variable {variable} is not bound in body"
                        )

        body_terms = {
            canonical_json(term)
            for literal in self.body
            for argument in literal.args
            for term in _walk_terms(argument)
        }
        for literal in self.head:
            for term in literal.args:
                if isinstance(term, Struct):
                    key = canonical_json(term)
                    if key not in body_terms:
                        raise ValueError(
                            "rule head creates a new structural term: "
                            f"{canonical_json(term)}"
                        )

        head_predicates = {literal.predicate.name for literal in self.head}
        body_predicates = {literal.predicate.name for literal in self.body}
        recursive_predicates = head_predicates & body_predicates
        if recursive_predicates and not recursive_predicates <= RECURSIVE_PREDICATES:
            raise ValueError("rule dependency cycle: direct recursion")
        return self

    @property
    def content_hash(self) -> str:
        return hash_content(self)


class QdlGraph(BaseModel):
    """An immutable, canonically ordered set of ground facts and rules."""

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    facts: tuple[Fact, ...] = ()
    rules: tuple[Rule, ...] = ()

    @field_validator("facts")
    @classmethod
    def normalize_facts(cls, facts: tuple[Fact, ...]) -> tuple[Fact, ...]:
        return tuple(sorted(facts, key=canonical_json))

    @field_validator("rules")
    @classmethod
    def normalize_rules(cls, rules: tuple[Rule, ...]) -> tuple[Rule, ...]:
        return tuple(sorted(rules, key=canonical_json))

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        for fact in self.facts:
            if any(_contains_variable(term) for term in fact.args):
                raise ValueError(
                    f"graph fact contains variable: {canonical_json(fact)}"
                )

        fact_keys = [canonical_json(fact) for fact in self.facts]
        rule_keys = [canonical_json(rule) for rule in self.rules]
        _reject_duplicates(fact_keys, kind="fact")
        _reject_duplicates(rule_keys, kind="rule")

        declarations = _collect_declarations(self.facts)
        for fact in self.facts:
            _validate_references(fact, declarations)
        for rule in self.rules:
            for literal in (*rule.body, *rule.head):
                _validate_references(literal, declarations)

        edges = _predicate_dependencies(self.rules)
        cycle = _find_disallowed_cycle(edges)
        if cycle is not None:
            raise ValueError("rule dependency cycle: " + " -> ".join(cycle))
        return self

    def facts_for(
        self,
        predicate: str,
        *,
        contexts: Collection[Context] | None = None,
    ) -> tuple[Fact, ...]:
        """Return facts for one predicate, optionally restricted by context."""

        facts = tuple(fact for fact in self.facts if fact.predicate.name == predicate)
        if contexts is None:
            return facts
        return tuple(fact for fact in facts if fact.context in contexts)

    def select_contexts(self, contexts: Collection[Context]) -> QdlGraph:
        """Project this validated graph while preserving graph invariants."""

        facts = tuple(fact for fact in self.facts if fact.context in contexts)
        rules = tuple(
            rule
            for rule in self.rules
            if all(literal.context in contexts for literal in (*rule.body, *rule.head))
        )
        if len(facts) == len(self.facts) and len(rules) == len(self.rules):
            return self
        return QdlGraph(facts=facts, rules=rules)

    def declarations_for(
        self,
        contexts: Collection[Context] | None = None,
    ) -> dict[str, Fact]:
        """Return ``is`` declarations indexed by their canonical term."""

        declarations: dict[str, Fact] = {}
        for fact in self.facts_for("is", contexts=contexts):
            if fact.args:
                declarations.setdefault(canonical_json(fact.args[0]), fact)
        return declarations

    def declared_identifiers(
        self,
        type_name: str,
        *,
        contexts: Collection[Context] | None = None,
    ) -> frozenset[str]:
        """Return string identifiers declared as one QDL type."""

        identifiers: set[str] = set()
        for fact in self.facts_for("is", contexts=contexts):
            if len(fact.args) != 2:
                continue
            identifier, declared_type = fact.args
            if (
                isinstance(identifier, Atom)
                and isinstance(identifier.value, str)
                and isinstance(declared_type, Atom)
                and declared_type.value == type_name
            ):
                identifiers.add(identifier.value)
        return frozenset(identifiers)

    @property
    def content_hash(self) -> str:
        return hash_content(self)


__all__ = ["Fact", "QdlGraph", "Rule"]
