"""Relationship graph used for object-level authorization."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RelationshipGraph:
    """An in-memory relationship graph with explicit tenant ownership."""

    _edges: set[tuple[str, str, str, str]] = field(default_factory=set)

    def add(
        self,
        subject_id: str,
        relation: str,
        resource_id: str,
        tenant_id: str,
    ) -> None:
        """Add a subject-relation-resource edge."""
        self._edges.add((subject_id, relation, resource_id, tenant_id))

    def remove(
        self,
        subject_id: str,
        relation: str,
        resource_id: str,
        tenant_id: str,
    ) -> None:
        """Remove an edge if it exists."""
        self._edges.discard((subject_id, relation, resource_id, tenant_id))

    def check(
        self,
        subject_id: str,
        relation: str,
        resource_id: str,
        tenant_id: str,
    ) -> bool:
        """Return True only for an exact tenant-scoped relationship."""
        return (subject_id, relation, resource_id, tenant_id) in self._edges
