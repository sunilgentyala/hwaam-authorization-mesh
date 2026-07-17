"""Revocation registry for principals, missions, and resources."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RevocationRegistry:
    """A simple fail-closed revocation source for the reference engine."""

    revoked_principals: set[str] = field(default_factory=set)
    revoked_missions: set[str] = field(default_factory=set)
    revoked_resources: set[str] = field(default_factory=set)

    def revoke_principal(self, principal_id: str) -> None:
        self.revoked_principals.add(principal_id)

    def revoke_mission(self, mission_id: str) -> None:
        self.revoked_missions.add(mission_id)

    def revoke_resource(self, resource_id: str) -> None:
        self.revoked_resources.add(resource_id)

    def is_principal_revoked(self, principal_id: str) -> bool:
        return principal_id in self.revoked_principals

    def is_mission_revoked(self, mission_id: str) -> bool:
        return mission_id in self.revoked_missions

    def is_resource_revoked(self, resource_id: str) -> bool:
        return resource_id in self.revoked_resources
