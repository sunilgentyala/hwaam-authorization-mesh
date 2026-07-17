"""HWAAM authorization reference implementation."""

from .engine import AuthorizationEngine
from .models import (
    Decision,
    MissionEnvelope,
    Principal,
    Resource,
    AuthorizationRequest,
)
from .policy import PolicyBundle, TenantTrustPolicy
from .relationships import RelationshipGraph
from .revocation import RevocationRegistry
from .trust import Approval, DelegationHop, SecurityContext

__all__ = [
    "Approval",
    "AuthorizationEngine",
    "AuthorizationRequest",
    "Decision",
    "DelegationHop",
    "MissionEnvelope",
    "PolicyBundle",
    "Principal",
    "RelationshipGraph",
    "Resource",
    "RevocationRegistry",
    "SecurityContext",
    "TenantTrustPolicy",
]

__version__ = "0.2.0"
