"""HWAAM authorization reference implementation."""

from .engine import AuthorizationEngine
from .models import (
    Decision,
    DelegationHop,
    MissionEnvelope,
    Principal,
    Resource,
    AuthorizationRequest,
)
from .policy import PolicyBundle
from .relationships import RelationshipGraph
from .revocation import RevocationRegistry

__all__ = [
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
]

__version__ = "0.1.0"
