"""
rachis_connector.callback.access
=================================

RBAC and ABAC evaluation for callback requests (thesis §12.1, and the promotion of purpose
to a primary control, §3.6). A request to resolve a withheld field is evaluated against
rules the source owner declares; the connector never releases without an explicit allow
from every rule.

The design keeps rules declarative and composable. Each rule is a small object with an
`evaluate(request) -> (allow, reason)` method, so a source owner assembles an access policy
from named rules rather than writing code — the same principle as the mapping (§9.2).

RBAC: role membership. ABAC: attributes of the requester, the resource and the context —
clearance, nationality, purpose, lawful basis, device posture, time window.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple

from ..models import CallbackRequest


class AccessRule(ABC):
    """One access rule. Returns (allow, reason). Reason is a category, never an explanation
    (thesis §12.1, Appendix A.9 — the requester learns 'not releasable', not why)."""

    @abstractmethod
    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]: ...


# --------------------------------------------------------------------------- RBAC

@dataclass
class RequireAnyRole(AccessRule):
    """RBAC: the requester must hold at least one of these roles."""
    roles: List[str]

    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]:
        if set(req.roles) & set(self.roles):
            return True, ""
        return False, "role"


# --------------------------------------------------------------------------- ABAC

@dataclass
class MinimumClearance(AccessRule):
    """ABAC: clearance must be at or above a level in the ordered scheme."""
    minimum: str
    order: List[str]

    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]:
        rank = {c: i for i, c in enumerate(self.order)}
        if rank.get(req.clearance, -1) >= rank.get(self.minimum, 10 ** 9):
            return True, ""
        return False, "clearance"


@dataclass
class ReleasableTo(AccessRule):
    """ABAC: nationality must be in the releasability set (Appendix A.9's denial reason)."""
    nations: List[str]

    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]:
        if req.nationality in self.nations:
            return True, ""
        return False, "releasability"


@dataclass
class PurposeIn(AccessRule):
    """ABAC: the stated purpose must be permitted. In policing/health this is a legal test
    (thesis §3.6)."""
    permitted: List[str]

    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]:
        if req.purpose in self.permitted:
            return True, ""
        return False, "purpose"


@dataclass
class RequireLawfulBasis(AccessRule):
    """ABAC: a lawful basis must be present (thesis §3.6, §23.3). Absence is a breach, not a
    preference, so it is denied."""

    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]:
        if req.lawful_basis:
            return True, ""
        return False, "lawful-basis"


@dataclass
class RequireDevicePosture(AccessRule):
    """ABAC: device posture must be acceptable (thesis §16.2 — device is part of identity)."""
    acceptable: List[str]

    def evaluate(self, req: CallbackRequest) -> Tuple[bool, str]:
        if req.device_posture in self.acceptable:
            return True, ""
        return False, "device-posture"


# --------------------------------------------------------------------------- engine

@dataclass
class AccessResult:
    allow: bool
    reason: str


class AccessPolicy:
    """A conjunction of rules: every rule must allow, or the request is denied. The first
    failing rule's category is the denial reason (thesis §12.1)."""

    def __init__(self, rules: List[AccessRule]) -> None:
        self._rules = rules

    def evaluate(self, req: CallbackRequest) -> AccessResult:
        for rule in self._rules:
            allow, reason = rule.evaluate(req)
            if not allow:
                return AccessResult(False, reason)
        return AccessResult(True, "")
