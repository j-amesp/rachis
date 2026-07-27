"""
RACHIS — Disclosure contract.

The callback path (thesis Chapter 12). A pointer field withheld at ingest is resolved only
by a request the source evaluates against its own policy and may refuse, bound, or revoke.

The property the tests must show (thesis §12.1): a value released *after* ingest still
verifies against the *original* signed root, because the source kept the salt (D1) and can
reconstruct the identical leaf. And the platform never held the value, so it could not have
released it — the decision is always the source's (§9.4, §11.3).

Disclosure is a normative contract precisely because making it optional would let an
implementation certify while demanding full content up front — the incumbent model with a
badge (thesis §17.2).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional

from .provenance import MerkleTree, Disposition, _leaf_hash
from .labels import Label
from .trust import SaltStore


class Decision(str, Enum):
    RELEASE = "release"
    DENY = "deny"


@dataclass
class CallbackRequest:
    """A request to resolve a pointer field (thesis §12.1, Appendix A.9)."""
    record_id: str
    field_name: str
    pointer: str
    requester: str
    organisation: str
    nationality: str
    clearance: str
    purpose: str
    device_posture: str = "managed-attested"
    requested_duration: str = "PT24H"


@dataclass
class CallbackResponse:
    decision: Decision
    reason: str
    value: Optional[object] = None
    value_repr: Optional[str] = None
    salt: Optional[str] = None
    inclusion_proof: Optional[List[tuple]] = None


# a source-owned rule returns (allow, reason)
CallbackRule = Callable[[CallbackRequest], tuple]


class CallbackHandler:
    """Source-side handler. Evaluates requests, logs every one, can revoke (thesis §12.1)."""

    def __init__(
        self,
        salt_store: SaltStore,
        rules: List[CallbackRule],
        value_lookup: Callable[[str, str], object],
        label_lookup: Callable[[str, str], Label],
        marking_policy_id: str,
    ) -> None:
        self._salts = salt_store
        self._rules = rules
        self._value = value_lookup      # (record_id, field) -> value, source-held
        self._label = label_lookup
        self._pid = marking_policy_id
        self._revoked: set = set()
        self.log: List[dict] = []       # local audit: everything asked and given (§12.1)

    def revoke(self, record_id: str, field_name: str, requester: str) -> None:
        self._revoked.add((record_id, field_name, requester))

    def handle(self, req: CallbackRequest,
               original_root: bytes,
               leaf_index_lookup: Callable[[str, str], int],
               all_leaf_hashes: Callable[[str], List[bytes]]) -> CallbackResponse:
        """Evaluate a callback and, if released, produce a proof against the ORIGINAL root.

        `all_leaf_hashes(record_id)` returns the full ordered leaf hash list for the record
        as it was bound. This lets the source rebuild the tree and produce an inclusion
        proof for the now-released field that verifies against the signature the platform
        already holds — no re-signing (thesis §12.1).
        """
        entry = {"record": req.record_id, "field": req.field_name,
                 "requester": req.requester, "purpose": req.purpose}

        if (req.record_id, req.field_name, req.requester) in self._revoked:
            entry["decision"] = "deny:revoked"
            self.log.append(entry)
            return CallbackResponse(Decision.DENY, "revoked")

        for rule in self._rules:
            allow, reason = rule(req)
            if not allow:
                entry["decision"] = f"deny:{reason}"
                self.log.append(entry)
                return CallbackResponse(Decision.DENY, reason)

        # authorised: reconstruct the leaf and prove it against the original root
        value = self._value(req.record_id, req.field_name)
        label = self._label(req.record_id, req.field_name)
        salt = self._salts.salt_for(req.record_id, req.field_name)
        value_repr = value if isinstance(value, str) else str(value)

        # the field was a POINTER at bind time; its leaf committed to name+label only.
        leaf = _leaf_hash(req.field_name, Disposition.POINTER, None, label, salt)
        leaves = all_leaf_hashes(req.record_id)
        idx = leaf_index_lookup(req.record_id, req.field_name)
        tree = MerkleTree(leaves)
        proof = tree.proof(idx)
        ok = MerkleTree.verify(leaf, proof, original_root)

        entry["decision"] = "release" if ok else "release:proof-fail"
        self.log.append(entry)
        return CallbackResponse(
            Decision.RELEASE, "authorised", value=value,
            value_repr=value_repr, salt=salt, inclusion_proof=proof,
        )


# --------------------------------------------------------------------------- common rules

def deny_below_clearance(minimum: str, order: List[str]) -> CallbackRule:
    rank = {c: i for i, c in enumerate(order)}
    def rule(req: CallbackRequest):
        if rank.get(req.clearance, -1) < rank.get(minimum, 999):
            return False, "clearance"
        return True, ""
    return rule


def deny_purpose(blocked: List[str]) -> CallbackRule:
    def rule(req: CallbackRequest):
        return (req.purpose not in blocked), ("purpose" if req.purpose in blocked else "")
    return rule


def require_releasable_to(allowed_nations: List[str]) -> CallbackRule:
    """Releasability caveat check — the maritime example's denial reason (Appendix A.9)."""
    def rule(req: CallbackRequest):
        return (req.nationality in allowed_nations), \
               ("releasability" if req.nationality not in allowed_nations else "")
    return rule
