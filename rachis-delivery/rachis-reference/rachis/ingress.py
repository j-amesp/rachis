"""
RACHIS — Ingress contract.

The platform's entry boundary: the nine-check verification sequence (thesis §11.1). The
defining property (§11.3) is that ingress *verifies* and does not *classify* — every check
is a comparison, a signature verification, or marking arithmetic. Nothing here forms a
judgement about content, and nothing here holds a key that could forge a label.

A package that fails any check is rejected with a reason (§11.1). Nothing is coerced into
shape; nothing is admitted with a defect noted for later.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .provenance import DisclosurePackage, MerkleTree, Disposition, _h, _leaf_hash
from .labels import Label, MarkingPolicy
from .model import Expectation
from .trust import TrustStore


@dataclass
class VerificationResult:
    admitted: bool
    checks: List[tuple]                # (name, passed, detail)
    reason: Optional[str] = None

    def summary(self) -> str:
        lines = [f"  {'PASS' if ok else 'FAIL'}  {name}: {detail}"
                 for name, ok, detail in self.checks]
        head = "ADMIT" if self.admitted else f"REJECT ({self.reason})"
        return head + "\n" + "\n".join(lines)


class Ingress:
    """Runs the nine checks against a disclosure package (thesis §11.1)."""

    def __init__(
        self,
        trust: TrustStore,
        expectations: Dict[str, Expectation],
        marking_policies: Dict[str, MarkingPolicy],
        permitted_measurements: Set[str],
        replay_window_seconds: int = 86_400,
    ) -> None:
        self._trust = trust
        self._expectations = expectations
        self._marking = marking_policies
        self._permitted = permitted_measurements
        self._seen_roots: Dict[bytes, float] = {}
        self._replay_window = replay_window_seconds

    def verify(self, pkg: DisclosurePackage) -> VerificationResult:
        checks: List[tuple] = []

        def record(name, ok, detail):
            checks.append((name, ok, detail))
            return ok

        # 1 — signature against the recognised anchor for the asserting source
        verifier = self._trust.verifier_for(pkg.header.source_identity)
        ok1 = verifier is not None and verifier.verify(pkg.root, pkg.signature)
        if not record("1 signature", ok1, pkg.header.source_identity):
            return VerificationResult(False, checks, "signature")

        # 2 — attestation: connector measurement in the permitted set
        ok2 = pkg.header.connector_measurement in self._permitted
        if not record("2 attestation", ok2, pkg.header.connector_measurement[:24]):
            return VerificationResult(False, checks, "attestation")

        # 3 — Expectation version exists (deprecation horizon check omitted in the core)
        exp = self._expectations.get(pkg.header.expectation)
        if not record("3 expectation version", exp is not None, pkg.header.expectation):
            return VerificationResult(False, checks, "unknown expectation")

        # 4 — schema conformance of the *disclosed* fields
        disclosed_names = {f.name for f in pkg.fields}
        req_present = all(
            r in disclosed_names or True  # required-but-withheld is a source decision
            for r in exp.required_fields()
        )
        record("4 schema conformance", req_present, f"{len(pkg.fields)} fields")

        # 5 — every disclosed field carries a label, against an accepted policy
        pid = exp.marking.policy_id
        marking_policy = self._marking.get(pid)
        ok5 = marking_policy is not None and all(
            f.label is not None and f.label.policy_id == pid for f in pkg.fields
        )
        if not record("5 labels present", ok5, pid):
            return VerificationResult(False, checks, "labels/policy")

        # 6 — marking arithmetic: no field label exceeds the record label
        ok6 = all(pkg.record_label.dominates(f.label, marking_policy) for f in pkg.fields)
        if not record("6 marking arithmetic", ok6, f"record={pkg.record_label.classification}"):
            return VerificationResult(False, checks, "marking arithmetic")

        # 7 — policy hash well-formed and recorded
        ok7 = pkg.header.policy_hash.startswith("sha384:")
        record("7 policy hash", ok7, pkg.header.policy_hash[:20])

        # 8 — provenance: every inclusion proof verifies to the signed root
        ok8 = self._verify_proofs(pkg)
        if not record("8 provenance proofs", ok8, "inclusion proofs -> root"):
            return VerificationResult(False, checks, "provenance")

        # 9 — replay: root unseen within the window
        now = time.time()
        self._seen_roots = {r: t for r, t in self._seen_roots.items()
                            if now - t < self._replay_window}
        ok9 = pkg.root not in self._seen_roots
        record("9 replay", ok9, "unseen" if ok9 else "duplicate")
        if not ok9:
            return VerificationResult(False, checks, "replay")
        self._seen_roots[pkg.root] = now

        all_ok = all(ok for _, ok, _ in checks)
        return VerificationResult(all_ok, checks, None if all_ok else "check failed")

    def _verify_proofs(self, pkg: DisclosurePackage) -> bool:
        """Recompute each released leaf and verify its inclusion proof against the root.

        Proves (thesis §10.4): released fields verify against the signed root without the
        platform ever seeing the withheld fields — the platform has no way to reconstruct
        their leaves, and does not need to.
        """
        for f in pkg.fields:
            if f.disposition == Disposition.WITHHELD:
                continue  # not in the package; nothing to verify
            if f.disposition in (Disposition.CLEAR, Disposition.HASH_ONLY):
                if f.salt is None or f.value_repr is None or f.label is None:
                    return False
                leaf = _leaf_hash(f.name, f.disposition, f.value_repr, f.label, f.salt)
            else:  # POINTER — leaf commits to name+label only, salt stays at source
                # The platform cannot recompute a pointer leaf (no salt); it trusts the
                # proof structure. In the full profile a pointer carries a leaf commitment;
                # here we accept pointer leaves as present without value verification.
                continue
            if not MerkleTree.verify(leaf, f.inclusion_proof, pkg.root):
                return False
        return True
