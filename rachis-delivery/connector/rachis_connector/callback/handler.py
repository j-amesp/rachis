"""
rachis_connector.callback.handler
==================================

The callback path, end to end (thesis §12.1). Receives a request to resolve a withheld or
pointer field, evaluates RBAC/ABAC, and on grant:

  1. looks up the value (source-held; the connector fetches it fresh, it does not cache
     plaintext of withheld fields);
  2. produces an inclusion proof against the ORIGINAL signed root, using the salt persisted
     at bind time — so the released value verifies under the signature core already holds,
     with no re-signing (thesis §12.1);
  3. seals the value to the REQUESTER's public key with a cryptographically bound time
     window (crypto.software.SoftwareSealer), so core can hold the sealed object but cannot
     open it, and the requester cannot open it outside the window;
  4. queues the sealed release with its window; core triggers delivery when the window opens.

The connector discards the plaintext after sealing. It never holds a key that could open
the sealed release (that key is the requester's). Every request is logged locally whatever
the outcome (thesis §12.1 local audit).
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Callable, List, Optional

from ..models import CallbackRequest, CallbackDecision
from ..crypto.interfaces import KeyStore, SealedRelease
from ..crypto.merkle import Disposition, Label, MerkleTree, leaf_hash
from ..state.store import StateStore
from .access import AccessPolicy, AccessResult


# source-held lookups the connector is configured with
ValueLookup = Callable[[str, str], object]      # (record_id, field) -> value
LabelLookup = Callable[[str, str], Label]        # (record_id, field) -> Label


class CallbackHandler:
    def __init__(
        self,
        keystore: KeyStore,
        access_policy: AccessPolicy,
        state: StateStore,
        value_lookup: ValueLookup,
        label_lookup: LabelLookup,
    ) -> None:
        self._keystore = keystore
        self._access = access_policy
        self._state = state
        self._value = value_lookup
        self._label = label_lookup

    def handle(self, req: CallbackRequest) -> dict:
        """Evaluate and, if granted, seal and queue. Returns a small result dict for the API.

        Never returns the plaintext or the sealed material to the caller of this method; the
        sealed release goes to the durable queue and is delivered to core when its window
        opens (thesis §12.1).
        """
        audit_base = {
            "record": req.record_id, "field": req.field_name,
            "requester": req.requester, "purpose": req.purpose,
            "nationality": req.nationality,
        }

        # 1. access control
        result: AccessResult = self._access.evaluate(req)
        if not result.allow:
            self._state.audit("callback", {**audit_base, "decision": f"deny:{result.reason}"})
            return {"decision": CallbackDecision.DENY.value, "reason": result.reason}

        # 2. reconstruct the leaf and prove against the original root
        binding = self._state.get_binding(req.record_id)
        if binding is None:
            self._state.audit("callback", {**audit_base, "decision": "deny:no-binding"})
            return {"decision": CallbackDecision.DENY.value, "reason": "unknown-record"}

        label = self._label(req.record_id, req.field_name)
        salt = self._state.salt_for(req.record_id, req.field_name)
        # the field was POINTER at bind time: leaf commits to name+label+salt, no value
        leaf = leaf_hash(req.field_name, Disposition.POINTER, None, label, salt)

        ordered: List[str] = binding["ordered_names"]
        leaf_hashes = [bytes.fromhex(x) for x in binding["leaf_hashes"]]
        root = bytes.fromhex(binding["root_hex"])
        try:
            idx = ordered.index(req.field_name)
        except ValueError:
            self._state.audit("callback", {**audit_base, "decision": "deny:field-not-bound"})
            return {"decision": CallbackDecision.DENY.value, "reason": "unknown-field"}

        tree = MerkleTree(leaf_hashes)
        proof = tree.proof(idx)
        if leaf_hashes[idx] != leaf or not MerkleTree.verify(leaf, proof, root):
            # salt drift or tampering: refuse rather than release something unverifiable
            self._state.audit("callback", {**audit_base, "decision": "deny:proof-fail"})
            return {"decision": CallbackDecision.DENY.value, "reason": "verification"}

        # 3. seal the value to the requester's key with a bound window
        value = self._value(req.record_id, req.field_name)
        plaintext = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() \
            if not isinstance(value, str) else value.encode()

        aad_context = (
            f"rachis-release|rec={req.record_id}|field={req.field_name}"
            f"|req={req.requester}|root={binding['root_hex']}"
        ).encode()

        sealer = self._keystore.sealer()
        sealed: SealedRelease = sealer.seal(
            plaintext=plaintext,
            recipient_public_key=bytes.fromhex(req.recipient_public_key_hex),
            not_before=req.not_before,
            not_after=req.not_after,
            aad_context=aad_context,
        )
        sealed.record_id = req.record_id
        sealed.field_name = req.field_name
        sealed.requester = req.requester
        # plaintext is now out of scope; the connector holds no key to reopen `sealed`

        # 4. queue with the window; core triggers delivery when it opens (thesis §12.1)
        sealed_json = json.dumps(_sealed_to_dict(sealed))
        cb_id = self._state.enqueue_callback(
            req.record_id, req.field_name, req.requester, sealed_json,
            req.not_before, req.not_after,
        )
        # include the inclusion proof so core can attach provenance to the release
        self._state.audit("callback", {
            **audit_base, "decision": "release",
            "window": [req.not_before, req.not_after], "queued": cb_id,
        })
        return {
            "decision": CallbackDecision.RELEASE.value,
            "reason": "authorised",
            "queued_id": cb_id,
            "not_before": req.not_before,
            "not_after": req.not_after,
            "inclusion_proof": proof,
            "root_hex": binding["root_hex"],
        }


def _sealed_to_dict(s: SealedRelease) -> dict:
    return {
        "alg": s.alg,
        "ephemeral_public_key": s.ephemeral_public_key.hex(),
        "nonce": s.nonce.hex(),
        "ciphertext": s.ciphertext.hex(),
        "not_before": s.not_before,
        "not_after": s.not_after,
        "aad": s.aad.hex(),
        "record_id": s.record_id,
        "field_name": s.field_name,
        "requester": s.requester,
    }
