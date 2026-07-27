"""
rachis_connector.pipeline.binder
=================================

Builds and signs a disclosure package (thesis §10.4). Runs at the source, inside the
connector. Persists the leaf order and hashes to durable state so that a later callback
release can reconstruct the tree and prove a field against the ORIGINAL root (thesis §12.1).

The binder is where "withheld means absent" is enforced physically (thesis §9.4): withheld
values are never read into the wire package; they contribute only their leaf hash to the
tree, committing to the field's existence and label without its value.
"""
from __future__ import annotations

import datetime as _dt
from typing import Dict, List, Optional

from ..crypto.interfaces import Signer
from ..crypto.merkle import (
    Disposition, Label, FivePartHeader, MerkleTree,
    leaf_hash, canonical_order,
)
from ..state.store import StateStore
from ..wire import (
    DisclosurePackage, WireField, WireHeader, WireLabel,
)


class Binder:
    def __init__(self, signer: Signer, state: StateStore, connector_measurement: str) -> None:
        self._signer = signer
        self._state = state
        self._measurement = connector_measurement

    def bind(
        self,
        record_id: str,
        header: FivePartHeader,
        record_label: Label,
        resolved: Dict[str, dict],
    ) -> DisclosurePackage:
        """Bind a resolved record into a signed, wire-ready package.

        `resolved` maps field -> {disposition, label, and disposition-specific material}.
        It is the output of policy application, with withheld values already dropped.
        """
        names = [n for n in resolved]
        ordered = canonical_order(names)   # header at 0, then core, then extensions

        leaf_hashes: List[bytes] = []
        salts: Dict[str, str] = {}
        for name in ordered:
            if name == "__header__":
                from ..crypto.merkle import h as _h
                leaf_hashes.append(_h(b"header", header.canonical()))
                continue
            spec = resolved[name]
            disp = Disposition(spec["disposition"])
            label: Label = spec["label"]
            salt = self._state.salt_for(record_id, name)
            salts[name] = salt
            vr = spec.get("value_repr")
            leaf_hashes.append(leaf_hash(name, disp, vr, label, salt))

        tree = MerkleTree(leaf_hashes)
        root = tree.root
        signature = self._signer.sign(root)

        # persist the binding for callback proofs (thesis §12.1)
        self._state.save_binding(
            record_id, ordered, [lh.hex() for lh in leaf_hashes],
            root.hex(), signature.hex(),
        )

        wire_fields: List[WireField] = []
        for i, name in enumerate(ordered):
            if name == "__header__":
                continue
            spec = resolved[name]
            disp = Disposition(spec["disposition"])
            label: Label = spec["label"]
            wl = WireLabel(policy_id=label.policy_id, classification=label.classification,
                           caveats=list(label.caveats))
            wf = WireField(name=name, disposition=disp,
                           inclusion_proof=tree.proof(i), label=wl)
            if disp == Disposition.CLEAR:
                wf.value = spec["value"]
                wf.value_repr = spec.get("value_repr")
                wf.salt = salts[name]                       # released salt, not secret
            elif disp == Disposition.HASH_ONLY:
                wf.correlation_digest = spec["correlation_digest"]
                wf.value_repr = spec.get("value_repr")
                wf.salt = salts[name]
            elif disp == Disposition.POINTER:
                wf.pointer = spec["pointer"]
                # salt withheld — needed at the source to honour a callback (D1)
            # WITHHELD: nothing carried
            wire_fields.append(wf)

        return DisclosurePackage(
            algorithm=self._signer.algorithm,
            root_hex=root.hex(),
            signature_hex=signature.hex(),
            header=WireHeader(
                expectation=header.expectation, mapping_hash=header.mapping_hash,
                policy_hash=header.policy_hash,
                connector_measurement=header.connector_measurement,
                source_identity=header.source_identity,
            ),
            record_label=WireLabel(
                policy_id=record_label.policy_id,
                classification=record_label.classification,
                caveats=list(record_label.caveats),
            ),
            fields=wire_fields,
            field_count=len(leaf_hashes),
            record_id=record_id,
            created_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )
