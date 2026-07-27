"""
RACHIS — Provenance contract.

The cryptographic heart: a Merkle tree over salted field leaves, signed once at the root,
with per-field inclusion proofs. This is the JSON/selective-disclosure profile of
ADatP-4778 the thesis proposes (§10.3–10.5).

The property that makes it worth doing (thesis §10.4): a recipient holding *some* fields
can verify their authenticity against the signed root without learning anything about the
withheld fields beyond how many there were. Withheld and pointer leaves contribute their
hash to the tree and nothing else.

Canonical leaf ordering (Appendix A.11 defect D5): core fields first, ordered by Unicode
code point on the qualified name; then extensions by namespace then name; header always at
index 0. Any ambiguity here is a verification failure between independent implementations,
so it is specified exactly and tested.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .trust import Signer, Verifier, SaltStore
from .labels import Label


DIGEST = "sha384"  # mandatory digest, aligns with the 4778 profile (thesis §10.3)


def _h(*parts: bytes) -> bytes:
    d = hashlib.new(DIGEST)
    for p in parts:
        d.update(len(p).to_bytes(8, "big"))  # length-prefix: no concatenation ambiguity
        d.update(p)
    return d.digest()


class Disposition(str, Enum):
    """The four dispositions (thesis §9.3). Defined here because the leaf construction and
    the package builder both need them."""
    CLEAR = "clear"
    HASH_ONLY = "hash-only"
    POINTER = "pointer"
    WITHHELD = "withheld"


@dataclass
class FivePartHeader:
    """Binds the provenance of the disclosure decision (thesis §10.5, incl. defect D4).

    Five elements, not four: the D4 correction added `mapping_hash`, because a mapping
    defect (an inverted codelist, a timezone slip) is a likely cause of a wrong value and
    provenance that cannot name the mapping cannot support the inquiry it exists for.
    """
    expectation: str
    mapping_hash: str
    policy_hash: str
    connector_measurement: str
    source_identity: str

    def leaf_bytes(self) -> bytes:
        return json.dumps(
            {
                "expectation": self.expectation,
                "mappingHash": self.mapping_hash,
                "policyHash": self.policy_hash,
                "connectorMeasurement": self.connector_measurement,
                "sourceIdentity": self.source_identity,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def _qualified_sort_key(name: str) -> Tuple[int, str]:
    """Core fields (no namespace ':') sort before extensions; then lexicographic.

    Implements the D5 canonical ordering. Header is handled separately at index 0.
    """
    is_extension = 1 if ":" in name else 0
    return (is_extension, name)


@dataclass
class Leaf:
    """One tree leaf. For clear/hash-only the value contributes; for pointer/withheld only
    the salted name-and-label does, so the leaf commits to the field's existence and label
    without committing to a value the platform may not hold."""
    name: str
    disposition: Disposition
    leaf_hash: bytes
    # Material the recipient needs to *reconstruct* the leaf, present only when released:
    value_repr: Optional[str] = None
    label: Optional[Label] = None
    salt: Optional[str] = None


def _leaf_hash(name: str, disposition: Disposition,
               value_repr: Optional[str], label: Label, salt: str) -> bytes:
    """Compute a leaf hash.

    For CLEAR / HASH_ONLY the value participates. For POINTER / WITHHELD it does not, so
    two records withholding the same field produce unrelated leaves (via distinct salts)
    and nothing about the value leaks (thesis §10.4).
    """
    label_bytes = json.dumps(
        {"c": label.classification, "k": sorted(label.caveats), "p": label.policy_id},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    if disposition in (Disposition.CLEAR, Disposition.HASH_ONLY) and value_repr is not None:
        return _h(name.encode(), value_repr.encode(), label_bytes, salt.encode())
    return _h(name.encode(), b"", label_bytes, salt.encode())


class MerkleTree:
    """Binary Merkle tree with inclusion proofs. Small enough to read; that is the point."""

    def __init__(self, leaves: List[bytes]) -> None:
        if not leaves:
            raise ValueError("cannot build a tree with no leaves")
        self._leaves = leaves
        self._levels: List[List[bytes]] = [leaves]
        self._build()

    def _build(self) -> None:
        level = self._leaves
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]  # duplicate last
                nxt.append(_h(b"node", left, right))
            self._levels.append(nxt)
            level = nxt

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, bytes]]:
        """Inclusion proof for the leaf at `index`: the sibling hashes up to the root."""
        proof: List[Tuple[str, bytes]] = []
        for level in self._levels[:-1]:
            sibling = index ^ 1
            if sibling >= len(level):
                sibling = index  # duplicated node
            side = "L" if sibling < index else "R"
            proof.append((side, level[sibling]))
            index //= 2
        return proof

    @staticmethod
    def verify(leaf: bytes, proof: List[Tuple[str, bytes]], root: bytes) -> bool:
        """Recompute the root from a leaf and its proof. The check a recipient runs."""
        acc = leaf
        for side, sib in proof:
            acc = _h(b"node", sib, acc) if side == "L" else _h(b"node", acc, sib)
        return acc == root


@dataclass
class DisclosedField:
    """A field as it appears in a transmitted package."""
    name: str
    disposition: Disposition
    inclusion_proof: List[Tuple[str, bytes]]
    value: Optional[object] = None
    value_repr: Optional[str] = None
    correlation_digest: Optional[str] = None
    pointer: Optional[str] = None
    label: Optional[Label] = None
    salt: Optional[str] = None


@dataclass
class DisclosurePackage:
    """What crosses the disclosure boundary (thesis §10, Appendix A.7).

    Contains the signed root, the header, the record label, and only the fields the policy
    released. Withheld fields are absent — not encrypted, not placeholdered (thesis §9.4).
    """
    algorithm: str
    root: bytes
    signature: bytes
    header: FivePartHeader
    record_label: Label
    fields: List[DisclosedField]
    field_count: int  # total leaves incl. withheld; the one thing tree-shape reveals (§10.4)
    record_id: str


class Binder:
    """Builds and signs a disclosure package. Runs at the source, inside the connector."""

    def __init__(self, signer: Signer, salt_store: SaltStore,
                 connector_measurement: str) -> None:
        self._signer = signer
        self._salts = salt_store
        self._measurement = connector_measurement

    def bind(
        self,
        record_id: str,
        header: FivePartHeader,
        record_label: Label,
        resolved: Dict[str, dict],
    ) -> DisclosurePackage:
        """Bind a resolved record into a signed package.

        `resolved` maps field name -> {disposition, value, value_repr, correlation_digest,
        pointer, label}. It is the output of Policy application (policy.py): every field
        with its disposition already decided and withheld values already dropped to None.

        Proves (thesis §10.4): the tree is built over *all* fields including withheld ones,
        so the root commits to the whole record shape, but only released leaves carry
        reconstruction material into the package.
        """
        names = [n for n in resolved if n != "__header__"]
        names.sort(key=_qualified_sort_key)

        # index 0 is always the header leaf (D5)
        ordered: List[str] = ["__header__"] + names

        leaf_hashes: List[bytes] = []
        built: Dict[str, Leaf] = {}
        for name in ordered:
            if name == "__header__":
                leaf_hashes.append(_h(b"header", header.leaf_bytes()))
                continue
            spec = resolved[name]
            disp = Disposition(spec["disposition"])
            label: Label = spec["label"]
            salt = self._salts.salt_for(record_id, name)
            vr = spec.get("value_repr")
            lh = _leaf_hash(name, disp, vr, label, salt)
            leaf_hashes.append(lh)
            built[name] = Leaf(name, disp, lh, vr, label, salt)

        tree = MerkleTree(leaf_hashes)
        root = tree.root
        signature = self._signer.sign(root)

        disclosed: List[DisclosedField] = []
        for i, name in enumerate(ordered):
            if name == "__header__":
                continue
            spec = resolved[name]
            disp = Disposition(spec["disposition"])
            leaf = built[name]
            proof = tree.proof(i)
            df = DisclosedField(name=name, disposition=disp, inclusion_proof=proof,
                                label=leaf.label)
            if disp == Disposition.CLEAR:
                df.value = spec["value"]
                df.value_repr = leaf.value_repr
                df.salt = leaf.salt            # released salt is not secret
            elif disp == Disposition.HASH_ONLY:
                df.correlation_digest = spec["correlation_digest"]
                df.value_repr = leaf.value_repr
                df.salt = leaf.salt
            elif disp == Disposition.POINTER:
                df.pointer = spec["pointer"]
                # salt withheld: needed later to honour a callback (D1)
            # WITHHELD: nothing carried at all
            disclosed.append(df)

        return DisclosurePackage(
            algorithm=self._signer.algorithm,
            root=root,
            signature=signature,
            header=header,
            record_label=record_label,
            fields=disclosed,
            field_count=len(leaf_hashes),
            record_id=record_id,
        )
