"""
rachis_connector.crypto.merkle
===============================

Merkle tree, salted leaves, inclusion proofs and the five-part header — the JSON/selective
disclosure profile of ADatP-4778 (thesis §10.3-10.5). This is the production version of the
reference core's provenance module, with the pointer-leaf commitment made explicit so that
a callback release (thesis §12.1) verifies against the original signed root.

Canonical leaf ordering (thesis Appendix A.11 D5): header at index 0; then core fields by
Unicode code point on the qualified name; then extension fields (those containing ':') by
namespace then name. Specified exactly because any ambiguity is a cross-implementation
verification failure.

Digest: SHA-384 throughout, mandatory in the 4778 profile.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


def h(*parts: bytes) -> bytes:
    """Length-prefixed SHA-384. Length prefixing removes concatenation ambiguity."""
    d = hashlib.sha384()
    for p in parts:
        d.update(len(p).to_bytes(8, "big"))
        d.update(p)
    return d.digest()


class Disposition(str, Enum):
    CLEAR = "clear"
    HASH_ONLY = "hash-only"
    POINTER = "pointer"
    WITHHELD = "withheld"


@dataclass(frozen=True)
class Label:
    policy_id: str
    classification: str
    caveats: Tuple[str, ...] = ()

    def canonical(self) -> bytes:
        return json.dumps(
            {"c": self.classification, "k": sorted(self.caveats), "p": self.policy_id},
            sort_keys=True, separators=(",", ":"),
        ).encode()


@dataclass
class FivePartHeader:
    """thesis §10.5 + Appendix A.11 D4 — five elements, mappingHash included."""
    expectation: str
    mapping_hash: str
    policy_hash: str
    connector_measurement: str
    source_identity: str

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "expectation": self.expectation,
                "mappingHash": self.mapping_hash,
                "policyHash": self.policy_hash,
                "connectorMeasurement": self.connector_measurement,
                "sourceIdentity": self.source_identity,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()


def leaf_hash(
    name: str,
    disposition: Disposition,
    value_repr: Optional[str],
    label: Label,
    salt: str,
) -> bytes:
    """Compute a leaf.

    CLEAR / HASH_ONLY: the value participates, so the leaf commits to the value.
    POINTER: the value does NOT participate (the platform never holds it), but the leaf
             still commits to name+label+salt, so a later callback release can reproduce
             the identical leaf and prove it against the original root (thesis §12.1).
    WITHHELD: same construction as POINTER; the field's existence is committed, its value
             is not, and nothing about it travels in the package.

    The pointer/withheld salt stays at the source (the salt store), which is why the
    connector is stateful (thesis Appendix A.11 D1).
    """
    lb = label.canonical()
    if disposition in (Disposition.CLEAR, Disposition.HASH_ONLY) and value_repr is not None:
        return h(name.encode(), value_repr.encode(), lb, salt.encode())
    return h(name.encode(), b"", lb, salt.encode())


def _order_key(name: str) -> Tuple[int, str]:
    return (1 if ":" in name else 0, name)


def canonical_order(field_names: List[str]) -> List[str]:
    """Header first, then core by name, then extensions by name (thesis D5)."""
    return ["__header__"] + sorted(field_names, key=_order_key)


class MerkleTree:
    def __init__(self, leaves: List[bytes]) -> None:
        if not leaves:
            raise ValueError("empty tree")
        self._levels: List[List[bytes]] = [leaves]
        level = leaves
        while len(level) > 1:
            nxt = [
                h(b"node", level[i], level[i + 1] if i + 1 < len(level) else level[i])
                for i in range(0, len(level), 2)
            ]
            self._levels.append(nxt)
            level = nxt

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, str]]:
        """Inclusion proof as (side, hex-sibling) pairs, JSON-serialisable for the wire."""
        out: List[Tuple[str, str]] = []
        for level in self._levels[:-1]:
            sib = index ^ 1
            if sib >= len(level):
                sib = index
            side = "L" if sib < index else "R"
            out.append((side, level[sib].hex()))
            index //= 2
        return out

    @staticmethod
    def verify(leaf: bytes, proof: List[Tuple[str, str]], root: bytes) -> bool:
        acc = leaf
        for side, sib_hex in proof:
            sib = bytes.fromhex(sib_hex)
            acc = h(b"node", sib, acc) if side == "L" else h(b"node", acc, sib)
        return acc == root
