"""
RACHIS — Trust contract.

Key custody and signing. The thesis (§16.1) requires that signing keys live with the
source and that the platform hold no key capable of forging a source signature. This
module expresses that as a hard interface boundary: a `Signer` can sign; a `Verifier`
holds only public material and can never produce a signature.

Post-quantum note (thesis §10.3): production RACHIS signs with ML-DSA (FIPS 204) on the
hot path and SLH-DSA (FIPS 205) for archive. Those live behind the `Signer` interface so
the algorithm is a one-class swap. Here we use Ed25519, which is available everywhere and
lets the whole system run and be tested without liboqs. The `algorithm` field records what
a real deployment would carry, so packages are shaped correctly.
"""
from __future__ import annotations

import os
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# --------------------------------------------------------------------------- signing

class Signer(ABC):
    """A signing identity held at a source. Only a Signer can produce signatures.

    Proves (thesis §16.1): signing authority is a source-side capability. The platform
    is given Verifiers, never Signers, so it structurally cannot forge a label.
    """

    #: The algorithm string a real deployment carries in the binding header.
    algorithm: str

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        ...

    @abstractmethod
    def verifier(self) -> "Verifier":
        """Return the public half — safe to hand to the platform."""


class Verifier(ABC):
    """Public verification material. Cannot sign. This is all the platform ever holds."""

    algorithm: str

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        ...


class Ed25519Signer(Signer):
    """Ed25519 stand-in for ML-DSA. The swap point for post-quantum signing."""

    algorithm = "Ed25519"  # production: "ML-DSA-65"

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._sk = private_key or Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def verifier(self) -> "Ed25519Verifier":
        return Ed25519Verifier(self._sk.public_key())


class Ed25519Verifier(Verifier):
    algorithm = "Ed25519"

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._pk = public_key

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        try:
            self._pk.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def public_bytes(self) -> bytes:
        return self._pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


# --------------------------------------------------------------------------- trust anchors

@dataclass
class TrustStore:
    """The federation's recognised source identities. Held by the platform.

    Maps a source identity URN to the Verifier the federation accepts for it. Ingress
    check 1 (thesis §11.1) resolves signatures against this. Contains no private keys.
    """

    _anchors: Dict[str, Verifier] = field(default_factory=dict)

    def register(self, source_identity: str, verifier: Verifier) -> None:
        self._anchors[source_identity] = verifier

    def verifier_for(self, source_identity: str) -> Verifier | None:
        return self._anchors.get(source_identity)


# --------------------------------------------------------------------------- salt store

class SaltStore:
    """Durable per-leaf salts held at the source.

    Proves (thesis Appendix A.11 defect D1): the connector is stateful. Salts for withheld
    and pointer leaves must persist for the record's lifetime, because a later callback
    release (§12.1) must reproduce a leaf that verifies against the *original* signed root.
    Lose the salt and you can never honour a callback for that field again.

    Salts for released fields travel in the package and are not secret; salts for withheld
    and pointer fields stay here and are what stop enumeration of low-entropy values.
    """

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}

    @staticmethod
    def _key(record_id: str, field_name: str) -> str:
        return f"{record_id}::{field_name}"

    def salt_for(self, record_id: str, field_name: str) -> str:
        """Return the salt for a (record, field), minting and persisting one if absent.

        Deterministic per (record, field): asking twice yields the same salt, which is
        what lets a callback release months later rebuild the identical leaf.
        """
        k = self._key(record_id, field_name)
        if k not in self._store:
            self._store[k] = os.urandom(16).hex()
        return self._store[k]

    def export(self) -> str:
        """Serialise the salt store. Part of what Exit (§17.4) must carry on withdrawal."""
        return json.dumps(self._store, sort_keys=True)

    @classmethod
    def load(cls, blob: str) -> "SaltStore":
        s = cls()
        s._store = json.loads(blob)
        return s
