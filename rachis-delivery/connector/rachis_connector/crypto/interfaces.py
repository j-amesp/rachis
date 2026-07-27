"""
rachis_connector.crypto.interfaces
==================================

The cryptographic boundary of the connector, expressed as interfaces so that the
production HSM is a drop-in and nothing above this layer knows or cares which
implementation is in use.

Design commitments (thesis §16.1, §16.7):

  * Signing keys never leave the HSM. The `KeyStore` interface exposes *operations*
    (sign, derive) and never returns private key material. The software implementation
    keeps keys in-process only because there is no hardware here; a PKCS#11 implementation
    of the same interface keeps them in the module. Code above this file is identical
    either way.

  * The connector holds no key that could decrypt content it was not given, and no key
    that could forge core's Expectation signature. It holds its own signing key (source
    identity) and it holds *public* keys for core and for callback requesters.

Post-quantum posture (thesis §10.3): signing is abstracted behind `Signer`. This build
ships classical Ed25519 (`algorithm = "Ed25519"`), which runs everywhere and needs no
liboqs. A production build swaps in an ML-DSA `Signer` and an SLH-DSA `Signer` for archive,
and may run them in hybrid with the classical one. The wire format already carries an
`algorithm` field so packages are shaped for the swap.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


class Signer(ABC):
    """Produces signatures. Only ever obtained from a KeyStore; never constructed with
    raw private material by calling code."""

    #: algorithm identifier carried in the wire format (e.g. "Ed25519", "ML-DSA-65")
    algorithm: str
    #: opaque key handle/label, meaningful to the KeyStore implementation
    key_id: str

    @abstractmethod
    def sign(self, message: bytes) -> bytes: ...

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """The public half, for distribution to core as the source's verification anchor."""


class Verifier(ABC):
    """Verifies signatures against a known public key. Holds no private material."""

    algorithm: str

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool: ...


class Sealer(ABC):
    """Seals a value to a recipient's public key with a cryptographically bound time window.

    This is the callback release primitive (thesis §12.1). The connector seals a withheld
    value *to the requester's public key* and *to a time window*, then hands the sealed
    object to core. Core cannot open it (wrong key). The requester cannot open it outside
    the window (the window is bound into the AEAD associated data, so tampering with the
    stated window fails authentication). The connector discards the plaintext after sealing.
    """

    @abstractmethod
    def seal(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        not_before: str,
        not_after: str,
        aad_context: bytes,
    ) -> "SealedRelease": ...


class KeyStore(ABC):
    """The HSM boundary. Vends Signers and performs key-agreement operations without ever
    exposing private key bytes.

    The production implementation is a thin PKCS#11 wrapper (see crypto/pkcs11_stub.py for
    the drop-in shape). The software implementation (crypto/software.py) is functionally
    identical from here up, and is what this build runs on.
    """

    @abstractmethod
    def signer(self, key_id: str) -> Signer:
        """Return a Signer bound to the named key. The key stays in the store."""

    @abstractmethod
    def sealer(self) -> Sealer:
        """Return a Sealer that performs ECDH against an ephemeral key it generates per seal."""

    @abstractmethod
    def health(self) -> "KeyStoreHealth":
        """Report whether the store is present and its keys are usable. Used by readiness."""


@dataclass
class KeyStoreHealth:
    present: bool
    backend: str            # "software" | "pkcs11" | ...
    signing_key_present: bool
    detail: str = ""


@dataclass
class SealedRelease:
    """A value sealed to a requester and a time window (thesis §12.1).

    Everything here is safe to hand to core. `ciphertext` opens only with the requester's
    private key, and only when the presented time falls within [not_before, not_after],
    because the window is authenticated in `aad`. `ephemeral_public_key` is the connector's
    per-seal ECDH public half.
    """
    alg: str                        # e.g. "X25519-HKDF-SHA384-AES256GCM"
    ephemeral_public_key: bytes
    nonce: bytes
    ciphertext: bytes               # includes the GCM tag
    not_before: str
    not_after: str
    aad: bytes                      # the authenticated context, incl. the window
    record_id: str
    field_name: str
    requester: str
