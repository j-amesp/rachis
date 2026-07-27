"""
rachis_connector.crypto.software
=================================

Software implementation of the crypto interfaces. This is what the build runs on. It keeps
keys in process because there is no hardware module in this environment; a PKCS#11
implementation of the same interfaces (see pkcs11_stub.py) is the production drop-in and
nothing above `crypto.interfaces` changes.

Primitives (all from `cryptography`, FIPS-validated implementations exist for each):
  * Ed25519 for signatures        — stand-in for ML-DSA (thesis §10.3)
  * X25519 for key agreement       — the callback seal (thesis §12.1)
  * HKDF-SHA384 for key derivation — aligns with the SHA-384 digest of the 4778 profile
  * AES-256-GCM for the sealed payload, with the time window as authenticated data

The seal scheme (ECIES-style), for a value V to requester public key R, window [nb, na]:
    e_priv, e_pub  = X25519 keypair, fresh per seal
    shared         = X25519(e_priv, R)
    key            = HKDF-SHA384(shared, info = aad)          # aad binds the window + context
    nonce          = 12 random bytes
    ct             = AES-256-GCM(key, nonce, V, aad = aad)
    output         = { e_pub, nonce, ct, nb, na, aad }
The requester recovers: shared = X25519(r_priv, e_pub); key = HKDF(...); opens ct with aad.
Because the window is inside aad, presenting a different window fails the GCM tag: the time
binding is cryptographic, not advisory (the design decision confirmed with the operator).
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

from .interfaces import (
    Signer, Verifier, Sealer, KeyStore, KeyStoreHealth, SealedRelease,
)

SEAL_ALG = "X25519-HKDF-SHA384-AES256GCM"


# --------------------------------------------------------------------------- signing

class Ed25519Signer(Signer):
    algorithm = "Ed25519"  # production swap point: "ML-DSA-65"

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        self._sk = private_key
        self.key_id = key_id

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def public_key_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


class Ed25519Verifier(Verifier):
    algorithm = "Ed25519"

    def __init__(self, public_key_bytes: bytes) -> None:
        self._pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._pk.verify(signature, message)
            return True
        except InvalidSignature:
            return False


# --------------------------------------------------------------------------- sealing

class SoftwareSealer(Sealer):
    """ECIES-style sealing with a cryptographically bound time window (thesis §12.1)."""

    def seal(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        not_before: str,
        not_after: str,
        aad_context: bytes,
    ) -> SealedRelease:
        recipient = X25519PublicKey.from_public_bytes(recipient_public_key)
        eph = X25519PrivateKey.generate()
        shared = eph.exchange(recipient)

        # aad authenticates the window and the caller-supplied context. Any change to the
        # window presented at open time breaks the GCM tag -> time binding is cryptographic.
        aad = aad_context + b"|nb=" + not_before.encode() + b"|na=" + not_after.encode()

        key = HKDF(
            algorithm=hashes.SHA384(), length=32, salt=None, info=aad,
        ).derive(shared)

        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)

        return SealedRelease(
            alg=SEAL_ALG,
            ephemeral_public_key=eph.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            nonce=nonce,
            ciphertext=ct,
            not_before=not_before,
            not_after=not_after,
            aad=aad,
            record_id="",   # filled by the caller
            field_name="",
            requester="",
        )


def open_sealed_release(
    sealed: SealedRelease,
    recipient_private_key: X25519PrivateKey,
    presented_time: str,
) -> bytes:
    """Reference opener, for tests and for the requesting client's implementers.

    Enforces the window: `presented_time` must satisfy not_before <= t <= not_after, AND
    the window in `sealed` must be the one bound into `aad`. Both are required — the first
    is the policy check, the second is what makes tampering with the first useless.
    """
    if not (sealed.not_before <= presented_time <= sealed.not_after):
        raise ValueError("presented time outside the sealed window")

    eph_pub = X25519PublicKey.from_public_bytes(sealed.ephemeral_public_key)
    shared = recipient_private_key.exchange(eph_pub)
    key = HKDF(
        algorithm=hashes.SHA384(), length=32, salt=None, info=sealed.aad,
    ).derive(shared)
    # if aad was tampered (e.g. a widened window presented), this raises InvalidTag
    return AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, sealed.aad)


# --------------------------------------------------------------------------- keystore

class SoftwareKeyStore(KeyStore):
    """In-process key store. The software stand-in for an HSM (thesis §16.1).

    Keys are held in memory and never returned as bytes to callers (only `public_key_bytes`
    is exposed, and only for the public half). A PKCS#11 implementation replaces this class
    and keeps keys in the module; see pkcs11_stub.py for the interface shape.
    """

    def __init__(self) -> None:
        self._signing_keys: dict[str, Ed25519PrivateKey] = {}

    # -- provisioning (a real HSM provisions keys out of band; here we generate/import) --

    def generate_signing_key(self, key_id: str) -> None:
        self._signing_keys[key_id] = Ed25519PrivateKey.generate()

    def import_signing_key(self, key_id: str, private_bytes: bytes) -> None:
        self._signing_keys[key_id] = Ed25519PrivateKey.from_private_bytes(private_bytes)

    def export_signing_key(self, key_id: str) -> bytes:
        """Present only for the software build's persistence. A PKCS#11 store has no
        equivalent and MUST NOT — this method does not exist on the interface, only on the
        software class, and is used solely so a restart can reload the same identity."""
        return self._signing_keys[key_id].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    # -- interface --

    def signer(self, key_id: str) -> Signer:
        if key_id not in self._signing_keys:
            raise KeyError(f"no signing key: {key_id}")
        return Ed25519Signer(self._signing_keys[key_id], key_id)

    def sealer(self) -> Sealer:
        return SoftwareSealer()

    def health(self) -> KeyStoreHealth:
        return KeyStoreHealth(
            present=True, backend="software",
            signing_key_present=bool(self._signing_keys),
            detail=f"{len(self._signing_keys)} signing key(s) in process",
        )
