"""
rachis_connector.crypto.pkcs11_stub
====================================

The shape of the production HSM implementation, provided so that whoever deploys this
connector can see exactly where the real module plugs in. It is a STUB: it raises on use.
It is not wired into the default configuration.

To go to production against a real HSM, an implementer:
  1. installs a PKCS#11 provider for their module (e.g. a Thales, Entrust, or YubiHSM lib);
  2. completes the methods below using `python-pkcs11` or the vendor SDK;
  3. sets `keystore.backend: pkcs11` in config.

Nothing above `crypto.interfaces` changes. The signing key is generated inside the module
and never leaves it; `sign` is a session operation; `sealer` performs the X25519 agreement
either in-module (if the HSM supports it) or with an in-module static key and in-process
ephemeral, depending on the module's capabilities.

The point of shipping this stub rather than omitting it: the thesis claim (§16.1) is that
signing keys never leave custody. That claim is only credible if the seam where a real HSM
attaches is visible and obviously narrow. It is this file.
"""
from __future__ import annotations

from .interfaces import Signer, Sealer, KeyStore, KeyStoreHealth


_NOT_IMPLEMENTED = (
    "PKCS#11 backend is a stub. Provide a module library and complete "
    "rachis_connector/crypto/pkcs11_stub.py, then set keystore.backend: pkcs11."
)


class PKCS11Signer(Signer):
    algorithm = "Ed25519"  # or "ML-DSA-65" once the module supports it

    def __init__(self, session, key_label: str) -> None:
        self._session = session
        self.key_id = key_label

    def sign(self, message: bytes) -> bytes:
        # session.sign(private_key_handle, message)  -- key never leaves the module
        raise NotImplementedError(_NOT_IMPLEMENTED)

    def public_key_bytes(self) -> bytes:
        raise NotImplementedError(_NOT_IMPLEMENTED)


class PKCS11Sealer(Sealer):
    def seal(self, plaintext, recipient_public_key, not_before, not_after, aad_context):
        # derive shared secret via module ECDH, HKDF + AES-GCM as in software.py
        raise NotImplementedError(_NOT_IMPLEMENTED)


class PKCS11KeyStore(KeyStore):
    """Drop-in for SoftwareKeyStore. Completing the three methods below is the whole task."""

    def __init__(self, library_path: str, slot: int, pin: str) -> None:
        self._library_path = library_path
        self._slot = slot
        self._pin = pin  # in production, sourced from the module's own auth, not config
        # self._session = pkcs11.lib(library_path).get_slot(slot).open(user_pin=pin)

    def signer(self, key_id: str) -> Signer:
        raise NotImplementedError(_NOT_IMPLEMENTED)

    def sealer(self) -> Sealer:
        raise NotImplementedError(_NOT_IMPLEMENTED)

    def health(self) -> KeyStoreHealth:
        return KeyStoreHealth(
            present=False, backend="pkcs11", signing_key_present=False,
            detail="stub — not implemented",
        )
