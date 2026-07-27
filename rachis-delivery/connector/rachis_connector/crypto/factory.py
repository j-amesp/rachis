"""
rachis_connector.crypto.factory
================================

Builds the configured KeyStore. This is the one place the backend choice is made; everything
above `crypto.interfaces` is backend-agnostic (thesis §16.1).

For the software backend, the signing key is loaded from disk if present, or generated and
persisted on first run so the source identity is stable across restarts. For PKCS#11, the
key lives in the module and this factory only opens a session.
"""
from __future__ import annotations

import os

from ..config import KeystoreConfig
from .interfaces import KeyStore
from .software import SoftwareKeyStore


def build_keystore(cfg: KeystoreConfig) -> KeyStore:
    if cfg.backend == "software":
        ks = SoftwareKeyStore()
        _load_or_create_software_key(ks, cfg)
        return ks
    if cfg.backend == "pkcs11":
        from .pkcs11_stub import PKCS11KeyStore
        return PKCS11KeyStore(cfg.pkcs11_library, cfg.pkcs11_slot, cfg.pkcs11_pin)
    raise ValueError(f"unknown keystore backend: {cfg.backend}")


def _load_or_create_software_key(ks: SoftwareKeyStore, cfg: KeystoreConfig) -> None:
    """Software backend only: persist the signing key so the identity survives restart.

    A real HSM has no equivalent — the key is generated in-module and never touches disk.
    This function exists purely because the software store is in-process.
    """
    path = cfg.software_key_path
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            ks.import_signing_key(cfg.signing_key_id, f.read())
        return
    ks.generate_signing_key(cfg.signing_key_id)
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # 0600 — the key is sensitive even in the software build
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(ks.export_signing_key(cfg.signing_key_id))
