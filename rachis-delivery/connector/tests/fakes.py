"""
In-memory transport double for tests. Simulates core: signs an Expectation with a known key,
accepts packages, accepts sealed releases. Lets the whole connector run without a network.
"""
from __future__ import annotations

import json
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from rachis_connector.core.client import Transport
from rachis_connector.models import Expectation, SignedExpectation


class FakeCore(Transport):
    """A stand-in core system for tests."""

    def __init__(self, expectation: Expectation) -> None:
        self._core_key = Ed25519PrivateKey.generate()
        self._expectation = expectation
        self.received_packages: List[dict] = []
        self.received_releases: List[dict] = []
        self.reachable = True

    def core_public_key_hex(self) -> str:
        return self._core_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def get_expectation(self, canonical: str) -> dict:
        signed = SignedExpectation(
            expectation=self._expectation,
            algorithm="Ed25519",
            signature_hex=self._core_key.sign(
                self._expectation.model_dump_json().encode()
            ).hex(),
        )
        return signed.model_dump()

    def sign_tampered_expectation(self, other: Expectation) -> dict:
        """Return an Expectation whose signature does not match its body (for a negative test)."""
        signed = SignedExpectation(
            expectation=other,
            algorithm="Ed25519",
            signature_hex=self._core_key.sign(b"different bytes").hex(),
        )
        return signed.model_dump()

    def post_package(self, package: dict) -> bool:
        if not self.reachable:
            raise ConnectionError("core unreachable")
        self.received_packages.append(package)
        return True

    def post_release(self, sealed: dict) -> bool:
        if not self.reachable:
            return False
        self.received_releases.append(sealed)
        return True
