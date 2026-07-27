"""
rachis_connector.core.client
=============================

The connector's only contact with the core system, and it is entirely source-initiated
(thesis §8.2 — pulled, never pushed; no platform-initiated inbound). Two jobs:

  * pull and verify the Expectation. The connector fetches the signed Expectation from core,
    verifies the signature against core's configured public key, and caches it. A tampered or
    unsigned Expectation is refused (thesis §8.2-§8.3).

  * deliver disclosure packages, with an offline queue. If core is unreachable, packages sit
    in the durable outbound queue and are retried; the connector degrades rather than fails
    (thesis §22.3 disconnected operation).

Transport is mTLS 1.3 in production. Here the transport is abstracted behind `Transport` so
the pipeline is testable without a network, and a real HTTP(S) transport drops in.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Optional

from ..models import SignedExpectation, Expectation
from ..crypto.software import Ed25519Verifier
from ..crypto.interfaces import Verifier
from ..state.store import StateStore
from ..wire import DisclosurePackage


class Transport(ABC):
    """Abstract transport to core. Production impl is mTLS 1.3 HTTP; tests use an in-memory
    double. Source-initiated only — there is no inbound server here (thesis §8.2)."""

    @abstractmethod
    def get_expectation(self, canonical: str) -> dict: ...

    @abstractmethod
    def post_package(self, package: dict) -> bool: ...

    @abstractmethod
    def post_release(self, sealed: dict) -> bool: ...


class ExpectationVerificationError(Exception):
    pass


class CoreClient:
    def __init__(
        self,
        transport: Transport,
        core_public_key_hex: str,
        state: StateStore,
        expectation_canonical: str,
    ) -> None:
        self._transport = transport
        self._verifier: Verifier = Ed25519Verifier(bytes.fromhex(core_public_key_hex))
        self._state = state
        self._canonical = expectation_canonical
        self._cached: Optional[Expectation] = None

    # ------------------------------------------------------------------ expectation intake

    def pull_expectation(self) -> Expectation:
        """Fetch, verify, cache. Refuses an Expectation core did not sign (thesis §8.2)."""
        raw = self._transport.get_expectation(self._canonical)
        signed = SignedExpectation.model_validate(raw)

        if not self._verifier.verify(signed.signing_bytes(), bytes.fromhex(signed.signature_hex)):
            self._state.audit("expectation", {"canonical": self._canonical,
                                              "result": "signature-invalid"})
            raise ExpectationVerificationError(
                "Expectation signature does not verify against core's public key. Refused."
            )

        self._cached = signed.expectation
        self._state.audit("expectation", {
            "canonical": self._canonical, "version": signed.expectation.version,
            "result": "accepted",
        })
        return signed.expectation

    @property
    def expectation(self) -> Optional[Expectation]:
        return self._cached

    # ------------------------------------------------------------------ delivery

    def deliver(self, package: DisclosurePackage) -> bool:
        """Deliver a package, queueing durably first so nothing is lost if core is down.

        Returns True if delivered now, False if queued for retry. Either way the package is
        persisted before any network attempt (thesis §22.3).
        """
        pkg_json = package.model_dump()
        oid = self._state.enqueue_outbound(package.record_id, json.dumps(pkg_json))
        return self._try_deliver_one(oid, pkg_json)

    def flush_outbound(self, limit: int = 100) -> int:
        """Retry queued packages. Returns how many were delivered this pass."""
        delivered = 0
        for item in self._state.pending_outbound(limit):
            if self._try_deliver_one(item["id"], item["package"]):
                delivered += 1
        return delivered

    def _try_deliver_one(self, outbound_id: int, pkg_json: dict) -> bool:
        self._state.record_attempt(outbound_id)
        try:
            ok = self._transport.post_package(pkg_json)
        except Exception as e:
            self._state.audit("delivery", {"id": outbound_id, "result": "error",
                                           "detail": str(e)})
            return False
        if ok:
            self._state.mark_delivered(outbound_id)
            self._state.audit("delivery", {"id": outbound_id, "result": "delivered"})
        return ok

    # ------------------------------------------------------------------ sealed releases

    def deliver_due_releases(self, now_iso: str) -> int:
        """Deliver time-bound sealed releases whose window has opened (thesis §12.1).

        Core triggers the actual disclosure to the requester; the connector's job is to hand
        core the sealed object once the window opens. Delivered count returned.
        """
        delivered = 0
        for cb in self._state.due_callbacks(now_iso):
            try:
                ok = self._transport.post_release(cb["sealed"])
            except Exception:
                ok = False
            if ok:
                self._state.mark_callback_delivered(cb["id"])
                delivered += 1
        return delivered
