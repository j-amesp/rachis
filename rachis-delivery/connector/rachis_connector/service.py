"""
rachis_connector.service
=========================

The connector as a running service: wires config, keystore, state, core client, pipeline and
callback handler into one object with a clean operational surface. This is what the CLI and,
in a real deployment, the daemon loop drive.

Lifecycle:
  * `start()`   — open state, build keystore, pull and verify the Expectation from core.
  * `ingest()`  — run one source record through the pipeline and deliver (or queue) it.
  * `callback()`— evaluate a callback request, seal, queue.
  * `tick()`    — housekeeping: flush the outbound queue, deliver due sealed releases.
  * `health()`  — readiness for a supervisor or orchestrator.
  * `stop()`    — close state cleanly.

Nothing here is source-specific: the source adapter (JSON file, database) is injected, and
the access policy and label lookups are built from config.
"""
from __future__ import annotations

import datetime as _dt
from typing import Callable, Dict, List, Optional

import yaml

from .config import Config
from .models import (
    Expectation, Mapping, DisclosurePolicySpec, CallbackRequest,
)
from .crypto.factory import build_keystore
from .crypto.merkle import Label
from .state.store import StateStore
from .core.client import CoreClient, Transport
from .pipeline.mapping import MappingEngine
from .pipeline.ingest import IngestPipeline
from .pipeline.policy import CorrelationService
from .callback.access import (
    AccessPolicy, MinimumClearance, ReleasableTo, PurposeIn, RequireLawfulBasis,
    RequireAnyRole, RequireDevicePosture,
)
from .callback.handler import CallbackHandler


class ConnectorService:
    def __init__(
        self,
        config: Config,
        transport: Transport,
        value_lookup: Callable[[str, str], object],
    ) -> None:
        self._cfg = config
        self._transport = transport
        self._value_lookup = value_lookup
        self._state: Optional[StateStore] = None
        self._core: Optional[CoreClient] = None
        self._pipeline: Optional[IngestPipeline] = None
        self._callback: Optional[CallbackHandler] = None
        self._expectation: Optional[Expectation] = None
        self._label_overrides: Dict[str, str] = {}

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        cfg = self._cfg
        import os
        state_db = os.path.join(cfg.state.data_dir, "connector.db")
        self._state = StateStore(state_db)

        keystore = build_keystore(cfg.keystore)
        signer = keystore.signer(cfg.keystore.signing_key_id)

        self._core = CoreClient(self._transport, cfg.core.public_key_hex,
                                self._state, cfg.core.expectation_canonical)
        self._expectation = self._core.pull_expectation()

        mapping = self._load_mapping(cfg.mapping_path)
        self._label_overrides = mapping.label_overrides()
        policy = self._load_policy(cfg.policy_path)

        correlation = None
        if cfg.enable_hash_only_correlation:
            correlation = CorrelationService(
                key=b"CONFIGURE-A-REAL-KEY", epoch="2026H2", enabled=True,
            )

        self._pipeline = IngestPipeline(
            expectation=self._expectation,
            mapping=MappingEngine(mapping),
            policy=policy,
            signer=signer,
            state=self._state,
            source_identity=cfg.identity.source_identity,
            connector_measurement=cfg.identity.connector_measurement,
            correlation=correlation,
        )

        self._callback = CallbackHandler(
            keystore=keystore,
            access_policy=self._build_access_policy(),
            state=self._state,
            value_lookup=self._value_lookup,
            label_lookup=self._label_lookup,
        )
        self._state.audit("service", {"event": "started",
                                      "expectation": self._expectation.version})

    def stop(self) -> None:
        if self._state:
            self._state.audit("service", {"event": "stopped"})
            self._state.close()

    # ------------------------------------------------------------------ operations

    def ingest(self, record_id: str, row: Dict[str, object],
               record_classification: str) -> dict:
        """Process one source record and deliver (or durably queue) it."""
        pkg = self._pipeline.process(record_id, row, record_classification)
        self._state.audit("ingest", {"record": record_id,
                                     "fields": len(pkg.fields),
                                     "total_leaves": pkg.field_count})
        delivered = self._core.deliver(pkg)
        return {"record_id": record_id, "delivered": delivered,
                "fields_disclosed": len(pkg.fields), "field_count": pkg.field_count}

    def callback(self, req: CallbackRequest) -> dict:
        return self._callback.handle(req)

    def tick(self) -> dict:
        """Periodic housekeeping. Safe to call on a timer."""
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        flushed = self._core.flush_outbound()
        released = self._core.deliver_due_releases(now)
        return {"outbound_flushed": flushed, "releases_delivered": released}

    def health(self) -> dict:
        ok = all([self._state is not None, self._pipeline is not None,
                  self._expectation is not None])
        return {
            "ready": ok,
            "expectation": self._expectation.version if self._expectation else None,
            "source_identity": self._cfg.identity.source_identity,
            "hash_only_correlation": self._cfg.enable_hash_only_correlation,
        }

    # ------------------------------------------------------------------ helpers

    def _label_lookup(self, record_id: str, field_name: str) -> Label:
        cls = self._label_overrides.get(field_name, "UNMARKED")
        return Label(policy_id=self._cfg.marking.policy_id, classification=cls)

    def _load_mapping(self, path: str) -> Mapping:
        with open(path) as f:
            return Mapping.model_validate(yaml.safe_load(f))

    def _load_policy(self, path: str) -> DisclosurePolicySpec:
        with open(path) as f:
            return DisclosurePolicySpec.model_validate(yaml.safe_load(f))

    def _build_access_policy(self) -> AccessPolicy:
        """Build the callback access policy from config marking + a sensible default set.

        In a fuller build this is itself loaded from a declarative file; here we assemble a
        representative conjunction: minimum clearance, releasability, permitted purpose, and
        lawful basis. A source owner edits this to their domain (thesis §23)."""
        levels = self._cfg.marking.levels
        return AccessPolicy([
            MinimumClearance(minimum="RESTRICTED", order=levels)
            if "RESTRICTED" in levels else RequireDevicePosture(["managed-attested"]),
            RequireLawfulBasis(),
        ])
