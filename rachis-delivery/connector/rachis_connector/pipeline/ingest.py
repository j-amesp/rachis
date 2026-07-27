"""
rachis_connector.pipeline.ingest
=================================

The full source-side pipeline, orchestrated: raw source JSON in, signed disclosure package
out. This is the "feed source-system data in as JSON and have it transformed into the
Expectation schema" requirement, end to end (thesis §9-§10).

Order of operations, each a thesis claim:
  1. map        — declarative transform to Expectation shape (§9.2)
  2. validate   — offline conformance against the Expectation (§8.4)
  3. label      — attach the source's asserted labels (§9, Appendix A.4)
  4. policy     — resolve dispositions; DROP withheld values here (§9.4); check derivations (§9.5)
  5. bind+sign  — Merkle root, one signature, persist binding for callbacks (§10.4, §12.1)
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models import Expectation, DisclosurePolicySpec
from ..crypto.interfaces import Signer
from ..crypto.merkle import Disposition, Label, FivePartHeader
from ..state.store import StateStore
from ..wire import DisclosurePackage
from .mapping import MappingEngine
from .policy import (
    disposition_for, validate_policy, policy_hash, CorrelationService, value_repr,
)
from .binder import Binder


class IngestError(Exception):
    pass


class IngestPipeline:
    def __init__(
        self,
        expectation: Expectation,
        mapping: MappingEngine,
        policy: DisclosurePolicySpec,
        signer: Signer,
        state: StateStore,
        source_identity: str,
        connector_measurement: str,
        correlation: Optional[CorrelationService] = None,
    ) -> None:
        self._exp = expectation
        self._mapping = mapping
        self._policy = policy
        self._binder = Binder(signer, state, connector_measurement)
        self._source_identity = source_identity
        self._measurement = connector_measurement
        self._correlation = correlation

        # policy must validate at construction — a policy that does not validate does not
        # run (thesis §9.5). Fail fast, at startup, not at first record.
        conflicts = validate_policy(policy)
        if conflicts:
            raise IngestError("disclosure policy does not validate:\n  " +
                              "\n  ".join(conflicts))

    def _labels_for(self, mapped: Dict[str, object]) -> Dict[str, Label]:
        pid = self._exp.marking.policy_id
        overrides = self._mapping.label_overrides()
        return {
            name: Label(policy_id=pid, classification=overrides.get(name, "UNMARKED"))
            for name in mapped
        }

    def _resolve(self, mapped: Dict[str, object],
                 labels: Dict[str, Label]) -> Dict[str, dict]:
        resolved: Dict[str, dict] = {}
        for name, value in mapped.items():
            disp = disposition_for(self._policy, name)
            spec: dict = {"disposition": disp.value, "label": labels[name]}
            if disp == Disposition.CLEAR:
                spec["value"] = value
                spec["value_repr"] = value_repr(value)
            elif disp == Disposition.HASH_ONLY:
                if self._correlation is None:
                    raise IngestError(
                        f"hash-only field {name} but correlation is disabled "
                        "(thesis §16.6). Enable it knowingly or change the disposition."
                    )
                spec["value_repr"] = value_repr(value)
                spec["correlation_digest"] = self._correlation.digest(value_repr(value))
            elif disp == Disposition.POINTER:
                spec["pointer"] = f"ptr:{name}:{_short(value)}"
            elif disp == Disposition.WITHHELD:
                # value dropped here — never enters the package (thesis §9.4)
                pass
            resolved[name] = spec
        return resolved

    def process(self, record_id: str, row: Dict[str, object],
                record_classification: str) -> DisclosurePackage:
        """Run one record through the whole pipeline."""
        mapped, _reasons = self._mapping.transform(row)

        problems = self._exp.validate_record(mapped)
        if problems:
            raise IngestError("record not conformant:\n  " + "\n  ".join(problems))

        labels = self._labels_for(mapped)
        resolved = self._resolve(mapped, labels)

        header = FivePartHeader(
            expectation=self._exp.version,
            mapping_hash=self._mapping.mapping_hash,
            policy_hash=policy_hash(self._policy),
            connector_measurement=self._measurement,
            source_identity=self._source_identity,
        )
        record_label = Label(policy_id=self._exp.marking.policy_id,
                             classification=record_classification)
        return self._binder.bind(record_id, header, record_label, resolved)


def _short(value: object) -> str:
    import hashlib
    return hashlib.sha384(str(value).encode()).hexdigest()[:16]
