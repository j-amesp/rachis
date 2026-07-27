"""
RACHIS — Connect contract.

The source-side connector. Retrieves the Expectation, applies a *declarative* mapping,
runs the offline validator, and hands a mapped record to Policy and Provenance. Everything
here runs inside the source estate, under source change control (thesis Chapter 8, §9.2).

The mapping is configuration, not code (thesis §9.2): transforms are named functions from a
published library, so a reviewer reads declarations, not a program. That constraint is what
keeps the connector small enough to audit and keeps mappings reusable across every
organisation running the same source product (§8.6).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .model import Expectation
from .labels import Label
from .policy import (
    DisclosurePolicy, DerivationConstraint, Granularity, apply_policy,
    CorrelationService,
)
from .provenance import Binder, FivePartHeader, DisclosurePackage
from .trust import Signer, SaltStore


# --------------------------------------------------------------------------- transform library

# The published standard library (thesis §9.2). A mapping may only name these; it cannot
# supply arbitrary logic. Adding a transform is a change to the *standard*, reusable by all.

TransformFn = Callable[[object], object]

def _trim(v): return v.strip() if isinstance(v, str) else v
def _upper(v): return v.upper() if isinstance(v, str) else v
def _prefix(pfx): return lambda v: f"{pfx}{v}" if v is not None else v
def _split(sep): return lambda v: [p.strip() for p in v.split(sep) if p.strip()] if isinstance(v, str) else v
def _codelist(table: Dict[str, str]): return lambda v: table.get(v, None) if v is not None else v

TRANSFORMS: Dict[str, Callable[..., TransformFn]] = {
    "trim": lambda: _trim,
    "upper": lambda: _upper,
    "prefix": _prefix,
    "split": _split,
    "codelist": _codelist,
}


@dataclass
class FieldMapping:
    """How one Expectation field is produced from a source field."""
    target: str
    source: Optional[str] = None
    transforms: List[TransformFn] = field(default_factory=list)
    on_unmapped: str = "error"  # or "omit_field_with_reason"

    def apply(self, row: Dict[str, object]) -> tuple[bool, object, Optional[str]]:
        """Return (present, value, reason_if_omitted)."""
        val = row.get(self.source) if self.source else None
        for t in self.transforms:
            val = t(val)
            if val is None and self.on_unmapped == "omit_field_with_reason":
                return False, None, f"{self.target}: unmapped source value for {self.source}"
        return True, val, None


@dataclass
class Mapping:
    """A declarative mapping from a source schema to an Expectation (thesis §9.2)."""
    mapping_id: str
    expectation: str
    fields: List[FieldMapping]
    label_default_source: Optional[str] = None
    label_default_transform: Optional[TransformFn] = None
    label_overrides: Dict[str, str] = field(default_factory=dict)  # field -> classification

    def mapping_hash(self) -> str:
        blob = json.dumps(
            {"id": self.mapping_id, "expectation": self.expectation,
             "fields": sorted(fm.target for fm in self.fields)},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return "sha384:" + hashlib.sha384(blob).hexdigest()

    def transform(self, row: Dict[str, object]) -> tuple[Dict[str, object], List[str]]:
        """Apply the mapping to one source row. Returns (mapped_record, omission_reasons)."""
        out: Dict[str, object] = {}
        reasons: List[str] = []
        for fm in self.fields:
            present, value, reason = fm.apply(row)
            if present:
                out[fm.target] = value
            elif reason:
                reasons.append(reason)
        return out, reasons


# --------------------------------------------------------------------------- validator

@dataclass
class ValidatorReport:
    conformant: bool
    schema_problems: List[str]
    proposed_derivations: List[DerivationConstraint]
    disclosure_preview: Dict[str, str]  # field -> disposition


class Validator:
    """The offline validator (thesis §8.4, §9.6).

    Runs with no network connection. Checks a mapping+policy against an Expectation, and
    proposes derivation constraints the source owner may not have thought of. The three
    modes of §9.6 (schema, library, statistical) are represented here by schema + library;
    the statistical mode is noted as a stub.

    Proves (thesis §8.4): a source owner can see exactly what would leave, before anything
    leaves, entirely locally.
    """

    #: library of common derivations (thesis §9.6 "library-matched"). A community artefact.
    LIBRARY = [
        # (target, {deriving set}, granularity, protects_at)
        ("lastKnownPosition.lat", {"lastPortCall.locode", "lastPortCall.departedAt"},
         Granularity.COARSE, Granularity.EXACT),
        ("dateOfBirth", {"approximateAge", "recordedAt"}, Granularity.COARSE, Granularity.EXACT),
    ]

    def run(
        self,
        expectation: Expectation,
        mapping: Mapping,
        policy: DisclosurePolicy,
        sample: Optional[List[Dict[str, object]]] = None,
    ) -> ValidatorReport:
        schema_problems: List[str] = []
        # map a sample row (or an empty probe) and check conformance offline
        if sample:
            for row in sample:
                mapped, _ = mapping.transform(row)
                schema_problems.extend(expectation.validate_record(mapped))

        proposed = self._propose_derivations(mapping, policy)
        preview = {fm.target: policy.disposition_for(fm.target).value for fm in mapping.fields}

        conformant = not schema_problems and not policy.validate()
        return ValidatorReport(conformant, schema_problems, proposed, preview)

    def _propose_derivations(self, mapping: Mapping,
                             policy: DisclosurePolicy) -> List[DerivationConstraint]:
        present = {fm.target for fm in mapping.fields}
        proposed: List[DerivationConstraint] = []
        for target, deriving, gran, protects in self.LIBRARY:
            if target in present and deriving <= present:
                already = any(d.field == target and set(d.derivable_from) == deriving
                              for d in policy.derivations)
                if not already:
                    proposed.append(DerivationConstraint(
                        field=target, derivable_from=sorted(deriving),
                        granularity=gran, accepted=False, protects_at=protects,
                        rationale="library-matched; review before accepting",
                    ))
        # statistical mode (thesis §9.6): STUB — would run association measures on `sample`.
        return proposed


# --------------------------------------------------------------------------- connector

class Connector:
    """Ties mapping, policy, labelling and binding together at the source (thesis §11 upstream).

    A real connector runs in an attested TEE (§16.3); here `measurement` is a recorded
    constant the platform checks against an allow-list (ingress check 2).
    """

    def __init__(
        self,
        expectation: Expectation,
        mapping: Mapping,
        policy: DisclosurePolicy,
        signer: Signer,
        salt_store: SaltStore,
        source_identity: str,
        measurement: str,
        correlation: Optional[CorrelationService] = None,
    ) -> None:
        self.expectation = expectation
        self.mapping = mapping
        self.policy = policy
        self.source_identity = source_identity
        self.measurement = measurement
        self._binder = Binder(signer, salt_store, measurement)
        self._correlation = correlation

    def _labels_for(self, mapped: Dict[str, object]) -> Dict[str, Label]:
        """Derive each field's label from the mapping's label rules (thesis Appendix A.4)."""
        pid = self.expectation.marking.policy_id
        out: Dict[str, Label] = {}
        for name in mapped:
            cls = self.mapping.label_overrides.get(name, "UNMARKED")
            out[name] = Label(policy_id=pid, classification=cls)
        return out

    def build_package(
        self, record_id: str, row: Dict[str, object], record_classification: str,
    ) -> DisclosurePackage:
        """The full source-side pipeline: map -> label -> apply policy -> bind & sign.

        Proves the end-to-end §9–§10 loop. Withheld fields are gone by the time we bind.
        """
        mapped, _reasons = self.mapping.transform(row)

        problems = self.expectation.validate_record(mapped)
        if problems:
            raise ValueError("record not conformant:\n  " + "\n  ".join(problems))

        labels = self._labels_for(mapped)
        resolved = apply_policy(self.policy, mapped, labels, correlation=self._correlation)

        header = FivePartHeader(
            expectation=self.expectation.version,
            mapping_hash=self.mapping.mapping_hash(),
            policy_hash=self.policy.policy_hash(),
            connector_measurement=self.measurement,
            source_identity=self.source_identity,
        )
        record_label = Label(policy_id=self.expectation.marking.policy_id,
                             classification=record_classification)
        return self._binder.bind(record_id, header, record_label, resolved)
