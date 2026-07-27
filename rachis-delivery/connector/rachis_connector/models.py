"""
rachis_connector.models
========================

The value objects the connector operates on: the Expectation received from core, the
mapping and disclosure policy authored at the source, and the wire form of a disclosure
package. All Pydantic v2, so they validate on construction and (de)serialise to JSON for
free — which matters because the Expectation arrives as signed JSON from core and the
package leaves as JSON over the wire.

Thesis references: Expectation §8; mapping/policy §9; package §10.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from .crypto.merkle import Disposition


# --------------------------------------------------------------------------- Expectation

class Obligation(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    CONDITIONAL = "conditional"


class FieldSpec(BaseModel):
    name: str
    type: str
    obligation: Obligation = Obligation.OPTIONAL
    pattern: Optional[str] = None
    enumeration: Optional[str] = None
    condition: Optional[str] = None
    note: Optional[str] = None


class MarkingRequirement(BaseModel):
    policy_id: str
    field_labels: str = "required"
    record_label: str = "required"


class Expectation(BaseModel):
    canonical: str
    version: str
    supersedes: Optional[str] = None
    deprecation_horizon: Optional[str] = None
    entity: str
    marking: MarkingRequirement
    fields: List[FieldSpec]
    core_field_budget: int = 40

    def field_map(self) -> Dict[str, FieldSpec]:
        return {f.name: f for f in self.fields}

    def required_fields(self) -> List[str]:
        return [f.name for f in self.fields if f.obligation == Obligation.REQUIRED]

    def validate_record(self, record: Dict[str, object]) -> List[str]:
        """Offline conformance check (thesis §8.4). Pure; no network."""
        import re
        problems: List[str] = []
        fmap = self.field_map()
        for name in self.required_fields():
            if record.get(name) is None:
                problems.append(f"required field missing: {name}")
        for name, value in record.items():
            spec = fmap.get(name)
            if spec is None:
                if ":" not in name:
                    problems.append(f"unknown field (not a namespaced extension): {name}")
                continue
            if value is None:
                continue
            t = spec.type
            if t == "string" and not isinstance(value, str):
                problems.append(f"{name}: expected string")
            elif t == "integer" and not isinstance(value, int):
                problems.append(f"{name}: expected integer")
            elif t == "decimal" and not isinstance(value, (int, float)):
                problems.append(f"{name}: expected decimal")
            elif t.startswith("array<") and not isinstance(value, list):
                problems.append(f"{name}: expected array")
            if spec.pattern and isinstance(value, str) and not re.match(spec.pattern, value):
                problems.append(f"{name}: does not match {spec.pattern}")
        return problems


class SignedExpectation(BaseModel):
    """An Expectation as it arrives from core: the JSON plus core's signature over it.

    The connector verifies `signature` against core's public key before caching (thesis
    §8.2 — pulled, verified, never pushed). `algorithm` records how it was signed.
    """
    expectation: Expectation
    algorithm: str
    signature_hex: str

    def signing_bytes(self) -> bytes:
        # canonical JSON of the expectation only; deterministic across round-trips
        return self.expectation.model_dump_json().encode()


# --------------------------------------------------------------------------- mapping / policy

class Granularity(str, Enum):
    EXACT = "exact"
    FINE = "fine"
    COARSE = "coarse"

    def defeats(self, protected_at: "Granularity") -> bool:
        order = {Granularity.COARSE: 0, Granularity.FINE: 1, Granularity.EXACT: 2}
        return order[self] >= order[protected_at]


class DerivationConstraint(BaseModel):
    field: str
    derivable_from: List[str]
    granularity: Granularity
    accepted: bool
    protects_at: Granularity = Granularity.EXACT
    rationale: str = ""


class FieldMappingSpec(BaseModel):
    """Declarative field mapping (thesis §9.2). `transforms` names library functions with
    optional arguments; no arbitrary code."""
    target: str
    source: Optional[str] = None
    transforms: List[dict] = Field(default_factory=list)   # [{"fn": "prefix", "arg": "IMO"}]
    on_unmapped: str = "error"
    classification: str = "UNMARKED"


class Mapping(BaseModel):
    mapping_id: str
    expectation: str
    source_table: Optional[str] = None
    fields: List[FieldMappingSpec]

    def label_overrides(self) -> Dict[str, str]:
        return {fm.target: fm.classification for fm in self.fields}


class DisclosurePolicySpec(BaseModel):
    policy_id: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    default: Disposition = Disposition.WITHHELD
    dispositions: Dict[str, Disposition] = Field(default_factory=dict)
    derivations: List[DerivationConstraint] = Field(default_factory=list)


# --------------------------------------------------------------------------- callback

class CallbackRequest(BaseModel):
    """A request from core to resolve a withheld/pointer field (thesis §12.1).

    Carries the requester's identity and attributes for RBAC/ABAC evaluation, the
    requester's public key to seal to, and the requested validity window.
    """
    record_id: str
    field_name: str
    pointer: str
    requester: str
    organisation: str
    nationality: str
    clearance: str
    roles: List[str] = Field(default_factory=list)
    purpose: str
    lawful_basis: Optional[str] = None
    device_posture: str = "unknown"
    recipient_public_key_hex: str          # X25519 public key to seal to
    not_before: str                        # ISO 8601; the requested window
    not_after: str


class CallbackDecision(str, Enum):
    RELEASE = "release"
    DENY = "deny"
