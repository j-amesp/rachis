"""
RACHIS — Model contract.

The Expectation: the published, versioned exchange contract (thesis Chapter 8). Authored
by the federation's model authority, retrieved by the source, and — the property that
matters most (§8.4) — testable offline. Nothing here touches the network; an Expectation
is a value object you can load, read, and validate a record against, entirely locally.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Obligation(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    CONDITIONAL = "conditional"


class FieldSpec(BaseModel):
    """One field in an Expectation."""

    name: str
    type: str
    obligation: Obligation = Obligation.OPTIONAL
    pattern: Optional[str] = None
    enumeration: Optional[str] = None
    condition: Optional[str] = None  # human-readable; conditional obligations
    note: Optional[str] = None


class MarkingRequirement(BaseModel):
    """Which markings the federation will accept (thesis §8.1, ingress checks 5–6)."""

    policy_id: str
    field_labels: str = "required"   # every disclosed field must carry a label
    record_label: str = "required"


class Expectation(BaseModel):
    """A versioned exchange contract for one entity type.

    Proves (thesis §8.3): identity is split into a stable canonical URN and a versioned
    URN, with an explicit deprecation horizon, so a source conformant to version n is not
    broken by version n+1 (the compatibility commitment).
    """

    canonical: str
    version: str
    supersedes: Optional[str] = None
    deprecation_horizon: Optional[str] = None
    entity: str
    marking: MarkingRequirement
    fields: List[FieldSpec]
    core_field_budget: int = 40  # constitutional constraint (thesis §8.7)

    def field_map(self) -> Dict[str, FieldSpec]:
        return {f.name: f for f in self.fields}

    def required_fields(self) -> List[str]:
        return [f.name for f in self.fields if f.obligation == Obligation.REQUIRED]

    def validate_record(self, record: Dict[str, object]) -> List[str]:
        """Check a candidate record against this Expectation. Returns a list of problems.

        Offline (§8.4): this is pure computation. A source owner runs it inside their own
        estate with no connection to the platform and sees exactly what ingress will check.
        Empty list == conformant. This is ingress checks 3–4 (§11.1), available to the
        source before anything is sent.
        """
        problems: List[str] = []
        fmap = self.field_map()

        for name in self.required_fields():
            if name not in record or record[name] is None:
                problems.append(f"required field missing: {name}")

        for name, value in record.items():
            spec = fmap.get(name)
            if spec is None:
                # namespaced extensions are permitted (§8.7); a bare unknown field is not
                if ":" not in name:
                    problems.append(f"unknown field (and not a namespaced extension): {name}")
                continue
            if value is None:
                continue
            problems.extend(self._check_type(spec, value))

        return problems

    @staticmethod
    def _check_type(spec: FieldSpec, value: object) -> List[str]:
        import re
        out: List[str] = []
        t = spec.type
        if t == "string" and not isinstance(value, str):
            out.append(f"{spec.name}: expected string")
        elif t == "integer" and not isinstance(value, int):
            out.append(f"{spec.name}: expected integer")
        elif t == "decimal" and not isinstance(value, (int, float)):
            out.append(f"{spec.name}: expected decimal")
        elif t.startswith("array<") and not isinstance(value, list):
            out.append(f"{spec.name}: expected array")
        if spec.pattern and isinstance(value, str):
            if not re.match(spec.pattern, value):
                out.append(f"{spec.name}: does not match pattern {spec.pattern}")
        return out
