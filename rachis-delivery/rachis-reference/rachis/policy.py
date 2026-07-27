"""
RACHIS — Policy contract.

The disclosure decision: per-field dispositions plus derivation constraints (thesis
§9.3–9.5). Two responsibilities:

  1. Resolve each field to clear / hash-only / pointer / withheld, dropping withheld values
     before they enter the pipeline (§9.4).
  2. Enforce derivation constraints — secondary suppression — so a withheld field cannot be
     reconstructed from released ones (§9.5). Constraints carry a *granularity* (Appendix
     A.11 refinement): a coarse derivation does not defeat a fine protection.

The default is withheld (§9.3): a field with no declared disposition does not cross.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from .provenance import Disposition
from .labels import Label


class Granularity(str, Enum):
    """How precisely one field derives another. A constraint binds only when the derivation
    is at least as precise as the protection it threatens (thesis Appendix A.11)."""
    EXACT = "exact"
    FINE = "fine"        # e.g. within 1 km / 1 day
    COARSE = "coarse"    # e.g. within 200 km / 1 year

    def defeats(self, protected_at: "Granularity") -> bool:
        order = {Granularity.COARSE: 0, Granularity.FINE: 1, Granularity.EXACT: 2}
        return order[self] >= order[protected_at]


@dataclass
class DerivationConstraint:
    """`field` is derivable from `derivable_from` at `granularity`.

    If accepted is False and the deriving set is released more permissively than `field`,
    the policy does not validate until the source resolves it (thesis §9.5).
    """
    field: str
    derivable_from: List[str]
    granularity: Granularity
    accepted: bool
    protects_at: Granularity = Granularity.EXACT
    rationale: str = ""


@dataclass
class DisclosurePolicy:
    """A signed, per-field release decision (thesis §9.1, §9.5). Separate artefact from the
    mapping, approved by the information asset owner, not the data team."""
    policy_id: str
    dispositions: Dict[str, Disposition]
    derivations: List[DerivationConstraint] = field(default_factory=list)
    default: Disposition = Disposition.WITHHELD

    def disposition_for(self, field_name: str) -> Disposition:
        return self.dispositions.get(field_name, self.default)

    def policy_hash(self) -> str:
        blob = json.dumps(
            {
                "policy_id": self.policy_id,
                "dispositions": {k: v.value for k, v in sorted(self.dispositions.items())},
                "default": self.default.value,
                "derivations": [
                    {"f": d.field, "from": sorted(d.derivable_from),
                     "g": d.granularity.value, "acc": d.accepted}
                    for d in self.derivations
                ],
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return "sha384:" + hashlib.sha384(blob).hexdigest()

    # ------------------------------------------------------------------ validation

    def validate(self) -> List[str]:
        """Return unresolved derivation conflicts. Empty == the policy may run (thesis §9.5).

        A conflict exists when a field is withheld (or pointer) but every member of a
        deriving set is released more permissively, at a granularity that defeats the
        field's protection, and the source has not explicitly accepted the leak.
        """
        problems: List[str] = []
        permissiveness = {
            Disposition.WITHHELD: 0,
            Disposition.POINTER: 1,
            Disposition.HASH_ONLY: 2,
            Disposition.CLEAR: 3,
        }
        for d in self.derivations:
            if d.accepted:
                continue
            target = self.disposition_for(d.field)
            if not d.granularity.defeats(d.protects_at):
                continue  # too coarse to matter
            deriving = [self.disposition_for(f) for f in d.derivable_from]
            if deriving and min(permissiveness[x] for x in deriving) > permissiveness[target]:
                problems.append(
                    f"derivation conflict: {d.field} ({target.value}) is derivable at "
                    f"{d.granularity.value} from {d.derivable_from}, which are released more "
                    f"permissively. Demote a member or accept the derivation."
                )
        return problems


# --------------------------------------------------------------------------- correlation

class CorrelationService:
    """Keyed digest for hash-only disposition (thesis §9.3, §16.6).

    STUB — thesis §16.6 resolution not implemented. Production selects per field by value-
    space entropy: a federation key (tier A) where enumeration is infeasible, and a
    THRESHOLD OBLIVIOUS PRF split t-of-m across sovereign members (tier B) where it is not.
    Here we use a single HMAC key as a stand-in so hash-only correlation can be demonstrated
    and tested. The `epoch` is carried so rotation works without a format change.

    Do not ship this as-is: a single shared key permits offline enumeration of low-entropy
    values, which is exactly the attack tier B exists to prevent.
    """

    def __init__(self, key: bytes, epoch: str = "demo-2026H2") -> None:
        self._key = key
        self.epoch = epoch

    def digest(self, value: str) -> str:
        mac = hmac.new(self._key, value.encode(), hashlib.sha384).hexdigest()
        return f"hmac-sha384:{self.epoch}:{mac}"


# --------------------------------------------------------------------------- application

def apply_policy(
    policy: DisclosurePolicy,
    record: Dict[str, object],
    labels: Dict[str, Label],
    correlation: Optional[CorrelationService] = None,
    pointer_fn: Optional[Callable[[str, object], str]] = None,
) -> Dict[str, dict]:
    """Resolve a mapped record against the disclosure policy.

    Returns a dict of field -> resolution spec ready for the Binder. Proves (thesis §9.4):
    withheld fields are dropped here, before the pipeline — their value never appears in
    the output, not even encrypted.

    Raises if the policy has unresolved derivation conflicts, because a policy that does not
    validate does not run (§9.5).
    """
    conflicts = policy.validate()
    if conflicts:
        raise ValueError("policy does not validate:\n  " + "\n  ".join(conflicts))

    pointer_fn = pointer_fn or (lambda name, val: f"ptr:{hashlib.sha384((name+str(val)).encode()).hexdigest()[:16]}")
    resolved: Dict[str, dict] = {}

    for name, value in record.items():
        disp = policy.disposition_for(name)
        label = labels[name]
        spec: dict = {"disposition": disp.value, "label": label}

        if disp == Disposition.CLEAR:
            spec["value"] = value
            spec["value_repr"] = _repr(value)
        elif disp == Disposition.HASH_ONLY:
            if correlation is None:
                raise ValueError(f"hash-only field {name} needs a CorrelationService")
            spec["value_repr"] = _repr(value)
            spec["correlation_digest"] = correlation.digest(_repr(value))
        elif disp == Disposition.POINTER:
            spec["pointer"] = pointer_fn(name, value)
        elif disp == Disposition.WITHHELD:
            # value is dropped: it does not enter the pipeline (§9.4)
            spec["value"] = None
        resolved[name] = spec

    return resolved


def _repr(value: object) -> str:
    """Canonical string form of a value for hashing. Deterministic across types."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
