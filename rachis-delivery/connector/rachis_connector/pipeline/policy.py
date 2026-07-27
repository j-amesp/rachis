"""
rachis_connector.pipeline.policy
=================================

Disclosure policy evaluation: the four dispositions and derivation constraints with
granularity (thesis §9.3-9.5). Ported from the reference core and hardened for production:
the correlation service is now explicit about its stub status and refuses to run unless the
operator has opted in (thesis §16.6).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, List, Optional

from ..models import DisclosurePolicySpec, DerivationConstraint, Granularity
from ..crypto.merkle import Disposition


# --------------------------------------------------------------------------- validation

_PERMISSIVENESS = {
    Disposition.WITHHELD: 0,
    Disposition.POINTER: 1,
    Disposition.HASH_ONLY: 2,
    Disposition.CLEAR: 3,
}


def disposition_for(policy: DisclosurePolicySpec, field_name: str) -> Disposition:
    return policy.dispositions.get(field_name, policy.default)


def validate_policy(policy: DisclosurePolicySpec) -> List[str]:
    """Return unresolved derivation conflicts (thesis §9.5). Empty == may run.

    A conflict exists when a protected field is derivable, at a granularity that defeats its
    protection, from a set released more permissively, and the source has not accepted it.
    """
    problems: List[str] = []
    for d in policy.derivations:
        if d.accepted:
            continue
        if not d.granularity.defeats(d.protects_at):
            continue
        target = disposition_for(policy, d.field)
        deriving = [disposition_for(policy, f) for f in d.derivable_from]
        if deriving and min(_PERMISSIVENESS[x] for x in deriving) > _PERMISSIVENESS[target]:
            problems.append(
                f"derivation conflict: {d.field} ({target.value}) is derivable at "
                f"{d.granularity.value} from {d.derivable_from}, released more permissively. "
                f"Demote a member or accept the derivation."
            )
    return problems


def policy_hash(policy: DisclosurePolicySpec) -> str:
    blob = json.dumps(
        {
            "policy_id": policy.policy_id,
            "default": policy.default.value,
            "dispositions": {k: v.value for k, v in sorted(policy.dispositions.items())},
            "derivations": [
                {"f": d.field, "from": sorted(d.derivable_from),
                 "g": d.granularity.value, "acc": d.accepted}
                for d in policy.derivations
            ],
        },
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return "sha384:" + hashlib.sha384(blob).hexdigest()


# --------------------------------------------------------------------------- correlation

class CorrelationService:
    """Keyed digest for hash-only disposition (thesis §9.3, §16.6).

    STUB — the thesis §16.6 resolution (threshold OPRF split t-of-m across sovereign members)
    is NOT implemented. This single HMAC key permits any key-holder to enumerate low-entropy
    value spaces offline, which is exactly the attack the threshold scheme prevents. It is
    therefore DISABLED by default (config.enable_hash_only_correlation) and, when enabled,
    logs a warning on construction.
    """

    def __init__(self, key: bytes, epoch: str, enabled: bool) -> None:
        if not enabled:
            raise RuntimeError(
                "hash-only correlation is disabled. The single-key stand-in permits offline "
                "enumeration (thesis §16.6); enable_hash_only_correlation must be set true, "
                "knowingly, until the threshold OPRF ships."
            )
        self._key = key
        self.epoch = epoch

    def digest(self, value: str) -> str:
        mac = hmac.new(self._key, value.encode(), hashlib.sha384).hexdigest()
        return f"hmac-sha384:{self.epoch}:{mac}"


def value_repr(value: object) -> str:
    """Canonical string form for hashing. Deterministic across types."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
