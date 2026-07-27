"""
RACHIS — marking arithmetic (shared by Policy, Provenance, Ingress).

The thesis (§3.5) states the design rule: *the marking vocabulary is pluggable, the
marking arithmetic is not*. This module is the arithmetic. It is deliberately tiny and
has no notion of any particular scheme — defence classifications, police handling codes,
health consent states all plug in as an ordered vocabulary plus a caveat set.

The invariants it must uphold (thesis §15.2), which the tests assert by property:
  - a derived label is never below the maximum of its inputs (high-water mark)
  - caveats union, never diminish
  - relaxation is only ever an explicit, attributed act — never emergent here
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Sequence, Tuple


class MarkingPolicy:
    """An ordered classification vocabulary. Pluggable per domain (thesis §3.5, §23.1).

    Levels are given low-to-high. The policy interprets a label's classification against
    this order; it does not itself carry any label.
    """

    def __init__(self, policy_id: str, levels: Sequence[str]) -> None:
        self.policy_id = policy_id
        self._levels: Tuple[str, ...] = tuple(levels)
        self._rank = {name: i for i, name in enumerate(self._levels)}

    def rank(self, classification: str) -> int:
        if classification not in self._rank:
            raise ValueError(
                f"classification {classification!r} not in policy {self.policy_id!r}"
            )
        return self._rank[classification]

    def name(self, rank: int) -> str:
        return self._levels[rank]

    def max_classification(self, a: str, b: str) -> str:
        return a if self.rank(a) >= self.rank(b) else b


@dataclass(frozen=True)
class Label:
    """A confidentiality label. Carries a classification and a set of handling caveats.

    Structurally mirrors the STANAG 4774 label the thesis builds on (§10.1), reduced to
    the two fields the arithmetic needs. `policy_id` names the vocabulary it is expressed
    against, so a verifier can reject a label from an unrecognised policy (ingress check 5).
    """

    policy_id: str
    classification: str
    caveats: FrozenSet[str] = field(default_factory=frozenset)

    def combine(self, other: "Label", policy: MarkingPolicy) -> "Label":
        """High-water combination. The core arithmetic operation (thesis §15.1).

        The result takes the higher classification and the *union* of caveats. There is no
        path through this function that lowers either — relaxation cannot be emergent.
        """
        if self.policy_id != other.policy_id:
            raise ValueError("cannot combine labels from different policies")
        return Label(
            policy_id=self.policy_id,
            classification=policy.max_classification(
                self.classification, other.classification
            ),
            caveats=self.caveats | other.caveats,
        )

    def dominates(self, other: "Label", policy: MarkingPolicy) -> bool:
        """True if this label is at least as restrictive as `other` in every respect.

        Used by ingress check 6 (§11.1): no field's label may exceed the record's.
        """
        return (
            policy.rank(self.classification) >= policy.rank(other.classification)
            and other.caveats <= self.caveats
        )


def high_water(labels: Sequence[Label], policy: MarkingPolicy) -> Label:
    """Combine many labels to their high-water mark.

    Proves (thesis §15.2): a derived artefact inherits the strictest classification and
    the union of caveats among its inputs. This is the function every derivation, every
    projection and every assertion routes through.
    """
    if not labels:
        raise ValueError("high_water of empty label set is undefined")
    acc = labels[0]
    for lbl in labels[1:]:
        acc = acc.combine(lbl, policy)
    return acc
