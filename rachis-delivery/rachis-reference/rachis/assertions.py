"""
RACHIS — Assertions contract.

The collaborative knowledge layer, and the identity model. Two theses claims live here:

  Identity is an assertion, not a pipeline stage (§13.2). The profile an analyst sees is a
  read-time projection over currently valid assertions. A merge, a split, an alias — each is
  an attributed, reversible statement in the same append-only store.

  Bitemporality with six timestamps (§14.2), and supersession distinct from withdrawal
  (§14.3): a superseded assertion was correct and is now stale; a withdrawn one was wrong.
  Withdrawal cascades to revalidation, never deletion (§14.4).

Identity pinning (§13.4): once an entity id is assigned it is never reassigned; splits
leave tombstones; merges keep both prior ids resolvable.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .labels import Label, MarkingPolicy, high_water


class AssertionType(str, Enum):
    ATTRIBUTE = "attribute"
    LINK = "link"
    MERGE = "merge"
    SPLIT = "split"
    ALIAS = "alias"
    NOTE = "note"


@dataclass
class Assertion:
    """One append-only, attributed, bitemporal statement (thesis §14.2)."""
    id: str
    type: AssertionType
    subject: str                       # entity id or record id
    body: dict
    author: str                        # who or what asserted it (§13.3)
    label: Label
    # six timestamps (§14.2)
    valid_from: str
    observed_at: str
    recorded_at: str
    valid_until: Optional[str] = None
    superseded_at: Optional[str] = None   # was correct, now stale (§14.3)
    withdrawn_at: Optional[str] = None    # was wrong (§14.3)
    supersedes: Optional[str] = None      # id of the assertion this replaces
    derived_from: List[str] = field(default_factory=list)  # for cascade (§14.4)
    flagged_for_revalidation: bool = False

    @property
    def is_live(self) -> bool:
        return self.superseded_at is None and self.withdrawn_at is None


class AssertionStore:
    """Append-only store with projection. Never updates in place (thesis §14, §17.4)."""

    def __init__(self, policy: MarkingPolicy) -> None:
        self._log: List[Assertion] = []
        self._by_id: Dict[str, Assertion] = {}
        self._policy = policy
        self._ids = itertools.count(1)
        self._entity_ids = itertools.count(1)
        self._tombstones: Dict[str, List[str]] = {}  # split: old id -> successor ids

    # ------------------------------------------------------------------ append

    def assert_(self, a: Assertion) -> Assertion:
        """Append an assertion. The only way to add knowledge; nothing is mutated."""
        self._log.append(a)
        self._by_id[a.id] = a
        return a

    def new_id(self) -> str:
        return f"asrt-{next(self._ids):06d}"

    def new_entity_id(self) -> str:
        return f"ent-{next(self._entity_ids):06d}"

    # ------------------------------------------------------------------ supersede / withdraw

    def supersede(self, old_id: str, new: Assertion, at: str) -> Assertion:
        """Replace a correct-but-stale assertion (thesis §14.3). Old one stays in the log."""
        old = self._by_id[old_id]
        old.superseded_at = at
        new.supersedes = old_id
        return self.assert_(new)

    def withdraw(self, asrt_id: str, at: str) -> List[str]:
        """Withdraw a wrong assertion and cascade to its dependents (thesis §14.4).

        Returns the ids flagged for revalidation. Nothing is deleted: the withdrawn
        assertion and everything derived from it stay in the log, flagged, so the reasoning
        remains inspectable by an inquiry.
        """
        target = self._by_id[asrt_id]
        target.withdrawn_at = at
        flagged: List[str] = []
        for a in self._log:
            if asrt_id in a.derived_from and not a.flagged_for_revalidation:
                a.flagged_for_revalidation = True
                flagged.append(a.id)
        return flagged

    # ------------------------------------------------------------------ projection

    def project_entity(self, entity_id: str) -> dict:
        """Read-time projection over currently valid assertions (thesis §13.2).

        Identity is not stored; it is computed. This resolves an entity to its live
        attributes, with the projected label being the high-water mark of the assertions
        that built it — so a profile is never under-classified relative to its sources.
        """
        # follow tombstones so a pinned-but-split id still resolves (§13.4)
        subjects = self._resolve_subjects(entity_id)
        live = [a for a in self._log
                if a.subject in subjects and a.is_live
                and not a.flagged_for_revalidation]

        attributes: Dict[str, object] = {}
        labels: List[Label] = []
        for a in live:
            labels.append(a.label)
            if a.type == AssertionType.ATTRIBUTE:
                attributes.update(a.body)

        projection = {
            "entity": entity_id,
            "resolves_to": sorted(subjects),
            "attributes": attributes,
            "assertion_count": len(live),
        }
        if labels:
            hw = high_water(labels, self._policy)
            projection["label"] = {"classification": hw.classification,
                                   "caveats": sorted(hw.caveats)}
        return projection

    def _resolve_subjects(self, entity_id: str) -> Set[str]:
        """Expand an entity id through any splits it has undergone (pinning, §13.4)."""
        out = {entity_id}
        for succ in self._tombstones.get(entity_id, []):
            out |= self._resolve_subjects(succ)
        return out

    # ------------------------------------------------------------------ merge / split (pinning)

    def merge(self, id_a: str, id_b: str, author: str, label: Label, ts: str) -> str:
        """Merge two entities. Both prior ids remain valid citations (thesis §13.4)."""
        merged = self.new_entity_id()
        self._tombstones[id_a] = [merged]
        self._tombstones[id_b] = [merged]
        self.assert_(Assertion(
            id=self.new_id(), type=AssertionType.MERGE, subject=merged,
            body={"merged_from": [id_a, id_b]}, author=author, label=label,
            valid_from=ts, observed_at=ts, recorded_at=ts,
        ))
        return merged

    def split(self, entity_id: str, author: str, label: Label, ts: str) -> List[str]:
        """Split an entity into two. The original id becomes a tombstone (thesis §13.4)."""
        a, b = self.new_entity_id(), self.new_entity_id()
        self._tombstones[entity_id] = [a, b]
        self.assert_(Assertion(
            id=self.new_id(), type=AssertionType.SPLIT, subject=entity_id,
            body={"split_into": [a, b]}, author=author, label=label,
            valid_from=ts, observed_at=ts, recorded_at=ts,
        ))
        return [a, b]

    # ------------------------------------------------------------------ export (Exit)

    def export(self) -> List[dict]:
        """Full export for portability (thesis §14.5, §17.4). Every assertion, in order."""
        return [
            {
                "id": a.id, "type": a.type.value, "subject": a.subject, "body": a.body,
                "author": a.author,
                "label": {"policy_id": a.label.policy_id,
                          "classification": a.label.classification,
                          "caveats": sorted(a.label.caveats)},
                "valid_from": a.valid_from, "valid_until": a.valid_until,
                "observed_at": a.observed_at, "recorded_at": a.recorded_at,
                "superseded_at": a.superseded_at, "withdrawn_at": a.withdrawn_at,
                "supersedes": a.supersedes, "derived_from": a.derived_from,
                "flagged_for_revalidation": a.flagged_for_revalidation,
            }
            for a in self._log
        ]
