"""
rachis_connector.pipeline.mapping
==================================

Applies a declarative mapping to a source record (thesis §9.2). Takes raw source JSON,
produces a record in Expectation shape. Every transform is a named library function; there
is no code path for arbitrary logic.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Tuple

from ..models import Mapping, FieldMappingSpec
from .transforms import build_chain


class MappingEngine:
    """Compiles a Mapping once, then applies it to many records."""

    def __init__(self, mapping: Mapping) -> None:
        self._mapping = mapping
        # compile transform chains once at construction; a bad transform fails here
        self._chains: Dict[str, list] = {
            fm.target: build_chain(fm.transforms) for fm in mapping.fields
        }

    @property
    def mapping_hash(self) -> str:
        blob = json.dumps(
            {"id": self._mapping.mapping_id, "expectation": self._mapping.expectation,
             "fields": sorted(fm.target for fm in self._mapping.fields)},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return "sha384:" + hashlib.sha384(blob).hexdigest()

    def label_overrides(self) -> Dict[str, str]:
        return self._mapping.label_overrides()

    def transform(self, row: Dict[str, object]) -> Tuple[Dict[str, object], List[str]]:
        """Apply the mapping to one source row.

        Returns (mapped_record, omission_reasons). A field whose transform yields None and
        whose on_unmapped is 'omit_field_with_reason' is dropped with a recorded reason,
        rather than emitted wrong (thesis Appendix A.4).
        """
        out: Dict[str, object] = {}
        reasons: List[str] = []
        for fm in self._mapping.fields:
            value = row.get(fm.source) if fm.source else None
            for fn in self._chains[fm.target]:
                value = fn(value)
                if value is None and fm.on_unmapped == "omit_field_with_reason":
                    reasons.append(f"{fm.target}: unmapped source value for {fm.source}")
                    break
            else:
                if value is not None:
                    out[fm.target] = value
                elif fm.on_unmapped == "error":
                    # leave absent; Expectation validation will flag if it was required
                    pass
        return out, reasons
