"""
rachis_connector.wire
=====================

The on-the-wire disclosure package (thesis §10, Appendix A.7). JSON-serialisable throughout,
because this is what crosses the disclosure boundary to core over mTLS. Withheld fields are
absent by construction — there is no representation for them here, which is the point
(thesis §9.4).
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from .crypto.merkle import Disposition


class WireLabel(BaseModel):
    policy_id: str
    classification: str
    caveats: List[str] = Field(default_factory=list)


class WireField(BaseModel):
    name: str
    disposition: Disposition
    inclusion_proof: List[Tuple[str, str]]      # (side, hex-sibling)
    label: WireLabel
    # present only for the disposition that carries it:
    value: Optional[object] = None              # CLEAR
    value_repr: Optional[str] = None            # CLEAR, HASH_ONLY (for recompute)
    salt: Optional[str] = None                  # CLEAR, HASH_ONLY (released salt, not secret)
    correlation_digest: Optional[str] = None    # HASH_ONLY
    pointer: Optional[str] = None               # POINTER


class WireHeader(BaseModel):
    expectation: str
    mapping_hash: str
    policy_hash: str
    connector_measurement: str
    source_identity: str


class DisclosurePackage(BaseModel):
    """What the connector ships to core. Signed once over the Merkle root (thesis §10.4)."""
    algorithm: str
    root_hex: str
    signature_hex: str
    header: WireHeader
    record_label: WireLabel
    fields: List[WireField]
    field_count: int                            # total leaves incl. withheld (§10.4)
    record_id: str
    created_at: str
