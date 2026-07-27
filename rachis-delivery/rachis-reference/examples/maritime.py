"""
The Appendix A maritime vessel example, as runnable code.

Everything here mirrors the thesis appendix: the Expectation (A.2), the source schema (A.3),
the declarative mapping (A.4), the disclosure policy with its two derivation constraints
(A.5), and the callback that is refused on a releasability caveat (A.9).

Import these builders in tests, or run this module directly for the A.6–A.9 walkthrough.
"""
from __future__ import annotations

from rachis.model import Expectation, FieldSpec, MarkingRequirement, Obligation
from rachis.labels import MarkingPolicy
from rachis.policy import (
    DisclosurePolicy, DerivationConstraint, Granularity, CorrelationService,
)
from rachis.provenance import Disposition
from rachis.connect import Mapping, FieldMapping, TRANSFORMS


# --- the AMOCO-demo marking policy (Appendix A uses UNMARKED < RESTRICTED < GENERAL < SECRET)
AMOCO = MarkingPolicy(
    policy_id="urn:rachis:policy:nato-amoco-demo",
    levels=["UNMARKED", "RESTRICTED", "GENERAL", "SECRET"],
)


def build_expectation() -> Expectation:
    """Appendix A.2 — the vessel Expectation (trimmed to the fields the example exercises)."""
    return Expectation(
        canonical="urn:rachis:expectation:maritime:vessel",
        version="urn:rachis:expectation:maritime:vessel:2:1",
        supersedes="urn:rachis:expectation:maritime:vessel:2:0",
        deprecation_horizon="2027-06-30",
        entity="vessel",
        marking=MarkingRequirement(policy_id=AMOCO.policy_id),
        core_field_budget=40,
        fields=[
            FieldSpec(name="imoNumber", type="string", obligation=Obligation.REQUIRED,
                      pattern=r"^IMO[0-9]{7}$"),
            FieldSpec(name="currentName", type="string", obligation=Obligation.REQUIRED),
            FieldSpec(name="priorNames", type="array<string>"),
            FieldSpec(name="flagState", type="string", obligation=Obligation.REQUIRED),
            FieldSpec(name="callSign", type="string"),
            FieldSpec(name="mmsi", type="string", pattern=r"^[0-9]{9}$"),
            FieldSpec(name="grossTonnage", type="integer"),
            FieldSpec(name="registeredOwner", type="string"),
            FieldSpec(name="beneficialOwner", type="string"),
            FieldSpec(name="lastPortCall.locode", type="string"),
            FieldSpec(name="lastPortCall.departedAt", type="string"),
            FieldSpec(name="lastKnownPosition.lat", type="decimal"),
            FieldSpec(name="lastKnownPosition.lon", type="decimal"),
            FieldSpec(name="lastKnownPosition.observedAt", type="string"),
            FieldSpec(name="assessment.summary", type="string"),
            FieldSpec(name="collectionMeans", type="string"),
        ],
    )


def build_mapping() -> Mapping:
    """Appendix A.4 — the declarative mapping from the VSL_MASTER schema."""
    flag_codes = {"GB": "GBR", "PA": "PAN", "LR": "LBR", "MH": "MHL"}
    return Mapping(
        mapping_id="urn:example:mapping:natmaritime-vslmaster:1:4",
        expectation="urn:rachis:expectation:maritime:vessel:2:1",
        fields=[
            FieldMapping("imoNumber", "IMO_NO", [TRANSFORMS["prefix"]("IMO")]),
            FieldMapping("currentName", "VSL_NM", [TRANSFORMS["trim"](), TRANSFORMS["upper"]()]),
            FieldMapping("priorNames", "VSL_NM_PREV", [TRANSFORMS["split"]("|")]),
            FieldMapping("flagState", "FLAG_CD", [TRANSFORMS["codelist"](flag_codes)]),
            FieldMapping("callSign", "CALL_SGN", [TRANSFORMS["trim"](), TRANSFORMS["upper"]()]),
            FieldMapping("mmsi", "MMSI_NO"),
            FieldMapping("grossTonnage", "GT"),
            FieldMapping("registeredOwner", "OWNR_REG_NM", [TRANSFORMS["trim"]()]),
            FieldMapping("beneficialOwner", "OWNR_BEN_NM", [TRANSFORMS["trim"]()]),
            FieldMapping("lastPortCall.departedAt", "PORT_DEP_DTM"),
            FieldMapping("lastKnownPosition.lat", "POS_LAT"),
            FieldMapping("lastKnownPosition.lon", "POS_LON"),
            FieldMapping("lastKnownPosition.observedAt", "POS_DTM"),
            FieldMapping("assessment.summary", "ASSESS_TXT"),
        ],
        label_overrides={
            "imoNumber": "UNMARKED", "currentName": "UNMARKED", "flagState": "UNMARKED",
            "priorNames": "UNMARKED", "callSign": "UNMARKED", "mmsi": "UNMARKED",
            "grossTonnage": "UNMARKED", "registeredOwner": "UNMARKED",
            "lastPortCall.departedAt": "UNMARKED",
            "beneficialOwner": "GENERAL",
            "lastKnownPosition.lat": "RESTRICTED", "lastKnownPosition.lon": "RESTRICTED",
            "lastKnownPosition.observedAt": "RESTRICTED",
            "assessment.summary": "GENERAL",
        },
    )


def build_policy() -> DisclosurePolicy:
    """Appendix A.5 — the disclosure policy with two derivation constraints."""
    return DisclosurePolicy(
        policy_id="urn:example:policy:natmaritime-vessel:3:2",
        default=Disposition.WITHHELD,
        dispositions={
            "imoNumber": Disposition.CLEAR,
            "currentName": Disposition.CLEAR,
            "priorNames": Disposition.CLEAR,
            "flagState": Disposition.CLEAR,
            "callSign": Disposition.CLEAR,
            "mmsi": Disposition.CLEAR,
            "grossTonnage": Disposition.CLEAR,
            "registeredOwner": Disposition.CLEAR,
            "lastPortCall.departedAt": Disposition.CLEAR,
            "beneficialOwner": Disposition.HASH_ONLY,
            "lastKnownPosition.lat": Disposition.POINTER,
            "lastKnownPosition.lon": Disposition.POINTER,
            # A.5: observedAt demoted CLEAR -> POINTER as the secondary-suppression resolution
            "lastKnownPosition.observedAt": Disposition.POINTER,
            "assessment.summary": Disposition.POINTER,
            # collectionMeans not present in this record; withheld by default anyway
        },
        derivations=[
            DerivationConstraint(
                field="lastKnownPosition.lat",
                derivable_from=["lastPortCall.locode", "lastPortCall.departedAt"],
                granularity=Granularity.COARSE, protects_at=Granularity.EXACT,
                accepted=True,
                rationale="Port call locates to ~200km; does not defeat precise-position "
                          "protection.",
            ),
            DerivationConstraint(
                field="collectionMeans",
                derivable_from=["lastKnownPosition.observedAt", "lastPortCall.departedAt"],
                granularity=Granularity.EXACT, protects_at=Granularity.EXACT,
                # RESOLVED (A.5): observedAt was demoted CLEAR -> POINTER in the dispositions
                # above, so the deriving set is no longer released permissively enough to
                # reconstruct collectionMeans. Marking accepted records that the resolution
                # has been applied.
                accepted=True,
                rationale="Revisit interval would disclose collection means exactly; "
                          "resolved by demoting observedAt to pointer (see dispositions).",
            ),
        ],
    )


def sample_row() -> dict:
    """Appendix A.3 — one VSL_MASTER row."""
    return {
        "VSL_PK": 88213,
        "IMO_NO": "7712345",
        "VSL_NM": "  northern star ",
        "VSL_NM_PREV": " POLAR DAWN | ARCTIC MERCHANT ",
        "FLAG_CD": "PA",
        "CALL_SGN": "3ewx4",
        "MMSI_NO": "351234567",
        "GT": 24911,
        "OWNR_REG_NM": " Meridian Shipping Ltd ",
        "OWNR_BEN_NM": " Kirov Holdings SA ",
        "PORT_DEP_DTM": "2026-07-18T22:04:00Z",
        "POS_LAT": 59.912300,
        "POS_LON": 10.751900,
        "POS_DTM": "2026-07-18T22:04:00Z",
        "ASSESS_TXT": "Pattern of AIS gaps consistent with STS transfers.",
        "COLL_MEANS_CD": "OSINT-AIS",
    }


def correlation_service() -> CorrelationService:
    """Single-key stand-in for the §16.6 threshold OPRF. See policy.CorrelationService."""
    return CorrelationService(key=b"demo-federation-key-not-for-production", epoch="2026H2")


if __name__ == "__main__":
    from rachis.trust import Ed25519Signer, SaltStore
    from rachis.connect import Connector

    exp, mp, pol = build_expectation(), build_mapping(), build_policy()
    signer, salts = Ed25519Signer(), SaltStore()
    conn = Connector(exp, mp, pol, signer, salts,
                     source_identity="urn:example:org:natmaritime-authority",
                     measurement="sev-snp:ld:4b19...0c7a",
                     correlation=correlation_service())
    pkg = conn.build_package("rec-4c81b", sample_row(), record_classification="GENERAL")
    print(f"bound {pkg.field_count} leaves; {len(pkg.fields)} disclosed")
    for f in pkg.fields:
        print(f"  {f.disposition.value:10} {f.name}")
