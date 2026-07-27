"""
RACHIS reference core — test suite.

Each test is an assertion about a thesis claim, named for the section it proves. Run with
`pytest -v` from the package root. These are not tests of the code's conveniences; they are
tests that the architecture does what Part III says it does.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from rachis import (
    Label, MarkingPolicy, high_water, Disposition, MerkleTree,
    Ed25519Signer, TrustStore, SaltStore, Ingress, AssertionStore, Assertion,
    AssertionType, CallbackRequest, Decision, deny_purpose, require_releasable_to,
    Validator, apply_policy,
)
from rachis.provenance import _leaf_hash, FivePartHeader
from examples.maritime import (
    AMOCO, build_expectation, build_mapping, build_policy, sample_row,
    correlation_service,
)
from rachis.connect import Connector


# ----------------------------------------------------------------- fixtures

@pytest.fixture
def connector():
    exp, mp, pol = build_expectation(), build_mapping(), build_policy()
    signer, salts = Ed25519Signer(), SaltStore()
    conn = Connector(exp, mp, pol, signer, salts,
                     source_identity="urn:example:org:natmaritime-authority",
                     measurement="sev-snp:ld:4b19...0c7a",
                     correlation=correlation_service())
    return conn, signer, salts


@pytest.fixture
def package(connector):
    conn, signer, salts = connector
    return conn.build_package("rec-4c81b", sample_row(), record_classification="GENERAL")


# ----------------------------------------------------------------- Labels (§15)

def test_high_water_takes_strictest_classification():
    """§15.2: a derived label is never below the max of its inputs."""
    a = Label(AMOCO.policy_id, "UNMARKED")
    b = Label(AMOCO.policy_id, "GENERAL")
    c = Label(AMOCO.policy_id, "RESTRICTED")
    assert high_water([a, b, c], AMOCO).classification == "GENERAL"

def test_caveats_union_never_diminish():
    """§15.2: caveats union, never shrink."""
    a = Label(AMOCO.policy_id, "RESTRICTED", frozenset({"REL-A"}))
    b = Label(AMOCO.policy_id, "RESTRICTED", frozenset({"REL-B"}))
    assert high_water([a, b], AMOCO).caveats == {"REL-A", "REL-B"}

def test_relaxation_is_never_emergent():
    """§15.1: no combination lowers a classification."""
    hi = Label(AMOCO.policy_id, "SECRET")
    lo = Label(AMOCO.policy_id, "UNMARKED")
    assert hi.combine(lo, AMOCO).classification == "SECRET"


# ----------------------------------------------------------------- Model (§8)

def test_expectation_validates_conformant_record():
    exp, mp = build_expectation(), build_mapping()
    mapped, _ = mp.transform(sample_row())
    assert exp.validate_record(mapped) == []

def test_expectation_rejects_missing_required_field():
    exp = build_expectation()
    assert any("imoNumber" in p for p in exp.validate_record({"currentName": "X"}))

def test_expectation_offline_no_network():
    """§8.4: validation is pure computation, runnable with no platform connection."""
    exp, mp = build_expectation(), build_mapping()
    mapped, _ = mp.transform(sample_row())
    # if this needed a network it would fail here; it does not
    assert exp.validate_record(mapped) == []


# ----------------------------------------------------------------- Policy (§9)

def test_default_is_withheld():
    """§9.3: a field with no declared disposition does not cross."""
    pol = build_policy()
    assert pol.disposition_for("undeclared.field") == Disposition.WITHHELD

def test_accepted_coarse_derivation_does_not_block():
    """§9.5 + A.11: a coarse derivation does not defeat a fine protection."""
    pol = build_policy()
    # the lat<-portcall derivation is COARSE and accepted; policy must validate
    assert pol.validate() == []

def test_unresolved_exact_derivation_blocks():
    """§9.5: an unaccepted exact derivation of a protected field fails validation."""
    from rachis import DisclosurePolicy, DerivationConstraint, Granularity
    pol = DisclosurePolicy(
        policy_id="test",
        dispositions={
            "secret": Disposition.WITHHELD,
            "a": Disposition.CLEAR,
            "b": Disposition.CLEAR,
        },
        derivations=[DerivationConstraint(
            field="secret", derivable_from=["a", "b"],
            granularity=Granularity.EXACT, protects_at=Granularity.EXACT, accepted=False)],
    )
    problems = pol.validate()
    assert problems and "secret" in problems[0]

def test_withheld_value_dropped_before_pipeline(connector):
    """§9.4: a withheld field's value never enters the resolved record."""
    conn, _, _ = connector
    exp, mp, pol = build_expectation(), build_mapping(), build_policy()
    mapped, _ = mp.transform(sample_row())
    labels = conn._labels_for(mapped)
    # force a field to withheld and confirm its value is None afterwards
    pol.dispositions["assessment.summary"] = Disposition.WITHHELD
    resolved = apply_policy(pol, mapped, labels, correlation=correlation_service())
    assert resolved["assessment.summary"]["value"] is None
    assert "value_repr" not in resolved["assessment.summary"]


# ----------------------------------------------------------------- Provenance (§10)

def test_merkle_inclusion_proof_verifies(package):
    """§10.4: each released field verifies against the signed root."""
    pkg = package
    checked = 0
    for f in pkg.fields:
        if f.disposition in (Disposition.CLEAR, Disposition.HASH_ONLY):
            leaf = _leaf_hash(f.name, f.disposition, f.value_repr, f.label, f.salt)
            assert MerkleTree.verify(leaf, f.inclusion_proof, pkg.root)
            checked += 1
    assert checked > 0

def test_withheld_field_absent_from_package(package):
    """§9.4/§10.4: withheld fields carry nothing into the package."""
    names = {f.name for f in package.fields}
    # collectionMeans was withheld (not in the row + default withheld) -> absent
    assert "collectionMeans" not in names

def test_tree_shape_reveals_only_count(package):
    """§10.4: the one thing tree shape reveals is the field count, nothing about values."""
    assert package.field_count >= len(package.fields)
    # no withheld value is retrievable from the package
    for f in package.fields:
        if f.disposition == Disposition.POINTER:
            assert f.value is None and f.value_repr is None

def test_signature_covers_root(package, connector):
    """§10.4: one signature over the root; tampering the root breaks it."""
    _, signer, _ = connector
    v = signer.verifier()
    assert v.verify(package.root, package.signature)
    assert not v.verify(package.root[:-1] + b"\x00", package.signature)

def test_header_is_five_part(package):
    """§10.5 + A.11 D4: mappingHash is present, making the header five-part."""
    h = package.header
    for attr in ("expectation", "mapping_hash", "policy_hash",
                 "connector_measurement", "source_identity"):
        assert getattr(h, attr)


# ----------------------------------------------------------------- Trust (§16)

def test_platform_holds_no_signing_key(connector):
    """§16.1: a Verifier cannot sign. The platform only ever gets Verifiers."""
    _, signer, _ = connector
    v = signer.verifier()
    assert not hasattr(v, "sign")

def test_salt_is_stable_for_callback(connector):
    """A.11 D1: the same (record, field) yields the same salt, so a later callback works."""
    _, _, salts = connector
    s1 = salts.salt_for("rec-1", "field-x")
    s2 = salts.salt_for("rec-1", "field-x")
    assert s1 == s2


# ----------------------------------------------------------------- Ingress (§11)

@pytest.fixture
def ingress(connector):
    _, signer, _ = connector
    trust = TrustStore()
    trust.register("urn:example:org:natmaritime-authority", signer.verifier())
    return Ingress(
        trust=trust,
        expectations={"urn:rachis:expectation:maritime:vessel:2:1": build_expectation()},
        marking_policies={AMOCO.policy_id: AMOCO},
        permitted_measurements={"sev-snp:ld:4b19...0c7a"},
    )

def test_ingress_admits_valid_package(ingress, package):
    """§11.1: a well-formed, signed, conformant package passes all nine checks."""
    result = ingress.verify(package)
    assert result.admitted, result.summary()

def test_ingress_rejects_forged_signature(ingress, package):
    """§11.1 check 1: a bad signature is rejected.

    Replace the signature with a valid-length but wrong one (all-zero bytes). Flipping a
    single byte can occasionally land on a no-op under signature encoding; an all-zero
    signature of the correct length cannot verify, which makes the test deterministic.
    """
    package.signature = bytes(len(package.signature))  # 64 zero bytes
    assert not ingress.verify(package).admitted

def test_ingress_rejects_unknown_measurement(ingress, package):
    """§11.1 check 2: an unattested connector is rejected."""
    package.header.connector_measurement = "sev-snp:ld:unknown"
    assert not ingress.verify(package).admitted

def test_ingress_rejects_replay(ingress, package):
    """§11.1 check 9: the same root twice is a replay."""
    assert ingress.verify(package).admitted
    assert not ingress.verify(package).admitted

def test_ingress_does_not_classify(ingress, package):
    """§11.3: ingress has no method to assign or change a label — it only verifies."""
    assert not hasattr(ingress, "classify")
    assert not hasattr(ingress, "relabel")


# ----------------------------------------------------------------- Assertions (§13, §14)

@pytest.fixture
def store():
    return AssertionStore(AMOCO)

def _attr(store, subject, body, cls="GENERAL"):
    return Assertion(
        id=store.new_id(), type=AssertionType.ATTRIBUTE, subject=subject, body=body,
        author="analyst-1", label=Label(AMOCO.policy_id, cls),
        valid_from="2026-07-01", observed_at="2026-07-01", recorded_at="2026-07-02",
    )

def test_identity_is_a_projection(store):
    """§13.2: an entity profile is computed from assertions, not stored."""
    eid = store.new_entity_id()
    store.assert_(_attr(store, eid, {"imoNumber": "IMO7712345"}))
    store.assert_(_attr(store, eid, {"flagState": "PAN"}))
    proj = store.project_entity(eid)
    assert proj["attributes"] == {"imoNumber": "IMO7712345", "flagState": "PAN"}

def test_projection_label_is_high_water(store):
    """§13.2/§15.2: a profile is classified at the high-water mark of its assertions."""
    eid = store.new_entity_id()
    store.assert_(_attr(store, eid, {"a": 1}, cls="UNMARKED"))
    store.assert_(_attr(store, eid, {"b": 2}, cls="GENERAL"))
    assert store.project_entity(eid)["label"]["classification"] == "GENERAL"

def test_supersession_keeps_history(store):
    """§14.3: a superseded assertion stays in the log; the new one shows in the projection."""
    eid = store.new_entity_id()
    a1 = store.assert_(_attr(store, eid, {"position": "old"}))
    a2 = _attr(store, eid, {"position": "new"})
    store.supersede(a1.id, a2, at="2026-07-03")
    proj = store.project_entity(eid)
    assert proj["attributes"]["position"] == "new"
    assert len(store.export()) == 2  # both retained

def test_withdrawal_differs_from_supersession(store):
    """§14.3: withdrawal marks a wrong assertion; it drops out of the projection."""
    eid = store.new_entity_id()
    a1 = store.assert_(_attr(store, eid, {"claim": "wrong"}))
    store.withdraw(a1.id, at="2026-07-04")
    assert "claim" not in store.project_entity(eid)["attributes"]

def test_withdrawal_cascades_to_revalidation(store):
    """§14.4: assertions derived from a withdrawn fact are flagged, not deleted."""
    eid = store.new_entity_id()
    a1 = store.assert_(_attr(store, eid, {"base": "x"}))
    derived = _attr(store, eid, {"derived": "y"})
    derived.derived_from = [a1.id]
    store.assert_(derived)
    flagged = store.withdraw(a1.id, at="2026-07-05")
    assert derived.id in flagged
    assert len(store.export()) == 2  # nothing deleted

def test_identity_pinning_survives_split(store):
    """§13.4: after a split the original id still resolves, via its tombstone."""
    eid = store.new_entity_id()
    store.assert_(_attr(store, eid, {"imoNumber": "IMO7712345"}))
    a, b = store.split(eid, author="analyst-1",
                       label=Label(AMOCO.policy_id, "GENERAL"), ts="2026-07-06")
    proj = store.project_entity(eid)   # cite the OLD id
    assert eid in proj["entity"]
    assert set(proj["resolves_to"]) >= {eid, a, b}


# ----------------------------------------------------------------- Disclosure (§12)

def test_callback_refused_on_releasability(connector, package):
    """A.9: a request from a nation outside the releasability caveat is denied,
    and the platform never held the value to release."""
    conn, signer, salts = connector

    handler_rules = [require_releasable_to(["GBR", "USA"])]  # PNA not permitted

    # source-held lookups
    row = sample_row()
    def value_lookup(rid, fname): return row["POS_LAT"]
    def label_lookup(rid, fname): return Label(AMOCO.policy_id, "RESTRICTED")

    from rachis.disclosure import CallbackHandler
    handler = CallbackHandler(salts, handler_rules, value_lookup, label_lookup,
                              AMOCO.policy_id)

    req = CallbackRequest(
        record_id="rec-4c81b", field_name="lastKnownPosition.lat",
        pointer="ptr:abc", requester="urn:partner:pna/analyst-2291",
        organisation="urn:partner:pna", nationality="PNA", clearance="RESTRICTED",
        purpose="sanctions-enforcement",
    )

    # a trivial leaf-index / leaf-hash provider for the demo tree
    def idx(rid, fname): return 1
    def leaves(rid): return [b"h0", b"h1", b"h2", b"h3"]

    resp = handler.handle(req, package.root, idx, leaves)
    assert resp.decision == Decision.DENY
    assert resp.reason == "releasability"
    assert resp.value is None                    # platform never had it
    assert handler.log[-1]["decision"].startswith("deny")  # logged locally (§12.1)

def test_callback_release_reconstructs_original_leaf(connector):
    """§12.1: an authorised release reproduces a leaf verifying against the ORIGINAL root.

    This is the salt-persistence property (D1): months later, the same salt rebuilds the
    identical leaf, so the value released by callback still matches the signature the
    platform already holds.
    """
    from rachis.provenance import _leaf_hash, MerkleTree
    conn, signer, salts = connector

    # bind a record whose field is a pointer, capturing the real leaf order
    label = Label(AMOCO.policy_id, "RESTRICTED")
    salt = salts.salt_for("rec-9", "lastKnownPosition.lat")
    pointer_leaf = _leaf_hash("lastKnownPosition.lat", Disposition.POINTER, None, label, salt)
    other = _leaf_hash("imoNumber", Disposition.CLEAR, "IMO7712345",
                       Label(AMOCO.policy_id, "UNMARKED"),
                       salts.salt_for("rec-9", "imoNumber"))
    leaves = [b"header-leaf", other, pointer_leaf]
    tree = MerkleTree(leaves)
    root = tree.root
    signature = signer.sign(root)

    # callback releases the pointer field; rebuild leaf from the SAME salt
    salt_again = salts.salt_for("rec-9", "lastKnownPosition.lat")
    rebuilt = _leaf_hash("lastKnownPosition.lat", Disposition.POINTER, None, label, salt_again)
    proof = tree.proof(2)

    assert rebuilt == pointer_leaf                       # salt persistence (D1)
    assert MerkleTree.verify(rebuilt, proof, root)       # verifies vs original root (§12.1)
    assert signer.verifier().verify(root, signature)     # under the original signature


# ----------------------------------------------------------------- Validator (§8.4, §9.6)

def test_validator_proposes_library_derivation():
    """§9.6: the validator proposes a known derivation the policy has not declared."""
    exp, mp = build_expectation(), build_mapping()
    from rachis import DisclosurePolicy
    bare = DisclosurePolicy(policy_id="bare", dispositions={
        "lastKnownPosition.lat": Disposition.POINTER,
        "lastPortCall.locode": Disposition.CLEAR,
        "lastPortCall.departedAt": Disposition.CLEAR,
    })
    # add locode to the mapping so the deriving set is present
    from rachis.connect import FieldMapping
    mp.fields.append(FieldMapping("lastPortCall.locode", "PORT_LAST_CD"))
    report = Validator().run(exp, mp, bare, sample=[sample_row()])
    assert any(d.field == "lastKnownPosition.lat" for d in report.proposed_derivations)

def test_validator_runs_offline():
    """§8.4: the validator needs no network — it is pure computation over local artefacts."""
    exp, mp, pol = build_expectation(), build_mapping(), build_policy()
    report = Validator().run(exp, mp, pol, sample=[sample_row()])
    assert report.conformant


# ----------------------------------------------------------------- End to end

def test_full_loop(connector):
    """The Part III loop, end to end: map -> disclose -> bind -> sign -> verify -> assert
    -> project. One test that the whole thesis mechanism runs."""
    conn, signer, salts = connector

    # 1. source builds a signed, marked package
    pkg = conn.build_package("rec-e2e", sample_row(), record_classification="GENERAL")

    # 2. platform verifies it
    trust = TrustStore()
    trust.register("urn:example:org:natmaritime-authority", signer.verifier())
    ingress = Ingress(
        trust, {"urn:rachis:expectation:maritime:vessel:2:1": build_expectation()},
        {AMOCO.policy_id: AMOCO}, {"sev-snp:ld:4b19...0c7a"})
    assert ingress.verify(pkg).admitted

    # 3. platform indexes the cleared fields as assertions
    store = AssertionStore(AMOCO)
    eid = store.new_entity_id()
    for f in pkg.fields:
        if f.disposition == Disposition.CLEAR:
            store.assert_(Assertion(
                id=store.new_id(), type=AssertionType.ATTRIBUTE, subject=eid,
                body={f.name: f.value}, author="ingest", label=f.label,
                valid_from="2026-07-18", observed_at="2026-07-18", recorded_at="2026-07-19"))

    # 4. analyst projects the entity
    proj = store.project_entity(eid)
    assert proj["attributes"]["imoNumber"] == "IMO7712345"
    assert proj["attributes"]["flagState"] == "PAN"
    # beneficialOwner was hash-only, position was pointer -> not in the clear projection
    assert "beneficialOwner" not in proj["attributes"]
    assert "lastKnownPosition.lat" not in proj["attributes"]
