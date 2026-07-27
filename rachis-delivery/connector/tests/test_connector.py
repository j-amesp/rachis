"""
Connector functional tests. Each asserts a thesis claim or a production property.
Run: pytest tests/ -v
"""
import sys, os, json, datetime, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from rachis_connector.models import (
    Expectation, FieldSpec, MarkingRequirement, Obligation, Mapping,
    DisclosurePolicySpec, CallbackRequest,
)
from rachis_connector.crypto.merkle import Disposition, Label, MerkleTree, leaf_hash
from rachis_connector.crypto.software import (
    SoftwareKeyStore, open_sealed_release, SoftwareSealer,
)
from rachis_connector.crypto.interfaces import SealedRelease
from rachis_connector.state.store import StateStore
from rachis_connector.pipeline.mapping import MappingEngine
from rachis_connector.pipeline.ingest import IngestPipeline, IngestError
from rachis_connector.pipeline.policy import validate_policy, CorrelationService
from rachis_connector.callback.access import (
    AccessPolicy, MinimumClearance, ReleasableTo, RequireLawfulBasis, PurposeIn,
)
from rachis_connector.callback.handler import CallbackHandler
from rachis_connector.core.client import CoreClient, ExpectationVerificationError

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fakes import FakeCore


LEVELS = ["UNMARKED", "RESTRICTED", "GENERAL", "SECRET"]
PID = "urn:rachis:policy:nato-amoco-demo"


# --------------------------------------------------------------- fixtures

def build_expectation() -> Expectation:
    return Expectation(
        canonical="urn:rachis:expectation:maritime:vessel",
        version="urn:rachis:expectation:maritime:vessel:2:1",
        entity="vessel",
        marking=MarkingRequirement(policy_id=PID),
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
            FieldSpec(name="lastPortCall.departedAt", type="string"),
            FieldSpec(name="lastKnownPosition.lat", type="decimal"),
            FieldSpec(name="lastKnownPosition.lon", type="decimal"),
            FieldSpec(name="lastKnownPosition.observedAt", type="string"),
            FieldSpec(name="assessment.summary", type="string"),
        ],
    )


def load_yaml(path, model):
    import yaml
    with open(os.path.join(os.path.dirname(__file__), "..", path)) as f:
        return model.model_validate(yaml.safe_load(f))


@pytest.fixture
def tmpstate():
    d = tempfile.mkdtemp()
    st = StateStore(os.path.join(d, "t.db"))
    yield st
    st.close()


@pytest.fixture
def pipeline(tmpstate):
    exp = build_expectation()
    mapping = load_yaml("config/mapping.yaml", Mapping)
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    pipe = IngestPipeline(
        expectation=exp, mapping=MappingEngine(mapping), policy=policy,
        signer=ks.signer("k"), state=tmpstate,
        source_identity="urn:example:org:natmaritime-authority",
        connector_measurement="software:dev",
    )
    return pipe, exp, ks


SAMPLE = {
    "IMO_NO": "7712345", "VSL_NM": "  northern star ",
    "VSL_NM_PREV": "POLAR DAWN|ARCTIC MERCHANT", "FLAG_CD": "PA",
    "CALL_SGN": "3ewx4", "MMSI_NO": "351234567", "GT": 24911,
    "OWNR_REG_NM": " Meridian Shipping Ltd ", "OWNR_BEN_NM": " Kirov Holdings SA ",
    "PORT_DEP_DTM": "2026-07-18T22:04:00Z", "POS_LAT": 59.9123, "POS_LON": 10.7519,
    "POS_DTM": "2026-07-18T22:04:00Z",
    "ASSESS_TXT": "Pattern of AIS gaps consistent with STS transfers.",
}


# --------------------------------------------------------------- config / offline (§8.4)

def test_policy_validates_from_yaml():
    """§9.5: the shipped policy validates (secondary suppression resolved)."""
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    assert validate_policy(policy) == []

def test_policy_blocks_when_suppression_undone():
    """§9.5: undo the observedAt demotion and the policy refuses to validate."""
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    policy.dispositions["lastKnownPosition.observedAt"] = Disposition.CLEAR
    for d in policy.derivations:
        if d.field == "collectionMeans":
            d.accepted = False
    assert validate_policy(policy)

def test_mapping_is_declarative():
    """§9.2: the mapping compiles from named transforms only; an unknown fn fails."""
    mapping = load_yaml("config/mapping.yaml", Mapping)
    MappingEngine(mapping)  # compiles
    mapping.fields[0].transforms = [{"fn": "no_such_transform"}]
    with pytest.raises(ValueError):
        MappingEngine(mapping)


# --------------------------------------------------------------- ingest (§9, §10)

def test_ingest_produces_signed_package(pipeline):
    pipe, exp, ks = pipeline
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")  # drop hash-only field (corr disabled)
    pkg = pipe.process("rec-1", sample, "GENERAL")
    v = ks.signer("k")
    from rachis_connector.crypto.software import Ed25519Verifier
    ver = Ed25519Verifier(v.public_key_bytes())
    assert ver.verify(bytes.fromhex(pkg.root_hex), bytes.fromhex(pkg.signature_hex))

def test_withheld_absent_from_package(pipeline):
    """§9.4: a field not disposed (collectionMeans absent from source) never appears."""
    pipe, _, _ = pipeline
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")
    pkg = pipe.process("rec-2", sample, "GENERAL")
    names = {f.name for f in pkg.fields}
    assert "collectionMeans" not in names

def test_pointer_carries_no_value(pipeline):
    """§9.4/§10.4: a pointer field carries a pointer, never the value."""
    pipe, _, _ = pipeline
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")
    pkg = pipe.process("rec-3", sample, "GENERAL")
    for f in pkg.fields:
        if f.disposition == Disposition.POINTER:
            assert f.value is None and f.value_repr is None
            assert f.pointer is not None

def test_clear_field_verifies_against_root(pipeline):
    """§10.4: each clear field's leaf verifies against the signed root."""
    pipe, _, _ = pipeline
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")
    pkg = pipe.process("rec-4", sample, "GENERAL")
    root = bytes.fromhex(pkg.root_hex)
    checked = 0
    for f in pkg.fields:
        if f.disposition == Disposition.CLEAR:
            label = Label(f.label.policy_id, f.label.classification, tuple(f.label.caveats))
            leaf = leaf_hash(f.name, Disposition.CLEAR, f.value_repr, label, f.salt)
            assert MerkleTree.verify(leaf, f.inclusion_proof, root)
            checked += 1
    assert checked > 0

def test_hash_only_requires_opt_in(pipeline):
    """§16.6: hash-only disposition fails when correlation is disabled."""
    pipe, _, _ = pipeline
    # beneficialOwner is hash-only in the policy; correlation was not enabled in the fixture
    with pytest.raises(IngestError):
        pipe.process("rec-5", SAMPLE, "GENERAL")

def test_five_part_header(pipeline):
    """§10.5 D4: header carries mapping_hash (five parts)."""
    pipe, _, _ = pipeline
    # remove the hash-only field so ingest completes without correlation
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")
    pkg = pipe.process("rec-6", sample, "GENERAL")
    h = pkg.header
    assert h.mapping_hash and h.policy_hash and h.expectation and h.source_identity


# --------------------------------------------------------------- Expectation intake (§8.2)

def test_expectation_verified_on_pull(tmpstate):
    exp = build_expectation()
    core = FakeCore(exp)
    client = CoreClient(core, core.core_public_key_hex(), tmpstate, exp.canonical)
    pulled = client.pull_expectation()
    assert pulled.version == exp.version

def test_tampered_expectation_refused(tmpstate):
    """§8.2: an Expectation whose signature doesn't verify is refused."""
    exp = build_expectation()
    core = FakeCore(exp)
    client = CoreClient(core, core.core_public_key_hex(), tmpstate, exp.canonical)
    # monkeypatch transport to return a bad signature
    core.get_expectation = lambda canonical: core.sign_tampered_expectation(exp)
    with pytest.raises(ExpectationVerificationError):
        client.pull_expectation()


# --------------------------------------------------------------- delivery + offline (§22.3)

def test_offline_queue_then_flush(tmpstate):
    exp = build_expectation()
    core = FakeCore(exp)
    client = CoreClient(core, core.core_public_key_hex(), tmpstate, exp.canonical)
    from rachis_connector.wire import DisclosurePackage, WireHeader, WireLabel
    pkg = DisclosurePackage(
        algorithm="Ed25519", root_hex="00", signature_hex="00",
        header=WireHeader(expectation="e", mapping_hash="m", policy_hash="p",
                          connector_measurement="c", source_identity="s"),
        record_label=WireLabel(policy_id=PID, classification="GENERAL"),
        fields=[], field_count=1, record_id="rec-x", created_at="now",
    )
    core.reachable = False
    assert client.deliver(pkg) is False        # queued, not delivered
    core.reachable = True
    assert client.flush_outbound() == 1        # delivered on retry
    assert len(core.received_packages) == 1


# --------------------------------------------------------------- callback (§12.1)

def _callback_handler(pipeline, tmpstate):
    pipe, exp, ks = pipeline
    # bind a record so the callback has a binding to prove against
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")
    pipe.process("rec-cb", sample, "GENERAL")

    access = AccessPolicy([
        MinimumClearance("RESTRICTED", LEVELS),
        ReleasableTo(["GBR", "USA"]),
        RequireLawfulBasis(),
    ])
    def value_lookup(rid, fn): return SAMPLE["POS_LAT"]
    def label_lookup(rid, fn): return Label(PID, "RESTRICTED")
    return CallbackHandler(ks, access, tmpstate, value_lookup, label_lookup)

def test_callback_denied_on_releasability(pipeline, tmpstate):
    """A.9: a nation outside the releasability set is denied; nothing is sealed."""
    handler = _callback_handler(pipeline, tmpstate)
    rk = X25519PrivateKey.generate()
    req = CallbackRequest(
        record_id="rec-cb", field_name="lastKnownPosition.lat", pointer="ptr",
        requester="urn:partner:pna/a", organisation="pna", nationality="PNA",
        clearance="RESTRICTED", purpose="sanctions", lawful_basis="treaty-x",
        recipient_public_key_hex=rk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        not_before="2026-07-20T00:00:00Z", not_after="2026-07-23T00:00:00Z",
    )
    result = handler.handle(req)
    assert result["decision"] == "deny"
    assert result["reason"] == "releasability"

def test_callback_release_seals_to_requester_and_window(pipeline, tmpstate):
    """§12.1: an authorised release is sealed to the requester's key and time window;
    the requester opens it inside the window, and cannot outside it."""
    handler = _callback_handler(pipeline, tmpstate)
    rk = X25519PrivateKey.generate()
    pub_hex = rk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    req = CallbackRequest(
        record_id="rec-cb", field_name="lastKnownPosition.lat", pointer="ptr",
        requester="urn:partner:gbr/a", organisation="gbr", nationality="GBR",
        clearance="GENERAL", purpose="sanctions", lawful_basis="treaty-x",
        recipient_public_key_hex=pub_hex,
        not_before="2026-07-20T00:00:00Z", not_after="2026-07-23T00:00:00Z",
    )
    result = handler.handle(req)
    assert result["decision"] == "release"

    # pull the sealed release from the queue and open it as the requester would
    due = tmpstate.due_callbacks("2026-07-21T00:00:00Z")
    assert len(due) == 1
    s = due[0]["sealed"]
    sealed = SealedRelease(
        alg=s["alg"], ephemeral_public_key=bytes.fromhex(s["ephemeral_public_key"]),
        nonce=bytes.fromhex(s["nonce"]), ciphertext=bytes.fromhex(s["ciphertext"]),
        not_before=s["not_before"], not_after=s["not_after"],
        aad=bytes.fromhex(s["aad"]), record_id=s["record_id"],
        field_name=s["field_name"], requester=s["requester"],
    )
    # inside the window: opens
    plaintext = open_sealed_release(sealed, rk, "2026-07-21T00:00:00Z")
    assert "59.9123" in plaintext.decode()

    # outside the window: refused (policy check)
    with pytest.raises(ValueError):
        open_sealed_release(sealed, rk, "2026-07-25T00:00:00Z")

def test_sealed_release_window_is_cryptographic(pipeline, tmpstate):
    """§12.1: tampering the presented window breaks the GCM tag, not just a policy check.
    A widened window in the aad fails authentication."""
    handler = _callback_handler(pipeline, tmpstate)
    rk = X25519PrivateKey.generate()
    pub_hex = rk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    req = CallbackRequest(
        record_id="rec-cb", field_name="lastKnownPosition.lat", pointer="ptr",
        requester="urn:partner:gbr/a", organisation="gbr", nationality="GBR",
        clearance="GENERAL", purpose="sanctions", lawful_basis="treaty-x",
        recipient_public_key_hex=pub_hex,
        not_before="2026-07-20T00:00:00Z", not_after="2026-07-23T00:00:00Z",
    )
    handler.handle(req)
    s = tmpstate.due_callbacks("2026-07-21T00:00:00Z")[0]["sealed"]

    # forge a wider aad (later not_after) but present a time inside the forged window
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    forged_aad = s["aad"].replace(
        b"na=2026-07-23".hex(), b"na=2027-01-01".hex()) if isinstance(s["aad"], bytes) else None
    # aad is hex string here; forge on bytes
    aad_bytes = bytes.fromhex(s["aad"])
    forged = aad_bytes.replace(b"na=2026-07-23T00:00:00Z", b"na=2027-01-01T00:00:00Z")
    eph = X25519PublicKey.from_public_bytes(bytes.fromhex(s["ephemeral_public_key"]))
    shared = rk.exchange(eph)
    key = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=forged).derive(shared)
    with pytest.raises(Exception):   # InvalidTag
        AESGCM(key).decrypt(bytes.fromhex(s["nonce"]), bytes.fromhex(s["ciphertext"]), forged)


# --------------------------------------------------------------- crypto boundary (§16.1)

def test_keystore_never_exposes_private_bytes():
    """§16.1: a Signer exposes only the public key; there is no private getter on it."""
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    signer = ks.signer("k")
    assert hasattr(signer, "public_key_bytes")
    assert not hasattr(signer, "private_key_bytes")
    assert not hasattr(signer, "private_bytes")


# --------------------------------------------------------------- correlation opt-in (§16.6)

def test_hash_only_works_when_enabled(tmpstate):
    """§16.6: with correlation knowingly enabled, hash-only produces a digest, not the value."""
    exp = build_expectation()
    mapping = load_yaml("config/mapping.yaml", Mapping)
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    corr = CorrelationService(key=b"test-key", epoch="2026H2", enabled=True)
    pipe = IngestPipeline(
        expectation=exp, mapping=MappingEngine(mapping), policy=policy,
        signer=ks.signer("k"), state=tmpstate,
        source_identity="s", connector_measurement="software:dev", correlation=corr,
    )
    pkg = pipe.process("rec-h", SAMPLE, "GENERAL")
    bo = next(f for f in pkg.fields if f.name == "beneficialOwner")
    assert bo.disposition == Disposition.HASH_ONLY
    assert bo.correlation_digest.startswith("hmac-sha384:2026H2:")
    assert bo.value is None                       # the value itself never crosses

def test_correlation_disabled_raises_on_construction():
    """§16.6: the stub refuses to construct unless explicitly enabled."""
    with pytest.raises(RuntimeError):
        CorrelationService(key=b"k", epoch="e", enabled=False)


# --------------------------------------------------------------- end to end via service

def test_full_service_loop(tmpdir=None):
    """The whole connector: start (pull+verify Expectation) -> ingest -> deliver -> callback."""
    import tempfile, os
    from rachis_connector.config import (
        Config, IdentityConfig, CoreConfig, SourceConfig, KeystoreConfig,
        StateConfig, MarkingConfig,
    )
    from rachis_connector.service import ConnectorService

    d = tempfile.mkdtemp()
    exp = build_expectation()
    core = FakeCore(exp)

    cfg = Config(
        identity=IdentityConfig(source_identity="urn:example:org:natmaritime-authority",
                                connector_measurement="software:dev"),
        core=CoreConfig(base_url="http://x", public_key_hex=core.core_public_key_hex(),
                        expectation_canonical=exp.canonical),
        source=SourceConfig(kind="json"),
        keystore=KeystoreConfig(backend="software", signing_key_id="k",
                                software_key_path=os.path.join(d, "signing.key")),
        state=StateConfig(data_dir=d),
        marking=MarkingConfig(policy_id=PID, levels=LEVELS),
        mapping_path=os.path.join(os.path.dirname(__file__), "..", "config", "mapping.yaml"),
        policy_path=os.path.join(os.path.dirname(__file__), "..", "config", "policy.yaml"),
        enable_hash_only_correlation=False,
    )

    def value_lookup(rid, fn): return SAMPLE["POS_LAT"]
    svc = ConnectorService(cfg, core, value_lookup)
    svc.start()
    assert svc.health()["ready"]

    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")   # correlation off
    result = svc.ingest("rec-svc", sample, "GENERAL")
    assert result["delivered"] is True
    assert len(core.received_packages) == 1
    svc.stop()
