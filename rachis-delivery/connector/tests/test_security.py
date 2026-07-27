"""
Connector security test suite.

These are the adversarial tests a security reviewer would demand before this connector went
near an accreditation. They are NOT an accreditation, and running tests I wrote against code
I wrote is not independent assurance (see docs/THREAT_MODEL.md). They exist to make the
security-relevant properties explicit and regression-proof.

Grouped by the property under attack:
  * forgery and tampering of the disclosure package
  * the disclosure boundary (withheld means absent)
  * the callback seal (wrong key, wrong window, tampered window)
  * the crypto boundary (no key exfiltration path)
  * input robustness (malformed source data, injection-shaped strings)
  * salt-store integrity (the callback depends on it)

Run: pytest tests/test_security.py -v
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from rachis_connector.models import (
    Expectation, FieldSpec, MarkingRequirement, Obligation, Mapping,
    DisclosurePolicySpec, CallbackRequest,
)
from rachis_connector.crypto.merkle import Disposition, Label, MerkleTree, leaf_hash, h
from rachis_connector.crypto.software import (
    SoftwareKeyStore, SoftwareSealer, open_sealed_release, Ed25519Verifier,
)
from rachis_connector.crypto.interfaces import SealedRelease
from rachis_connector.state.store import StateStore
from rachis_connector.pipeline.mapping import MappingEngine
from rachis_connector.pipeline.ingest import IngestPipeline, IngestError

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(__file__))
from test_connector import build_expectation, load_yaml, SAMPLE, LEVELS, PID


@pytest.fixture
def tmpstate():
    d = tempfile.mkdtemp()
    st = StateStore(os.path.join(d, "t.db"))
    yield st
    st.close()


@pytest.fixture
def package_and_verifier(tmpstate):
    exp = build_expectation()
    mapping = load_yaml("config/mapping.yaml", Mapping)
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    pipe = IngestPipeline(
        expectation=exp, mapping=MappingEngine(mapping), policy=policy,
        signer=ks.signer("k"), state=tmpstate, source_identity="s",
        connector_measurement="software:dev",
    )
    sample = dict(SAMPLE); sample.pop("OWNR_BEN_NM")
    pkg = pipe.process("rec-sec", sample, "GENERAL")
    ver = Ed25519Verifier(ks.signer("k").public_key_bytes())
    return pkg, ver


# --------------------------------------------------------------- forgery / tampering

def test_tampered_value_breaks_inclusion_proof(package_and_verifier):
    """Changing a released value must break its proof against the root (integrity)."""
    pkg, _ = package_and_verifier
    root = bytes.fromhex(pkg.root_hex)
    f = next(x for x in pkg.fields if x.disposition == Disposition.CLEAR)
    label = Label(f.label.policy_id, f.label.classification, tuple(f.label.caveats))
    forged_leaf = leaf_hash(f.name, Disposition.CLEAR, "TAMPERED", label, f.salt)
    assert not MerkleTree.verify(forged_leaf, f.inclusion_proof, root)

def test_forged_signature_rejected(package_and_verifier):
    """A zero signature must not verify against the root."""
    pkg, ver = package_and_verifier
    assert not ver.verify(bytes.fromhex(pkg.root_hex), bytes(64))

def test_tampered_root_breaks_signature(package_and_verifier):
    """Flipping the root must break the signature over it."""
    pkg, ver = package_and_verifier
    bad = bytearray(bytes.fromhex(pkg.root_hex)); bad[0] ^= 0xFF
    assert not ver.verify(bytes(bad), bytes.fromhex(pkg.signature_hex))

def test_swapped_inclusion_proof_fails(package_and_verifier):
    """A proof from one field must not validate another field's leaf."""
    pkg, _ = package_and_verifier
    root = bytes.fromhex(pkg.root_hex)
    clears = [x for x in pkg.fields if x.disposition == Disposition.CLEAR]
    if len(clears) < 2:
        pytest.skip("need two clear fields")
    a, b = clears[0], clears[1]
    la = Label(a.label.policy_id, a.label.classification, tuple(a.label.caveats))
    leaf_a = leaf_hash(a.name, Disposition.CLEAR, a.value_repr, la, a.salt)
    assert not MerkleTree.verify(leaf_a, b.inclusion_proof, root)


# --------------------------------------------------------------- disclosure boundary

def test_no_withheld_value_anywhere_in_wire(package_and_verifier):
    """The serialised package must contain no withheld value. Whole-blob check."""
    pkg, _ = package_and_verifier
    blob = json.dumps(pkg.model_dump(), default=str)
    # collectionMeans was absent; assessment.summary was a pointer -> its text must not appear
    assert "STS transfers" not in blob            # assessment.summary value (pointer)
    # position values are pointer -> the precise coordinate must not appear
    assert "59.9123" not in blob

def test_pointer_leaf_has_no_recoverable_value(package_and_verifier):
    """A pointer field's wire form carries no value or value_repr."""
    pkg, _ = package_and_verifier
    for f in pkg.fields:
        if f.disposition == Disposition.POINTER:
            assert f.value is None
            assert f.value_repr is None
            assert f.salt is None                 # salt stays at source (D1)


# --------------------------------------------------------------- callback seal

def _sealed():
    sealer = SoftwareSealer()
    rk = X25519PrivateKey.generate()
    pub = rk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sealed = sealer.seal(b"secret-position", pub,
                         "2026-07-20T00:00:00Z", "2026-07-23T00:00:00Z", b"ctx")
    return sealed, rk

def test_seal_opens_only_with_correct_key():
    """A sealed release must not open with a different private key."""
    sealed, rk = _sealed()
    wrong = X25519PrivateKey.generate()
    with pytest.raises(Exception):
        open_sealed_release(sealed, wrong, "2026-07-21T00:00:00Z")

def test_seal_refuses_outside_window():
    """The policy window is enforced on open."""
    sealed, rk = _sealed()
    with pytest.raises(ValueError):
        open_sealed_release(sealed, rk, "2026-07-25T00:00:00Z")
    with pytest.raises(ValueError):
        open_sealed_release(sealed, rk, "2026-07-19T00:00:00Z")

def test_seal_window_tampering_breaks_auth():
    """Widening the window in the aad breaks the GCM tag — the binding is cryptographic."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    sealed, rk = _sealed()
    forged = sealed.aad.replace(b"na=2026-07-23T00:00:00Z", b"na=2099-01-01T00:00:00Z")
    eph = X25519PublicKey.from_public_bytes(sealed.ephemeral_public_key)
    key = HKDF(algorithm=hashes.SHA384(), length=32, salt=None,
               info=forged).derive(rk.exchange(eph))
    with pytest.raises(Exception):
        AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, forged)


# --------------------------------------------------------------- crypto boundary

def test_no_private_key_getter_on_signer():
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    s = ks.signer("k")
    for attr in ("private_bytes", "private_key", "private_key_bytes", "_sk"):
        # _sk exists internally but is not a public accessor; ensure no public getter
        assert not (hasattr(s, attr) and attr in ("private_bytes", "private_key",
                                                  "private_key_bytes"))

def test_pkcs11_stub_refuses_use():
    """The HSM stub must fail closed, not silently no-op."""
    from rachis_connector.crypto.pkcs11_stub import PKCS11KeyStore
    ks = PKCS11KeyStore("lib", 0, "pin")
    with pytest.raises(NotImplementedError):
        ks.signer("k")


# --------------------------------------------------------------- input robustness

def test_malformed_source_row_does_not_crash(tmpstate):
    """Garbage source input yields a clean IngestError, never an unhandled exception."""
    exp = build_expectation()
    mapping = load_yaml("config/mapping.yaml", Mapping)
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    pipe = IngestPipeline(
        expectation=exp, mapping=MappingEngine(mapping), policy=policy,
        signer=ks.signer("k"), state=tmpstate, source_identity="s",
        connector_measurement="software:dev",
    )
    # missing required fields entirely
    with pytest.raises(IngestError):
        pipe.process("rec-bad", {"NONSENSE": object()}, "GENERAL")

def test_injection_shaped_strings_are_data_not_code(tmpstate):
    """A source value that looks like an injection is treated as an opaque string.
    The mapping is declarative; there is no eval path for source data to reach."""
    exp = build_expectation()
    mapping = load_yaml("config/mapping.yaml", Mapping)
    policy = load_yaml("config/policy.yaml", DisclosurePolicySpec)
    ks = SoftwareKeyStore(); ks.generate_signing_key("k")
    pipe = IngestPipeline(
        expectation=exp, mapping=MappingEngine(mapping), policy=policy,
        signer=ks.signer("k"), state=tmpstate, source_identity="s",
        connector_measurement="software:dev",
    )
    evil = dict(SAMPLE); evil.pop("OWNR_BEN_NM")
    evil["VSL_NM"] = "'; DROP TABLE vessels;-- {{7*7}} ${jndi:ldap://x}"
    pkg = pipe.process("rec-evil", evil, "GENERAL")
    name_field = next(f for f in pkg.fields if f.name == "currentName")
    # the value is carried verbatim as data, upper-cased by the mapping, nothing executed
    assert "DROP TABLE" in name_field.value


# --------------------------------------------------------------- salt-store integrity

def test_salt_persists_across_store_reopen():
    """The callback depends on salt persistence (D1). A reopened store yields the same salt."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "s.db")
    st1 = StateStore(path)
    s1 = st1.salt_for("rec", "field")
    st1.close()
    st2 = StateStore(path)
    s2 = st2.salt_for("rec", "field")
    st2.close()
    assert s1 == s2

def test_binding_persists_for_callback_proof():
    """The bound leaf order/hashes must survive so a later callback can prove against root."""
    d = tempfile.mkdtemp()
    st = StateStore(os.path.join(d, "s.db"))
    st.save_binding("rec", ["__header__", "f"], ["aa", "bb"], "cc", "dd")
    b = st.get_binding("rec")
    assert b["ordered_names"] == ["__header__", "f"]
    assert b["root_hex"] == "cc"
    st.close()
