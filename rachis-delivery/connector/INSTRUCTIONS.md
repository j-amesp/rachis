# INSTRUCTIONS — testing RACHIS

This repository contains two runnable codebases that together demonstrate the thesis
*Disclosure Without Surrender*:

1. **`rachis-reference/`** — the **Spiral 0 reference core**: a minimal but real
   implementation of all **eight normative contracts**, proving the mechanism end to end.
2. **`connector/`** — the **production-shaped source-side connector**: the deployable product
   that ships to source systems.

This document tells anyone — a reviewer, an implementer, an accreditor — how to run and read
both. Every test is named for the thesis claim it proves, so the suites double as a checkable
index of the argument.

---

## 0. Prerequisites

```bash
python --version            # 3.11 or newer
pip install pydantic cryptography pytest pyyaml
```

No network, no server, no framework. Everything runs locally and offline.

---

## 1. The Spiral 0 reference core (eight contracts)

```bash
cd rachis-reference
python -m pytest tests/ -v          # 33 tests, all eight contracts
python -m examples.maritime         # the worked walkthrough
```

### What each contract's tests prove

The eight normative contracts from the thesis, and the tests that demonstrate each:

**Trust** (`trust.py`) — signing lives with the source; the platform cannot forge.
- `test_platform_holds_no_signing_key` — a Verifier has no `sign` method. Structural, not
  promised.
- `test_salt_is_stable_for_callback` — the same (record, field) yields the same salt, so a
  later callback can rebuild the leaf.

**Model** (`model.py`) — the Expectation is versioned and offline-testable.
- `test_expectation_offline_no_network` — validation is pure computation; no platform contact.
- `test_expectation_validates_conformant_record`, `test_expectation_rejects_missing_required_field`.

**Policy** (`policy.py`) — four dispositions, derivation constraints with granularity.
- `test_default_is_withheld` — a field with no disposition does not cross.
- `test_unresolved_exact_derivation_blocks` — **secondary suppression is enforced**: an
  unaccepted exact derivation of a protected field refuses to validate.
- `test_accepted_coarse_derivation_does_not_block` — a coarse derivation does not block a fine
  protection.
- `test_withheld_value_dropped_before_pipeline` — a withheld value never reaches the package.

**Provenance** (`provenance.py`) — Merkle selective disclosure, five-part header.
- `test_merkle_inclusion_proof_verifies` — released fields verify against the signed root.
- `test_withheld_field_absent_from_package`, `test_tree_shape_reveals_only_count` — the only
  thing tree shape reveals is the field count.
- `test_signature_covers_root`, `test_header_is_five_part`.

**Connect** (`connect.py`) — declarative mapping, offline validator.
- `test_validator_proposes_library_derivation` — the validator proposes a derivation the
  policy did not declare.
- `test_validator_runs_offline`.

**Ingress** (`ingress.py`) — the nine-check sequence; verify, don't classify.
- `test_ingress_admits_valid_package`.
- `test_ingress_rejects_forged_signature`, `test_ingress_rejects_unknown_measurement`,
  `test_ingress_rejects_replay`.
- `test_ingress_does_not_classify` — ingress has no `classify` or `relabel` method. Structural.

**Assertions** (`assertions.py`) — identity as projection; six timestamps.
- `test_identity_is_a_projection` — a profile is computed from assertions, not stored.
- `test_projection_label_is_high_water`.
- `test_supersession_keeps_history` vs `test_withdrawal_differs_from_supersession` —
  superseded ≠ withdrawn.
- `test_withdrawal_cascades_to_revalidation` — dependents are flagged, never deleted.
- `test_identity_pinning_survives_split` — a cited id still resolves after a split.

**Disclosure** (`disclosure.py`) — the callback.
- `test_callback_refused_on_releasability` — a request outside the caveat is denied.
- `test_callback_release_reconstructs_original_leaf` — a value released *after* ingest still
  verifies against the *original* signature, via the persisted salt. No re-signing.

**End to end**
- `test_full_loop` — the entire Part III loop in one test: map → disclose → bind → sign →
  verify → index → project → callback.

### The one result to look at

The reference core catches the thesis being sloppy and confirms it being right. Run this:

```bash
cd rachis-reference
python3 -c "
from examples.maritime import build_policy
from rachis import Disposition
pol = build_policy()
print('policy validates:', pol.validate() == [])
pol.dispositions['lastKnownPosition.observedAt'] = Disposition.CLEAR
pol.derivations[1].accepted = False
print('with suppression undone:', 'BLOCKS' if pol.validate() else 'passes')
for p in pol.validate(): print(' ', p)
"
```

The policy validates; undo the one secondary-suppression demotion the worked example made,
and it refuses to run, naming the reconstructible field. That is thesis §9.5 as an executable
check, not a paragraph.

---

## 2. The production connector

```bash
cd connector
python -m pytest tests/ -v                      # 34 tests total
python -m pytest tests/test_connector.py -v      # 19 functional
python -m pytest tests/test_security.py -v       # 15 security / adversarial
```

### Functional tests (`test_connector.py`) — what they prove

- **Offline & config** — `test_policy_validates_from_yaml`,
  `test_policy_blocks_when_suppression_undone`, `test_mapping_is_declarative` (an unknown
  transform fails at load, not at first record).
- **Ingest** — `test_ingest_produces_signed_package`, `test_withheld_absent_from_package`,
  `test_pointer_carries_no_value`, `test_clear_field_verifies_against_root`,
  `test_five_part_header`.
- **Correlation opt-in (§16.6)** — `test_hash_only_requires_opt_in` (fails safe when
  disabled), `test_hash_only_works_when_enabled` (produces a digest, never the value),
  `test_correlation_disabled_raises_on_construction`.
- **Expectation intake (§8.2)** — `test_expectation_verified_on_pull`,
  `test_tampered_expectation_refused`.
- **Delivery & offline (§22.3)** — `test_offline_queue_then_flush`.
- **Callback (§12.1)** — `test_callback_denied_on_releasability`,
  `test_callback_release_seals_to_requester_and_window`,
  `test_sealed_release_window_is_cryptographic`.
- **Crypto boundary (§16.1)** — `test_keystore_never_exposes_private_bytes`.
- **End to end** — `test_full_service_loop`: start (pull + verify Expectation) → ingest →
  deliver, through the wired `ConnectorService`.

### Security tests (`test_security.py`) — what they attack

Grouped by the property under attack; the full mapping is in `docs/THREAT_MODEL.md`.

- **Forgery / tampering** — tampered value breaks its proof; tampered root breaks the
  signature; a zero signature is rejected; a proof from one field does not validate another.
- **Disclosure boundary** — no withheld value or precise coordinate anywhere in the
  serialised package; pointer leaves carry no value, value-repr, or salt.
- **Callback seal** — opens only with the right key; refused outside the window; **widening
  the window in the AEAD breaks the GCM tag** (the time binding is cryptographic).
- **Crypto boundary** — no private-key getter on the signer; the PKCS#11 stub fails closed.
- **Input robustness** — injection-shaped strings are carried as opaque data (no eval path);
  malformed rows yield a clean error.
- **Salt-store integrity** — salts and bindings persist across store reopen, so callbacks
  survive a restart.

### Operate the connector by hand (CLI)

```bash
cd connector

# point the CLI at a config; the shipped example uses the maritime vessel
cat > /tmp/connector.yaml <<'YAML'
identity: {source_identity: "urn:example:org:natmaritime-authority", connector_measurement: "software:dev"}
core: {base_url: "https://core.example", public_key_hex: "00", expectation_canonical: "urn:rachis:expectation:maritime:vessel"}
source: {kind: "json"}
keystore: {backend: "software", signing_key_id: "source-signing", software_key_path: "/tmp/rachis/signing.key"}
state: {data_dir: "/tmp/rachis"}
marking: {policy_id: "urn:rachis:policy:nato-amoco-demo", levels: ["UNMARKED","RESTRICTED","GENERAL","SECRET"]}
mapping_path: "config/mapping.yaml"
policy_path: "config/policy.yaml"
enable_hash_only_correlation: false
YAML

# offline: does the mapping compile, does the policy validate, what would leave?
python -m rachis_connector.cli --config /tmp/connector.yaml validate

# generate the source signing key; register the printed public key with core
python -m rachis_connector.cli --config /tmp/connector.yaml keygen

# readiness
python -m rachis_connector.cli --config /tmp/connector.yaml health
```

`validate` is the most important command to try first: it is the **offline testability** the
thesis leans on (§8.4). A source owner runs it inside their own estate, with no connection to
the platform, and sees exactly what would leave — before anything leaves.

---

## 3. Reading order for a reviewer

If you have thirty minutes:

1. `rachis-reference/` → run the suite, then read `test_full_loop` and the
   secondary-suppression snippet in §1 above.
2. `connector/` → run both suites, then read `test_sealed_release_window_is_cryptographic`
   (the callback seal) and `test_tampered_expectation_refused` (Expectation intake).
3. `connector/docs/THREAT_MODEL.md` → the "Threats NOT defended here" section. That is where
   the honesty is, and it is the section that tells you what a real deployment still owes.

The suites are the argument made executable. If a test's name claims something the thesis
claims, and it passes, that part of the mechanism is real. Where the thesis says a thing is
unsolved — aggregation, the correlation key, real accreditation — the code says so too, in the
same words.
