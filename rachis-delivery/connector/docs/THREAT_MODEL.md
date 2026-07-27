# RACHIS connector — threat model

This document states what the connector defends against, what it does not, and what a real
deployment must still do before it goes near classified or otherwise regulated information.
It is written to be read by a security team, an accreditor, and the next implementer — and to
say the uncomfortable things before they find them.

## Honest framing first

The security tests in `tests/test_security.py` were written and are run against this same
codebase. **That is not independent assurance.** It regression-proofs the security-relevant
properties and makes them explicit; it is not a penetration test, a formal review, or an
accreditation. A real deployment needs all three, performed by people who did not write this
code.

## What the connector is trusted to do

The connector runs inside the source estate, under the source owner's change control. It is
trusted by the source owner, because they deploy it, can read it (it is small and declarative
on purpose), and can attest its measurement. The trust boundary is the **disclosure
boundary**: everything the connector emits crosses to core, and the security claim is about
what does and does not cross.

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Source signing key | HSM (software stand-in here) | Never leaves custody; no exfiltration path in the interface |
| Withheld field values | Source system only | Never enter the pipeline; never in a package |
| Pointer/withheld salts | Durable salt store, source-side | Needed to honour callbacks; sensitive; must be backed up and marked |
| The disclosure policy | Signed artefact, source-side | Determines what may leave; its hash travels with every package |
| Sealed callback releases | Queued, then handed to core | Opens only with the requester's key, only within the bound window |

## Threats considered, and the defence

**T1 — Forged or tampered disclosure package.**
A package's Merkle root is signed once. Tampering any released value breaks its inclusion
proof against the root; tampering the root breaks the signature. Core verifies both.
*Tests: `test_tampered_value_breaks_inclusion_proof`, `test_tampered_root_breaks_signature`,
`test_forged_signature_rejected`, `test_swapped_inclusion_proof_fails`.*

**T2 — Withheld data leaking across the boundary.**
Withheld fields never enter the pipeline. Pointer fields carry a pointer and no value, no
value-repr, and no salt. A whole-package serialisation is checked to contain no withheld
value or precise coordinate.
*Tests: `test_no_withheld_value_anywhere_in_wire`, `test_pointer_leaf_has_no_recoverable_value`,
`test_withheld_absent_from_package`, `test_pointer_carries_no_value`.*

**T3 — Unauthorised callback release.**
Every callback is evaluated against a conjunction of RBAC/ABAC rules; any failing rule denies,
and the denial reason is a category, never an explanation. Nothing is sealed on a denial.
*Tests: `test_callback_denied_on_releasability`.*

**T4 — Callback release opened by the wrong party or at the wrong time.**
The release is sealed to the requester's X25519 public key (wrong key cannot open it) and the
time window is bound into the AEAD associated data. Presenting a widened window breaks the GCM
tag — the time binding is **cryptographic, not advisory**. The connector holds no key that
can reopen the sealed release.
*Tests: `test_seal_opens_only_with_correct_key`, `test_seal_refuses_outside_window`,
`test_seal_window_tampering_breaks_auth`, `test_sealed_release_window_is_cryptographic`.*

**T5 — A malicious or unsigned Expectation from core (or a core impersonator).**
The Expectation is verified against core's configured public key before it is cached. A bad
signature is refused.
*Tests: `test_tampered_expectation_refused`.*

**T6 — Signing-key exfiltration.**
The `Signer` interface exposes only the public key. There is no method that returns private
material. The software store's export exists only for restart persistence and is not on the
interface; a PKCS#11 module has no equivalent.
*Tests: `test_keystore_never_exposes_private_bytes`, `test_no_private_key_getter_on_signer`.*

**T7 — Malicious source input (injection, malformed rows).**
The mapping is declarative — named library transforms only, no eval path. An injection-shaped
string is carried as opaque data. Malformed input yields a clean error, never an unhandled
exception or a wrong emitted value.
*Tests: `test_injection_shaped_strings_are_data_not_code`, `test_malformed_source_row_does_not_crash`.*

**T8 — Loss of the salt store.**
Salts persist across restart in SQLite. Losing them means callbacks can no longer be honoured
(the leaf cannot be reconstructed against the original root). The salt store is therefore a
backup-and-integrity asset, not a cache.
*Tests: `test_salt_persists_across_store_reopen`, `test_binding_persists_for_callback_proof`.*

**T9 — Core unreachable.**
Packages are persisted to a durable outbound queue before any network attempt and retried;
the connector degrades rather than loses data.
*Tests: `test_offline_queue_then_flush`.*

## Threats NOT defended here — a real deployment must address these

**N1 — The HSM is a software stand-in.** Keys are in process. A real deployment uses a
PKCS#11 module (the stub shows exactly where). Until then, the signing key is only as safe as
the host.

**N2 — Signatures are classical (Ed25519).** ML-DSA/SLH-DSA are behind the interface but not
wired, because liboqs is not present. A real deployment validates the PQC path independently.

**N3 — Hash-only correlation is a single-key stand-in.** It permits offline enumeration of
low-entropy values and is disabled by default. **It must not ship enabled** until the thesis
§16.6 threshold OPRF replaces it.

**N4 — Connector measurement is a recorded constant.** Real attestation against SEV-SNP/TDX
is not performed here. Core's ingress check against a measurement allow-list is only as strong
as the attestation feeding it.

**N5 — Transport security.** The `Transport` interface is abstract; a real deployment uses
mTLS 1.3 with certificate pinning. None of that is exercised here.

**N6 — Host and supply chain.** Nothing here defends the host OS, the Python runtime, or the
dependency supply chain. Standard hardening, reproducible builds, and dependency pinning are a
deployment responsibility.

**N7 — Aggregation and differencing.** Out of scope for the connector by design (they are
platform-side and, per the thesis, provably not solvable in general). The connector's
per-record derivation constraints do not and cannot address cross-record disclosure.

## What "ready" means

This connector is ready to be *taken to* accreditation: it is small, inspectable, correct
against its own tests, and honest about its seams. It is not ready to *be trusted* with real
regulated data until N1–N6 are closed for the specific deployment and an independent team has
tested it. Those two sentences are the whole point.
