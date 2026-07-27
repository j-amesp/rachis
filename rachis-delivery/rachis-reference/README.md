# RACHIS reference core

A minimal but real implementation of the eight normative contracts from the thesis
*Disclosure Without Surrender*, exercised end to end on the Appendix A maritime vessel
example. This is Spiral 0 of the roadmap (thesis §22.3): the walking skeleton, built with
working functions and real tests rather than mocks.

It exists to answer one question — *is the mechanism buildable in simple, effective Python?*
— and to answer it by running rather than asserting.

## Run it

    pip install pydantic cryptography pytest
    python -m pytest tests/ -v        # 33 tests, each named for the thesis claim it proves
    python -m examples.maritime       # the A.6–A.9 walkthrough

## The loop

The whole of Part III, executable, in `test_full_loop`:

    Expectation ──pull──▶ Mapping ──▶ Disclosure Policy ──▶ Derivation check
        ──▶ Bind & Sign (Merkle root, one signature) ──▶ [boundary] ──▶ Ingress (9 checks)
        ──▶ Index as assertions ──▶ Read-time projection ──▶ Callback (refused)

## Contract → module → proof

| Contract | Module | Key tests |
|---|---|---|
| Trust | `trust.py` | platform holds no signing key; salt is stable for callback |
| Model | `model.py` | offline validation; rejects missing required field |
| Policy | `policy.py` | default withheld; **unresolved exact derivation blocks**; withheld value dropped before pipeline |
| Provenance | `provenance.py` | inclusion proof verifies; withheld field absent; five-part header |
| Connect | `connect.py` | validator proposes library derivation; runs offline |
| Ingress | `ingress.py` | admits valid; rejects forged signature / bad attestation / replay; **does not classify** |
| Assertions | `assertions.py` | identity is a projection; supersession ≠ withdrawal; withdrawal cascades; pinning survives split |
| Disclosure | `disclosure.py` | callback refused on releasability; **released leaf verifies against the original root** |

## The two results worth looking at

**Secondary suppression is enforced, not decorative.** The maritime policy validates. Undo
the one demotion the appendix made — put `lastKnownPosition.observedAt` back to `clear` —
and the policy refuses to run, naming `collectionMeans` as reconstructible. That is thesis
§9.5 as an executable check.

**A callback released months later still verifies against the original signature.** Because
the source persists the salt (defect D1), it rebuilds the identical leaf, and the value
released after ingest verifies against the root the platform already holds — no re-signing.
That is thesis §12.1, in `test_callback_release_reconstructs_original_leaf`.

## What is stubbed, and where

Flagged in-code at each site:

- **Threshold OPRF correlation** (§16.6) — `policy.CorrelationService` uses a single HMAC
  key. Production splits it t-of-m across sovereign members; the single key permits offline
  enumeration and must not ship.
- **ML-DSA / SLH-DSA** (§10.3) — `trust.Ed25519Signer` stands in behind the `Signer`
  interface. The swap is one class; `algorithm` already records what a real package carries.
- **TEE attestation** (§16.3) — the connector measurement is a recorded constant checked
  against an allow-list at ingress.
- **Index** — in-memory; production is OpenSearch (§22.2).
- **Graph / AI / Studio** — out of scope for the core.

None of the stubs is load-bearing for the claims the tests make.

## Design rules held throughout

- Pure standard library + pydantic + cryptography. No framework.
- Every public function docstring cites the thesis section it proves.
- Withheld means absent: withheld values are dropped before binding, never carried.
- Deterministic canonical ordering wherever a hash depends on it (defect D5).
- Tests assert thesis claims, not the code's own conveniences.
