# RACHIS reference core — build plan

A minimal but real implementation of the eight normative contracts, exercised end to end
on the Appendix A maritime vessel example. Every claim in Part III of the thesis maps to a
passing test.

## Package layout

    rachis/
      __init__.py
      trust.py         # Trust    — Signer interface, Ed25519 impl (ML-DSA stand-in), salt store
      model.py         # Model    — Expectation, fields, obligations, marking rules, versioning
      labels.py        # (shared) — label + marking arithmetic (high-water, caveat union)
      provenance.py    # Provenance — Merkle tree, inclusion proofs, five-part header, package
      policy.py        # Policy   — four dispositions, derivation constraints w/ granularity
      connect.py       # Connect  — mapping engine, transform library, validator, connector
      ingress.py       # Ingress  — nine-check verification sequence
      assertions.py    # Assertions — append-only store, six timestamps, supersession/withdrawal,
                       #              identity projection with pinning
      disclosure.py    # Disclosure — callback: authorise / deny / revoke
    examples/
      maritime.py      # the Appendix A vessel: Expectation, mapping, policy, one record
    tests/
      test_*.py        # one file per contract + one end-to-end

## Contract → module → thesis claim

| Contract | Proves (thesis §) |
|---|---|
| Trust | signing at source; platform holds no signing key (§16.1) |
| Model | Expectation is versioned, offline-loadable, marking-required (§8) |
| Provenance | Merkle selective disclosure; withheld leaf reveals nothing (§10.4); five-part header (§10.5, D4) |
| Policy | four dispositions; derivation w/ granularity; secondary suppression (§9.3–9.5) |
| Connect | declarative mapping; validator proposes derivations offline (§9.2, §9.6); withheld never enters pipeline (§9.4) |
| Ingress | nine checks; verifies not classifies; rejects unmarked (§11.1–11.3) |
| Assertions | identity is a projection; pinning; supersession ≠ withdrawal; cascade (§13, §14) |
| Disclosure | callback refused; value released post-hoc still verifies vs original root (§12.1) |

## Deliberately stubbed (flagged in code)

- Threshold OPRF correlation (§16.6) — interface + single-key stand-in, documented.
- ML-DSA / SLH-DSA — Ed25519 behind `Signer`; swap point is one class.
- TEE attestation (§16.3) — connector measurement is a recorded constant, checked against an allow-list.
- Index — in-memory dict, not OpenSearch.
- Graph / AI / Studio — out of scope for the core.

## Design rules

- Pure standard library + pydantic + cryptography. No framework.
- Every public function has a docstring stating what it proves and citing the thesis section.
- Withheld means absent: withheld fields are dropped before the package is built, never carried.
- Deterministic canonical ordering everywhere a hash depends on it (D5).
- Tests are assertions about the thesis, not about the code's own conveniences.
