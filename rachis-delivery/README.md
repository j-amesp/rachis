# RACHIS — reference implementation and source-side connector

Running proof that the thesis *Disclosure Without Surrender* is buildable in simple,
effective Python. Two codebases:

- **`rachis-reference/`** — the **Spiral 0 reference core**. A minimal but real implementation
  of all eight normative contracts, proving the mechanism end to end. 33 tests.
- **`connector/`** — the **production-shaped source-side connector**. The deployable product
  that ships to source systems: receives a signed Expectation from core, transforms source
  JSON into it, applies a source-authored disclosure policy, binds and signs a Merkle
  selective-disclosure package, and answers callbacks by sealing to the requester's key with a
  cryptographically bound time window. 34 tests (19 functional + 15 security).

The platform side is deliberately out of scope. The whole argument of RACHIS is that a source
needs nothing from the platform but a published contract and a public key.

## Start here

```bash
pip install pydantic cryptography pytest pyyaml

cd rachis-reference && python -m pytest tests/ -q      # 33 pass — the eight contracts
cd ../connector     && python -m pytest tests/ -q      # 34 pass — the product
```

Then read **`INSTRUCTIONS.md`**, which walks through what every test proves and how to drive
the connector by hand.

## What flips the argument

The connector is the artefact that matters, because it is the *inverted control* made real: it
runs inside the source estate, under the source owner's change control, small enough to read
and declarative enough to audit. A source owner can see exactly what would leave — before
anything leaves — by running one offline command. That is the property every other assurance
in RACHIS rests on, and here it is executable.

## Honesty

These codebases are built to production engineering standards and are written to be *taken to*
accreditation. They are **not accredited**, and tests written and run against their own code
are **not independent assurance**. `connector/docs/THREAT_MODEL.md` states exactly what a real
deployment still requires — a real HSM, validated post-quantum signing, the §16.6 correlation
resolution, TEE attestation, mTLS, and an independent security review. Where the thesis says a
thing is unsolved, the code says so too, in the same words.

## Licence

MIT — see `LICENSE.md`. Permissive on purpose: the exchange layer should be public
infrastructure anyone can implement, fork, and take to their own accreditation. A restrictive
licence would contradict the thesis.
