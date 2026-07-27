# RACHIS source-side connector

A production-shaped, deployable connector that ships to source systems and implements the
source side of the thesis *Disclosure Without Surrender*. It lets a source owner participate
in a federated exchange **without surrendering control of their data** — the whole argument
of RACHIS made into running software.

The connector:

- **receives a signed Expectation** from the core system and verifies it against core's
  public key before caching it (source-initiated, never pushed);
- **transforms source JSON** into the Expectation schema through a *declarative* mapping —
  named library transforms only, no code;
- **applies a source-authored disclosure policy** — four dispositions (clear / hash-only /
  pointer / withheld) plus derivation constraints that enforce secondary suppression;
- **binds and signs** the result as a Merkle selective-disclosure package (pre-PQC crypto,
  HSM-ready), so a recipient can verify released fields without learning anything about the
  withheld ones;
- **answers callbacks** for withheld information by checking RBAC/ABAC and sealing the value
  to the requester's public key with a **cryptographically bound time window**, then queueing
  it for core to release when the window opens.

The platform side is deliberately **out of scope**. The point of RACHIS is that a source
needs nothing from the platform but a published contract and a public key.

## The loop, in one line

```
Expectation (pulled, verified) → map (declarative) → policy (dispositions + derivations)
  → bind & sign (Merkle root) → deliver to core → callback (RBAC/ABAC → seal to requester + window)
```

## Install

```bash
pip install pydantic cryptography pytest pyyaml
```

Python 3.11+. No framework, no server dependency. SQLite (standard library) backs durable
state. Air-gap installable — vendor the four wheels and go.

## Run the tests

```bash
cd connector
python -m pytest tests/ -v          # 34 tests: 19 functional + 15 security
```

See `INSTRUCTIONS.md` for a full walkthrough of what each test proves.

## Operate it (CLI)

```bash
# offline: does the mapping compile, does the policy validate, what would leave?
python -m rachis_connector.cli --config config/connector.yaml validate --sample vessel.json

# generate the source signing key; register the printed public key with core
python -m rachis_connector.cli --config config/connector.yaml keygen

# readiness, and the local audit log
python -m rachis_connector.cli --config config/connector.yaml health
python -m rachis_connector.cli --config config/connector.yaml audit
```

Everything is config-driven. A source administrator operates the connector without writing
code — which is the point: the connector is small enough to read and declarative enough to
audit.

## Layout

```
rachis_connector/
  crypto/         interfaces (HSM boundary), software impl, PKCS#11 stub, Merkle binding
  models.py       Expectation, mapping, policy, callback — Pydantic value objects
  config.py       typed config; secrets from ${ENV}, never from the file
  state/          SQLite salt store, audit, callback queue, outbound queue (durable)
  pipeline/       transforms, mapping engine, policy engine, binder, ingest orchestration
  callback/       RBAC/ABAC access rules, and the seal-and-queue handler
  core/           Expectation intake + delivery with an offline retry queue
  service.py      the wired connector: start / ingest / callback / tick / health / stop
  cli.py          the operator command line
config/           connector.yaml, mapping.yaml, policy.yaml (the maritime example)
tests/            functional + security suites
docs/             THREAT_MODEL.md and operator guidance
```

## The three seams a production implementer completes

This is a real, onwards-developable connector, not a demo. Three things are deliberately
stubbed, each small, each clearly marked in code:

1. **The HSM.** `crypto/software.py` keeps keys in process because there is no hardware here.
   `crypto/pkcs11_stub.py` is the drop-in shape for a real module — complete three methods,
   set `keystore.backend: pkcs11`, and nothing above `crypto/interfaces.py` changes.

2. **Post-quantum signing.** Ed25519 stands in for ML-DSA behind the `Signer` interface. The
   swap is one class; the wire format already carries an `algorithm` field.

3. **Hash-only correlation.** `pipeline/policy.py` ships a single-key HMAC stand-in for the
   thesis §16.6 threshold OPRF. It is **disabled by default** and refuses to construct unless
   explicitly enabled, because a single shared key permits offline enumeration of low-entropy
   values. Do not ship it enabled until the threshold scheme replaces it.

## What this is, and what it is not

This connector is built to production engineering standards — durable state, real crypto,
typed config, an offline queue, a security test suite, a threat model. It is written to be
taken to accreditation by a security team.

It is **not itself accredited**, and the security tests here — written and run against this
same code — are **not independent assurance**. `docs/THREAT_MODEL.md` states plainly what a
real deployment still requires: independent security testing, TEE attestation against actual
hardware, accreditation against a specific deployment's threat model, and the §16.6
correlation resolution. Claiming otherwise would be exactly the kind of unearned assurance
the thesis is built against.

## Licence

MIT. See `LICENSE.md`. Permissive on purpose: the argument of RACHIS is that the exchange
layer should be public infrastructure that anyone can implement, fork, and take to their own
accreditation. A restrictive licence on the connector would contradict the thesis.
