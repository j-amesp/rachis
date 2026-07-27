"""
RACHIS source-side connector.

A production-shaped, deployable connector that ships to source systems. It receives a signed
Expectation from the core system, transforms source JSON into that Expectation's schema,
applies a source-authored disclosure policy, binds and signs the result (pre-PQC crypto
designed for the source environment, HSM-ready), and ships it to core. It answers callback
requests for withheld information by checking RBAC/ABAC, sealing the value to the requester's
public key with a cryptographically bound time window, and queueing it for core to release.

This implements the source side of the thesis "Disclosure Without Surrender". The platform
side is out of scope by design — the whole point is that the source needs nothing from the
platform but a published contract and a public key.

Onwards-developable: the crypto backend (crypto/pkcs11_stub.py), the source adapter, and the
correlation service (§16.6 threshold OPRF) are the three seams a production implementer
completes. Each is small and clearly marked.
"""

__version__ = "0.1.0"
