"""
RACHIS reference core.

A minimal but real implementation of the eight normative contracts from the thesis
"Disclosure Without Surrender", exercised on the Appendix A maritime vessel example.

This is Spiral 0 of the roadmap (thesis §22.3): the walking skeleton, built with real
functions and real tests rather than mocked. It proves the Part III loop end to end —
publish Expectation, map, decide disclosure, check derivations, bind, sign, verify, index,
assert, project, callback, refuse — and every test is an assertion about a thesis claim.

Deliberately out of scope (each flagged where it occurs):
  - threshold OPRF correlation (§16.6)  -> single-key stand-in in policy.CorrelationService
  - ML-DSA / SLH-DSA (§10.3)            -> Ed25519 behind trust.Signer
  - TEE attestation (§16.3)             -> recorded measurement + allow-list
  - OpenSearch index                    -> in-memory
  - graph / AI / Studio layers
"""

from .model import Expectation, FieldSpec, MarkingRequirement, Obligation
from .labels import Label, MarkingPolicy, high_water
from .trust import Ed25519Signer, TrustStore, SaltStore
from .policy import (
    DisclosurePolicy, DerivationConstraint, Granularity, CorrelationService, apply_policy,
)
from .provenance import Binder, FivePartHeader, DisclosurePackage, Disposition, MerkleTree
from .connect import Connector, Mapping, FieldMapping, Validator, TRANSFORMS
from .ingress import Ingress
from .assertions import AssertionStore, Assertion, AssertionType
from .disclosure import (
    CallbackHandler, CallbackRequest, Decision,
    deny_below_clearance, deny_purpose, require_releasable_to,
)

__all__ = [
    "Expectation", "FieldSpec", "MarkingRequirement", "Obligation",
    "Label", "MarkingPolicy", "high_water",
    "Ed25519Signer", "TrustStore", "SaltStore",
    "DisclosurePolicy", "DerivationConstraint", "Granularity", "CorrelationService",
    "apply_policy",
    "Binder", "FivePartHeader", "DisclosurePackage", "Disposition", "MerkleTree",
    "Connector", "Mapping", "FieldMapping", "Validator", "TRANSFORMS",
    "Ingress",
    "AssertionStore", "Assertion", "AssertionType",
    "CallbackHandler", "CallbackRequest", "Decision",
    "deny_below_clearance", "deny_purpose", "require_releasable_to",
]
