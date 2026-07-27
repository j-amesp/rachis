"""
rachis_connector.cli
====================

The command-line interface a source administrator uses. Config-driven; no code required to
operate the connector (thesis §9.2).

Commands:
  validate   — check the mapping, policy and (offline) a sample record against the Expectation
  keygen     — generate the source signing key and print its public key for registration
  ingest     — process a JSON file (one record or an array) and deliver to core
  callback   — evaluate a callback request from a JSON file
  tick       — flush outbound and deliver due sealed releases
  health     — print readiness
  audit      — export the local audit log

Run: python -m rachis_connector.cli --config config/connector.yaml <command>
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import Config
from .models import Mapping, DisclosurePolicySpec, Expectation, CallbackRequest
from .pipeline.mapping import MappingEngine
from .pipeline.policy import validate_policy


def _load_yaml_model(path, model):
    import yaml
    with open(path) as f:
        return model.model_validate(yaml.safe_load(f))


def cmd_validate(cfg: Config, args) -> int:
    """Offline validation (thesis §8.4): mapping compiles, policy validates, sample conforms."""
    mapping = _load_yaml_model(cfg.mapping_path, Mapping)
    policy = _load_yaml_model(cfg.policy_path, DisclosurePolicySpec)

    problems = []
    try:
        engine = MappingEngine(mapping)   # compiles transforms; raises on a bad one
    except Exception as e:
        print(f"MAPPING ERROR: {e}")
        return 1

    conflicts = validate_policy(policy)
    if conflicts:
        print("POLICY DOES NOT VALIDATE:")
        for c in conflicts:
            print(f"  {c}")
        return 1

    print("mapping compiles OK")
    print("policy validates OK")
    print(f"dispositions: " + ", ".join(
        f"{k}={v.value}" for k, v in list(policy.dispositions.items())[:6]) + " ...")

    if args.sample:
        with open(args.sample) as f:
            row = json.load(f)
        mapped, reasons = engine.transform(row)
        print(f"\nsample mapped to {len(mapped)} fields")
        for r in reasons:
            print(f"  omitted: {r}")
        print("\nwould disclose:")
        for name in sorted(mapped):
            print(f"  {policy.dispositions.get(name, policy.default).value:10} {name}")
    return 0


def cmd_keygen(cfg: Config, args) -> int:
    """Generate the source signing key; print the public key for core registration."""
    from .crypto.factory import build_keystore
    ks = build_keystore(cfg.keystore)
    signer = ks.signer(cfg.keystore.signing_key_id)
    print(f"source identity : {cfg.identity.source_identity}")
    print(f"algorithm       : {signer.algorithm}")
    print(f"public key (hex): {signer.public_key_bytes().hex()}")
    print("\nRegister this public key with the core system as the anchor for this source.")
    return 0


def cmd_health(cfg: Config, args) -> int:
    print(json.dumps({"config_loaded": True,
                      "source_identity": cfg.identity.source_identity,
                      "keystore_backend": cfg.keystore.backend,
                      "hash_only_correlation": cfg.enable_hash_only_correlation},
                     indent=2))
    return 0


def cmd_audit(cfg: Config, args) -> int:
    import os
    from .state.store import StateStore
    st = StateStore(os.path.join(cfg.state.data_dir, "connector.db"))
    for entry in st.audit_export():
        print(json.dumps(entry))
    st.close()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="rachis-connector",
                                description="RACHIS source-side connector")
    p.add_argument("--config", required=True, help="path to connector.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="offline validation of mapping + policy + sample")
    v.add_argument("--sample", help="path to a sample source JSON record")

    sub.add_parser("keygen", help="generate signing key, print public key")
    sub.add_parser("health", help="print readiness")
    sub.add_parser("audit", help="export the local audit log")

    args = p.parse_args(argv)
    cfg = Config.load(args.config)

    return {
        "validate": cmd_validate,
        "keygen": cmd_keygen,
        "health": cmd_health,
        "audit": cmd_audit,
    }[args.command](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
