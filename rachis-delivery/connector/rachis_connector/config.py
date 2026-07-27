"""
rachis_connector.config
========================

Typed configuration. The connector is config-driven so that a source owner deploys it
without writing code (thesis §9.2 — the connector is small and inspectable; its behaviour
is declared, not programmed).

Configuration is split by sensitivity:
  * the YAML config file holds non-secret operational settings and paths;
  * secrets (source-DB credentials, HSM PIN) come from the environment or, in production,
    from the platform's own secret store — never from the config file. A `${ENV_VAR}`
    reference in the YAML is resolved from the environment at load time.

Everything is validated on load; a malformed config fails fast with a specific message
rather than at first use.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator


_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _resolve_env(value):
    """Replace ${VAR} with the environment value. Raises if unset, so a missing secret is a
    startup failure rather than a silent empty string."""
    if isinstance(value, str):
        def sub(m):
            var = m.group(1)
            if var not in os.environ:
                raise ValueError(f"config references unset environment variable {var}")
            return os.environ[var]
        return _ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    return value


class KeystoreConfig(BaseModel):
    backend: str = "software"                # "software" | "pkcs11"
    signing_key_id: str = "source-signing"
    # software backend persistence (a PKCS#11 module has no equivalent and ignores this)
    software_key_path: Optional[str] = None
    # pkcs11 backend
    pkcs11_library: Optional[str] = None
    pkcs11_slot: Optional[int] = None
    pkcs11_pin: Optional[str] = None

    @field_validator("backend")
    @classmethod
    def _known(cls, v):
        if v not in ("software", "pkcs11"):
            raise ValueError("keystore.backend must be 'software' or 'pkcs11'")
        return v


class CoreConfig(BaseModel):
    """Connection to the core system (thesis §8.2 — source-initiated only)."""
    base_url: str
    public_key_hex: str                      # core's key, to verify the Expectation
    expectation_canonical: str               # which Expectation this source serves
    tls_ca_cert: Optional[str] = None        # pin core's CA
    poll_interval_seconds: int = 3600


class SourceConfig(BaseModel):
    """The source system the connector reads. Credentials come from the environment."""
    kind: str = "json"                       # "json" | "postgres" | ...
    dsn: Optional[str] = None                # e.g. ${SOURCE_DB_DSN}
    json_input_path: Optional[str] = None    # for kind: json


class StateConfig(BaseModel):
    """Durable state paths (thesis Appendix A.11 D1 — the connector is stateful)."""
    data_dir: str = "/var/lib/rachis-connector"
    salt_store: str = "salts.db"
    audit_log: str = "audit.db"
    callback_queue: str = "callbacks.db"
    outbound_queue: str = "outbound.db"


class IdentityConfig(BaseModel):
    source_identity: str                     # URN of this source organisation
    connector_measurement: str = "software:dev"   # attestation stand-in (thesis §16.3)


class MarkingConfig(BaseModel):
    policy_id: str
    levels: List[str]                        # ordered low->high; the pluggable vocabulary


class Config(BaseModel):
    identity: IdentityConfig
    core: CoreConfig
    source: SourceConfig
    keystore: KeystoreConfig = Field(default_factory=KeystoreConfig)
    state: StateConfig = Field(default_factory=StateConfig)
    marking: MarkingConfig
    mapping_path: str
    policy_path: str
    #: hash-only correlation. OFF by default: the single-key stand-in permits offline
    #: enumeration (thesis §16.6). Only enable with the threshold OPRF, or knowingly.
    enable_hash_only_correlation: bool = False

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path) as f:
            raw = yaml.safe_load(f)
        raw = _resolve_env(raw)
        return cls.model_validate(raw)
