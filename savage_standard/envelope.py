"""SRE-1 — the Savage Receipt Envelope, version 1.

One minimal envelope that wraps ANY estate receipt dialect without
rewriting its producer. The native receipt travels verbatim inside
``native``; the envelope adds only what an outsider needs to find,
identify, and verify the claim: who issued it, what it claims, which
gate decided, what evidence it points at (with hashes), when, and how
it chains to the previous envelope from the same issuer.

Envelope digest: SHA-256 over the RFC 8785 (JCS) canonical form of the
envelope without ``envelope_digest`` — the same canonicalization the
marketplace dialect already uses, so one canonicalizer serves both.

Honesty rules baked into the format (modeled on the delivery-ledger's
boundary statements):
- ``recorded_at`` is producer-reported and is NOT a trusted timestamp.
- Wrapping adds NO signature. The envelope is hash-bound, exactly as
  strong as the native dialect it wraps — never stronger. Signing is a
  separate, optional step (``savage_standard/signing.py``): when an
  issuer signs, the ``signatures`` member carries the signature and
  the boundary statement is replaced with one that says so. The
  ``signatures`` member is excluded from the envelope digest (as
  ``envelope_digest`` itself is); the signature is computed OVER the
  digest, binding every other field.
"""
from __future__ import annotations

import hashlib

from . import canonical

SCHEMA = "savage/receipt-envelope/1"

BOUNDARIES = [
    "This envelope wraps a native receipt verbatim; it adds identification, evidence pointers, and a hash chain — not trust.",
    "recorded_at is producer-reported and is NOT a trusted timestamp.",
    "The envelope is hash-bound, not signed. Estate key custody for envelope-level signatures is still owed.",
    "A VERIFIED verdict means every recomputable check in the native dialect passed; legs that cannot be recomputed are reported UNVERIFIABLE, never silently passed.",
]


def native_digest(native) -> str:
    """Digest of the wrapped native receipt: SHA-256 over its JCS form."""
    return hashlib.sha256(canonical.jcs(native).encode("utf-8")).hexdigest()


def wrap(native, *, claim_id: str, claim_kind: str, statement: str,
         issuer_line: str, issuer_system: str, dialect: str,
         native_schema: str, gate_name: str, gate_verdict: str,
         recorded_at: str, evidence: list | None = None,
         artifact_hashes: list | None = None,
         prev_digest: str | None = None) -> dict:
    env = {
        "schema": SCHEMA,
        "envelope_version": 1,
        "claim": {"id": claim_id, "kind": claim_kind, "statement": statement},
        "issuer": {"line": issuer_line, "system": issuer_system, "dialect": dialect},
        "subject": {
            "native_schema": native_schema,
            "native_digest": native_digest(native),
            "artifact_hashes": artifact_hashes or [],
        },
        "evidence": evidence or [],
        "gate": {"name": gate_name, "verdict": gate_verdict},
        "recorded_at": recorded_at,
        "timestamp_trust": "producer-reported; NOT a trusted timestamp",
        "chain": {"prev_digest": prev_digest},
        "native": native,
        "boundaries": list(BOUNDARIES),
    }
    env["envelope_digest"] = envelope_digest(env)
    return env


def envelope_digest(env: dict) -> str:
    # ``signatures`` is excluded alongside ``envelope_digest``: the
    # signature is computed over this digest, so it cannot be an input
    # to it. Envelopes without a signatures member digest exactly as
    # they did before the custody build (proven by the fixture suite).
    core = {k: v for k, v in env.items()
            if k not in ("envelope_digest", "signatures")}
    return hashlib.sha256(canonical.jcs(core).encode("utf-8")).hexdigest()


def is_envelope(obj) -> bool:
    return isinstance(obj, dict) and obj.get("schema") == SCHEMA


def check_envelope(env: dict) -> list:
    """Structural legs for an envelope itself (digest, native binding,
    chain field). Returns Leg objects."""
    from .dialects import Leg
    legs = []
    try:
        ok = envelope_digest(env) == env.get("envelope_digest")
        legs.append(Leg("envelope-digest", "pass" if ok else "fail",
                        "envelope_digest recomputed over JCS core"))
    except canonical.CanonicalError as e:
        legs.append(Leg("envelope-digest", "fail", f"uncanonicalizable: {e}"))
    native = env.get("native")
    if native is None:
        legs.append(Leg("native-binding", "fail", "envelope carries no native receipt"))
    else:
        try:
            ok = native_digest(native) == (env.get("subject") or {}).get("native_digest")
            legs.append(Leg("native-binding", "pass" if ok else "fail",
                            "subject.native_digest recomputed over the embedded native receipt"))
        except canonical.CanonicalError as e:
            legs.append(Leg("native-binding", "fail", f"uncanonicalizable: {e}"))
    chain = env.get("chain") or {}
    legs.append(Leg("chain-field", "pass" if "prev_digest" in chain else "fail",
                    "chain.prev_digest present (null only for an issuer's first envelope)"))
    return legs
