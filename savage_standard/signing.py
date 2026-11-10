"""Estate key custody for SRE-1 envelope signatures.

The custody design, fitted to how this estate actually works (no secret
server; git repos are the distribution channel):

- PUBLIC keys live in a registry that is committed to this repo
  (``savage_standard/key_registry.json``) and therefore distributed,
  reviewable, and revocable in the open: key id, algorithm, modulus,
  validity window, status, and a human note per key.
- The PRIVATE key never enters any repo. An operator generates it
  locally (``savage-verify keygen``), which writes it — mode 0600, and
  refusing to overwrite — to a path the operator chooses OUTSIDE any
  repository, and prints only the public registry entry. At signing
  time the key is read from that file (``--key-file`` or the
  ``SAVAGE_SIGNING_KEY_FILE`` environment variable), used in memory,
  and never copied anywhere else by this code.
- Minting the real estate key is the operator's act. This repo ships
  exactly one registry entry: a THROWAWAY demo key (usage ``demo``)
  whose private half was destroyed after signing the demo fixture in
  ``fixtures/signed-envelope-demo.json``. It proves the mechanism end
  to end and attests nothing — the verifier says so on its leg.

Signature leg semantics in the universal verifier (never a silent
pass): a present-but-invalid signature is a ``fail`` (REJECTED); a
signature whose key is unknown, revoked, or outside its validity
window is ``unverifiable`` (the envelope caps at VERIFIED-STRUCTURAL);
an absent signature adds no leg at all, so unsigned envelopes keep
exactly their pre-custody verdicts — hash-bound only, and their
boundary statement still says so.

What is signed: the envelope digest (SHA-256 over the JCS canonical
core, which excludes ``envelope_digest`` itself and the ``signatures``
member) under a domain-separated message. The signature therefore
binds every envelope field — claim, issuer, subject, evidence, gate,
``recorded_at``, chain, and the verbatim native receipt — and any
edit, including the re-digest attack that defeats bare hash-binding,
fails verification. ``recorded_at`` stays issuer-reported: the
signature proves the issuer attested that time, it is not a trusted
third-party timestamp.

Algorithm: RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), Savage-original
stdlib implementation in ``rsa.py``. CLASSICAL, NOT post-quantum; the
ML-DSA-87 leg named in CEROS receipts is a different leg and remains
not-built.
"""
from __future__ import annotations

import base64
import copy
import json
import os
from datetime import datetime, timezone

from . import envelope, rsa
from .dialects import Leg

ALGORITHM = "RSASSA-PKCS1-v1_5/SHA-256"
SIGNATURES_FIELD = "signatures"
REGISTRY_SCHEMA = "savage/key-registry/1"
PRIVATE_KEY_SCHEMA = "savage/rsa-private-key/1"
KEY_FILE_ENV = "SAVAGE_SIGNING_KEY_FILE"
MIN_KEY_BITS = 2048

_MESSAGE_PREFIX = b"savage/receipt-envelope/1:signature:v1\n"

SIGNED_BOUNDARY = (
    "This envelope is SIGNED by its issuer (RSASSA-PKCS1-v1_5/SHA-256; "
    "verify against the savage-standard key registry). The signature "
    "binds every envelope field, including recorded_at — which remains "
    "issuer-reported: a signature is not a trusted third-party "
    "timestamp. The signature is classical RSA, NOT post-quantum."
)


# ── integer <-> base64url (registry / key-file encoding) ────────────────────

def _int_to_b64u(x: int) -> str:
    raw = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_to_int(s: str) -> int:
    pad = "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")


def _bytes_to_b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_to_bytes(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ── key generation + private-key file (operator side) ───────────────────────

def generate_signing_key(key_id: str, bits: int = 3072) -> tuple:
    """Generate a custody-grade keypair. Returns (private_key_record,
    registry_entry). The caller decides where the private record goes —
    this function writes nothing."""
    if bits < MIN_KEY_BITS:
        raise ValueError(
            f"signing keys must be at least {MIN_KEY_BITS} bits (got {bits})")
    kp = rsa.generate_keypair(bits)
    private = {
        "schema": PRIVATE_KEY_SCHEMA,
        "key_id": key_id,
        "algorithm": ALGORITHM,
        "bits": bits,
        "n": _int_to_b64u(kp["n"]),
        "e": kp["e"],
        "d": _int_to_b64u(kp["d"]),
        "p": _int_to_b64u(kp["p"]),
        "q": _int_to_b64u(kp["q"]),
    }
    return private, public_entry(private, status="active")


def public_entry(private_or_public: dict, *, status: str = "active",
                 usage: str = "signing", not_before: str | None = None,
                 not_after: str | None = None, note: str = "") -> dict:
    """The committable public registry entry for a key record."""
    return {
        "key_id": private_or_public["key_id"],
        "algorithm": ALGORITHM,
        "usage": usage,
        "status": status,
        "public": {"n": private_or_public["n"],
                   "e": private_or_public["e"]},
        "bits": private_or_public["bits"],
        "not_before": not_before,
        "not_after": not_after,
        "note": note,
    }


def save_private_key(private: dict, path: str) -> str:
    """Write the private key record to ``path`` with mode 0600, refusing
    to overwrite an existing file. Returns the path. The caller must
    choose a location OUTSIDE any git repository — this is the custody
    boundary, and it is the operator's to keep."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(private, fh, indent=1)
        fh.write("\n")
    return path


def load_private_key(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    if rec.get("schema") != PRIVATE_KEY_SCHEMA:
        raise ValueError(f"{path}: not a {PRIVATE_KEY_SCHEMA} record")
    if rec.get("algorithm") != ALGORITHM:
        raise ValueError(f"{path}: unsupported algorithm {rec.get('algorithm')!r}")
    return rec


def private_key_from_env() -> dict:
    path = os.environ.get(KEY_FILE_ENV)
    if not path:
        raise ValueError(
            f"no key file given and ${KEY_FILE_ENV} is not set")
    return load_private_key(path)


def _private_ints(private: dict) -> dict:
    return {"n": _b64u_to_int(private["n"]), "e": int(private["e"]),
            "d": _b64u_to_int(private["d"])}


# ── registry ────────────────────────────────────────────────────────────────

def default_registry_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "key_registry.json")


def load_registry(path: str | None = None) -> dict:
    with open(path or default_registry_path(), encoding="utf-8") as fh:
        reg = json.load(fh)
    if reg.get("schema") != REGISTRY_SCHEMA:
        raise ValueError("not a savage key registry")
    return reg


def find_key(registry: dict, key_id: str) -> dict | None:
    for entry in registry.get("keys", []):
        if entry.get("key_id") == key_id:
            return entry
    return None


# ── signing (issuer side) ───────────────────────────────────────────────────

def _signed_message(digest_hex: str) -> bytes:
    return _MESSAGE_PREFIX + digest_hex.encode("ascii")


def sign_envelope(env: dict, private: dict, *, key_id: str | None = None,
                  signed_at: str | None = None) -> dict:
    """Return a signed copy of an SRE-1 envelope. The private key record
    is used in memory only. Any existing signatures are replaced."""
    if not envelope.is_envelope(env):
        raise ValueError("input is not an SRE-1 envelope")
    key_id = key_id or private.get("key_id")
    if not key_id:
        raise ValueError("no key_id: pass one or use a key record that carries it")
    if _b64u_to_int(private["n"]).bit_length() < MIN_KEY_BITS:
        raise ValueError(
            f"refusing to sign with a key below {MIN_KEY_BITS} bits")
    out = copy.deepcopy(env)
    out.pop(SIGNATURES_FIELD, None)
    boundaries = out.get("boundaries") or []
    out["boundaries"] = [
        SIGNED_BOUNDARY if b == envelope.BOUNDARIES[2] else b
        for b in boundaries]
    if SIGNED_BOUNDARY not in out["boundaries"]:
        out["boundaries"].append(SIGNED_BOUNDARY)
    digest = envelope.envelope_digest(out)
    out["envelope_digest"] = digest
    sig = rsa.sign(_private_ints(private), _signed_message(digest))
    out[SIGNATURES_FIELD] = [{
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "signed_at": signed_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "value": _bytes_to_b64u(sig),
    }]
    return out


# ── verification legs (verifier side) ───────────────────────────────────────

def signature_legs(env: dict, registry: dict | None = None) -> list:
    """Signature legs for an envelope. No ``signatures`` member → no
    legs (unsigned envelopes keep their pre-custody verdicts exactly).
    Registry defaults to the one shipped in this package."""
    sigs = env.get(SIGNATURES_FIELD)
    if sigs is None:
        return []
    if not isinstance(sigs, list) or not sigs:
        return [Leg("envelope-signature", "fail",
                    "signatures member present but empty or not a list")]
    if registry is None:
        registry = load_registry()
    legs = []
    digest = env.get("envelope_digest")
    for sig in sigs:
        legs.append(_verify_one(env, sig, registry, digest))
    return legs


def _verify_one(env: dict, sig, registry: dict, digest) -> Leg:
    name = "envelope-signature"
    if not isinstance(sig, dict):
        return Leg(name, "fail", "signature entry is not an object")
    key_id = sig.get("key_id")
    if sig.get("algorithm") != ALGORITHM:
        return Leg(name, "fail",
                   f"unsupported signature algorithm {sig.get('algorithm')!r}")
    entry = find_key(registry, key_id) if key_id else None
    if entry is None:
        return Leg(name, "unverifiable",
                   f"key {key_id!r} is not in the registry — "
                   "the signature cannot be checked")
    if entry.get("status") == "revoked":
        return Leg(name, "unverifiable",
                   f"key {key_id!r} is REVOKED in the registry — "
                   "its signatures are not trusted")
    recorded = env.get("recorded_at") or ""
    nb, na = entry.get("not_before"), entry.get("not_after")
    if (nb and recorded and recorded < nb) or (na and recorded and recorded > na):
        return Leg(name, "unverifiable",
                   f"envelope recorded_at {recorded!r} falls outside key "
                   f"{key_id!r}'s validity window [{nb}, {na}] "
                   "(recorded_at is issuer-reported, so this is not "
                   "trusted as a rejection either)")
    try:
        pub = {"n": _b64u_to_int(entry["public"]["n"]),
               "e": int(entry["public"]["e"])}
        sig_bytes = _b64u_to_bytes(sig.get("value", ""))
    except Exception as e:
        return Leg(name, "fail", f"malformed registry entry or signature: {e}")
    if not isinstance(digest, str) or not rsa.verify(
            pub, _signed_message(digest), sig_bytes):
        return Leg(name, "fail",
                   f"signature does not verify against key {key_id!r} "
                   "over the envelope digest — the envelope was altered "
                   "after signing, or the signature is forged")
    if entry.get("usage") == "demo":
        detail = (f"signature verifies against key {key_id!r} — the "
                  "registry's THROWAWAY DEMO key: this proves the "
                  "signing mechanism, it attests NOTHING about the issuer")
    else:
        detail = (f"signature verifies against registry key {key_id!r} "
                  f"({entry.get('bits')}-bit RSA) over the envelope digest")
    return Leg(name, "pass", detail)
