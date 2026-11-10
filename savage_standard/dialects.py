"""Per-dialect verification adapters.

Each adapter re-implements its dialect's own verification from the
producing source code (clean-room) and returns a Leg list. A leg is one
independently recomputed check. Overall dialect result:

- "pass"  — every checkable leg passed, none unverifiable;
- "structural" — every checkable leg passed, but at least one leg is
  unverifiable in principle from the artifact (e.g. a signature scheme
  with no stdlib verifier, or a MAC the producer never persisted);
- "fail"  — at least one recomputed check failed (tamper evidence);
- "unverifiable" — nothing could be recomputed at all.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

from . import canonical


@dataclass
class Leg:
    name: str
    status: str  # "pass" | "fail" | "unverifiable"
    detail: str = ""


@dataclass
class DialectResult:
    dialect: str
    legs: list = field(default_factory=list)
    claim: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    @property
    def result(self) -> str:
        if any(l.status == "fail" for l in self.legs):
            return "fail"
        if self.legs and all(l.status == "pass" for l in self.legs):
            return "pass"
        if any(l.status == "pass" for l in self.legs):
            return "structural"
        return "unverifiable"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _read_bytes(path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _read_sha(path) -> str:
    return _sha(_read_bytes(path))


def _hex64(s) -> bool:
    return (isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdef" for c in s))


# ── Marketplace delivery-ledger ─────────────────────────────────────────────

_ENTRY_BODY_KEYS = ("schema", "seq", "kind", "orderId", "recordedAt",
                    "payload", "prevHash")


def verify_marketplace(receipt: dict, pair: dict | None = None,
                       artifact_dir: str | None = None) -> DialectResult:
    r = DialectResult(dialect="marketplace-delivery")
    entry = receipt.get("entry") or {}
    body = {k: entry.get(k) for k in _ENTRY_BODY_KEYS}
    r.claim = {"kind": receipt.get("kind"), "orderId": receipt.get("orderId"),
               "sku": (entry.get("payload") or {}).get("sku")}
    try:
        recomputed = _sha(canonical.jcs(body).encode("utf-8"))
        r.legs.append(Leg("entry-hash", "pass" if recomputed == entry.get("entryHash")
                          else "fail", "entryHash recomputed over JCS body"))
    except canonical.CanonicalError as e:
        r.legs.append(Leg("entry-hash", "fail", f"uncanonicalizable: {e}"))
    core = {k: v for k, v in receipt.items() if k != "receiptDigest"}
    try:
        recomputed = _sha(canonical.jcs(core).encode("utf-8"))
        r.legs.append(Leg("receipt-digest", "pass" if recomputed == receipt.get("receiptDigest")
                          else "fail", "receiptDigest recomputed over receipt core"))
    except canonical.CanonicalError as e:
        r.legs.append(Leg("receipt-digest", "fail", f"uncanonicalizable: {e}"))
    if pair is not None:
        pay, dlv = (receipt, pair) if receipt.get("kind") == "payment" else (pair, receipt)
        checks = [
            ("pair-order", pay.get("orderId") == dlv.get("orderId")),
            ("pair-binding", (dlv.get("entry", {}).get("payload") or {}).get("paymentEntryHash")
             == pay.get("entry", {}).get("entryHash")),
            ("pair-receipt-binding", dlv.get("paymentReceiptDigest") == pay.get("receiptDigest")),
            ("pair-sku", (pay.get("entry", {}).get("payload") or {}).get("sku")
             == (dlv.get("entry", {}).get("payload") or {}).get("sku")),
        ]
        for name, ok in checks:
            r.legs.append(Leg(name, "pass" if ok else "fail", "payment/delivery pair binding"))
        for a in (dlv.get("entry", {}).get("payload") or {}).get("artifacts", []):
            path = os.path.join(artifact_dir, a["name"]) if artifact_dir else None
            if path and os.path.exists(path):
                data = _read_bytes(path)
                ok = _sha(data) == a["sha256"] and len(data) == a["bytes"]
                r.legs.append(Leg(f"artifact:{a['name']}", "pass" if ok else "fail",
                                  "delivered artifact bytes re-hashed"))
            else:
                r.legs.append(Leg(f"artifact:{a['name']}", "unverifiable",
                                  "artifact bytes not supplied; digest attests bytes at recording time only"))
    r.notes.append("Hash-bound, not signed (the dialect's own boundary). recordedAt is producer-reported.")
    return r


# ── sia-v6-core benchmark receipts ──────────────────────────────────────────

def verify_siacore(records: list) -> DialectResult:
    r = DialectResult(dialect="siav6core-benchmark")
    prev = None
    ok_chain, ok_hash, ok_seq, ok_schema = True, True, True, True
    for i, rec in enumerate(records):
        if rec.get("schema") != "sia.benchmark-receipt.v1":
            ok_schema = False
        if rec.get("seq") != i:
            ok_seq = False
        if rec.get("prev_hash") != prev:
            ok_chain = False
        body = {k: v for k, v in rec.items() if k != "receipt_hash"}
        try:
            if _sha(canonical.sorted_compact(body).encode("utf-8")) != rec.get("receipt_hash"):
                ok_hash = False
        except Exception:
            ok_hash = False
        prev = rec.get("receipt_hash")
    for name, ok in (("schema", ok_schema), ("sequence", ok_seq),
                     ("chain-linkage", ok_chain), ("receipt-hashes", ok_hash)):
        r.legs.append(Leg(name, "pass" if ok else "fail", f"{len(records)} record(s)"))
    if records:
        r.claim = {"acceptance": records[-1].get("acceptance"),
                   "records": len(records),
                   "recorded_at_utc": records[-1].get("recorded_at_utc")}
    r.notes.append("A receipt proves a run happened with these outputs; it does not make a failing gate pass.")
    return r


# ── Relay event log ─────────────────────────────────────────────────────────

def verify_relay(records: list) -> DialectResult:
    r = DialectResult(dialect="relay-event-log")
    prev = "0" * 64
    ok = True
    for i, rec in enumerate(records):
        body = {k: rec.get(k) for k in ("seq", "ts", "kind", "data", "prev")}
        if rec.get("prev") != prev:
            ok = False
            break
        if _sha(canonical.sorted_compact(body).encode("utf-8")) != rec.get("hash"):
            ok = False
            break
        if rec.get("seq") != i + 1:
            ok = False
            break
        prev = rec["hash"]
    r.legs.append(Leg("hash-chain", "pass" if ok else "fail",
                      f"{len(records)} event(s), genesis prev = 0*64"))
    if records:
        r.claim = {"events": len(records), "tip": prev,
                   "first_kind": records[0].get("kind"), "last_kind": records[-1].get("kind")}
    return r


# ── Breakthrough evidence ───────────────────────────────────────────────────

_EVIDENCE_FIELDS = ("candidateId", "lawId", "outcome", "source", "method",
                    "observedAt", "payload")
_SELF_SOURCES = {"self", "candidate", "asserted", "assertion"}
_PROMO_PREFIXES = ("promotion:", "gold:", "receipt:", "cycle:")
FLOOR = 0.85


def _record_problem(rec, candidate_id):
    if not isinstance(rec, dict):
        return "malformed"
    if (not isinstance(rec.get("candidateId"), str)
            or not isinstance(rec.get("lawId"), str)
            or rec.get("outcome") not in ("pass", "fail")
            or not isinstance(rec.get("source"), str) or not rec.get("source")
            or not isinstance(rec.get("method"), str) or not rec.get("method")
            or not isinstance(rec.get("observedAt"), str)
            or not isinstance(rec.get("payload"), str)
            or not isinstance(rec.get("digest"), str)):
        return "malformed"
    if rec["candidateId"] != candidate_id:
        return "candidate-mismatch"
    text = canonical.js_stringify_ordered([(k, rec[k]) for k in _EVIDENCE_FIELDS])
    if _sha(text.encode("utf-8")) != rec["digest"]:
        return "digest-mismatch"
    if rec["source"] == candidate_id or rec["source"] in _SELF_SOURCES:
        return "self-asserted"
    if any(rec["source"].startswith(p) for p in _PROMO_PREFIXES):
        return "promotion-derived"
    return None


def verify_breakthrough(book: dict, bound_laws: dict | None = None,
                        score_claim: dict | None = None,
                        artifact_dir: str | None = None) -> DialectResult:
    r = DialectResult(dialect="breakthrough-evidence")
    all_digests_ok = True
    total_rejected = 0
    summaries = {}
    for cid, records in book.items():
        valid_pass, valid_fail, rejected = set(), set(), []
        seen_digests = set()
        for rec in records:
            problem = _record_problem(rec, cid)
            if problem is None and rec.get("digest") in seen_digests:
                problem = "digest-mismatch"
            if problem:
                if problem == "digest-mismatch":
                    all_digests_ok = False
                rejected.append({"lawId": rec.get("lawId") if isinstance(rec, dict) else None,
                                 "reason": problem})
                continue
            seen_digests.add(rec["digest"])
            (valid_pass if rec["outcome"] == "pass" else valid_fail).add(rec["lawId"])
        total_rejected += len(rejected)
        laws = (bound_laws or {}).get(cid)
        if laws:
            bound = len(laws)
            passed = len([l for l in laws if l in valid_pass and l not in valid_fail])
            score = passed / bound if bound else 0.0
            eligible = bound > 0 and score >= FLOOR and not valid_fail
            unmeasured = [l for l in laws if l not in valid_pass and l not in valid_fail]
            summaries[cid] = {"score": score, "eligible": eligible,
                              "unmeasured": unmeasured, "rejected": rejected}
        else:
            summaries[cid] = {"score": None, "eligible": None,
                              "note": "bound-law set not supplied; score not derivable",
                              "rejected": rejected}
    r.legs.append(Leg("evidence-digests", "pass" if all_digests_ok else "fail",
                      "every record digest recomputed over the fixed-order canonical form"))
    r.legs.append(Leg("provenance-firewall", "pass",
                      f"{total_rejected} record(s) refused by the dialect's own provenance rules"))
    for cid, s in summaries.items():
        if s["score"] is None:
            r.legs.append(Leg(f"score:{cid}", "unverifiable", s["note"]))
        else:
            r.legs.append(Leg(f"score:{cid}", "pass",
                              f"re-derived score {s['score']:.4f}, eligible={s['eligible']}, unmeasured={len(s['unmeasured'])}"))
    if score_claim:
        for cid, claimed in score_claim.items():
            derived = summaries.get(cid, {})
            match = (derived.get("score") == claimed.get("score")
                     and derived.get("eligible") == claimed.get("promotionEligible"))
            r.legs.append(Leg(f"checker-consistency:{cid}", "pass" if match else "fail",
                              "claimed PrimitiveScoreResult vs independent re-derivation"))
    if artifact_dir:
        seen_paths = set()
        for records in book.values():
            for rec in records:
                try:
                    payload = json.loads(rec.get("payload") or "")
                except Exception:
                    continue
                path = payload.get("path")
                if not path or path in seen_paths:
                    continue
                seen_paths.add(path)
                full = os.path.join(artifact_dir, path)
                if os.path.exists(full):
                    measured = _read_sha(full)
                    ok = measured == payload.get("measuredSha256") and bool(payload.get("digestMatch"))
                    r.legs.append(Leg(f"measured-artifact:{path}", "pass" if ok else "fail",
                                      "artifact bytes re-hashed against the measurer's sealed payload"))
                else:
                    r.legs.append(Leg(f"measured-artifact:{path}", "unverifiable",
                                      "measured artifact not supplied"))
    r.claim = {"candidates": summaries}
    return r


# ── SIA-v6 benchmark manifest ───────────────────────────────────────────────

# Reporter thresholds (benchmark/reporter.py), recomputed, not trusted.
_CERT_TIERS = ((0.95, 90.0, "CERTIFIED"), (0.85, 80.0, "CERTIFIED WITH DEGRADATION"),
               (0.70, 0.0, "RESEARCH-ONLY"))


def verify_siav6_manifest(manifest: dict, artifact_dir: str | None = None,
                          suite_summary_csv: str | None = None) -> DialectResult:
    r = DialectResult(dialect="siav6-benchmark-manifest")
    r.claim = {"run_id": manifest.get("run_id"), "engine": manifest.get("engine"),
               "certification_status": manifest.get("certification_status")}
    for name, art in (manifest.get("artifacts") or {}).items():
        path = os.path.join(artifact_dir, os.path.basename(art["path"])) if artifact_dir else None
        if path and os.path.exists(path):
            ok = _read_sha(path) == art["sha256"]
            r.legs.append(Leg(f"artifact:{name}", "pass" if ok else "fail",
                              "manifest-listed artifact bytes re-hashed"))
        else:
            r.legs.append(Leg(f"artifact:{name}", "unverifiable",
                              "artifact bytes not supplied"))
    if suite_summary_csv:
        import csv, io
        rows = list(csv.DictReader(io.StringIO(suite_summary_csv)))
        try:
            total = sum(float(row["total_points"]) for row in rows)
            pct = (sum(float(row["certified_pct"]) * float(row["total_points"])
                       for row in rows) / total if total else 0.0)
            mean = (sum(float(row["mean_score"]) * float(row["total_points"])
                        for row in rows) / total if total else 0.0)
            status = "FAILED CERTIFICATION"
            for pmin, mmin, label in _CERT_TIERS:
                if pct / 100.0 >= pmin and mean >= mmin:
                    status = label
                    break
            ok = status == manifest.get("certification_status")
            r.legs.append(Leg("certification-arithmetic", "pass" if ok else "fail",
                              f"recomputed {status} (certified {pct:.2f}%, weighted mean {mean:.2f}) from suite summary"))
        except Exception as e:
            r.legs.append(Leg("certification-arithmetic", "unverifiable", f"suite summary unparsable: {e}"))
    else:
        r.legs.append(Leg("certification-arithmetic", "unverifiable",
                          "suite_summary.csv not supplied"))
    r.legs.append(Leg("record-macs", "unverifiable",
                      "per-record HMACs are verified in-process by the producer and never persisted; "
                      "only the hmac_valid boolean is stored, so record MACs cannot be recomputed from artifacts"))
    return r


# ── CEROS PromotionEngine ───────────────────────────────────────────────────

_DIMENSIONS = ("identity", "build", "theatre", "triad", "newTests", "metrics")


def verify_ceros(receipt: dict) -> DialectResult:
    r = DialectResult(dialect="ceros-promotion")
    r.claim = {"candidateId": receipt.get("candidateId"), "verdict": receipt.get("verdict"),
               "total": receipt.get("total")}
    dims = receipt.get("dimensions") or {}
    shape_ok = (isinstance(receipt.get("candidateId"), str)
                and receipt.get("verdict") in ("PROMOTE", "HOLD", "REJECT", "ESCALATE")
                and isinstance(receipt.get("total"), (int, float))
                and all(isinstance(dims.get(d), (int, float)) for d in _DIMENSIONS)
                and isinstance(receipt.get("evaluatedAt"), str))
    total_ok = shape_ok and abs(sum(dims[d] for d in _DIMENSIONS) - receipt["total"]) < 1e-9
    r.legs.append(Leg("receipt-shape", "pass" if shape_ok else "fail",
                      "PromotionVerdictReceipt fields per src/triadic/PromotionEngine.ts"))
    r.legs.append(Leg("dimension-total", "pass" if total_ok else "fail",
                      "total recomputed as the sum of the six dimensions"))
    core = canonical.js_stringify_ordered([
        ("candidateId", receipt.get("candidateId")),
        ("verdict", receipt.get("verdict")),
        ("total", receipt.get("total")),
        ("dimensions", {d: dims.get(d) for d in _DIMENSIONS}),
        ("evaluatedAt", receipt.get("evaluatedAt")),
    ])
    r.legs.append(Leg("signed-core-form", "pass" if shape_ok else "fail",
                      f"signed core reconstructed byte-exactly ({len(core)} chars)"))
    falcon = receipt.get("falconSignature") or {}
    sig_hex = falcon.get("signatureHex")
    sig_shape = (isinstance(falcon.get("scheme"), str) and bool(falcon.get("scheme"))
                 and isinstance(sig_hex, str) and len(sig_hex) > 64
                 and all(c in "0123456789abcdefABCDEF" for c in sig_hex)
                 and isinstance(falcon.get("publicKeyHex"), str) and bool(falcon.get("publicKeyHex"))
                 and receipt.get("signature") == sig_hex)
    r.legs.append(Leg("signature-shape", "pass" if sig_shape else "fail",
                      "falconSignature present; receipt.signature mirrors signatureHex"))
    r.legs.append(Leg("mldsa87-signature", "unverifiable",
                      "ML-DSA-87 (FIPS 204) has no verifier in the Python standard library; "
                      "signature validity itself is NOT checked here — verify with the producer's "
                      "verifyReceipt under Node for the cryptographic leg"))
    return r


# ── Starr bounce receipt ────────────────────────────────────────────────────

def verify_starr(receipt: dict, artifact_path: str | None = None) -> DialectResult:
    r = DialectResult(dialect="starr-bounce")
    r.claim = {"bounceId": receipt.get("bounceId"),
               "fileName": (receipt.get("artifact") or {}).get("fileName")}
    body = {k: v for k, v in receipt.items() if k != "receiptHash"}
    try:
        recomputed = _sha(canonical.starr(body).encode("utf-8"))
        r.legs.append(Leg("receipt-hash", "pass" if recomputed == receipt.get("receiptHash")
                          else "fail", "receiptHash recomputed over Starr canonicalJson body"))
    except canonical.CanonicalError as e:
        r.legs.append(Leg("receipt-hash", "fail", f"uncanonicalizable: {e}"))
    art = receipt.get("artifact") or {}
    if artifact_path and os.path.exists(artifact_path):
        data = _read_bytes(artifact_path)
        ok = _sha(data) == art.get("sha256") and len(data) == art.get("sizeInBytes")
        r.legs.append(Leg("artifact-bytes", "pass" if ok else "fail",
                          "bounced file bytes re-hashed against the receipt"))
    else:
        r.legs.append(Leg("artifact-bytes", "unverifiable",
                          "bounced file not supplied; measurement values are producer-reported"))
    return r
