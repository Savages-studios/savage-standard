"""The universal verifier: dialect detection + verdict assembly.

Verdict taxonomy (never a silent pass):
- VERIFIED            — every leg recomputed and passed.
- VERIFIED-STRUCTURAL — every recomputable leg passed; some leg is
                        unverifiable in principle from the artifact and
                        is named in the legs (e.g. CEROS's ML-DSA-87
                        signature under a stdlib-only verifier).
- REJECTED            — at least one recomputed check failed.
- UNVERIFIABLE        — the dialect is recognized but nothing could be
                        recomputed, or the input matches no dialect.
"""
from __future__ import annotations

import json
import os

from . import dialects, envelope


def detect(obj) -> str | None:
    if envelope.is_envelope(obj):
        return "envelope"
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) and x.get("schema") == "sia.benchmark-receipt.v1" for x in obj):
            return "siav6core-benchmark"
        if obj and all(isinstance(x, dict) and "hash" in x and "prev" in x and "kind" in x for x in obj):
            return "relay-event-log"
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("schema") == "savage/delivery-receipt/1":
        return "marketplace-delivery"
    if obj.get("schema") == "sia.benchmark-receipt.v1":
        return "siav6core-benchmark"
    if "certification_status" in obj and "artifacts" in obj:
        return "siav6-benchmark-manifest"
    if "falconSignature" in obj and "dimensions" in obj:
        return "ceros-promotion"
    if obj.get("receiptVersion") == "starr.bounce-receipt.v1":
        return "starr-bounce"
    if obj.get("schema") == "savage/external-benchmark-recompute/1":
        return "helm-benchmark"
    if obj and all(isinstance(v, list) and v and isinstance(v[0], dict)
                   and "digest" in v[0] and "lawId" in v[0] for v in obj.values()):
        return "breakthrough-evidence"
    if "hash" in obj and "prev" in obj and "kind" in obj and "data" in obj:
        return "relay-event-log"
    return None


def _verdict(result: dialects.DialectResult, extra_legs=()) -> dict:
    legs = list(extra_legs) + result.legs
    if any(l.status == "fail" for l in legs):
        verdict = "REJECTED"
    elif legs and all(l.status == "pass" for l in legs):
        verdict = "VERIFIED"
    elif any(l.status == "pass" for l in legs):
        verdict = "VERIFIED-STRUCTURAL"
    else:
        verdict = "UNVERIFIABLE"
    return {
        "verdict": verdict,
        "dialect": result.dialect,
        "claim": result.claim,
        "legs": [{"name": l.name, "status": l.status, "detail": l.detail} for l in legs],
        "notes": result.notes,
    }


def verify(obj, *, pair=None, artifact_dir=None, artifact_file=None,
           bound_laws=None, score_claim=None) -> dict:
    """Verify a receipt object (native or SRE-1 envelope)."""
    kind = detect(obj)
    if kind is None:
        return {"verdict": "UNVERIFIABLE", "dialect": None, "claim": {},
                "legs": [{"name": "dialect-detection", "status": "unverifiable",
                          "detail": "input matches no known estate dialect"}],
                "notes": []}
    if kind == "envelope":
        legs = envelope.check_envelope(obj)
        if any(l.status == "fail" for l in legs):
            inner = dialects.DialectResult(dialect="envelope", legs=[])
            return _verdict(inner, legs)
        native = obj["native"]
        inner = verify(native, pair=pair, artifact_dir=artifact_dir,
                       artifact_file=artifact_file, bound_laws=bound_laws,
                       score_claim=score_claim)
        result = dialects.DialectResult(dialect=inner["dialect"],
                                        legs=[dialects.Leg(l["name"], l["status"], l["detail"])
                                              for l in inner["legs"]],
                                        claim=inner["claim"], notes=inner["notes"])
        return _verdict(result, legs)
    if kind == "marketplace-delivery":
        result = dialects.verify_marketplace(obj, pair=pair, artifact_dir=artifact_dir)
    elif kind == "siav6core-benchmark":
        records = obj if isinstance(obj, list) else [obj]
        result = dialects.verify_siacore(records)
    elif kind == "relay-event-log":
        records = obj if isinstance(obj, list) else [obj]
        result = dialects.verify_relay(records)
    elif kind == "breakthrough-evidence":
        result = dialects.verify_breakthrough(obj, bound_laws=bound_laws,
                                              score_claim=score_claim,
                                              artifact_dir=artifact_dir)
    elif kind == "siav6-benchmark-manifest":
        summary = None
        if artifact_dir:
            p = os.path.join(artifact_dir, "suite_summary.csv")
            if os.path.exists(p):
                summary = open(p, encoding="utf-8").read()
        result = dialects.verify_siav6_manifest(obj, artifact_dir=artifact_dir,
                                                suite_summary_csv=summary)
    elif kind == "ceros-promotion":
        result = dialects.verify_ceros(obj)
    elif kind == "starr-bounce":
        result = dialects.verify_starr(obj, artifact_path=artifact_file)
    elif kind == "helm-benchmark":
        result = dialects.verify_helm(obj, artifact_path=artifact_file,
                                      artifact_dir=artifact_dir)
    else:  # pragma: no cover
        result = dialects.DialectResult(dialect=kind)
    return _verdict(result)


def load_input(path: str):
    """Load a receipt file: JSON object, or JSONL chain (returned as list)."""
    text = open(path, encoding="utf-8").read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
