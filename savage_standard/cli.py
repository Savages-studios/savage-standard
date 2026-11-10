"""savage-verify — the universal verifier CLI.

Usage:
  savage-verify RECEIPT [--pair RECEIPT] [--artifacts DIR] [--file PATH]
                        [--bound-laws CANDIDATE=LAW1,LAW2,...] [--json]
  savage-verify wrap NATIVE --claim-id ID --claim-kind KIND --statement S
                        --issuer-line L --issuer-system S --dialect D
                        --native-schema S --gate-name G --gate-verdict V
                        --recorded-at T [--prev-digest HEX] [-o OUT]
  savage-verify recompute PER_INSTANCE_STATS --metric M --split S
                        --benchmark B --release R --scenario SC --run RUN
                        --model M-ID --model-display D --metric-label L
                        --published-value V --published-source URL
                        [--published-source URL ...] --source-url URL
                        [--source-file NAME] [--recorded-at T] [-o OUT]
  savage-verify claims        (print the claims-gate inventory summary)
  savage-verify keygen --key-id ID --out PRIVATE.json [--bits 3072]
                        (generate an estate signing key: the PRIVATE key
                        is written mode-0600 to --out — choose a path
                        OUTSIDE any repository — and only the public
                        registry entry is printed, for committing to
                        savage_standard/key_registry.json)
  savage-verify sign ENVELOPE --key-file PRIVATE.json [-o OUT]
                        (sign an SRE-1 envelope; the key file may also
                        come from $SAVAGE_SIGNING_KEY_FILE)

Verify accepts [--keys REGISTRY.json] to check envelope signatures
against a registry other than the one shipped in the package.

Exit codes: 0 = VERIFIED or VERIFIED-STRUCTURAL; 1 = REJECTED;
2 = UNVERIFIABLE or usage error. A tampered receipt never exits 0.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import envelope, helm, signing, verify as verify_mod
from .claims import INVENTORY, summary_line


def _print_human(out: dict) -> None:
    print(f"verdict: {out['verdict']}")
    print(f"dialect: {out['dialect']}")
    for leg in out["legs"]:
        print(f"  [{leg['status']:>12}] {leg['name']} — {leg['detail']}")
    for note in out.get("notes", []):
        print(f"  note: {note}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "claims":
        for row in INVENTORY:
            print(f"{row['id']:<28} {row['class']:<16} gated={row['gated']!s:<5} {row['claim']}")
        print(summary_line())
        return 0
    if argv and argv[0] == "keygen":
        p = argparse.ArgumentParser(prog="savage-verify keygen")
        p.add_argument("--key-id", required=True)
        p.add_argument("--out", required=True,
                       help="where to write the PRIVATE key (mode 0600, "
                            "must not exist). Choose a path OUTSIDE any "
                            "git repository — that is the custody boundary.")
        p.add_argument("--bits", type=int, default=3072)
        p.add_argument("--note", default="")
        a = p.parse_args(argv[1:])
        try:
            private, entry = signing.generate_signing_key(a.key_id, bits=a.bits)
            entry["not_before"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            entry["note"] = a.note
            signing.save_private_key(private, a.out)
        except (ValueError, FileExistsError) as e:
            print(f"keygen refused: {e}", file=sys.stderr)
            return 2
        print(f"private key written to {a.out} (mode 0600) — keep it "
              "outside every repository and never commit it",
              file=sys.stderr)
        print("public registry entry (commit this to "
              "savage_standard/key_registry.json):", file=sys.stderr)
        print(json.dumps(entry, indent=1))
        return 0
    if argv and argv[0] == "sign":
        p = argparse.ArgumentParser(prog="savage-verify sign")
        p.add_argument("envelope")
        p.add_argument("--key-file",
                       help="private key record (default: $"
                            "SAVAGE_SIGNING_KEY_FILE)")
        p.add_argument("--key-id")
        p.add_argument("-o", "--out")
        a = p.parse_args(argv[1:])
        try:
            private = (signing.load_private_key(a.key_file) if a.key_file
                       else signing.private_key_from_env())
            env = verify_mod.load_input(a.envelope)
            signed = signing.sign_envelope(env, private, key_id=a.key_id)
        except (ValueError, OSError) as e:
            print(f"sign refused: {e}", file=sys.stderr)
            return 2
        text = json.dumps(signed, indent=1) + "\n"
        if a.out:
            open(a.out, "w", encoding="utf-8").write(text)
        else:
            print(text, end="")
        return 0
    if argv and argv[0] == "wrap":
        p = argparse.ArgumentParser(prog="savage-verify wrap")
        p.add_argument("native")
        for flag in ("claim-id", "claim-kind", "statement", "issuer-line",
                     "issuer-system", "dialect", "native-schema", "gate-name",
                     "gate-verdict", "recorded-at"):
            p.add_argument(f"--{flag}", required=True)
        p.add_argument("--prev-digest")
        p.add_argument("-o", "--out")
        a = p.parse_args(argv[1:])
        native = verify_mod.load_input(a.native)
        env = envelope.wrap(
            native, claim_id=a.claim_id, claim_kind=a.claim_kind,
            statement=a.statement, issuer_line=a.issuer_line,
            issuer_system=a.issuer_system, dialect=a.dialect,
            native_schema=a.native_schema, gate_name=a.gate_name,
            gate_verdict=a.gate_verdict, recorded_at=a.recorded_at,
            prev_digest=a.prev_digest)
        text = json.dumps(env, indent=1) + "\n"
        if a.out:
            open(a.out, "w", encoding="utf-8").write(text)
        else:
            print(text, end="")
        return 0
    if argv and argv[0] == "recompute":
        p = argparse.ArgumentParser(prog="savage-verify recompute")
        p.add_argument("per_instance_stats")
        for flag in ("metric", "split", "benchmark", "release", "scenario",
                     "run", "model", "model-display", "metric-label",
                     "source-url"):
            p.add_argument(f"--{flag}", required=True)
        p.add_argument("--published-value", required=True, type=float)
        p.add_argument("--published-source", action="append", required=True)
        p.add_argument("--source-file")
        p.add_argument("--recorded-at")
        p.add_argument("-o", "--out")
        a = p.parse_args(argv[1:])
        with open(a.per_instance_stats, "rb") as fh:
            data = fh.read()
        recorded = a.recorded_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        try:
            receipt = helm.mint_receipt(
                data, benchmark=a.benchmark, release=a.release,
                scenario=a.scenario, run=a.run, model=a.model,
                model_display=a.model_display, metric=a.metric,
                metric_label=a.metric_label, split=a.split,
                published_value=a.published_value,
                published_sources=a.published_source,
                source_url=a.source_url,
                source_file=a.source_file or "per_instance_stats.json",
                recorded_at=recorded)
        except ValueError as e:
            print(f"recompute refused: {e}", file=sys.stderr)
            return 2
        text = json.dumps(receipt, indent=1) + "\n"
        if a.out:
            open(a.out, "w", encoding="utf-8").write(text)
        else:
            print(text, end="")
        return 0
    p = argparse.ArgumentParser(prog="savage-verify")
    p.add_argument("receipt")
    p.add_argument("--pair")
    p.add_argument("--artifacts", help="directory holding referenced evidence/artifact files")
    p.add_argument("--file", help="the single artifact file a receipt describes (e.g. a Starr bounce WAV)")
    p.add_argument("--bound-laws", action="append", default=[],
                   help="CANDIDATE=LAW1,LAW2,... bound-law set for Breakthrough scoring")
    p.add_argument("--keys", help="key registry JSON for envelope "
                                  "signatures (default: the registry "
                                  "shipped in the package)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    obj = verify_mod.load_input(a.receipt)
    pair = verify_mod.load_input(a.pair) if a.pair else None
    bound = {}
    for spec in a.bound_laws:
        cid, _, laws = spec.partition("=")
        bound[cid] = [x for x in laws.split(",") if x]
    registry = signing.load_registry(a.keys) if a.keys else None
    out = verify_mod.verify(obj, pair=pair, artifact_dir=a.artifacts,
                            artifact_file=a.file, bound_laws=bound or None,
                            key_registry=registry)
    if a.json:
        print(json.dumps(out, indent=1))
    else:
        _print_human(out)
    if out["verdict"] in ("VERIFIED", "VERIFIED-STRUCTURAL"):
        return 0
    if out["verdict"] == "REJECTED":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
