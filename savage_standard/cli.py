"""savage-verify — the universal verifier CLI.

Usage:
  savage-verify RECEIPT [--pair RECEIPT] [--artifacts DIR] [--file PATH]
                        [--bound-laws CANDIDATE=LAW1,LAW2,...] [--json]
  savage-verify wrap NATIVE --claim-id ID --claim-kind KIND --statement S
                        --issuer-line L --issuer-system S --dialect D
                        --native-schema S --gate-name G --gate-verdict V
                        --recorded-at T [--prev-digest HEX] [-o OUT]
  savage-verify claims        (print the claims-gate inventory summary)

Exit codes: 0 = VERIFIED or VERIFIED-STRUCTURAL; 1 = REJECTED;
2 = UNVERIFIABLE or usage error. A tampered receipt never exits 0.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import envelope, verify as verify_mod
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
    p = argparse.ArgumentParser(prog="savage-verify")
    p.add_argument("receipt")
    p.add_argument("--pair")
    p.add_argument("--artifacts", help="directory holding referenced evidence/artifact files")
    p.add_argument("--file", help="the single artifact file a receipt describes (e.g. a Starr bounce WAV)")
    p.add_argument("--bound-laws", action="append", default=[],
                   help="CANDIDATE=LAW1,LAW2,... bound-law set for Breakthrough scoring")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    obj = verify_mod.load_input(a.receipt)
    pair = verify_mod.load_input(a.pair) if a.pair else None
    bound = {}
    for spec in a.bound_laws:
        cid, _, laws = spec.partition("=")
        bound[cid] = [x for x in laws.split(",") if x]
    out = verify_mod.verify(obj, pair=pair, artifact_dir=a.artifacts,
                            artifact_file=a.file, bound_laws=bound or None)
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
