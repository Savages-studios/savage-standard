"""PROOF-E1 — the estate attestation: one command, one artifact.

``savage-verify estate`` attests the whole estate at once from a single
snapshot: for every repository it records the default-branch head, the
GROUND_TRUTH.md citation state (does the file exist, which head does it
cite, is that citation current), the latest recorded CI state, and the
claims-gate rows that concern the repo — then seals the result with a
SHA-256 digest over the canonical JSON of the artifact, embedding the
snapshot verbatim so any outsider can re-derive every verdict with
:func:`verify_artifact`. Before this build the CLI had no estate
subcommand at all: repositories attested per run = 0.

Snapshot shape (produced by ``estate_fetch.fetch_snapshot`` for token
holders, or by hand / by any other collector)::

    {"org": str, "taken_at": ISO-8601 Z str,
     "repos": [{"name": str, "head": full sha str,
                "ground_truth": full GROUND_TRUTH.md text or None,
                "ci": [{"workflow": str, "status": str,
                        "conclusion": str or None,
                        "updated_at": ISO-8601 str}]}]}

GROUND_TRUTH citation conventions (the estate's, verified across
repos): a ``**Head:**`` line carries the cited head; otherwise a
``**Canonical branch:** main @ `<sha>` `` line does. Extraction prefers
the ``**Head:**`` line's first hex token (7–40 chars, backticks
allowed), else the ``Canonical branch:`` line's first hex token after
``@``, else no citation. Currency is a prefix comparison in both
directions at >= 7 chars, so a short citation of the current head is
CURRENT and any other citation is DRIFTED. ``**Last verified:**
YYYY-MM-DD`` is parsed when present and aged against ``taken_at``;
its absence is reported (null), not failed — the named GT failures
are exactly MISSING, UNPINNED and DRIFTED.

CI state is derived from the latest run per workflow (by
``updated_at``): FAILING if any latest run concluded ``failure`` (the
workflow is named in the failures), PASSING if at least one latest run
completed with ``success`` and none failed, IN_PROGRESS if any latest
run has not completed and none failed, NONE_RECORDED if the snapshot
carries no runs at all — a named failure, never a silent pass. A repo
whose latest runs all completed with no success and no failure (e.g.
all cancelled) is NOT_PASSING with each such workflow named.

Claims cross-reference rule: a row of ``claims.INVENTORY`` attaches to
a repo when the repo's name appears as a case-sensitive substring of
the row's ``claim`` or ``basis`` text. The attached record is exactly
``{"id", "gated"}`` — the inventory's receipt status is carried, not
re-adjudicated.

Honesty boundary: the attestation reports GT *citation* drift and the
*recorded* CI state. It does not re-verify GROUND_TRUTH contents and
does not re-run any test suite. Savage-original, stdlib only.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from . import canonical
from .claims import INVENTORY

KIND = "savage.estate_attestation.v1"

_HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{7,40}(?![0-9a-fA-F])")
_LAST_VERIFIED = re.compile(
    r"Last verified:\s*\**\s*(\d{4})-(\d{2})-(\d{2})")


def extract_cited_head(ground_truth: str):
    """The head a GROUND_TRUTH.md cites, or None. ``**Head:**`` lines
    win over ``Canonical branch:`` lines wherever they appear."""
    lines = ground_truth.splitlines()
    for line in lines:
        if "**Head:**" in line:
            m = _HEX_TOKEN.search(line.split("**Head:**", 1)[1])
            if m:
                return m.group(0)
    for line in lines:
        if "Canonical branch:" in line and "@" in line:
            m = _HEX_TOKEN.search(line.split("@", 1)[1])
            if m:
                return m.group(0)
    return None


def extract_last_verified(ground_truth: str):
    """The ``**Last verified:** YYYY-MM-DD`` date string, or None."""
    m = _LAST_VERIFIED.search(ground_truth)
    if not m:
        return None
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"


def _taken_date(taken_at):
    """The UTC calendar date of an ISO-8601 ``taken_at``, or None."""
    if not isinstance(taken_at, str):
        return None
    try:
        dt = datetime.fromisoformat(taken_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.date()


def _heads_match(cited: str, head: str) -> bool:
    """Prefix comparison in both directions at >= 7 chars."""
    a, b = cited.lower(), head.lower()
    if len(a) < 7 or len(b) < 7:
        return False
    return a == b or b.startswith(a) or a.startswith(b)


def _latest_per_workflow(ci_list):
    """Latest run per workflow name, by (updated_at, input order)."""
    latest = {}
    for idx, run in enumerate(ci_list):
        if not isinstance(run, dict):
            continue
        name = run.get("workflow") or run.get("name") or ""
        key = (run.get("updated_at") or "", idx)
        if name not in latest or key >= latest[name][0]:
            latest[name] = (key, {
                "workflow": name,
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
                "updated_at": run.get("updated_at"),
            })
    return [latest[name][1] for name in sorted(latest)]


def derive_record(repo_entry: dict, taken_at) -> dict:
    """One repo's attestation record, derived purely from its snapshot
    entry. Raises ValueError on a malformed entry (no name / head)."""
    if not isinstance(repo_entry, dict):
        raise ValueError("repo entry is not an object")
    name = repo_entry.get("name")
    head = repo_entry.get("head")
    if not name or not isinstance(name, str):
        raise ValueError("repo entry missing 'name'")
    if not head or not isinstance(head, str):
        raise ValueError(f"repo {name}: entry missing 'head'")
    failures = []

    # ── Ground truth ────────────────────────────────────────────────
    gt_text = repo_entry.get("ground_truth")
    present = isinstance(gt_text, str)
    cited = extract_cited_head(gt_text) if present else None
    last_verified = extract_last_verified(gt_text) if present else None
    age_days = None
    if last_verified is not None:
        taken = _taken_date(taken_at)
        if taken is not None:
            try:
                lv = datetime.strptime(last_verified, "%Y-%m-%d").date()
                age_days = (taken - lv).days
            except ValueError:
                age_days = None
    if not present:
        currency = "MISSING"
        failures.append(
            "ground truth missing: no GROUND_TRUTH.md in snapshot")
    elif cited is None:
        currency = "UNPINNED"
        failures.append(
            "ground truth unpinned: no head citation in GROUND_TRUTH.md")
    elif _heads_match(cited, head):
        currency = "CURRENT"
    else:
        currency = "DRIFTED"
        failures.append(
            f"ground truth drifted: cites {cited} but head is {head}")
    gt = {"present": present, "cited_head": cited, "currency": currency,
          "last_verified": last_verified, "age_days": age_days}

    # ── CI ──────────────────────────────────────────────────────────
    ci_list = repo_entry.get("ci") or []
    if not isinstance(ci_list, list):
        ci_list = []
    workflows = _latest_per_workflow(ci_list)
    if not ci_list:
        ci_state = "NONE_RECORDED"
        failures.append("no CI state recorded")
    else:
        failed = [w for w in workflows if w["conclusion"] == "failure"]
        running = [w for w in workflows if w["status"] != "completed"]
        succeeded = [w for w in workflows
                     if w["status"] == "completed"
                     and w["conclusion"] == "success"]
        if failed:
            ci_state = "FAILING"
            for w in failed:
                failures.append(
                    f"CI failing: workflow '{w['workflow']}' "
                    f"concluded failure")
        elif running:
            ci_state = "IN_PROGRESS"
        elif succeeded:
            ci_state = "PASSING"
        else:
            ci_state = "NOT_PASSING"
            for w in workflows:
                failures.append(
                    f"CI not passing: workflow '{w['workflow']}' "
                    f"concluded {w['conclusion']}")
    ci = {"state": ci_state, "workflows": workflows}

    # ── Claims cross-reference (rule in the module docstring) ───────
    attached = [{"id": row["id"], "gated": row["gated"]}
                for row in INVENTORY
                if name in row["claim"] or name in row["basis"]]

    return {"repo": name, "head": head, "gt": gt, "ci": ci,
            "claims": attached, "failures": failures}


def _digest(core: dict) -> str:
    """SHA-256 over the JCS canonical form (the envelope's own
    canonicalizer — one canonicalizer serves the whole package)."""
    return hashlib.sha256(canonical.jcs(core).encode("utf-8")).hexdigest()


def artifact_digest(artifact: dict) -> str:
    core = {k: v for k, v in artifact.items() if k != "digest"}
    return _digest(core)


def build_attestation(snapshot: dict) -> dict:
    """Build the sealed attestation artifact from a snapshot dict.
    Raises ValueError on a malformed snapshot — including an empty
    repos list: attesting nothing is never a silent success."""
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot is not a JSON object")
    org = snapshot.get("org")
    taken_at = snapshot.get("taken_at")
    repos = snapshot.get("repos")
    if not org or not isinstance(org, str):
        raise ValueError("snapshot missing 'org'")
    if not taken_at or not isinstance(taken_at, str):
        raise ValueError("snapshot missing 'taken_at'")
    if not isinstance(repos, list) or not repos:
        raise ValueError("snapshot 'repos' is missing or empty — "
                         "refusing to attest nothing")
    records = [derive_record(entry, taken_at) for entry in repos]
    failures = [{"repo": rec["repo"], "reason": reason}
                for rec in records for reason in rec["failures"]]
    summary = {
        "repos_attested": len(records),
        "gt_present": sum(1 for r in records if r["gt"]["present"]),
        "gt_current": sum(1 for r in records
                          if r["gt"]["currency"] == "CURRENT"),
        "ci_passing": sum(1 for r in records
                          if r["ci"]["state"] == "PASSING"),
        "claims_rows_attached": sum(len(r["claims"]) for r in records),
        "claims_gated": sum(1 for r in records for c in r["claims"]
                            if c["gated"]),
    }
    artifact = {"kind": KIND, "org": org, "taken_at": taken_at,
                "snapshot": snapshot, "records": records,
                "summary": summary, "failures": failures}
    artifact["digest"] = artifact_digest(artifact)
    return artifact


def _get_path(obj, path):
    cur = obj
    for part in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


_RECORD_FIELDS = [
    ("head",), ("gt", "present"), ("gt", "cited_head"),
    ("gt", "currency"), ("gt", "last_verified"), ("gt", "age_days"),
    ("ci", "state"), ("ci", "workflows"), ("claims",), ("failures",),
]


def verify_artifact(artifact) -> tuple:
    """Verify a sealed attestation: recompute the digest AND re-derive
    every record from the embedded snapshot and compare field by
    field. Returns (ok, mismatches) — each mismatch names the repo and
    the field (or the artifact-level field) that disagrees. Any
    tampered verdict, record, count or failure list is caught."""
    mismatches = []
    if not isinstance(artifact, dict):
        return False, ["artifact is not a JSON object"]
    if artifact.get("kind") != KIND:
        mismatches.append(
            f"kind: expected {KIND!r}, found {artifact.get('kind')!r}")
    try:
        recomputed = artifact_digest(artifact)
    except canonical.CanonicalError as e:
        return False, mismatches + [f"digest: uncanonicalizable ({e})"]
    if artifact.get("digest") != recomputed:
        mismatches.append(
            "digest: stored digest does not match the recomputed "
            "SHA-256 of the artifact without the digest field")
    snapshot = artifact.get("snapshot")
    if not isinstance(snapshot, dict):
        return False, mismatches + ["snapshot: missing or not an object"]
    try:
        expected = build_attestation(snapshot)
    except ValueError as e:
        return False, mismatches + [
            f"snapshot: records cannot be re-derived ({e})"]
    for field in ("org", "taken_at"):
        if artifact.get(field) != expected[field]:
            mismatches.append(
                f"{field}: artifact has {artifact.get(field)!r}, "
                f"snapshot says {expected[field]!r}")
    stored_records = artifact.get("records")
    if not isinstance(stored_records, list):
        mismatches.append("records: missing or not a list")
        stored_records = []
    if len(stored_records) != len(expected["records"]):
        mismatches.append(
            f"records: artifact holds {len(stored_records)} records, "
            f"snapshot re-derives {len(expected['records'])}")
    for want, got in zip(expected["records"], stored_records):
        repo = want["repo"]
        if not isinstance(got, dict):
            mismatches.append(f"{repo}: record is not an object")
            continue
        if got.get("repo") != repo:
            mismatches.append(
                f"{repo}: repo mismatch: artifact record is for "
                f"{got.get('repo')!r}")
            continue
        for path in _RECORD_FIELDS:
            dotted = ".".join(path)
            gv, wv = _get_path(got, path), _get_path(want, path)
            if gv != wv:
                mismatches.append(
                    f"{repo}: {dotted} mismatch: artifact has {gv!r}, "
                    f"re-derived {wv!r}")
        if got != want and not any(
                m.startswith(f"{repo}: ") for m in mismatches):
            mismatches.append(
                f"{repo}: record mismatch: fields beyond the named "
                f"checks differ from the re-derived record")
    stored_summary = artifact.get("summary")
    if not isinstance(stored_summary, dict):
        mismatches.append("summary: missing or not an object")
    else:
        for key, wv in expected["summary"].items():
            if stored_summary.get(key) != wv:
                mismatches.append(
                    f"summary.{key}: artifact has "
                    f"{stored_summary.get(key)!r}, re-derived {wv!r}")
    if artifact.get("failures") != expected["failures"]:
        mismatches.append(
            "failures: artifact failure list does not match the "
            "failures re-derived from the snapshot")
    return (not mismatches), mismatches
