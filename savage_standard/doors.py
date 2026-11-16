"""DATA-E1 — the Door Registry: the estate's named assets ("doors")
under one sealed, re-derivable registry artifact.

A door is a named asset the estate exposes or operates: an org
repository, a commercial payment door, a service seat. Before this
module the estate's doors lived in separate, unsealed places — the org
listing behind the estate attestation's snapshot, the payment doors in
savage-marketplace's register — and one whole class (the assets riding
the pending ~94 GB transfer) lived in no registry at all. This module
generalizes the attestation pattern of estate.py to doors:

    doors snapshot ──► derived door records ──► sealed artifact
    (landed sources)   (pure derivation)        (digest + verify)

Snapshot shape (every field below is required unless noted):

    {
      "org": "Savages-studios",
      "taken_at": "<ISO-8601>",
      "sources": {
        "repos":            {"repo": ..., "path": ..., "as_of": ...},
        "commercial_doors": {"repo": ..., "path": ..., "as_of": ...}
      },
      "repos":            [{"name": ..., "head": ...}, ...],
      "commercial_doors": [{"sku": ..., "product_name": ...,
                            "url": ..., "amount_minor": ...,
                            "currency": ..., "recurring": ...,
                            "active": true|false}, ...],
      "gated":            [{"name": ..., "reason": ...}, ...]
    }

Derivation rules (mechanical; no judgment calls at build time):

- Every registered section must declare its source in "sources"
  ({repo, path, as_of}). A section carrying entries without a declared
  source raises ValueError — there are no unsourced doors.
- "repos" and "commercial_doors" may each be absent or empty, but the
  registry refuses a snapshot whose TOTAL registered doors is zero:
  registering nothing is never a silent success (estate.py's rule).
- A repo entry missing name/head, or a commercial entry missing
  sku/url, is malformed and raises ValueError — identity fields are
  not optional and are never invented.
- A commercial door whose source entry does not carry active=true is
  registered WITH a named failure ("not active in its source
  registry" / "active flag absent in its source entry") — the fact is
  carried, never hidden and never fatal to the build.
- A duplicate (kind, name) pair names a failure on the later record.
- "gated" entries are program declarations, not sourced facts: asset
  classes that cannot be enumerated from landed sources today (the
  transfer payload's contents). They are carried verbatim as records
  with locator null and their reason stated, so the gated universe is
  PRESENT in the registry — labeled, never silently absent and never
  fabricated into doors.

The artifact (savage.door_registry.v1) embeds the snapshot verbatim;
its digest is SHA-256 over this package's JCS canonical form (the same
canonicalizer estate.py uses). verify_registry re-derives EVERY record
from the embedded snapshot and compares field by field, so tampering
that honestly recomputes the digest is still rejected, naming the door
and the field.

Stdlib only, like the rest of the package. No fetcher ships: snapshots
are composed by the operator from landed sources (see the module's
GROUND_TRUTH entry for the composition of record).
"""

import hashlib

from . import canonical

KIND = "savage.door_registry.v1"

_SECTIONS = ("repos", "commercial_doors")


def _declared_source(snapshot, section):
    """The declared source dict for a snapshot section, or raise."""
    sources = snapshot.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("snapshot missing 'sources' — no unsourced doors")
    source = sources.get(section)
    if not isinstance(source, dict):
        raise ValueError(
            f"snapshot section {section!r} has entries but no declared "
            f"source in 'sources' — no unsourced doors")
    for field in ("repo", "path", "as_of"):
        if not source.get(field) or not isinstance(source.get(field), str):
            raise ValueError(
                f"snapshot source for {section!r} missing {field!r}")
    return {"repo": source["repo"], "path": source["path"],
            "as_of": source["as_of"]}


def _derive_repo(entry, source):
    if not isinstance(entry, dict):
        raise ValueError("repo door entry is not an object")
    name = entry.get("name")
    head = entry.get("head")
    if not name or not isinstance(name, str):
        raise ValueError("repo door entry missing 'name'")
    if not head or not isinstance(head, str):
        raise ValueError(f"repo door {name}: entry missing 'head'")
    return {"name": name, "kind": "repo", "locator": f"repo:{name}",
            "head": head, "source": source, "failures": []}


def _derive_commercial(entry, source):
    if not isinstance(entry, dict):
        raise ValueError("commercial door entry is not an object")
    sku = entry.get("sku")
    url = entry.get("url")
    if not sku or not isinstance(sku, str):
        raise ValueError("commercial door entry missing 'sku'")
    if not url or not isinstance(url, str):
        raise ValueError(f"commercial door {sku}: entry missing 'url'")
    failures = []
    active = entry.get("active")
    if active is True:
        pass
    elif active is None:
        failures.append("active flag absent in its source entry")
    else:
        failures.append("commercial door not active in its source registry")
    return {"name": sku, "kind": "commercial", "locator": url,
            "product_name": entry.get("product_name"),
            "amount_minor": entry.get("amount_minor"),
            "currency": entry.get("currency"),
            "recurring": entry.get("recurring"),
            "active": active, "source": source, "failures": failures}


def _derive_gated(entry):
    if not isinstance(entry, dict):
        raise ValueError("gated entry is not an object")
    name = entry.get("name")
    reason = entry.get("reason")
    if not name or not isinstance(name, str):
        raise ValueError("gated entry missing 'name'")
    if not reason or not isinstance(reason, str):
        raise ValueError(f"gated entry {name}: missing 'reason'")
    return {"name": name, "kind": "gated", "locator": None,
            "reason": reason, "source": None, "failures": []}


def _digest(core: dict) -> str:
    """SHA-256 over the JCS canonical form (the package's one
    canonicalizer, shared with estate.py)."""
    return hashlib.sha256(canonical.jcs(core).encode("utf-8")).hexdigest()


def artifact_digest(artifact: dict) -> str:
    core = {k: v for k, v in artifact.items() if k != "digest"}
    return _digest(core)


def build_registry(snapshot: dict) -> dict:
    """Build the sealed door-registry artifact from a snapshot dict.
    Raises ValueError on a malformed snapshot — including a snapshot
    registering zero doors: registering nothing is never a silent
    success."""
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot is not a JSON object")
    org = snapshot.get("org")
    taken_at = snapshot.get("taken_at")
    if not org or not isinstance(org, str):
        raise ValueError("snapshot missing 'org'")
    if not taken_at or not isinstance(taken_at, str):
        raise ValueError("snapshot missing 'taken_at'")

    records = []
    for section, derive in (("repos", _derive_repo),
                            ("commercial_doors", _derive_commercial)):
        entries = snapshot.get(section) or []
        if not isinstance(entries, list):
            raise ValueError(f"snapshot {section!r} is not a list")
        if entries:
            source = _declared_source(snapshot, section)
            records.extend(derive(entry, source) for entry in entries)
    gated_entries = snapshot.get("gated") or []
    if not isinstance(gated_entries, list):
        raise ValueError("snapshot 'gated' is not a list")
    records.extend(_derive_gated(entry) for entry in gated_entries)

    seen = set()
    for rec in records:
        key = (rec["kind"], rec["name"])
        if key in seen:
            rec["failures"].append(
                f"duplicate {rec['kind']} door name in snapshot")
        seen.add(key)

    registered = [r for r in records if r["kind"] != "gated"]
    if not registered:
        raise ValueError(
            "snapshot registers zero doors — refusing to register nothing")
    failures = [{"door": rec["name"], "kind": rec["kind"], "reason": reason}
                for rec in records for reason in rec["failures"]]
    summary = {
        "doors_registered": len(registered),
        "repos": sum(1 for r in records if r["kind"] == "repo"),
        "commercial_doors": sum(1 for r in records
                                if r["kind"] == "commercial"),
        "commercial_active": sum(1 for r in records
                                 if r["kind"] == "commercial"
                                 and r["active"] is True),
        "gated": sum(1 for r in records if r["kind"] == "gated"),
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
    ("name",), ("kind",), ("locator",), ("head",), ("product_name",),
    ("amount_minor",), ("currency",), ("recurring",), ("active",),
    ("reason",), ("source", "repo"), ("source", "path"),
    ("source", "as_of"), ("failures",),
]


def verify_registry(artifact) -> tuple:
    """Verify a sealed door registry: recompute the digest AND
    re-derive every record from the embedded snapshot and compare
    field by field. Returns (ok, mismatches) — each mismatch names
    the door and the field (or the artifact-level field) that
    disagrees. Any tampered record, count or failure list is caught,
    including tampering that honestly recomputes the digest."""
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
        expected = build_registry(snapshot)
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
        door = want["name"]
        if not isinstance(got, dict):
            mismatches.append(f"{door}: record is not an object")
            continue
        if got.get("name") != door:
            mismatches.append(
                f"{door}: name mismatch: artifact record is for "
                f"{got.get('name')!r}")
            continue
        for path in _RECORD_FIELDS:
            dotted = ".".join(path)
            gv, wv = _get_path(got, path), _get_path(want, path)
            if gv != wv:
                mismatches.append(
                    f"{door}: {dotted} mismatch: artifact has {gv!r}, "
                    f"re-derived {wv!r}")
    if artifact.get("summary") != expected["summary"]:
        mismatches.append(
            f"summary: artifact has {artifact.get('summary')!r}, "
            f"re-derived {expected['summary']!r}")
    if artifact.get("failures") != expected["failures"]:
        mismatches.append(
            "failures: artifact failure list does not match the "
            "re-derived list")
    return (not mismatches), mismatches
