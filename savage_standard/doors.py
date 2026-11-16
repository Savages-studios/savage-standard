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

Cross-verification (commercial doors, this build): a commercial
entry may carry per-source observations —

    "commercial_doors": [{"sku": ...,
                          "observations": {
                            "register": {...},
                            "registry_of_record": {...},
                            "readback": {...}}}, ...]

— and "sources"."commercial_doors" then declares one source per
observation instead of a single source:

    "commercial_doors": {
      "register":           {"repo": ..., "path": ..., "as_of": ...},
      "registry_of_record": {"repo": ..., "path": ..., "as_of": ...,
                             "sha256": ... (optional, preserved)},
      "readback":           {"repo": ..., "path": ..., "as_of": ...}}

Each observation carries the fields that source actually carries, in
that source's own names where they differ (the registry of record's
"name" / "amount_cents" / "billing" are read as product_name /
amount_minor / recurring — "one_time" -> null, "subscription_month"
-> "month", "subscription_year" -> "year"; a source that carries no
currency simply does not vote on currency). The record's identity
fields are DERIVED from the observations: for each field, the value
of the latest-as_of source that carries it (the readback in the live
registry — the latest first-hand observation). The record's
verification state is likewise derived, never asserted:

- every source carrying a field agrees on it -> "VERIFIED", with
  "verification_sources" naming the sources that observed the door;
- any field disagrees -> "DISAGREEMENT", the record follows the
  latest observation for every field, and a named failure records,
  per disagreed field, which sources held which value and which
  source the record followed.

An entry with no observations keeps the original single-source
derivation and carries verification / verification_sources /
observations all null — transcribed, not cross-verified; the
distinction is in the record, never hidden, and a registry built
from a pre-cross-verification snapshot re-derives byte-identically
(records and summary) under this code.

Derivation rules (mechanical; no judgment calls at build time):

- Every registered section must declare its source in "sources"
  ({repo, path, as_of}). A section carrying entries without a declared
  source raises ValueError — there are no unsourced doors.
- "repos" and "commercial_doors" may each be absent or empty, but the
  registry refuses a snapshot whose TOTAL registered doors is zero:
  registering nothing is never a silent success (estate.py's rule).
- A repo entry missing name/head, or a commercial entry missing
  sku/url, is malformed and raises ValueError — identity fields are
  not optional and are never invented. (With observations, the url
  identity is the derived canonical url; a door no source gives a
  url to is malformed on the same rule.)
- A commercial door whose source entry does not carry active=true is
  registered WITH a named failure ("not active in its source
  registry" / "active flag absent in its source entry") — the fact is
  carried, never hidden and never fatal to the build. For a
  cross-verified door whose sources disagree on "active", the
  disagreement failure is that door's named failure (it already
  records the inactive latest value); the generic not-active failure
  is not duplicated on top of it.
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
from the embedded snapshot and compares field by field — including
each commercial record's embedded observations, its verification
verdict and its source declarations — so tampering that honestly
recomputes the digest is still rejected, naming the door and the
field: flipping an observation in a record, erasing a disagreement
failure, or upgrading a verdict to VERIFIED all fail re-derivation,
because the verdict is recomputed from the snapshot's observations,
never read off the record.

Stdlib only, like the rest of the package. No fetcher ships: snapshots
are composed by the operator from landed sources (see the module's
GROUND_TRUTH entry for the composition of record).
"""

import copy
import hashlib

from . import canonical

KIND = "savage.door_registry.v1"

_SECTIONS = ("repos", "commercial_doors")

# Cross-verification source names, in declaration order. A commercial
# entry's "observations" may carry any non-empty subset of these.
_OBSERVATION_SOURCES = ("register", "registry_of_record", "readback")

# The identity fields cross-verification votes on, in failure-report
# order. A source votes only on the fields its observation carries.
_IDENTITY_FIELDS = ("product_name", "url", "amount_minor", "currency",
                    "recurring", "active")

# The registry of record's native billing vocabulary -> recurring.
_BILLING_RECURRING = {"one_time": None, "subscription_month": "month",
                      "subscription_year": "year"}


def _validate_source(source, label):
    if not isinstance(source, dict):
        raise ValueError(f"snapshot source for {label!r} is not an object")
    for field in ("repo", "path", "as_of"):
        if not source.get(field) or not isinstance(source.get(field), str):
            raise ValueError(
                f"snapshot source for {label!r} missing {field!r}")
    out = {"repo": source["repo"], "path": source["path"],
           "as_of": source["as_of"]}
    # Extra string declarations (e.g. a source file's sha256, an
    # as_of evidence note) are part of the declaration: preserve them
    # so re-derivation compares them too.
    for key, value in source.items():
        if key not in out and isinstance(value, str):
            out[key] = value
    return out


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
    return _validate_source(source, section)


def _commercial_sources(snapshot):
    """(primary source, per-source map or None) for commercial doors.

    Legacy snapshots declare one source dict ({repo, path, as_of}):
    the map is None. Cross-verifying snapshots declare one source
    per observation name; the map carries every declared source and
    the primary (record-level "source") is the register's."""
    sources = snapshot.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("snapshot missing 'sources' — no unsourced doors")
    raw = sources.get("commercial_doors")
    if not isinstance(raw, dict):
        raise ValueError(
            "snapshot section 'commercial_doors' has entries but no "
            "declared source in 'sources' — no unsourced doors")
    if "repo" in raw or "path" in raw or "as_of" in raw:
        return _validate_source(raw, "commercial_doors"), None
    declared = {}
    for name, source in raw.items():
        if name not in _OBSERVATION_SOURCES:
            raise ValueError(
                f"snapshot declares unknown commercial source {name!r}")
        declared[name] = _validate_source(source, f"commercial_doors.{name}")
    if "register" not in declared:
        raise ValueError(
            "snapshot commercial sources declare no 'register' source")
    return declared["register"], declared


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


def _normalize_observation(sku, source_name, obs):
    """One source's observation, normalized to the identity fields
    that source actually carries. Native names are translated
    mechanically (name -> product_name, amount_cents -> amount_minor,
    billing -> recurring); a field the source does not carry is
    absent from the result and does not vote on that field."""
    if not isinstance(obs, dict):
        raise ValueError(
            f"commercial door {sku}: {source_name} observation is not "
            f"an object")
    if obs.get("sku") is not None and obs.get("sku") != sku:
        raise ValueError(
            f"commercial door {sku}: {source_name} observation carries "
            f"sku {obs.get('sku')!r}")
    out = {}
    if "product_name" in obs:
        out["product_name"] = obs["product_name"]
    elif "name" in obs:
        out["product_name"] = obs["name"]
    if "url" in obs:
        out["url"] = obs["url"]
    if "amount_minor" in obs:
        out["amount_minor"] = obs["amount_minor"]
    elif "amount_cents" in obs:
        out["amount_minor"] = obs["amount_cents"]
    if "currency" in obs:
        out["currency"] = obs["currency"]
    if "recurring" in obs:
        out["recurring"] = obs["recurring"]
    elif "billing" in obs:
        billing = obs["billing"]
        if billing not in _BILLING_RECURRING:
            raise ValueError(
                f"commercial door {sku}: {source_name} observation "
                f"carries unknown billing {billing!r}")
        out["recurring"] = _BILLING_RECURRING[billing]
    if "active" in obs:
        out["active"] = obs["active"]
    return out


def _derive_commercial_cross(sku, entry, source, sources_map):
    observations = entry.get("observations")
    if not isinstance(observations, dict) or not observations:
        raise ValueError(
            f"commercial door {sku}: 'observations' is not a non-empty "
            f"object")
    for name in observations:
        if name not in _OBSERVATION_SOURCES:
            raise ValueError(
                f"commercial door {sku}: unknown observation source "
                f"{name!r}")
        if sources_map is None or name not in sources_map:
            raise ValueError(
                f"commercial door {sku}: observation from {name!r} but "
                f"the snapshot declares no source for it — no unsourced "
                f"doors")
    present = [n for n in _OBSERVATION_SOURCES if n in observations]
    normalized = {n: _normalize_observation(sku, n, observations[n])
                  for n in present}
    # Canonical precedence: latest declared as_of first (the latest
    # first-hand observation governs); ties break by declaration
    # order, later source winning.
    precedence = sorted(
        present,
        key=lambda n: (sources_map[n]["as_of"],
                       _OBSERVATION_SOURCES.index(n)),
        reverse=True)
    canonical_fields = {}
    followed = {}
    for field in _IDENTITY_FIELDS:
        for name in precedence:
            if field in normalized[name]:
                canonical_fields[field] = normalized[name][field]
                followed[field] = name
                break
    url = canonical_fields.get("url")
    if not url or not isinstance(url, str):
        raise ValueError(f"commercial door {sku}: entry missing 'url'")
    disagreements = []
    for field in _IDENTITY_FIELDS:
        votes = {n: normalized[n][field] for n in present
                 if field in normalized[n]}
        distinct = []
        for value in votes.values():
            if value not in distinct:
                distinct.append(value)
        if len(distinct) > 1:
            disagreements.append((field, votes))
    failures = []
    for field, votes in disagreements:
        detail = ", ".join(f"{n}={votes[n]!r}" for n in present
                           if n in votes)
        failures.append(
            f"cross-verification disagreement on {field}: {detail} "
            f"(record follows latest first-hand observation: "
            f"{followed[field]})")
    active = canonical_fields.get("active")
    if not any(field == "active" for field, _ in disagreements):
        if active is None:
            failures.append("active flag absent in its source entry")
        elif active is not True:
            failures.append(
                "commercial door not active in its source registry")
    return {"name": sku, "kind": "commercial", "locator": url,
            "product_name": canonical_fields.get("product_name"),
            "amount_minor": canonical_fields.get("amount_minor"),
            "currency": canonical_fields.get("currency"),
            "recurring": canonical_fields.get("recurring"),
            "active": active, "source": source,
            "sources": sources_map,
            "observations": copy.deepcopy(observations),
            "verification": "DISAGREEMENT" if disagreements else "VERIFIED",
            "verification_sources": present,
            "failures": failures}


def _derive_commercial(entry, source, sources_map=None):
    if not isinstance(entry, dict):
        raise ValueError("commercial door entry is not an object")
    sku = entry.get("sku")
    if not sku or not isinstance(sku, str):
        raise ValueError("commercial door entry missing 'sku'")
    if entry.get("observations") is not None:
        return _derive_commercial_cross(sku, entry, source, sources_map)
    url = entry.get("url")
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
            "active": active, "source": source, "sources": sources_map,
            "observations": None, "verification": None,
            "verification_sources": None, "failures": failures}


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
    repo_entries = snapshot.get("repos") or []
    if not isinstance(repo_entries, list):
        raise ValueError("snapshot 'repos' is not a list")
    if repo_entries:
        source = _declared_source(snapshot, "repos")
        records.extend(_derive_repo(entry, source)
                       for entry in repo_entries)
    commercial_entries = snapshot.get("commercial_doors") or []
    if not isinstance(commercial_entries, list):
        raise ValueError("snapshot 'commercial_doors' is not a list")
    if commercial_entries:
        source, sources_map = _commercial_sources(snapshot)
        records.extend(_derive_commercial(entry, source, sources_map)
                       for entry in commercial_entries)
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
    if any(r["kind"] == "commercial" and r.get("verification") is not None
           for r in records):
        summary["commercial_verified"] = sum(
            1 for r in records if r["kind"] == "commercial"
            and r.get("verification") == "VERIFIED")
        summary["commercial_disagreements"] = sum(
            1 for r in records if r["kind"] == "commercial"
            and r.get("verification") == "DISAGREEMENT")
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
    ("source", "as_of"), ("sources",), ("observations",),
    ("verification",), ("verification_sources",), ("failures",),
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
