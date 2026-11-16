"""The estate claim gate — one CI-runnable check that FAILS a repo
whose public documents carry contradicted or unlabeled claims.

This build composes two landed machines:

* PROOF-E1's estate attestation (``savage_standard/estate.py``):
  per-repo verdicts — GT currency CURRENT / DRIFTED / UNPINNED /
  MISSING and the latest-recorded CI state — sealed in a
  ``savage.estate_attestation.v1`` artifact whose every record
  re-derives under ``estate.verify_artifact``.
* EVO-29's claim-state linter (Savage-AI-style
  ``scripts/claim_linter.py`` @ ``6a7f65e6``): the rule set that
  requires claim-state labels on numeric performance figures and
  capability claims in public documents.

The linter's rule set is composed here CLEAN-ROOM: the label forms,
claim patterns, qualification forms and exemptions below were
re-implemented in this module from the linter's documented behavior
(its module docstring states the convention, the qualification forms
and the claim / not-a-claim boundary in full). No code is imported
from Savage-AI-style and this package gains no runtime dependency on
that repository — the two repos stay independently installable, and
the gate runs from this package alone.

BEFORE this build: claim gates that fail CI on a contradicted or
unlabeled claim = **0**. The ``claims`` subcommand only *prints* the
claims-gate inventory; the ``estate`` subcommand attests GT/CI state
but never reads a repo's prose; the linter lives in another repo,
checks labels only, and is wired to no other repo's CI. Nothing
composed them, and nothing failed on a claim contradicted by
attestation evidence.

SCOPE RULE (the linter's, unchanged): the public documents of a repo
tree are the Markdown files at the tree root plus every Markdown
file under ``docs/`` (recursively). The apparatus documents
``ARTIFACT_INDEX.md`` and ``GROUND_TRUTH.md`` are not scanned
wherever they appear: they are the apparatus the labels point to,
not surfaces riding on it.

UNLABELED rule (the linter's catch semantics, unchanged): a claim is
a numeric performance figure (percentages; latency / throughput /
percentile figures; fraction scores in a score context; step /
convergence figures; perfection ratios; agent/heap byte-footprint
figures; correlation figures) or a capability claim (CERTIFIED in
status-label form, READY TO GO LIVE, MISSION COMPLETE /
ACCOMPLISHED, VAULT SEALED, LIVE in a status position). A claim is
QUALIFIED — not a failure — when any of the linter's forms holds:
(1) a claim-state banner in the file's first 20 lines; (2) the file
is inventoried as the subject of a row in the tree's
``ARTIFACT_INDEX.md``; (3) a claim-state label on the claim's own
line or within the 10 lines above it (labels are state words in an
evidence-state context — ``Evidence state: X``, ``Verdict: **X**``,
a bare state cell in a table that declares an Evidence/Claim state
column, ``labeled X`` / ``corrected to X`` and kin), or an
``ARTIFACT_INDEX`` reference on the line or within the 10 lines
above. NOT claims (the linter's boundary, unchanged): dates,
timestamps, hashes; plain counts with no performance unit; version
numbers; figures inside code fences; figures inside an ``e.g.``
example; figures stated as targets / KPI thresholds (unless the line
asserts measurement); figures inside a ``(target ...)``
parenthetical; a named code constant stated alone. The claim-state
vocabulary is the estate's: verified / observed / reported / stale /
contradicted / unknown / unproven / coded / tested / deployed /
customer-used / revenue-verified / partial / reopened / live /
mixed / unverified.

CONTRADICTED rules (few, mechanical, complete — no others exist):
the gate extracts each claim's STATED state — the claim-state labels
that qualify it (same-line / 10-line window / file banner), plus
``live`` for a LIVE status-form capability claim — and refutes it
against evidence:

  C1. Stated ``verified``, and the attestation record for this repo
      shows GT currency DRIFTED or MISSING → CONTRADICTED.
  C2. Stated ``verified``, and the attestation record shows CI
      state FAILING → CONTRADICTED.
  C3. Stated ``verified``, no attestation record is in play, and
      the tree itself has no ``GROUND_TRUTH.md`` at its root (the
      local evidence the label points to does not exist) →
      CONTRADICTED. Applies only without an attestation record:
      the sealed attestation is the stronger evidence and C1/C2
      govern then.
  C4. Stated ``live`` (LIVE status-form claim), and the attestation
      record shows CI state FAILING or GT currency MISSING →
      CONTRADICTED.

GT BUDGET rule: when an attestation record is in play, its GT
currency counts 1 against the budget when it is DRIFTED or MISSING
(UNPINNED and CURRENT count 0). A count above ``--gt-budget``
(default 0) is a GT-BUDGET failure.

ATTESTATION handling: a supplied artifact is first verified with
``estate.verify_artifact`` (digest recompute + full re-derivation);
an artifact that does not verify is itself a failure and no verdict
is taken from it. The record in play is selected by ``--repo NAME``
when given, else the artifact's only record when it holds exactly
one, else the record named by the tree directory's basename; a
supplied artifact with no matching record is a named failure
(fail-closed, never a silent pass).

Exit codes (the CLI's): 0 = gate PASS, 1 = gate FAIL (every failure
named), 2 = usage / input error (missing tree, unreadable or
non-artifact attestation JSON).

Honesty boundary: the gate checks claim LABELS and their agreement
with attestation / local-GT evidence. It does not re-measure any
figure, re-run any suite, or adjudicate whether a labeled claim is
true beyond the mechanical contradiction rules above. Savage-
original, stdlib only.
"""
from __future__ import annotations

import os
import re

from . import estate as estate_mod

# ── Claim-state vocabulary (the estate's, per the linter) ───────────
CLAIM_STATES = [
    "verified", "observed", "reported", "stale", "contradicted",
    "unknown", "unproven", "coded", "tested", "deployed",
    "customer-used", "revenue-verified", "partial", "reopened",
    "live", "mixed", "unverified",
]
_STATE_ALT = "|".join(CLAIM_STATES)
_STATE_RE = re.compile(r"\b(" + _STATE_ALT + r")\b", re.IGNORECASE)
_LABEL_CONTEXT_RE = re.compile(
    r"(evidence\s+state|claim\s+state|verdict|status|state)\b"
    r"[^.\n]{0,40}?\b(" + _STATE_ALT + r")\b", re.IGNORECASE)
_BANNER_RE = re.compile(
    r"(evidence\s+state|claim\s+state|correction\s*\([^)]*BRAND_SYSTEM)",
    re.IGNORECASE)
_TABLE_CELL_STATE_RE = re.compile(
    r"\|\s*\**\s*(" + _STATE_ALT + r")\s*\**\s*(\||$)", re.IGNORECASE)
_LABELED_RE = re.compile(
    r"\b(label(?:ed|s)?|corrected\s+to|marked|ruled|carries|carry)\b"
    r"[^.\n]{0,30}?\b(" + _STATE_ALT + r")\b", re.IGNORECASE)

# ── Claim patterns (the linter's documented catch set) ──────────────
_NUM = r"\d[\d,]*(?:\.\d+)?"
_CLAIM_PATTERNS = [
    (re.compile(_NUM + r"\s*%"), "percent-figure"),
    (re.compile(_NUM + r"\s+percent\b", re.IGNORECASE), "percent-figure"),
    (re.compile(_NUM + r"\s*(?:µs|μs|us|µsec)\b"), "latency-figure"),
    (re.compile(_NUM + r"\s*microseconds?\b", re.IGNORECASE),
     "latency-figure"),
    (re.compile(r"\bsub-\s*" + _NUM + r"\s*(?:µs|μs|us|ms|microseconds?)\b",
                re.IGNORECASE), "latency-figure"),
    (re.compile(_NUM + r"\s*ms\b[^.\n]{0,40}?\b(latency|throughput|cycle|"
                r"extraction|processing|response|runtime|window|execution)\b",
                re.IGNORECASE), "latency-figure"),
    (re.compile(r"\b(latency|throughput|cycle|extraction|processing|"
                r"response|runtime|window|execution)\b[^.\n]{0,40}?"
                + _NUM + r"\s*ms\b", re.IGNORECASE), "latency-figure"),
    (re.compile(_NUM + r"\s*(?:M\s*)?ops\s*/\s*(?:sec|s)\b",
                re.IGNORECASE), "throughput-figure"),
    (re.compile(r"\bthroughput\b[^.\n]{0,40}?" + _NUM, re.IGNORECASE),
     "throughput-figure"),
    (re.compile(r"\bp(?:50|90|95|99)\b\s*[:=]?\s*" + _NUM),
     "percentile-figure"),
    (re.compile(_NUM + r"\s*/\s*" + _NUM +
                r"\s*(tests?|constraints?|PASS|readiness|sessions?|cycles?)?",
                re.IGNORECASE), "fraction-score"),
    (re.compile(_NUM + r"\s*steps?\b[^.\n]{0,30}?\b(convergence|attraction|"
                r"reduc\w*)\b", re.IGNORECASE), "convergence-figure"),
    (re.compile(r"\b(convergence|attraction|reduc\w*)\b[^.\n]{0,30}?"
                + _NUM + r"\s*steps?\b", re.IGNORECASE),
     "convergence-figure"),
    (re.compile(r"\breduced\s+from\s+" + _NUM + r"\s+to\s+" + _NUM,
                re.IGNORECASE), "convergence-figure"),
    (re.compile(r"\b" + _NUM + r"-step\s+attraction\b", re.IGNORECASE),
     "convergence-figure"),
    (re.compile(r"\b(yield|determinism|accuracy|rejection\s+rate|"
                r"reproducibility|stability\s+index)\b[^.\n]{0,30}?"
                r"(0\.\d+|1\.0+)(?![\d])", re.IGNORECASE), "ratio-figure"),
    (re.compile(r"\b(yield|determinism|accuracy|rejection\s+rate|"
                r"reproducibility|stability\s+index)\b\s*:\s*100(?![\d])",
                re.IGNORECASE), "ratio-figure"),
    (re.compile(_NUM + r"\s+agents?\b[^.\n]{0,64}?" + _NUM +
                r"\s*-?\s*bytes?\b", re.IGNORECASE), "footprint-figure"),
    (re.compile(_NUM + r"\s+agents?\b[^.\n]{0,80}?\b(heap)\b",
                re.IGNORECASE), "footprint-figure"),
    (re.compile(_NUM + r"\s+\S+\s+agents?\b[^.\n]{0,80}?\b(heap)\b",
                re.IGNORECASE), "footprint-figure"),
    (re.compile(r"\br\^?2\s*=\s*" + _NUM, re.IGNORECASE),
     "correlation-figure"),
    (re.compile(_NUM + r"\s+(correlation|match)\b", re.IGNORECASE),
     "correlation-figure"),
    (re.compile(r"\bCERTIFIED\b"), "capability-claim"),
    (re.compile(r"\bREADY\s+TO\s+GO\s+LIVE\b", re.IGNORECASE),
     "capability-claim"),
    (re.compile(r"\bMISSION\s+(COMPLETE|ACCOMPLISHED)\b", re.IGNORECASE),
     "capability-claim"),
    (re.compile(r"\bVAULT\s+SEALED\b", re.IGNORECASE), "capability-claim"),
    (re.compile(r"(\|\s*\**\s*LIVE\s*\**\s*\|)|\bStatus\s*:\s*\**\s*LIVE\b|"
                r"✅\s*LIVE\b", re.IGNORECASE), "capability-claim"),
]
_LIVE_FORM_RE = re.compile(
    r"(\|\s*\**\s*LIVE\s*\**\s*\|)|\bStatus\s*:\s*\**\s*LIVE\b|"
    r"✅\s*LIVE\b|\bREADY\s+TO\s+GO\s+LIVE\b", re.IGNORECASE)

_SPEC_WORD_RE = re.compile(r"\b(target|KPI|threshold|goal)\b", re.IGNORECASE)
_MEASURED_RE = re.compile(r"\b(measured|certified|recorded|observed)\b",
                          re.IGNORECASE)
_HEADING_SPEC_RE = re.compile(r"\b(KPI|target|threshold)\b", re.IGNORECASE)

APPARATUS_BASENAMES = frozenset(["ARTIFACT_INDEX.md", "GROUND_TRUTH.md"])

_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z?)?\b"
    r"|\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},?\s+\d{4}\b"
    r"|\b\d{1,2}:\d{2}:\d{2}\b")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+|\b[0-9a-f]{64}\b")


def _strip_nonclaim_spans(line):
    """Remove dates / hashes so their digits are never read as figures."""
    line = _DATE_RE.sub(" ", line)
    return _HEX_RE.sub(" ", line)


def line_label_states(line, in_state_table=False):
    """The claim states a line LABELS, in label context only.

    A state word counts when it appears in an evidence-state context,
    in a bare cell of a table that declares an Evidence/Claim state
    column (``in_state_table``), or after a labeling verb. A bare
    state word in ordinary prose is not a label.
    """
    states = set()
    for m in _LABEL_CONTEXT_RE.finditer(line):
        states.add(m.group(2).lower())
    if in_state_table:
        for m in _TABLE_CELL_STATE_RE.finditer(line):
            states.add(m.group(1).lower())
    for m in _LABELED_RE.finditer(line):
        states.add(m.group(2).lower())
    return states


def _state_table_rows(lines):
    """Line indexes that are rows of an evidence/claim-state table."""
    rows = set()
    i = 0
    while i < len(lines) - 1:
        if lines[i].lstrip().startswith("|") and re.match(
                r"^\s*\|[\s:|-]+\|?\s*$", lines[i + 1]):
            header = lines[i].lower()
            is_state = ("evidence state" in header
                        or "claim state" in header)
            j = i
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                if is_state:
                    rows.add(j)
                j += 1
            i = j
        else:
            i += 1
    return rows


def parse_index_references(index_text):
    """Artifacts inventoried in ARTIFACT_INDEX.md: a document is
    covered only when its name appears in the FIRST cell of an index
    table row (the subject form); a mere mention in a basis cell
    carries no claim state of its own."""
    refs = set()
    for line in index_text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 3:
            continue
        for match in re.findall(r"`([^`]+)`", cells[1]):
            refs.add(match.strip())
            refs.add(os.path.basename(match.strip()))
    return refs


def find_claims_in_line(line):
    """All (kind, matched_text) claims on one prose line, de-duplicated
    by span (longest match wins). Fraction scores count only in a
    score context or with a score-like denominator."""
    cleaned = _strip_nonclaim_spans(line)
    target_spans = [m.span() for m in re.finditer(
        r"\(\s*target\b[^)]*\)", cleaned, re.IGNORECASE)]
    found = []
    for pattern, kind in _CLAIM_PATTERNS:
        for match in pattern.finditer(cleaned):
            if any(match.start() >= s and match.end() <= e
                   for s, e in target_spans):
                continue
            found.append((match.span(), kind, match.group(0)))
    kept = []
    for span, kind, text in sorted(
            found, key=lambda f: f[0][1] - f[0][0], reverse=True):
        if any(span[0] < k[0][1] and k[0][0] < span[1] for k in kept):
            continue
        kept.append((span, kind, text))
    out = []
    for _span, kind, text in kept:
        if kind == "fraction-score":
            if not re.search(r"(test|constraint|PASS|readiness|session|"
                             r"cycle|passed|verified|complete)", line,
                             re.IGNORECASE):
                if not re.search(r"/\s*(100|10)\b", text):
                    continue
        out.append((kind, text))
    return out


def scan_document(relpath, text, index_refs):
    """Scan one document; return its claims, each a dict with
    file / line / kind / text / source / qualified / states.

    ``states`` is the claim's stated claim-state set: the labels that
    qualify it (banner states when the file is banner-qualified,
    else the same-line and 10-line-window label states), plus
    ``live`` for a LIVE status-form capability claim.
    """
    lines = text.splitlines()
    basename = os.path.basename(relpath)
    if basename in APPARATUS_BASENAMES:
        return []
    # File-level qualification, form 1: banner in the first 20 lines.
    banner_states = set()
    for ln in lines[:20]:
        if _BANNER_RE.search(ln):
            banner_states |= {s.lower() for s in _STATE_RE.findall(ln)}
        if "Correction" in ln and "BRAND_SYSTEM" in ln:
            banner_states |= {s.lower() for s in _STATE_RE.findall(ln)}
    file_qualified = bool(banner_states)
    # File-level qualification, form 2: inventoried in ARTIFACT_INDEX.
    if relpath in index_refs or basename in index_refs:
        file_qualified = True

    state_rows = _state_table_rows(lines)
    label_states = [line_label_states(ln, in_state_table=i in state_rows)
                    for i, ln in enumerate(lines)]
    index_ref_lines = {i for i, ln in enumerate(lines)
                       if "ARTIFACT_INDEX" in ln}
    # A KPI / target heading makes only its own contiguous list block
    # a specification (bullets within 6 lines, no intervening prose).
    heading_spec = [False] * len(lines)
    spec_heading_at = None
    spec_broken = True
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("#"):
            spec_heading_at = i if _HEADING_SPEC_RE.search(ln) else None
            spec_broken = spec_heading_at is None
            continue
        if spec_heading_at is None or spec_broken:
            continue
        if i - spec_heading_at > 6:
            spec_broken = True
            continue
        stripped_ln = ln.strip()
        if not stripped_ln:
            continue
        if re.match(r"^([-*+]|\d+\.)\s", stripped_ln) \
                or stripped_ln.startswith("|"):
            heading_spec[i] = True
        else:
            spec_broken = True

    claims = []
    in_fence = False
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or not stripped:
            continue
        if re.search(r"\be\.g\.", ln):
            continue
        found = find_claims_in_line(ln)
        if not found:
            continue
        if (_SPEC_WORD_RE.search(ln) or heading_spec[i]) \
                and not _MEASURED_RE.search(ln):
            continue
        window_start = max(0, i - 10)
        window_states = set()
        for j in range(window_start, i + 1):
            window_states |= label_states[j]
        qualified = file_qualified or bool(window_states) or any(
            window_start <= j <= i for j in index_ref_lines)
        states = set(banner_states) if banner_states else set(window_states)
        if any(kind == "capability-claim" and _LIVE_FORM_RE.search(text)
               for kind, text in found):
            states.add("live")
        for kind, text_found in found:
            claims.append({
                "file": relpath, "line": i + 1, "kind": kind,
                "text": text_found.strip(), "source": stripped[:160],
                "qualified": qualified, "states": sorted(states),
            })
    return claims


def collect_documents(root):
    """The scope rule: root Markdown plus the docs/ tree."""
    docs = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if os.path.isfile(path) and name.lower().endswith(".md"):
            docs.append(path)
    docs_dir = os.path.join(root, "docs")
    if os.path.isdir(docs_dir):
        for dirpath, _dirnames, filenames in os.walk(docs_dir):
            for name in sorted(filenames):
                if name.lower().endswith(".md"):
                    docs.append(os.path.join(dirpath, name))
    return docs


def select_record(artifact, repo_name, root):
    """The attestation record in play, per the documented selection
    rule; None when no record matches."""
    records = artifact.get("records") or []
    if repo_name:
        for rec in records:
            if isinstance(rec, dict) and rec.get("repo") == repo_name:
                return rec
        return None
    if len(records) == 1 and isinstance(records[0], dict):
        return records[0]
    base = os.path.basename(os.path.abspath(root))
    for rec in records:
        if isinstance(rec, dict) and rec.get("repo") == base:
            return rec
    return None


def gate_tree(root, attestation=None, repo_name=None, gt_budget=0):
    """Run the gate over a materialized repo tree.

    ``attestation`` is a parsed ``savage.estate_attestation.v1``
    artifact dict or None. Returns a report dict: documents scanned,
    claims found, the attestation record in play (or None), the GT
    budget count, and ``failures`` — every failure a dict with
    ``check`` in {UNLABELED, CONTRADICTED, GT-BUDGET, ATTESTATION}
    naming the file, line and claim (or the repo, for record-level
    failures). The gate passes iff ``failures`` is empty.
    """
    failures = []
    record = None
    if attestation is not None:
        ok, mismatches = estate_mod.verify_artifact(attestation)
        if not ok:
            for m in mismatches:
                failures.append({
                    "check": "ATTESTATION", "file": None, "line": None,
                    "kind": "attestation", "text": "",
                    "detail": f"attestation does not verify: {m}"})
        else:
            record = select_record(attestation, repo_name, root)
            if record is None:
                failures.append({
                    "check": "ATTESTATION", "file": None, "line": None,
                    "kind": "attestation", "text": "",
                    "detail": "attestation holds no record for this "
                              "repo (selection: --repo, else a "
                              "single-record artifact, else the tree "
                              "directory name)"})

    index_refs = set()
    index_path = os.path.join(root, "ARTIFACT_INDEX.md")
    if os.path.isfile(index_path):
        with open(index_path, encoding="utf-8", errors="replace") as fh:
            index_refs = parse_index_references(fh.read())

    claims = []
    documents = collect_documents(root)
    for path in documents:
        relpath = os.path.relpath(path, root)
        with open(path, encoding="utf-8", errors="replace") as fh:
            claims.extend(scan_document(relpath, fh.read(), index_refs))

    gt_currency = (record or {}).get("gt", {}).get("currency")
    ci_state = (record or {}).get("ci", {}).get("state")
    local_gt = os.path.isfile(os.path.join(root, "GROUND_TRUTH.md"))

    for claim in claims:
        if not claim["qualified"]:
            failures.append({
                "check": "UNLABELED", "file": claim["file"],
                "line": claim["line"], "kind": claim["kind"],
                "text": claim["text"],
                "detail": "claim carries no claim-state label and no "
                          "ARTIFACT_INDEX.md reference"})
        states = set(claim["states"])
        contra = None
        if "verified" in states:
            if record is not None and gt_currency in ("DRIFTED", "MISSING"):
                contra = (f"C1: labeled verified but the attestation "
                          f"record for {record.get('repo')} shows GT "
                          f"currency {gt_currency}")
            elif record is not None and ci_state == "FAILING":
                contra = (f"C2: labeled verified but the attestation "
                          f"record for {record.get('repo')} shows CI "
                          f"state FAILING")
            elif record is None and attestation is None and not local_gt:
                contra = ("C3: labeled verified but the tree has no "
                          "GROUND_TRUTH.md at its root")
        if contra is None and "live" in states and record is not None:
            if ci_state == "FAILING" or gt_currency == "MISSING":
                contra = (f"C4: stated LIVE but the attestation record "
                          f"for {record.get('repo')} shows CI state "
                          f"{ci_state} / GT currency {gt_currency}")
        if contra:
            failures.append({
                "check": "CONTRADICTED", "file": claim["file"],
                "line": claim["line"], "kind": claim["kind"],
                "text": claim["text"], "detail": contra})

    gt_over = 0
    if record is not None and gt_currency in ("DRIFTED", "MISSING"):
        gt_over = 1
    if gt_over > gt_budget:
        failures.append({
            "check": "GT-BUDGET", "file": None, "line": None,
            "kind": "gt-budget", "text": "",
            "detail": f"GT currency {gt_currency} for "
                      f"{record.get('repo')} counts {gt_over} against "
                      f"a budget of {gt_budget}"})

    return {
        "root": root,
        "repo": record.get("repo") if record else repo_name,
        "documents_scanned": len(documents),
        "claims_found": len(claims),
        "claims": claims,
        "record": ({"repo": record.get("repo"),
                    "gt_currency": gt_currency, "ci_state": ci_state}
                   if record else None),
        "gt_budget": gt_budget, "gt_over_budget_count": gt_over,
        "failures": failures,
        "verdict": "PASS" if not failures else "FAIL",
    }


def format_failure(failure):
    """One named failure, one line."""
    where = ""
    if failure.get("file"):
        where = f"{failure['file']}:{failure['line']}: "
    claim = f" {failure['kind']} '{failure['text']}'" if failure.get("text") \
        else f" {failure['kind']}"
    return f"{where}{failure['check']}{claim} — {failure['detail']}"
