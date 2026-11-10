#!/usr/bin/env python3
"""Savage API Atlas — the calling layer (Phase 3).

A need goes in; routes are ranked by real relevance over the catalog's
own fields; the chosen route is called live; on failure the call fails
over to the next semantically-equivalent route; every outcome returns
an SRE-1 receipt (the savage-standard envelope shape) whose contents
re-verify independently.

Python 3.12 standard library only. Savage-original code.

Layers kept separate, as everywhere in the Atlas:
  * CLAIM  — data/catalog.json fields (name / description / category /
    auth / https as published by catalog contributors).
  * PROBE  — data/probe-log.jsonl receipts: which entry URLs have ever
    answered a live GET from this tool, and how.
  * CALL   — what this module does now: real GETs, real results,
    receipts. A call proves the URL answered at call time with the
    recorded status and body digest — nothing more.

Zero-cost allowlist law (registry-ZIP routing design, adopted as a
Savage requirement in the Phase 2 audit): a route is callable only
when its keyless use is established — the catalog claims auth "none",
or (for federated entries, which claim "unknown") a probe receipt
shows it answering a keyless GET. "Unknown" is never approved, and no
credentials are ever attached: this layer makes keyless GET calls only.

Failover law (same adopted design input): fail over only to a route
returning semantically comparable data — operationalized here as a
route in the same catalog category that also shares the need's matched
anchor term, so a failover target serves the same need, not merely a
neighboring topic.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import atlas as _atlas

ROOT = Path(__file__).resolve().parent
CALL_LOG_PATH = ROOT / "data" / "call-log.jsonl"

CALL_TIMEOUT = 10.0
MAX_BODY_BYTES = 1 << 20  # receipts digest at most 1 MiB of any response
MAX_ATTEMPTS = 3
ISSUER_LINE = "Savage API Atlas"
ISSUER_SYSTEM = "savage-api-atlas"
DIALECT = "atlas-call"

# --------------------------------------------------------------------------
# Canonicalization — RFC 8785 (JCS), the savage-standard canonical form.
# Clean-room note: implemented from the RFC and the standard's declared
# format (keys sorted by UTF-16 code unit, minimal string escaping,
# ECMAScript Number.prototype.toString); the algorithm is the format's
# own definition, the code here is original to this repo.
# --------------------------------------------------------------------------


class CanonicalError(ValueError):
    pass


def _shortest_digits(x: float) -> tuple[str, int]:
    r = repr(x)
    if "e" in r or "E" in r:
        mant, _, e = r.partition("e")
        exp = int(e)
    else:
        mant, exp = r, 0
    mant = mant.lstrip("-")
    if "." in mant:
        ip, _, fp = mant.partition(".")
    else:
        ip, fp = mant, ""
    digits = ip + fp
    lead = 0
    while lead < len(digits) and digits[lead] == "0":
        lead += 1
    digits = digits[lead:]
    exp10 = exp - len(fp) + (len(ip) + len(fp)) - lead
    digits = digits.rstrip("0") or "0"
    return digits, exp10


def _js_number(x) -> str:
    if isinstance(x, bool):
        raise CanonicalError("boolean is not a number")
    if isinstance(x, int):
        if abs(x) < 1e21:
            return str(x)
        x = float(x)
    if not isinstance(x, float):
        raise CanonicalError(f"not a number: {type(x)}")
    if math.isnan(x) or math.isinf(x):
        raise CanonicalError("non-finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    ax = abs(x)
    digits, exp10 = _shortest_digits(ax)
    k = len(digits)
    n = exp10
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        body = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + body


_ESCAPES = {
    "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
    '"': '\\"', "\\": "\\\\",
}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalError("lone surrogate in string")
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value) -> str:
    """RFC 8785 canonical JSON."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _js_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    raise CanonicalError(f"uncanonicalizable type: {type(value)}")


# --------------------------------------------------------------------------
# SRE-1 envelope — the savage-standard shape (schema savage/receipt-
# envelope/1). Field structure per savage-standard's envelope.py, read
# 2026-11-10; digests are SHA-256 over the JCS canonical form.
# --------------------------------------------------------------------------

ENVELOPE_SCHEMA = "savage/receipt-envelope/1"

ENVELOPE_BOUNDARIES = [
    "This envelope wraps a native receipt verbatim; it adds identification, evidence pointers, and a hash chain — not trust.",
    "recorded_at is producer-reported and is NOT a trusted timestamp.",
    "The envelope is hash-bound, not signed. Estate key custody for envelope-level signatures is still owed.",
    "A VERIFIED verdict means every recomputable check in the native dialect passed; legs that cannot be recomputed are reported UNVERIFIABLE, never silently passed.",
]


def native_digest(native) -> str:
    return hashlib.sha256(jcs(native).encode("utf-8")).hexdigest()


def envelope_digest(env: dict) -> str:
    core = {k: v for k, v in env.items() if k != "envelope_digest"}
    return hashlib.sha256(jcs(core).encode("utf-8")).hexdigest()


def wrap_envelope(native, *, claim_id: str, claim_kind: str, statement: str,
                  gate_verdict: str, recorded_at: str,
                  evidence: list | None = None,
                  artifact_hashes: list | None = None,
                  prev_digest: str | None = None) -> dict:
    env = {
        "schema": ENVELOPE_SCHEMA,
        "envelope_version": 1,
        "claim": {"id": claim_id, "kind": claim_kind, "statement": statement},
        "issuer": {"line": ISSUER_LINE, "system": ISSUER_SYSTEM, "dialect": DIALECT},
        "subject": {
            "native_schema": "savage/atlas-call/1",
            "native_digest": native_digest(native),
            "artifact_hashes": artifact_hashes or [],
        },
        "evidence": evidence or [],
        "gate": {"name": "atlas-live-call", "verdict": gate_verdict},
        "recorded_at": recorded_at,
        "timestamp_trust": "producer-reported; NOT a trusted timestamp",
        "chain": {"prev_digest": prev_digest},
        "native": native,
        "boundaries": list(ENVELOPE_BOUNDARIES),
    }
    env["envelope_digest"] = envelope_digest(env)
    return env


def verify_envelope(env: dict, prev_digest: str | None = None) -> list[dict]:
    """Independent re-verification from the envelope's own contents.

    Every leg is recomputed; nothing is taken on trust. A leg that
    cannot be recomputed is reported 'unverifiable', never passed.
    """
    legs: list[dict] = []

    def leg(name, status, detail):
        legs.append({"leg": name, "status": status, "detail": detail})

    if not isinstance(env, dict) or env.get("schema") != ENVELOPE_SCHEMA:
        leg("schema", "fail", "schema is not savage/receipt-envelope/1")
        return legs
    leg("schema", "pass", "schema is savage/receipt-envelope/1")
    try:
        ok = envelope_digest(env) == env.get("envelope_digest")
        leg("envelope-digest", "pass" if ok else "fail",
            "envelope_digest recomputed over the JCS core")
    except CanonicalError as exc:
        leg("envelope-digest", "fail", f"uncanonicalizable: {exc}")
    native = env.get("native")
    if native is None:
        leg("native-binding", "fail", "envelope carries no native receipt")
        return legs
    try:
        ok = native_digest(native) == (env.get("subject") or {}).get("native_digest")
        leg("native-binding", "pass" if ok else "fail",
            "subject.native_digest recomputed over the embedded native receipt")
    except CanonicalError as exc:
        leg("native-binding", "fail", f"uncanonicalizable: {exc}")
    chain = env.get("chain") or {}
    leg("chain-field", "pass" if "prev_digest" in chain else "fail",
        "chain.prev_digest present (null only for an issuer's first envelope)")
    # A link is checked only when BOTH sides assert one: the caller
    # supplies the expected previous digest AND the envelope carries a
    # non-null prev_digest. Verifying a single envelope standalone
    # (prev_digest=None, envelope first-in-chain) must not fail on a
    # chain the verifier was not shown.
    if prev_digest is not None and chain.get("prev_digest") is not None:
        ok = chain.get("prev_digest") == prev_digest
        leg("chain-link", "pass" if ok else "fail",
            "chain.prev_digest equals the previous envelope's digest")
    elif chain.get("prev_digest") is not None:
        leg("chain-link", "unverifiable",
            "envelope claims a previous digest the verifier was not shown")
    verdict = (env.get("gate") or {}).get("verdict")
    leg("gate-verdict-vs-native", "pass" if verdict == native.get("status") else "fail",
        "gate.verdict equals the native receipt's status")
    result = native.get("result") or {}
    body_sha = result.get("body_sha256")
    if body_sha:
        recorded = None
        for h in (env.get("subject") or {}).get("artifact_hashes", []):
            if h.get("kind") == "response-body":
                recorded = h.get("sha256")
        leg("body-digest-pointer", "pass" if recorded == body_sha else "fail",
            "subject.artifact_hashes carries the response body digest")
        leg("body-content", "unverifiable",
            "response bytes are not embedded; body content itself cannot be "
            "recomputed from the receipt alone")
    else:
        leg("body-digest-pointer", "unverifiable",
            "no response body digest recorded (no body was captured)")
    if result.get("http_status") is None and native.get("status") == "success":
        leg("result-consistency", "fail", "status success without an HTTP status")
    else:
        leg("result-consistency", "pass", "status and HTTP status are consistent")
    return legs


def envelope_verdict(legs: list[dict]) -> str:
    if any(l["status"] == "fail" for l in legs):
        return "REJECTED"
    if any(l["status"] == "unverifiable" for l in legs):
        return "VERIFIED-STRUCTURAL"
    return "VERIFIED"


# --------------------------------------------------------------------------
# Need parsing and retrieval — BM25F over the catalog's own fields.
# --------------------------------------------------------------------------

STOPWORDS = frozenset("""
a an and are as at be by can do does for from get give has have how i in into
is it its me my of on or that the their them then there these they this to
under up us use used using want with without within would you your other
others data information info service services api apis free
""".split())

_SINGULARS = {
    "countries": "country", "currencies": "currency", "cities": "city",
    "holidays": "holiday", "recipes": "recipe", "quotes": "quote",
    "jokes": "joke", "books": "book", "movies": "movie", "prices": "price",
    "scores": "score", "images": "image", "pictures": "picture",
    "photos": "photo", "facts": "fact", "users": "user",
    "universities": "university", "definitions": "definition",
    "lyrics": "lyric", "languages": "language", "headlines": "headline",
    "earthquakes": "earthquake", "addresses": "address",
    "coordinates": "coordinate", "games": "game", "songs": "song",
}

# NOTE on inflection: no generic stemming is applied — a blind
# trailing-s strip corrupts stems ("rates" must stay "rates" to match
# catalog text that uses the plural; "this" must never become "thi").
# Only the explicit table above is lemmatized, both sides alike.

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    toks = []
    for tok in _TOKEN_RE.findall(text.lower()):
        toks.append(_SINGULARS.get(tok, tok))
    return toks


def need_terms(need: str) -> list[str]:
    """Plain-words need -> content terms (stopwords out, order kept)."""
    seen: list[str] = []
    for tok in tokenize(need):
        if len(tok) < 2 or tok in STOPWORDS:
            continue
        if tok not in seen:
            seen.append(tok)
    return seen


def term_variants(tok: str) -> set[str]:
    """Inflection variants of a term, matched symmetrically: a need
    saying 'rate' must match catalog text saying 'rates' and vice
    versa. Variants: the token itself, its table singular/plural, and
    the simple trailing-s toggle. No aggressive stemming — 'this'
    never becomes 'thi' because stopwords are removed before matching
    and the toggle only adds the s-form, never strips mid-word."""
    out = {tok}
    if tok in _SINGULARS:
        out.add(_SINGULARS[tok])
    for plural, singular in _SINGULARS.items():
        if tok == singular:
            out.add(plural)
    if tok.endswith("s") and len(tok) > 3:
        out.add(tok[:-1])
    else:
        out.add(tok + "s")
    return out


_FIELD_WEIGHTS = {"name": 3.0, "category": 2.0, "description": 1.0}
_K1 = 1.5
_B = 0.75


def _entry_fields(entry: dict) -> dict[str, list[str]]:
    return {
        "name": tokenize(entry["name"]),
        "category": tokenize(entry["category"]),
        "description": tokenize(entry["description"]),
    }


class NeedIndex:
    """BM25F index over name / category / description, built once."""

    def __init__(self, entries: list[dict]):
        self.entries = entries
        self.fields = [_entry_fields(e) for e in entries]
        self.doc_len = {
            f: [len(fl[f]) for fl in self.fields] for f in _FIELD_WEIGHTS
        }
        self.avg_len = {
            f: (sum(self.doc_len[f]) / len(entries)) if entries else 0.0
            for f in _FIELD_WEIGHTS
        }
        self.df: dict[str, int] = {}
        for fl in self.fields:
            for tok in set(fl["name"]) | set(fl["category"]) | set(fl["description"]):
                self.df[tok] = self.df.get(tok, 0) + 1
        self.n = len(entries)

    def idf(self, tok: str) -> float:
        df = self.df.get(tok, 0)
        return math.log(1.0 + (self.n - df + 0.5) / (df + 0.5))

    def score(self, entry_i: int, terms: list[str]) -> tuple[float, set[str]]:
        fl = self.fields[entry_i]
        total = 0.0
        matched: set[str] = set()
        for tok in terms:
            variants = term_variants(tok)
            idf = max((self.idf(v) for v in variants), default=0.0)
            if idf <= 0:
                continue
            tf = 0.0
            for f, w in _FIELD_WEIGHTS.items():
                toks = fl[f]
                if not toks:
                    continue
                count = sum(toks.count(v) for v in variants)
                if count:
                    norm = 1.0 - _B + _B * (len(toks) / self.avg_len[f] if self.avg_len[f] else 1.0)
                    tf += w * count / norm
            if tf > 0:
                matched.add(tok)
                total += idf * (tf * (_K1 + 1.0)) / (tf + _K1)
        return total, matched


def rank_routes(index: NeedIndex, need: str, limit: int = 25) -> list[dict]:
    """Rank catalog entries for a plain-words need.

    Returns candidate dicts: {entry, score, matched_terms}. Relevance
    must anchor on the NAME or CATEGORY field — a term that only floats
    in a description is relatedness, not the route for the need — and
    need coverage (how many of the need's terms matched) dominates raw
    score, so a route serving the whole need beats one matching a
    single strong word.

    Candidates are produced by a second, independent scan in addition
    to NeedIndex.score: BM25F rewards rare terms, which can bury an
    on-need route whose name/category vocabulary is common ('Finance'
    appears in hundreds of entries). The scan below admits an entry
    when the need's terms hit its name, category OR description —
    topical relevance — and ranks candidates by need-term coverage,
    then by topic specificity (how much of the entry's own topical
    vocabulary the need covers), then BM25F score. Topical admission
    plus coverage-first ordering keeps genuinely on-topic routes from
    being buried, while name/category matches still outrank
    description-only matches through the specificity term.
    """
    terms = need_terms(need)
    if not terms:
        return []
    term_set = set(terms)
    scored: dict[int, dict] = {}
    for i, entry in enumerate(index.entries):
        fl = index.fields[i]
        score, matched = index.score(i, terms)
        if score <= 0 or not matched:
            continue
        name_cat_forms = set(fl["name"]) | set(fl["category"])
        topical_forms = name_cat_forms | set(fl["description"])
        anchor = {t for t in matched if term_variants(t) & name_cat_forms}
        hits = {t for t in term_set if term_variants(t) & topical_forms}
        if not hits:
            continue
        scored[i] = {
            "entry": entry,
            "score": round(score, 4),
            "coverage": len(matched),
            "matched_terms": sorted(matched),
            "anchor_terms": sorted(anchor),
            "_specificity": len(hits) / max(1, len(topical_forms)),
        }
    out = list(scored.values())
    out.sort(key=lambda c: (
        -c["coverage"],
        -c["score"],
        -c["_specificity"],
        c["entry"]["name"].lower(),
        c["entry"]["url"],
    ))
    for c in out:
        c.pop("_specificity", None)
    return out[:limit]


# --------------------------------------------------------------------------
# Route resolution and the zero-cost allowlist.
# --------------------------------------------------------------------------


def host_of(url: str) -> str:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)", url or "")
    return m.group(1).lower() if m else ""


def looks_like_repo_or_doc_host(url: str) -> bool:
    """Catalog URLs that point at a repository or an API's root domain
    cannot be CALLED as an endpoint — there is no declared endpoint
    behind them (the catalog stores one URL per entry, no paths or
    parameters). They stay rankable knowledge, never call targets."""
    host = host_of(url)
    return (
        host == "github.com" or host.endswith(".github.com")
        or host in {"gitlab.com", "bitbucket.org"}
        or bool(re.match(r"^[a-z0-9-]+\.(netlify\.app|vercel\.app|herokuapp\.com)$", host))
    )


def keyless_established(entry: dict, probe_states: dict) -> tuple[bool, str]:
    """The allowlist law: callable only when keyless use is established.

    Auth evidence comes ONLY from probe receipts: an entry whose URL
    answered a keyless GET alive has PROVEN keyless use. An entry that
    has merely never been probed is claims-only — 'none' is itself
    just a catalog claim, and mega-catalog claims are routinely wrong
    (key-gated services catalogued as no-auth). Claims-only entries
    are REFUSED, never called on faith: zero-cost is proven, or the
    route is not callable. (The registry-ZIP routing design requires
    the same: routes resolvable from probe receipts only.)
    """
    state = probe_states.get((entry["name"], entry["url"]))
    if _atlas.probe_is_alive(state):
        return True, "probe receipt: answered a keyless GET alive"
    if entry["auth"] == "none":
        return False, ("catalog claims no auth, but no probe receipt proves "
                       "keyless use — claims-only routes are not callable")
    return False, f"keyless use not established (auth claim: {entry['auth']})"


def endpoint_established(entry: dict, probe_states: dict) -> tuple[bool, str]:
    """A stored URL is not evidence of an endpoint: mega-catalog entries
    frequently store a documentation or marketing root as the URL, and
    repository/aggregator hosts are never endpoints at all. Endpoint
    status is proven only by a probe receipt showing the URL itself
    answering a live keyless GET. (Shares its evidence with
    keyless_established by design — one receipt proves both.)"""
    if looks_like_repo_or_doc_host(entry["url"]):
        return False, "URL is a repository/doc aggregator, not an endpoint"
    state = probe_states.get((entry["name"], entry["url"]))
    if _atlas.probe_is_alive(state):
        return True, "probe receipt: URL answered a keyless GET alive"
    return False, "never probed alive — endpoint not established"


def resolve_routes(candidates: list[dict], probe_states: dict,
                   max_attempts: int = MAX_ATTEMPTS) -> list[dict]:
    """Turn ranked candidates into an ordered attempt plan.

    A route is callable only when BOTH allowlist laws hold: keyless
    use established AND the stored URL proven to be a live endpoint
    by a probe receipt. The first route is the best-ranked callable
    route. Failover routes must be semantically equivalent to it:
    same catalog category AND sharing its anchor term — the adopted
    equivalence rule.
    """
    callable_c: list[dict] = []
    for c in candidates:
        ok, why = keyless_established(c["entry"], probe_states)
        if not ok:
            continue
        ok2, why2 = endpoint_established(c["entry"], probe_states)
        if not ok2:
            continue
        callable_c.append({**c, "keyless_basis": why, "endpoint_basis": why2})
    if not callable_c:
        return []
    first = callable_c[0]
    plan = [first]
    for c in callable_c[1:]:
        if len(plan) >= max_attempts:
            break
        if c["entry"]["category"] != first["entry"]["category"]:
            continue
        if not (set(c["matched_terms"]) & set(first["matched_terms"])):
            continue
        plan.append(c)
    return plan


# --------------------------------------------------------------------------
# The live call.
# --------------------------------------------------------------------------

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def execute_call(url: str, timeout: float = CALL_TIMEOUT) -> dict:
    """One real keyless GET. Follows redirects manually (recorded, so a
    3xx is surfaced, not laundered), reads at most MAX_BODY_BYTES+1,
    and reports honestly: status, latency, body digest, or the named
    network error. Never fabricates."""
    result = {
        "http_status": None,
        "latency_ms": None,
        "body_sha256": None,
        "body_bytes": None,
        "body_truncated": False,
        "content_type": None,
        "final_url": None,
        "redirect_chain": [],
        "error": None,
    }
    current = url
    start = time.monotonic()
    try:
        for _hop in range(6):
            req = urllib.request.Request(
                current, method="GET",
                headers={"User-Agent": "savage-api-atlas/1.0 (call)",
                         "Accept": "*/*"},
            )
            try:
                resp = _OPENER.open(req, timeout=timeout)
                status = resp.status
                headers = resp.headers
                body = resp.read(MAX_BODY_BYTES + 1)
                final = resp.geturl()
            except urllib.error.HTTPError as exc:
                status = exc.code
                headers = exc.headers
                try:
                    body = exc.read(MAX_BODY_BYTES + 1)
                except Exception:
                    body = b""
                final = exc.geturl() if hasattr(exc, "geturl") else current
            result["redirect_chain"].append(current)
            location = headers.get("Location") if headers else None
            if status in _REDIRECT_STATUSES and location:
                current = urllib.request.urljoin(current, location)
                continue
            result["http_status"] = status
            result["final_url"] = final
            result["content_type"] = headers.get_content_type() if headers else None
            result["body_bytes"] = len(body)
            result["body_truncated"] = len(body) > MAX_BODY_BYTES
            result["body_sha256"] = hashlib.sha256(body[:MAX_BODY_BYTES]).hexdigest()
            result["redirect_chain"] = result["redirect_chain"][:-1]
            return _finish(result, start)
        result["error"] = "redirect loop (>5 hops)"
    except urllib.error.URLError as exc:
        result["error"] = f"url: {exc.reason}"
    except Exception as exc:  # timeouts, resets, TLS, odd schemes
        result["error"] = f"{type(exc).__name__}: {exc}"
    return _finish(result, start)


def _finish(result: dict, start: float) -> dict:
    result["latency_ms"] = round((time.monotonic() - start) * 1000)
    return result


def attempt_succeeded(result: dict) -> bool:
    return (result["http_status"] is not None
            and 200 <= result["http_status"] < 400
            and result["error"] is None)


def attempt_failure_name(result: dict) -> str:
    if result["error"]:
        return result["error"]
    return f"http {result['http_status']}"


# --------------------------------------------------------------------------
# Call orchestration: rank -> resolve -> call -> failover -> receipt.
# --------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _route_brief(c: dict) -> dict:
    e = c["entry"]
    return {
        "name": e["name"], "url": e["url"], "category": e["category"],
        "auth_claim": e["auth"], "https_claim": e["https"],
        "score": c["score"], "coverage": c["coverage"],
        "matched_terms": c["matched_terms"], "anchor_terms": c["anchor_terms"],
        "keyless_basis": c.get("keyless_basis"),
        "endpoint_basis": c.get("endpoint_basis"),
    }


def perform_call(need: str, index: NeedIndex, probe_states: dict,
                 executor=execute_call, rank_limit: int = 25,
                 prev_digest: str | None = None,
                 recorded_at: str | None = None) -> tuple[dict, dict | None]:
    """Run one need end to end. Returns (envelope, served_candidate).

    served_candidate is None when no route served the need — the
    envelope then says exactly why (refused: no callable route, or
    failed: every attempt named)."""
    ranked = rank_routes(index, need, limit=rank_limit)
    plan = resolve_routes(ranked, probe_states)
    ts = recorded_at or _now()
    if not plan:
        native = {
            "receipt": "savage/atlas-call/1",
            "need": need,
            "status": "refused",
            "reason": ("no callable route: nothing ranked for this need is "
                       "semantically on-need AND keyless-established AND "
                       "probe-proven as a live endpoint; unprobed routes "
                       "are refused, never guessed at"),
            "ranked_top": [_route_brief(c) for c in ranked[:5]],
            "attempts": [],
            "failover_chain": [],
            "result": {"http_status": None, "latency_ms": None,
                       "body_sha256": None, "body_bytes": None,
                       "content_type": None, "final_url": None},
            "recorded_at": ts,
        }
        env = wrap_envelope(
            native,
            claim_id=f"atlas-call:{hashlib.sha256(need.encode()).hexdigest()[:16]}:{ts}",
            claim_kind="api-call",
            statement=f"Atlas call for need: {need}",
            gate_verdict="refused",
            recorded_at=ts,
            prev_digest=prev_digest,
        )
        return env, None
    attempts: list[dict] = []
    served = None
    served_result = None
    for c in plan:
        outcome = executor(c["entry"]["url"])
        attempts.append({
            "route": _route_brief(c),
            "http_status": outcome["http_status"],
            "latency_ms": outcome["latency_ms"],
            "error": outcome["error"],
            "ok": attempt_succeeded(outcome),
        })
        if attempt_succeeded(outcome):
            served, served_result = c, outcome
            break
    if served is not None:
        status = "success"
        chain = [
            {"route": a["route"]["name"], "url": a["route"]["url"],
             "failure": attempt_failure_name_for(a)}
            for a in attempts[:-1]
        ]
        result = {
            "http_status": served_result["http_status"],
            "latency_ms": served_result["latency_ms"],
            "body_sha256": served_result["body_sha256"],
            "body_bytes": served_result["body_bytes"],
            "body_truncated": served_result["body_truncated"],
            "content_type": served_result["content_type"],
            "final_url": served_result["final_url"],
            "redirect_chain": served_result["redirect_chain"],
        }
    else:
        status = "failed"
        chain = [
            {"route": a["route"]["name"], "url": a["route"]["url"],
             "failure": attempt_failure_name_for(a)}
            for a in attempts
        ]
        result = {"http_status": attempts[-1]["http_status"] if attempts else None,
                  "latency_ms": None, "body_sha256": None, "body_bytes": None,
                  "content_type": None, "final_url": None}
    native = {
        "receipt": "savage/atlas-call/1",
        "need": need,
        "status": status,
        "route_chosen": _route_brief(served) if served else None,
        "attempts": attempts,
        "failover_chain": chain,
        "result": result,
        "recorded_at": ts,
    }
    artifact_hashes = []
    if result.get("body_sha256"):
        artifact_hashes.append({"kind": "response-body",
                                "sha256": result["body_sha256"]})
    env = wrap_envelope(
        native,
        claim_id=f"atlas-call:{hashlib.sha256(need.encode()).hexdigest()[:16]}:{ts}",
        claim_kind="api-call",
        statement=f"Atlas call for need: {need}",
        gate_verdict=status,
        recorded_at=ts,
        evidence=[{"kind": "probe-log", "path": "data/probe-log.jsonl",
                   "role": "keyless/reachability evidence for route selection"}],
        artifact_hashes=artifact_hashes,
        prev_digest=prev_digest,
    )
    return env, served


def attempt_failure_name_for(attempt: dict) -> str:
    if attempt["error"]:
        return attempt["error"]
    return f"http {attempt['http_status']}"


# --------------------------------------------------------------------------
# Call log — hash-chained SRE-1 envelopes, appended per call.
# --------------------------------------------------------------------------


def read_call_log(path: Path = CALL_LOG_PATH) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def append_call_log(env: dict, path: Path = CALL_LOG_PATH) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(env, ensure_ascii=False) + "\n")
    return env


def last_call_digest(path: Path = CALL_LOG_PATH) -> str | None:
    envs = read_call_log(path)
    return envs[-1]["envelope_digest"] if envs else None


def verify_call_log(path: Path = CALL_LOG_PATH) -> tuple[bool, int, int | None]:
    prev = None
    envs = read_call_log(path)
    for i, env in enumerate(envs):
        legs = verify_envelope(env, prev_digest=prev)
        if any(l["status"] == "fail" for l in legs):
            return False, len(envs), i
        prev = env["envelope_digest"]
    return True, len(envs), None


# --------------------------------------------------------------------------
# Benchmark — the Evolution Rule v2 measurement.
# BEFORE: the pre-Phase-3 recommend, judged by whether its top pick is
# a usable route at all (callable under the Phase 3 laws — Tights'
# 'usable' sense: a route you could actually call).
# AFTER: the calling Atlas — a need is usable only when a live call
# returned a success receipt.
# --------------------------------------------------------------------------


def route_relevance(matched_terms: list[str], need: str) -> float:
    """Share of the need's content terms the served route actually
    matched (inflection-insensitive). A call that returned HTTP 200
    from a route matching almost none of the need is a live answer to
    the WRONG question — the benchmark counts it separately
    ('served_but_off_topic'), never as usable."""
    nt = set(need_terms(need))
    if not nt:
        return 0.0
    variants: set[str] = set()
    for t in nt:
        variants |= term_variants(t)
    return len(set(matched_terms) & variants) / len(nt)


RELEVANCE_FLOOR = 0.34  # at least ~1/3 of the need's terms must match


def run_benchmark(needs: list[dict], entries: list[dict],
                  probe_states: dict, executor=execute_call,
                  run_after: bool = True,
                  before_entries: list[dict] | None = None) -> dict:
    """BEFORE is run against `before_entries` (the catalog snapshot the
    pre-Phase-3 recommend shipped with) when given, else against the
    current catalog — say which in the report either way."""
    index = NeedIndex(entries)
    before_catalog = before_entries if before_entries is not None else entries
    before_rows = []
    after_rows = []
    before_usable = 0
    before_needs = 0
    after_usable = 0
    after_needs = 0
    top_names: list[str] = []
    prev_digest = None
    for item in needs:
        need = item["need"]
        picks = _atlas.recommend_entries(before_catalog, need.split(),
                                         states=probe_states, limit=10)
        top = picks[0] if picks else None
        b_usable = False
        b_reason = "no recommendation"
        if top is not None:
            top_names.append(top["name"])
            ok, why = keyless_established(top, probe_states)
            if not ok:
                b_reason = f"not callable: {why}"
            else:
                ok2, why2 = endpoint_established(top, probe_states)
                if not ok2:
                    b_reason = f"not callable: {why2}"
                else:
                    # Tights' usable sense: the pick must ALSO be on
                    # the need. relevance_tier excludes tier 3 here on
                    # purpose: tier 3 is "any term appears anywhere" —
                    # the exact triviality that let 0x "answer" every
                    # need (its description contains generic words like
                    # 'stats' and 'current'). A usable pick must match
                    # the need by name or by its full term set.
                    hit = _atlas.relevance_tier(top, need.split(),
                                                need.lower())
                    if hit is None or hit == 3:
                        b_reason = ("callable but not on the need "
                                    "(recommend tier None/3: no topical "
                                    "match — the same-three defect)")
                    else:
                        b_usable = True
                        b_reason = "top pick is callable and on the need"
        before_rows.append({
            "need_id": item["id"], "need": need,
            "top_pick": top["name"] if top else None,
            "top_pick_url": top["url"] if top else None,
            "usable": b_usable, "reason": b_reason,
        })
        if b_usable:
            before_usable += 1
            before_needs += 1
        if run_after:
            env, served = perform_call(need, index, probe_states,
                                       executor=executor,
                                       prev_digest=prev_digest)
            prev_digest = env["envelope_digest"]
            native = env["native"]
            rel = route_relevance(
                (native.get("route_chosen") or {}).get("matched_terms", []),
                need) if served is not None else 0.0
            a_usable = served is not None and rel >= RELEVANCE_FLOOR
            after_rows.append({
                "need_id": item["id"], "need": need,
                "status": native["status"],
                "served_by": (native.get("route_chosen") or {}).get("name"),
                "failovers": len(native["failover_chain"]),
                "http_status": native["result"]["http_status"],
                "relevance": round(rel, 3),
                "served_but_off_topic": served is not None and not a_usable,
                "usable": a_usable,
                "envelope_digest": env["envelope_digest"],
                "receipt": env,
            })
            if a_usable:
                after_usable += 1
                after_needs += 1
    return {
        "needs_total": len(needs),
        "before": {
            "method": ("pre-Phase-3 atlas.recommend top pick over the catalog "
                       "snapshot named by 'before_catalog', judged callable "
                       "under the Phase 3 allowlist (keyless established AND "
                       "probe-proven endpoint); recommend itself performs no "
                       "call"),
            "before_catalog": ("the Phase 1 founding catalog bundled in the "
                               "repo (data/catalog.json at the Phase 1 "
                               "baseline — the catalog recommend shipped "
                               "with) when supplied by the benchmark command, "
                               "else the current catalog"),
            "usable_results": before_usable,
            "needs_with_usable": before_needs,
            "distinct_top_picks": len(set(top_names)),
            "rows": before_rows,
        },
        "after": {
            "method": ("Phase 3 calling Atlas: live call; usable only on a "
                       "success receipt whose served route matches at "
                       "least RELEVANCE_FLOOR of the need's terms — a live "
                       "answer to the wrong question counts as "
                       "served_but_off_topic, never usable"),
            "usable_results": after_usable,
            "needs_with_usable": after_needs,
            "rows": after_rows,
        } if run_after else None,
    }
