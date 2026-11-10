"""Canonical JSON encodings used by the estate's receipt dialects.

Three encodings appear in the wild, each re-implemented here from the
producing source code (clean-room: the algorithms are the dialects' own
declared formats; this code is original):

1. ``jcs`` — RFC 8785 JSON Canonicalization Scheme, as implemented by the
   marketplace ``@savage/core`` package (packages/core/src/canonical.ts):
   keys sorted by UTF-16 code unit, minimal string escaping, ECMAScript
   ``Number.prototype.toString`` number serialization, undefined object
   members dropped, lone surrogates rejected.
2. ``sorted_compact`` — Python ``json.dumps(sort_keys=True,
   separators=(",", ":"), ensure_ascii=True)``: sia-v6-core receipts and
   the Relay event log (Relay uses ``ensure_ascii`` default True).
3. ``starr`` — Starr's ``canonicalJson`` (server/lib/audioQc.ts): keys
   sorted recursively, primitives via JS ``JSON.stringify`` semantics
   (non-ASCII literal), undefined object members dropped.
"""
from __future__ import annotations

import json
import math


class CanonicalError(ValueError):
    pass


# ── ECMAScript Number.prototype.toString ────────────────────────────────────

def _shortest_digits(x: float) -> tuple[str, int]:
    """Return (digits, exp10) such that x = 0.digits * 10**exp10, using the
    shortest round-trip decimal representation (Python repr agrees with
    ECMAScript on the digit sequence for doubles)."""
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
    # value = int(digits) * 10^(exp - len(fp)); normalize to 0.digits form
    lead = 0
    while lead < len(digits) and digits[lead] == "0":
        lead += 1
    digits = digits[lead:]
    exp10 = exp - len(fp) + (len(ip) + len(fp)) - lead
    digits = digits.rstrip("0") or "0"
    return digits, exp10


def js_number(x) -> str:
    """ECMAScript Number.prototype.toString for a JSON number."""
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
    n = exp10  # decimal point sits after the first n digits of 0.digits*10^n
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


# ── JCS (RFC 8785) string escaping ──────────────────────────────────────────

_ESCAPES = {
    "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
    '"': '\\"', "\\": "\\\\",
}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _check_lone_surrogates(s: str) -> None:
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalError("lone surrogate in string")


def jcs(value) -> str:
    """RFC 8785 canonical JSON, byte-compatible with @savage/core."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        _check_lone_surrogates(value)
        return _jcs_string(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return js_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = [(k, v) for k, v in value.items() if v is not _UNDEFINED]
        for k, _ in items:
            _check_lone_surrogates(k)
        items.sort(key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    raise CanonicalError(f"uncanonicalizable type: {type(value)}")


class _Undefined:
    pass


_UNDEFINED = _Undefined()


# ── Python sorted-compact (sia-v6-core, Relay) ──────────────────────────────

def sorted_compact(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


# ── Starr canonicalJson ─────────────────────────────────────────────────────

def _js_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def starr(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return js_number(value)
    if isinstance(value, list):
        return "[" + ",".join(starr(v) for v in value) + "]"
    if isinstance(value, dict):
        items = [(k, v) for k, v in value.items() if v is not _UNDEFINED]
        items.sort(key=lambda kv: kv[0])
        return "{" + ",".join(_js_string(k) + ":" + starr(v) for k, v in items) + "}"
    raise CanonicalError(f"uncanonicalizable type: {type(value)}")


# ── JS JSON.stringify with fixed insertion order (Breakthrough, CEROS) ─────

def js_stringify_ordered(pairs) -> str:
    """JSON.stringify of an object literal built from (key, value) pairs in
    the given order. Values in these dialects are strings/numbers/bools or
    flat records of numbers (CEROS dimensions)."""
    parts = []
    for k, v in pairs:
        parts.append(_js_string(k) + ":" + _js_value(v))
    return "{" + ",".join(parts) + "}"


def _js_value(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _js_string(v)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return js_number(v)
    if isinstance(v, list):
        return "[" + ",".join(_js_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(
            _js_string(k) + ":" + _js_value(x) for k, x in v.items()) + "}"
    raise CanonicalError(f"unsupported value type: {type(v)}")
