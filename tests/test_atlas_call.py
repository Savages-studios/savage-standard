"""Atlas-call dialect proof suite (estate fix #82): the universal
verifier natively verifies savage-api-atlas call receipts — the
envelope layer AND the atlas-call dialect legs — so Atlas receipts no
longer depend on the producer's own local verifier.

BEFORE (measured on the pristine trees, 2026-11-10): the 30 landed
benchmark receipts verified under the standard's verify() as
VERIFIED-STRUCTURAL — but HOLLOW: legs were envelope-digest,
native-binding, chain-field and a single UNVERIFIABLE dialect-detection
leg; dialect was None, claim was {}, and NONE of the atlas-call checks
(gate-verdict-vs-native, body-digest-pointer, body-content,
result-consistency) ever ran. The envelope shell was checked; the
receipt inside it was not.

AFTER: an atlas-call envelope (issuer dialect "atlas-call" + subject
native_schema "savage/atlas-call/1") routes to
dialects.verify_atlas_call, which recomputes the producer's four
dialect legs from the receipt. The genuine landed receipts verify
VERIFIED-STRUCTURAL WITH the dialect legs passing (the body-content
leg keeps the producer's by-design ceiling). Tamper controls: the two
controls Knights ran against call.py on 2026-11-10 (claim statement
flipped; subject.native_digest zeroed) REJECT; and honest-recompute
dialect tampers (status flipped with binding+digest honestly
recomputed; body digest swapped likewise) fail their dialect legs.
Atlas envelopes can also be SIGNED under the fix-#78 custody stack and
verify with the signature leg passing — the producer's own verifier
could not do this at all (its digest core did not exclude a
signatures member).

Fixtures: tests/fixtures/atlas-call-envelopes.json — three genuine
receipts copied verbatim from savage-api-atlas
benchmarks/needs-benchmark.json at atlas main d9c24a21d8f7 (one
success, one refused, one failed). The pre-convergence producer source
they were minted by travels at vendor/atlas_call_v1.py and is pinned
by hash (dialects.ATLAS_CALL_SOURCE_SHA256).
Stdlib unittest only.
"""
import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from savage_standard import dialects, envelope, signing, verify  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures",
                        "atlas-call-envelopes.json")
VENDOR = os.path.join(os.path.dirname(__file__), "..", "vendor",
                      "atlas_call_v1.py")


def _load():
    with open(FIXTURES, encoding="utf-8") as fh:
        return json.load(fh)


def _fails(result):
    return [l["name"] for l in result["legs"] if l["status"] == "fail"]


class TestAtlasCallDialect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = _load()

    def test_success_envelope_verifies_with_dialect_legs(self):
        r = verify.verify(self.fx["success"])
        self.assertEqual(r["verdict"], "VERIFIED-STRUCTURAL")
        self.assertEqual(r["dialect"], "atlas-call")
        self.assertEqual(r["claim"]["status"], "success")
        names = {l["name"]: l["status"] for l in r["legs"]}
        for leg in ("envelope-digest", "native-binding", "chain-field"):
            self.assertEqual(names[leg], "pass", leg)
        for leg in ("gate-verdict-vs-native", "body-digest-pointer",
                    "result-consistency"):
            self.assertEqual(names[leg], "pass", leg)
        # The producer's by-design ceiling: bodies are digested, not
        # embedded, so body content is unverifiable in principle.
        self.assertEqual(names["body-content"], "unverifiable")

    def test_refused_envelope_verifies(self):
        r = verify.verify(self.fx["refused"])
        self.assertEqual(r["dialect"], "atlas-call")
        self.assertEqual(r["claim"]["status"], "refused")
        self.assertEqual(r["verdict"], "VERIFIED-STRUCTURAL")
        names = {l["name"]: l["status"] for l in r["legs"]}
        self.assertEqual(names["gate-verdict-vs-native"], "pass")
        self.assertEqual(names["result-consistency"], "pass")
        # No body was captured (refused before any call), so the
        # pointer leg is unverifiable — the producer's own semantics.
        self.assertEqual(names["body-digest-pointer"], "unverifiable")

    def test_failed_envelope_verifies(self):
        r = verify.verify(self.fx["failed"])
        self.assertEqual(r["dialect"], "atlas-call")
        self.assertEqual(r["claim"]["status"], "failed")
        self.assertEqual(r["verdict"], "VERIFIED-STRUCTURAL")
        self.assertEqual(_fails(r), [])

    def test_tamper_claim_statement_rejected(self):
        # Knights' control #1 against call.py, 2026-11-10.
        env = copy.deepcopy(self.fx["success"])
        env["claim"]["statement"] = "Atlas call for need: something else"
        self.assertEqual(verify.verify(env)["verdict"], "REJECTED")

    def test_tamper_native_digest_zeroed_rejected(self):
        # Knights' control #2 against call.py, 2026-11-10.
        env = copy.deepcopy(self.fx["success"])
        env["subject"]["native_digest"] = "0" * 64
        r = verify.verify(env)
        self.assertEqual(r["verdict"], "REJECTED")
        self.assertIn("native-binding", _fails(r))

    def test_tamper_status_flip_honest_redigest_rejected(self):
        env = copy.deepcopy(self.fx["success"])
        env["native"]["status"] = "failed"
        env["subject"]["native_digest"] = envelope.native_digest(env["native"])
        env["envelope_digest"] = envelope.envelope_digest(env)
        r = verify.verify(env)
        self.assertEqual(r["verdict"], "REJECTED")
        self.assertIn("gate-verdict-vs-native", _fails(r))

    def test_tamper_body_digest_honest_redigest_rejected(self):
        env = copy.deepcopy(self.fx["success"])
        env["native"]["result"]["body_sha256"] = "f" * 64
        env["subject"]["native_digest"] = envelope.native_digest(env["native"])
        env["envelope_digest"] = envelope.envelope_digest(env)
        r = verify.verify(env)
        self.assertEqual(r["verdict"], "REJECTED")
        self.assertIn("body-digest-pointer", _fails(r))

    def test_tamper_success_without_http_status_rejected(self):
        env = copy.deepcopy(self.fx["success"])
        env["native"]["result"]["http_status"] = None
        env["subject"]["native_digest"] = envelope.native_digest(env["native"])
        env["envelope_digest"] = envelope.envelope_digest(env)
        r = verify.verify(env)
        self.assertEqual(r["verdict"], "REJECTED")
        self.assertIn("result-consistency", _fails(r))

    def test_chain_pointer_rewrite_rejected_by_digest(self):
        # chain.prev_digest is inside the digest core: rewriting it
        # without the private ability to re-issue breaks the envelope
        # digest. (Recomputing the digest honestly is re-issuance, not
        # tampering; sequence agreement stays the producer's
        # chain-aware checks — see dialects.py.)
        env = copy.deepcopy(self.fx["success"])
        env["chain"]["prev_digest"] = "0" * 64
        r = verify.verify(env)
        self.assertEqual(r["verdict"], "REJECTED")
        self.assertIn("envelope-digest", _fails(r))

    def test_bare_native_is_not_an_atlas_dialect(self):
        # Convergence is envelope-level by design: the bare native is
        # not self-describing, and the standard says so rather than
        # guessing.
        r = verify.verify(self.fx["success"]["native"])
        self.assertEqual(r["verdict"], "UNVERIFIABLE")
        self.assertIsNone(r["dialect"])

    def test_signed_atlas_envelope_verifies(self):
        private, entry = signing.generate_signing_key(
            "atlas-call-test-throwaway", bits=2048)
        registry = {"schema": signing.REGISTRY_SCHEMA, "keys": [entry]}
        signed = signing.sign_envelope(copy.deepcopy(self.fx["success"]),
                                       private)
        r = verify.verify(signed, key_registry=registry)
        self.assertEqual(r["dialect"], "atlas-call")
        self.assertEqual(r["verdict"], "VERIFIED-STRUCTURAL")
        names = {l["name"]: l["status"] for l in r["legs"]}
        self.assertEqual(names["envelope-signature"], "pass")
        self.assertEqual(names["gate-verdict-vs-native"], "pass")
        # Redigest forgery against the signed envelope breaks on the
        # signature leg.
        forged = copy.deepcopy(signed)
        forged["claim"]["statement"] = "forged"
        forged["envelope_digest"] = envelope.envelope_digest(forged)
        r2 = verify.verify(forged, key_registry=registry)
        self.assertEqual(r2["verdict"], "REJECTED")
        self.assertIn("envelope-signature", _fails(r2))

    def test_vendored_producer_matches_declared_pin(self):
        with open(VENDOR, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(digest, dialects.ATLAS_CALL_SOURCE_SHA256)


if __name__ == "__main__":
    unittest.main()
