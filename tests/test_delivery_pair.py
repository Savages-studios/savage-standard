"""Delivery-pair bridge proof suite (estate fix #81): a marketplace
delivery-ledger receipt PAIR is a first-class dialect of the universal
verifier, so the pair itself can be issued as the native payload of a
signed SRE-1 envelope.

BEFORE (measured on the pre-bridge tree, savage-standard @ 29c28131):
a real pair — exactly what the ledger's receiptsFor() returns —
verified UNVERIFIABLE ("input matches no known estate dialect"); the
pair wrapped + signed as an envelope native returned
VERIFIED-STRUCTURAL with dialect None and ZERO of the pair's own legs
run; and the only signed route (fix #78) carried the delivery receipt
inside the envelope while the payment receipt rode OUTSIDE it as an
unsigned --pair input — omit --pair and the envelope still verified
VERIFIED with no pair leg at all.

AFTER: the pair is detected (marked savage/delivery-receipt-pair/1, or
the unmarked receiptsFor() shape), both receipts' entry hashes and
receipt digests are recomputed, the four pair bindings and the
artifact legs run, and a signed envelope over the pair verifies end to
end with the signature leg passing. Tamper controls: an edited amount
fails the payment entry-hash leg; an edited amount with honestly
recomputed payment digests fails the pair binding legs; a re-digested
claim forgery against the signed envelope fails the signature leg.

Fixtures: fixtures/payment.json + fixtures/delivery.json (the genuine
EVO-9 measurement pair) and fixtures/delivery-pair.json (a pair minted
by the ledger package's own compiled code from savage-marketplace main
bfaa3a18 for this build, with its delivered artifact bytes in
fixtures/delivery-pair-artifacts/ — see fixtures/PROVENANCE.md).
Stdlib unittest only.
"""
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from savage_standard import canonical, cli, dialects, envelope, signing, verify  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
ART_DIR = os.path.join(FIX, "delivery-pair-artifacts")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def legs_by_name(out):
    return {l["name"]: l["status"] for l in out["legs"]}


def wrap_pair(native, claim_id="pair-test-1"):
    return envelope.wrap(
        native, claim_id=claim_id, claim_kind="delivery",
        statement="delivery recorded against a verified payment",
        issuer_line="Savage Marketplace", issuer_system="savage-marketplace",
        dialect="marketplace-delivery-pair",
        native_schema=dialects.PAIR_SCHEMA,
        gate_name="delivery-ledger", gate_verdict="recorded",
        recorded_at="2026-11-10T23:00:00Z")


class TestPairNative(unittest.TestCase):
    def setUp(self):
        self.measured = {"payment": load("payment.json"),
                         "delivery": load("delivery.json")}
        self.minted = load("delivery-pair.json")

    def test_marked_pair_verifies_with_all_binding_legs(self):
        native = dialects.marketplace_pair_native(**self.measured)
        out = verify.verify(native)
        self.assertEqual(out["dialect"], "marketplace-delivery-pair")
        legs = legs_by_name(out)
        for name in ("pair-shape", "payment-entry-hash",
                     "payment-receipt-digest", "delivery-entry-hash",
                     "delivery-receipt-digest", "pair-order", "pair-binding",
                     "pair-receipt-binding", "pair-sku"):
            self.assertEqual(legs.get(name), "pass", name)
        # The measurement pair's artifact bytes are not in this repo:
        # that leg is unverifiable, so the verdict caps at structural.
        self.assertEqual(legs.get("artifact:deliverable.bin"), "unverifiable")
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")
        self.assertEqual(out["claim"]["orderId"], "measure-01-tooldiff")

    def test_unmarked_receiptsfor_shape_is_detected(self):
        out = verify.verify(self.measured)  # exactly receiptsFor() output
        self.assertEqual(out["dialect"], "marketplace-delivery-pair")
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")

    def test_minted_pair_verifies_fully_with_artifact_bytes(self):
        native = dialects.marketplace_pair_native(**self.minted)
        out = verify.verify(native, artifact_dir=ART_DIR)
        self.assertEqual(out["verdict"], "VERIFIED")
        legs = legs_by_name(out)
        self.assertEqual(legs.get("artifact:facturforge-pack.zip"), "pass")
        fails = [n for n, s in legs.items() if s == "fail"]
        self.assertEqual(fails, [])

    def test_tampered_amount_fails_payment_entry_hash(self):
        bad = dialects.marketplace_pair_native(**copy.deepcopy(self.minted))
        bad["payment"]["entry"]["payload"]["amountMinor"] = 1
        out = verify.verify(bad, artifact_dir=ART_DIR)
        self.assertEqual(out["verdict"], "REJECTED")
        legs = legs_by_name(out)
        self.assertEqual(legs.get("payment-entry-hash"), "fail")

    def test_redigested_payment_fails_pair_binding(self):
        """A forger who knows the format edits the amount AND honestly
        recomputes the payment receipt's entry hash and receipt digest.
        The pair still dies: the delivery receipt binds the ORIGINAL
        payment hashes, and it was not (cannot honestly be) rewritten."""
        bad = dialects.marketplace_pair_native(**copy.deepcopy(self.minted))
        pay = bad["payment"]
        pay["entry"]["payload"]["amountMinor"] = 1
        body = {k: pay["entry"].get(k) for k in
                ("schema", "seq", "kind", "orderId", "recordedAt",
                 "payload", "prevHash")}
        pay["entry"]["entryHash"] = hashlib.sha256(
            canonical.jcs(body).encode("utf-8")).hexdigest()
        core = {k: v for k, v in pay.items() if k != "receiptDigest"}
        pay["receiptDigest"] = hashlib.sha256(
            canonical.jcs(core).encode("utf-8")).hexdigest()
        out = verify.verify(bad, artifact_dir=ART_DIR)
        self.assertEqual(out["verdict"], "REJECTED")
        legs = legs_by_name(out)
        self.assertEqual(legs.get("payment-entry-hash"), "pass")
        self.assertEqual(legs.get("payment-receipt-digest"), "pass")
        self.assertEqual(legs.get("pair-binding"), "fail")
        self.assertEqual(legs.get("pair-receipt-binding"), "fail")

    def test_swapped_members_rejected(self):
        bad = dialects.marketplace_pair_native(
            payment=self.measured["delivery"],
            delivery=self.measured["payment"])
        out = verify.verify(bad)
        self.assertEqual(out["verdict"], "REJECTED")
        self.assertEqual(legs_by_name(out).get("pair-shape"), "fail")

    def test_malformed_member_rejected_without_crashing(self):
        out = verify.verify({"schema": dialects.PAIR_SCHEMA,
                             "payment": "junk",
                             "delivery": self.measured["delivery"]})
        self.assertEqual(out["verdict"], "REJECTED")
        self.assertEqual(legs_by_name(out).get("pair-shape"), "fail")


class TestSignedPairEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private, cls.entry = signing.generate_signing_key(
            "pair-test-key", bits=2048)
        cls.registry = {"schema": signing.REGISTRY_SCHEMA,
                        "registry_version": 1, "keys": [cls.entry]}

    def setUp(self):
        self.native = dialects.marketplace_pair_native(
            **load("delivery-pair.json"))

    def sign(self, env):
        return signing.sign_envelope(env, self.private,
                                     signed_at="2026-11-10T23:00:00Z")

    def test_signed_pair_envelope_verifies_end_to_end(self):
        out = verify.verify(self.sign(wrap_pair(self.native)),
                            artifact_dir=ART_DIR,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "VERIFIED")
        self.assertEqual(out["dialect"], "marketplace-delivery-pair")
        legs = legs_by_name(out)
        self.assertEqual(legs.get("envelope-signature"), "pass")
        self.assertEqual(legs.get("pair-binding"), "pass")
        self.assertEqual(legs.get("payment-entry-hash"), "pass")

    def test_claim_forgery_with_redigest_rejected_by_signature(self):
        forged = self.sign(wrap_pair(self.native))
        forged["claim"]["statement"] = "FORGED: delivery of a different order"
        forged["envelope_digest"] = envelope.envelope_digest(forged)
        out = verify.verify(forged, artifact_dir=ART_DIR,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "REJECTED")
        self.assertEqual(legs_by_name(out).get("envelope-signature"), "fail")

    def test_native_pair_swap_inside_signed_envelope_rejected(self):
        """Replacing the whole native pair with a different order's pair
        (and honestly re-digesting) dies on native-binding/signature:
        the signed subject digest names the original pair."""
        other = dialects.marketplace_pair_native(
            payment=load("payment.json"), delivery=load("delivery.json"))
        forged = self.sign(wrap_pair(self.native))
        forged["native"] = other
        forged["subject"]["native_digest"] = envelope.native_digest(other)
        forged["envelope_digest"] = envelope.envelope_digest(forged)
        out = verify.verify(forged, artifact_dir=ART_DIR,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_unsigned_pair_envelope_adds_no_signature_leg(self):
        out = verify.verify(wrap_pair(self.native), artifact_dir=ART_DIR,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "VERIFIED")
        self.assertNotIn("envelope-signature", legs_by_name(out))

    def test_cli_forms_signs_and_verifies_the_pair(self):
        with tempfile.TemporaryDirectory() as td:
            pair_path = os.path.join(td, "pair.json")
            with open(pair_path, "w", encoding="utf-8") as fh:
                json.dump(self.native, fh)
            # The raw pair file verifies natively through the CLI.
            with redirect_stdout(io.StringIO()):
                rc = cli.main([pair_path, "--artifacts", ART_DIR])
            self.assertEqual(rc, 0)  # VERIFIED
            key_path = os.path.join(td, "pair.key.json")
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                rc = cli.main(["keygen", "--key-id", "cli-pair-key",
                               "--out", key_path, "--bits", "2048"])
            self.assertEqual(rc, 0)
            reg_path = os.path.join(td, "registry.json")
            with open(reg_path, "w", encoding="utf-8") as fh:
                json.dump({"schema": signing.REGISTRY_SCHEMA,
                           "registry_version": 1,
                           "keys": [json.loads(buf.getvalue())]}, fh)
            env_path = os.path.join(td, "env.json")
            with redirect_stderr(io.StringIO()):
                rc = cli.main(["wrap", pair_path,
                               "--claim-id", "cli-pair-1",
                               "--claim-kind", "delivery",
                               "--statement",
                               "delivery recorded against a verified payment",
                               "--issuer-line", "Savage Marketplace",
                               "--issuer-system", "savage-marketplace",
                               "--dialect", "marketplace-delivery-pair",
                               "--native-schema", dialects.PAIR_SCHEMA,
                               "--gate-name", "delivery-ledger",
                               "--gate-verdict", "recorded",
                               "--recorded-at", "2026-11-10T23:00:00Z",
                               "-o", env_path])
            self.assertEqual(rc, 0)
            signed_path = os.path.join(td, "signed.json")
            with redirect_stderr(io.StringIO()):
                rc = cli.main(["sign", env_path, "--key-file", key_path,
                               "-o", signed_path])
            self.assertEqual(rc, 0)
            with redirect_stdout(io.StringIO()):
                rc = cli.main([signed_path, "--artifacts", ART_DIR,
                               "--keys", reg_path])
            self.assertEqual(rc, 0)  # VERIFIED, signature leg included


if __name__ == "__main__":
    unittest.main()
