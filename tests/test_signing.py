"""Estate key-custody proof suite: SRE-1 envelopes can now carry a real
signature, and the universal verifier checks it against the committed
public registry.

BEFORE (measured on the pre-custody tree): the verifier emitted ZERO
signature legs, and an envelope whose claim statement, gate verdict,
and issuer were forged — with the envelope digest honestly recomputed,
as anyone can, since a hash is unkeyed — verified VERIFIED. Hash
binding alone cannot stop a re-digesting forger.

AFTER: the same forgery against a signed envelope is REJECTED by the
signature leg; a genuine signed envelope verifies end to end; unknown
or revoked keys cap the verdict at VERIFIED-STRUCTURAL (never a silent
pass); unsigned envelopes keep exactly their pre-custody verdicts.

Keys in this suite are ephemeral test keys generated in setUpClass and
never written anywhere. The one committed key (the registry's demo
key) is a throwaway whose private half was destroyed at build time.
Stdlib unittest only.
"""
import copy
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from savage_standard import cli, envelope, rsa, signing, verify  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
WAV = os.path.join(FIX, "bounce_sie2.wav")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def wrap_starr():
    return envelope.wrap(
        load("starr-receipt.json"), claim_id="signing-test-1",
        claim_kind="certification",
        statement="bounce measured across the Starr QC gates",
        issuer_line="Starr", issuer_system="star", dialect="starr-bounce",
        native_schema="starr.bounce-receipt.v1", gate_name="audioQc",
        gate_verdict="sealed", recorded_at="2026-11-10T20:53:00Z")


def sig_leg(out):
    legs = [l for l in out["legs"] if l["name"] == "envelope-signature"]
    return legs[0] if legs else None


class TestRsa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kp = rsa.generate_keypair(1024)  # test-only size, speed only

    def test_emsa_block_is_byte_exact_rfc8017(self):
        em = rsa.emsa_encode(b"abc", 128)
        self.assertEqual(em[:2], b"\x00\x01")
        digest = hashlib.sha256(b"abc").digest()
        t = rsa.SHA256_DIGESTINFO_PREFIX + digest
        self.assertTrue(em.endswith(b"\x00" + t))
        ps = em[2:len(em) - len(t) - 1]
        self.assertTrue(all(b == 0xFF for b in ps))
        self.assertGreaterEqual(len(ps), 8)

    def test_sign_verify_roundtrip(self):
        sig = rsa.sign(self.kp, b"estate message")
        pub = {"n": self.kp["n"], "e": self.kp["e"]}
        self.assertTrue(rsa.verify(pub, b"estate message", sig))
        self.assertFalse(rsa.verify(pub, b"estate message!", sig))

    def test_verify_rejects_garbage(self):
        pub = {"n": self.kp["n"], "e": self.kp["e"]}
        self.assertFalse(rsa.verify(pub, b"m", b""))
        self.assertFalse(rsa.verify(pub, b"m", b"\x00" * 128))
        self.assertFalse(rsa.verify(pub, b"m", b"\xff" * 129))
        self.assertFalse(rsa.verify({"n": 0, "e": 0}, b"m", b"x"))


class TestSigning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private, cls.entry = signing.generate_signing_key(
            "test-key-1", bits=2048)
        cls.registry = {"schema": signing.REGISTRY_SCHEMA,
                        "registry_version": 1, "keys": [cls.entry]}

    def sign(self, env=None):
        return signing.sign_envelope(env or wrap_starr(), self.private,
                                     signed_at="2026-11-10T20:53:00Z")

    def test_signed_envelope_verifies_end_to_end(self):
        out = verify.verify(self.sign(), artifact_file=WAV,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "VERIFIED")
        leg = sig_leg(out)
        self.assertIsNotNone(leg)
        self.assertEqual(leg["status"], "pass")
        self.assertIn("test-key-1", leg["detail"])

    def test_redigest_forgery_now_rejected(self):
        """The pre-custody attack, verbatim: forge envelope-level
        claims, recompute the envelope digest honestly — it must die
        on the signature leg now."""
        forged = self.sign()
        forged["claim"]["statement"] = "FORGED: passed with honors"
        forged["gate"]["verdict"] = "passed-everything"
        forged["issuer"]["line"] = "ForgedIssuer"
        forged["envelope_digest"] = envelope.envelope_digest(forged)
        out = verify.verify(forged, artifact_file=WAV,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "REJECTED")
        self.assertEqual(sig_leg(out)["status"], "fail")

    def test_tampered_signature_rejected(self):
        bad = self.sign()
        v = bad["signatures"][0]["value"]
        bad["signatures"][0]["value"] = ("A" if v[0] != "A" else "B") + v[1:]
        out = verify.verify(bad, artifact_file=WAV,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_tampered_native_rejected(self):
        bad = self.sign()
        bad["native"]["measurements"]["integratedLoudnessLufs"] = -1.0
        out = verify.verify(bad, key_registry=self.registry)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_wrong_public_key_rejected(self):
        _, other_entry = signing.generate_signing_key("test-key-1",
                                                      bits=2048)
        wrong = {"schema": signing.REGISTRY_SCHEMA, "registry_version": 1,
                 "keys": [other_entry]}
        out = verify.verify(self.sign(), artifact_file=WAV,
                            key_registry=wrong)
        self.assertEqual(out["verdict"], "REJECTED")
        self.assertEqual(sig_leg(out)["status"], "fail")

    def test_unknown_key_caps_at_structural(self):
        empty = {"schema": signing.REGISTRY_SCHEMA, "registry_version": 1,
                 "keys": []}
        out = verify.verify(self.sign(), artifact_file=WAV,
                            key_registry=empty)
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")
        self.assertEqual(sig_leg(out)["status"], "unverifiable")

    def test_revoked_key_caps_at_structural(self):
        revoked = copy.deepcopy(self.registry)
        revoked["keys"][0]["status"] = "revoked"
        out = verify.verify(self.sign(), artifact_file=WAV,
                            key_registry=revoked)
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")
        self.assertEqual(sig_leg(out)["status"], "unverifiable")
        self.assertIn("REVOKED", sig_leg(out)["detail"])

    def test_unsigned_envelope_verdict_unchanged(self):
        out = verify.verify(wrap_starr(), artifact_file=WAV,
                            key_registry=self.registry)
        self.assertEqual(out["verdict"], "VERIFIED")
        self.assertIsNone(sig_leg(out))

    def test_marketplace_consumer_envelope_signed(self):
        """One real consumer wired: an EVO-9 marketplace delivery
        receipt, envelope-wrapped and signed, verifies through the
        universal verifier with the pair — signature leg included."""
        env = envelope.wrap(
            load("delivery.json"), claim_id="signing-test-marketplace-1",
            claim_kind="delivery",
            statement="delivery recorded against a verified payment",
            issuer_line="Savage Marketplace", issuer_system="savage-marketplace",
            dialect="marketplace-delivery",
            native_schema="savage/delivery-receipt/1",
            gate_name="delivery-ledger", gate_verdict="recorded",
            recorded_at="2026-11-10T20:53:00Z")
        signed = signing.sign_envelope(env, self.private,
                                       signed_at="2026-11-10T20:53:00Z")
        out = verify.verify(signed, pair=load("payment.json"),
                            key_registry=self.registry)
        # artifact bytes not supplied: structural, as before custody —
        # but now with a PASSING signature leg in the list.
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")
        self.assertEqual(sig_leg(out)["status"], "pass")
        fails = [l for l in out["legs"] if l["status"] == "fail"]
        self.assertEqual(fails, [])


class TestDemoAndCustody(unittest.TestCase):
    def test_shipped_demo_fixture_verifies(self):
        env = load("signed-envelope-demo.json")
        out = verify.verify(env, artifact_file=WAV)  # default registry
        self.assertEqual(out["verdict"], "VERIFIED")
        leg = sig_leg(out)
        self.assertEqual(leg["status"], "pass")
        self.assertIn("DEMO", leg["detail"])

    def test_shipped_registry_has_only_the_demo_key(self):
        reg = signing.load_registry()
        self.assertEqual(len(reg["keys"]), 1)
        self.assertEqual(reg["keys"][0]["usage"], "demo")

    def test_private_key_file_is_0600_and_roundtrips(self):
        private, _ = signing.generate_signing_key("file-key", bits=2048)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "key.json")
            signing.save_private_key(private, path)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
            self.assertEqual(signing.load_private_key(path), private)
            with self.assertRaises(FileExistsError):
                signing.save_private_key(private, path)

    def test_signing_refuses_small_keys(self):
        kp = rsa.generate_keypair(1024)
        small = {"schema": signing.PRIVATE_KEY_SCHEMA, "key_id": "small",
                 "algorithm": signing.ALGORITHM, "bits": 1024,
                 "n": signing._int_to_b64u(kp["n"]), "e": kp["e"],
                 "d": signing._int_to_b64u(kp["d"]),
                 "p": signing._int_to_b64u(kp["p"]),
                 "q": signing._int_to_b64u(kp["q"])}
        with self.assertRaises(ValueError):
            signing.sign_envelope(wrap_starr(), small)

    def test_cli_keygen_sign_verify(self):
        with tempfile.TemporaryDirectory() as td:
            key_path = os.path.join(td, "estate.key.json")
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                rc = cli.main(["keygen", "--key-id", "cli-key",
                               "--out", key_path, "--bits", "2048"])
            self.assertEqual(rc, 0)
            entry = json.loads(buf.getvalue())
            reg_path = os.path.join(td, "registry.json")
            with open(reg_path, "w", encoding="utf-8") as fh:
                json.dump({"schema": signing.REGISTRY_SCHEMA,
                           "registry_version": 1, "keys": [entry]}, fh)
            env_path = os.path.join(td, "env.json")
            with open(env_path, "w", encoding="utf-8") as fh:
                json.dump(wrap_starr(), fh)
            out_path = os.path.join(td, "signed.json")
            with redirect_stderr(io.StringIO()):
                rc = cli.main(["sign", env_path, "--key-file", key_path,
                               "-o", out_path])
            self.assertEqual(rc, 0)
            with redirect_stdout(io.StringIO()):
                rc = cli.main([out_path, "--file", WAV,
                               "--keys", reg_path])
            self.assertEqual(rc, 0)  # VERIFIED


if __name__ == "__main__":
    unittest.main()
