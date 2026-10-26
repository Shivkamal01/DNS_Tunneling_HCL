"""Unit tests for the DNS feature-extraction and risk-scoring engine."""

import math
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import utils  # noqa: E402


BENIGN_CASES = [
    ("www.google.com", 1),
    ("login.microsoftonline.com", 1),
    ("api.github.com", 1),
    ("outlook.office365.com", 1),
    ("cdn.jsdelivr.net", 1),
    ("static-assets.prod.us-east-1.mycompany.com", 1),
    ("a1b2c3d4e5f6.internal.corp.example.com", 1),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.sha256.digicert.com", 1),
    ("_dmarc.google.com", 16),
    ("selector1._domainkey.outlook.com", 16),
    ("analytics-prod-usw2.internal.aws.example.com", 1),
]

MALICIOUS_CASES = [
    ("7365637265742d646174612d64756d702d3031.c2-command.org", 16),
    ("61646d696e5f70617373776f72645f68617368.c2-command.org", 10),
    ("dnscat.0102030405060708deadbeef.malicious-tunnel.com", 16),
    ("dnscat.fa73b92c4e1198501234abcd.malicious-tunnel.com", 16),
    ("4g6d8e0f1g2h3j4k5l6m7n8p9q0r1s2t.tunnel-endpoint.biz", 5),
    ("f9e8d7c6b5a43210f9e8d7c6b5a43210f9e8d7c6b5a43210.exfil-dns.net", 16),
    ("783261623938633736643534653332663161306239386337.exfil-dns.net", 16),
    ("mjqwq3dmnfsdgnbwmy2dsnzyhjrgk4tf.evil-c2.net", 16),
]


class ScoringCorpusTests(unittest.TestCase):
    def tearDown(self):
        # Whitelist is module-global; leave it in the default state for the
        # next test module.
        utils.set_whitelist(utils.DEFAULT_WHITELIST)

    def test_benign_corpus_stays_below_high(self):
        for domain, qtype in BENIGN_CASES:
            with self.subTest(domain=domain):
                features = utils.extract_dns_features(domain, qtype)
                score, severity, _ = utils.evaluate_risk(features)
                self.assertLess(score, 50, f"{domain} scored {score}")
                self.assertNotIn(severity, ("High", "Critical"))

    def test_malicious_corpus_reaches_high(self):
        for domain, qtype in MALICIOUS_CASES:
            with self.subTest(domain=domain):
                features = utils.extract_dns_features(domain, qtype)
                score, severity, _ = utils.evaluate_risk(features)
                self.assertGreaterEqual(score, 50, f"{domain} scored {score}")
                self.assertIn(severity, ("High", "Critical"))

    def test_whitelist_short_circuits_to_zero(self):
        utils.set_whitelist(["evil-c2.net"])
        features = utils.extract_dns_features(
            "mjqwq3dmnfsdgnbwmy2dsnzyhjrgk4tf.evil-c2.net", 16
        )
        score, severity, indicators = utils.evaluate_risk(features)
        self.assertEqual(score, 0)
        self.assertEqual(severity, "Low")
        self.assertTrue(any("whitelist" in item.lower() for item in indicators))

    def test_deleted_default_rule_no_longer_suppresses(self):
        utils.set_whitelist([])
        features = utils.extract_dns_features("www.google.com", 1)
        self.assertFalse(features["is_whitelisted"])

    def test_service_record_entropy_is_discounted(self):
        features = utils.extract_dns_features("_dmarc.example.org", 16)
        self.assertTrue(features["is_service_record"])
        score, _, _ = utils.evaluate_risk(features)
        self.assertLess(score, 50)


class EntropyTests(unittest.TestCase):
    def test_short_labels_are_normalised(self):
        entropy = utils.calculate_entropy("abcd")
        self.assertAlmostEqual(entropy, 2.0)
        self.assertAlmostEqual(utils.normalized_entropy(entropy, 4), 1.0)

    def test_long_base32_payload_keeps_a_useful_ratio(self):
        # Regression guard for normalising against the 63-octet label limit:
        # a long, genuinely random base32 label must still read as high entropy.
        payload = "abcdefghijklmnopqrstuvwxyz234567" * 2
        entropy = utils.calculate_entropy(payload)
        ratio = utils.normalized_entropy(entropy, len(payload))
        self.assertGreater(ratio, 0.9)
        self.assertLessEqual(ratio, 1.0)
        self.assertLess(math.log2(37), math.log2(63))

    def test_ceiling_never_exceeds_one(self):
        self.assertEqual(utils.normalized_entropy(99.0, 64), 1.0)
        self.assertEqual(utils.normalized_entropy(0.0, 0), 0.0)


class EncodingTests(unittest.TestCase):
    def test_base32_foreign_ratio_is_inverted(self):
        self.assertEqual(utils.base32_foreign_ratio("ABCDEFGHIJKLMNOP"), 0.0)
        self.assertGreater(utils.base32_foreign_ratio("www.example.com"), 0.0)

    def test_base32_decode_requires_printable_output(self):
        decoded, printable = utils.try_base32_decode("MZXW6YZFOI======")
        self.assertTrue(decoded)
        self.assertGreaterEqual(printable, 0.99)

    def test_hex_encoded_ascii_is_recognised(self):
        features = utils.extract_dns_features(
            "7365637265742d64617461.c2.example", 10
        )
        self.assertEqual(features["encoding"], "hex")
        self.assertAlmostEqual(features["hex_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
