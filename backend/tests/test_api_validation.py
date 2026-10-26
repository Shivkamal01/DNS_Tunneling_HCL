"""Validation tests for the request models in api.py."""

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from pydantic import ValidationError  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api import (  # noqa: E402
    IncidentUpdate,
    SimulationRequest,
    StatusUpdate,
    WhitelistCreate,
    app,
)


class StatusModelTests(unittest.TestCase):
    def test_alert_status_is_normalised(self):
        self.assertEqual(StatusUpdate(status=" resolved ").status, "RESOLVED")

    def test_unknown_alert_status_is_rejected(self):
        with self.assertRaises(ValidationError):
            StatusUpdate(status="DELETED")

    def test_incident_accepts_closed(self):
        self.assertEqual(IncidentUpdate(status="closed").status, "CLOSED")

    def test_notes_are_bounded(self):
        with self.assertRaises(ValidationError):
            StatusUpdate(status="OPEN", analyst_notes="x" * 4001)


class WhitelistModelTests(unittest.TestCase):
    def test_domain_is_normalised(self):
        entry = WhitelistCreate(domain_pattern="  Example.COM.  ")
        self.assertEqual(entry.domain_pattern, "example.com")

    def test_wildcards_are_rejected(self):
        with self.assertRaises(ValidationError):
            WhitelistCreate(domain_pattern="*.example.com")

    def test_empty_label_is_rejected(self):
        with self.assertRaises(ValidationError):
            WhitelistCreate(domain_pattern="example..com")

    def test_service_label_is_accepted(self):
        entry = WhitelistCreate(domain_pattern="_dmarc.example.com")
        self.assertEqual(entry.domain_pattern, "_dmarc.example.com")


class SimulationModelTests(unittest.TestCase):
    def test_count_is_bounded(self):
        with self.assertRaises(ValidationError):
            SimulationRequest(scenario="all", count=0)
        self.assertEqual(SimulationRequest(scenario="all", count=15).count, 15)


class ErrorEnvelopeTests(unittest.TestCase):
    """Validation and routing failures should share the API error contract."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_validation_errors_use_error_envelope(self):
        response = self.client.post(
            "/api/whitelist",
            json={"domain_pattern": "*.example.com", "reason": "smoke test"},
        )
        self.assertEqual(response.status_code, 422)
        body = response.json()
        self.assertEqual(body["error"]["message"], "Validation failed")
        self.assertIn("domain_pattern", body["error"]["detail"])
        self.assertNotIn("detail", body)

    def test_unknown_route_uses_error_envelope(self):
        response = self.client.get("/api/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["message"], "Not Found")


if __name__ == "__main__":
    unittest.main()
