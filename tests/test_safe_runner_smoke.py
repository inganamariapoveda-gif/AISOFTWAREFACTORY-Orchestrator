"""Benign in-memory runtime smoke payload; no technical/security approval."""

import json
import unittest


class SafeRunnerSmokeTests(unittest.TestCase):
    def test_integer_arithmetic(self):
        self.assertEqual(divmod(17, 5), (3, 2))

    def test_utf8_round_trip(self):
        text = "Safe runner: \u00f1 \u03bb"
        self.assertEqual(text.encode("utf-8").decode("utf-8"), text)

    def test_json_round_trip(self):
        payload = {"values": [1, 2, 3], "enabled": True, "optional": None}
        self.assertEqual(json.loads(json.dumps(payload)), payload)


if __name__ == "__main__":
    unittest.main()
