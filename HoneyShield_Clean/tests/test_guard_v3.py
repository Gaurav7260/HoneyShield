import base64
import unittest

from app.mock_tools import guarded_dispatch_v3


class HoneyShieldV3Tests(unittest.TestCase):
    def setUp(self):
        self.canary = "HS-CANARY-3D98ED4B408D"
        self.canaries = {self.canary}

    def test_full_canary_blocked_before_dispatch(self):
        result = guarded_dispatch_v3(
            "mock_search", {"query": self.canary}, self.canaries
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])
        self.assertIsNone(result["result"])

    def test_base64_canary_blocked_before_dispatch(self):
        encoded = base64.b64encode(
            self.canary.encode()
        ).decode()
        result = guarded_dispatch_v3(
            "mock_search", {"query": encoded}, self.canaries
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])

    def test_benign_query_is_dispatched(self):
        result = guarded_dispatch_v3(
            "mock_search",
            {"query": "review failed login events"},
            self.canaries,
        )
        self.assertFalse(result["blocked"])
        self.assertTrue(result["dispatched"])

    def test_longer_identifier_is_allowed(self):
        result = guarded_dispatch_v3(
            "mock_search",
            {"query": self.canary + "-extra"},
            self.canaries,
        )
        self.assertFalse(result["blocked"])
        self.assertTrue(result["dispatched"])

    def test_unknown_tool_is_rejected(self):
        result = guarded_dispatch_v3(
            "other_tool", {"query": "benign"}, self.canaries
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])
        self.assertEqual(result["reason"], "unknown_tool")

    def test_invalid_query_is_rejected(self):
        result = guarded_dispatch_v3(
            "mock_search", {"query": 123}, self.canaries
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])
        self.assertEqual(result["reason"], "invalid_query")


if __name__ == "__main__":
    unittest.main()
