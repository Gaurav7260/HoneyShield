
import unittest

from app.canaries import generate_canary
from app.guard import inspect_text, inspect_tool_arguments
from app.mock_tools import guarded_dispatch


class HoneyShieldGuardTests(unittest.TestCase):
    def setUp(self):
        self.canary = generate_canary()
        self.canaries = {self.canary}

    def test_canary_in_text_is_detected(self):
        result = inspect_text(
            f"Sensitive marker: {self.canary}",
            self.canaries,
        )
        self.assertTrue(result.blocked)

    def test_benign_text_is_allowed(self):
        result = inspect_text(
            "Network security fundamentals",
            self.canaries,
        )
        self.assertFalse(result.blocked)

    def test_canary_in_tool_arguments_is_detected(self):
        result = inspect_tool_arguments(
            {"query": self.canary},
            self.canaries,
        )
        self.assertTrue(result.blocked)

    def test_canary_is_blocked_before_dispatch(self):
        result = guarded_dispatch(
            "mock_search",
            {"query": self.canary},
            self.canaries,
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])

    def test_benign_query_is_dispatched(self):
        result = guarded_dispatch(
            "mock_search",
            {"query": "network security basics"},
            self.canaries,
        )
        self.assertFalse(result["blocked"])
        self.assertTrue(result["dispatched"])

    def test_unknown_tool_is_rejected(self):
        result = guarded_dispatch(
            "unknown_tool",
            {"query": "hello"},
            self.canaries,
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])

    def test_invalid_query_is_rejected(self):
        result = guarded_dispatch(
            "mock_search",
            {"query": 123},
            self.canaries,
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dispatched"])



    def test_canary_in_nested_tool_arguments_is_detected(self):
        from app.guard import inspect_tool_arguments

        canary = "HS-CANARY-NestedTest123"
        result = inspect_tool_arguments(
            {"payload": {"metadata": {"query": canary}}},
            {canary},
        )
        self.assertTrue(result.blocked)
        self.assertEqual(
            result.reason, "registered_canary_detected"
        )

    def test_benign_nested_tool_arguments_are_allowed(self):
        from app.guard import inspect_tool_arguments

        result = inspect_tool_arguments(
            {"payload": {"metadata": {"query": "incident response"}}},
            {"HS-CANARY-NotPresent123"},
        )
        self.assertFalse(result.blocked)

    def test_non_json_tool_arguments_are_rejected(self):
        from app.guard import inspect_tool_arguments

        result = inspect_tool_arguments(
            {"query": {"unsupported": object()}},
            set(),
        )
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, "invalid_tool_arguments")



if __name__ == "__main__":
    unittest.main()

            
        
