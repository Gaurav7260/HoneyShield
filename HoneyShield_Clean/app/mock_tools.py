
"""Harmless mock tools for HoneyShield experiments."""

from app.guard import inspect_tool_arguments


def mock_search(query: str) -> dict:
    """Simulate a search without accessing the internet."""
    return {
        "tool": "mock_search",
        "executed": True,
        "result": f"Mock result for: {query}",
    }


def guarded_dispatch(
    tool_name: str,
    arguments: dict,
    canaries: set[str],
) -> dict:
    """Inspect arguments before dispatching to an allowed mock tool."""

    guard_result = inspect_tool_arguments(arguments, canaries)

    if guard_result.blocked:
        return {
            "dispatched": False,
            "blocked": True,
            "reason": guard_result.reason,
            "result": None,
        }

    if tool_name != "mock_search":
        return {
            "dispatched": False,
            "blocked": True,
            "reason": "unknown_tool",
            "result": None,
        }

    if not isinstance(arguments.get("query"), str):
        return {
            "dispatched": False,
            "blocked": True,
            "reason": "invalid_query",
            "result": None,
        }

    result = mock_search(arguments["query"])

    return {
        "dispatched": True,
        "blocked": False,
        "reason": "allowed",
        "result": result,
    }



def guarded_dispatch_v3(
    tool_name: str,
    arguments: dict,
    canaries: set[str],
) -> dict:
    """Inspect tool arguments with experimental v3 before mock dispatch."""
    from app.encoded_guard_v3 import inspect_tool_arguments_with_base64_v3

    guard_result = inspect_tool_arguments_with_base64_v3(
        arguments, canaries
    )

    if guard_result.blocked:
        return {
            "dispatched": False,
            "blocked": True,
            "reason": guard_result.reason,
            "result": None,
        }

    if tool_name != "mock_search":
        return {
            "dispatched": False,
            "blocked": True,
            "reason": "unknown_tool",
            "result": None,
        }

    if not isinstance(arguments.get("query"), str):
        return {
            "dispatched": False,
            "blocked": True,
            "reason": "invalid_query",
            "result": None,
        }

    result = mock_search(arguments["query"])

    return {
        "dispatched": True,
        "blocked": False,
        "reason": "allowed",
        "result": result,
    }
