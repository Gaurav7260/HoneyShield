
"""HoneyShield exact-match enforcement guards."""
import json
from dataclasses import dataclass
from typing import Any


@dataclass
class GuardResult:
    blocked: bool
    reason: str


def inspect_text(text: str, canaries: set[str]) -> GuardResult:
    """Block text containing a registered synthetic canary."""
    for canary in canaries:
        if canary and canary in text:
            return GuardResult(
                blocked=True,
                reason="registered_canary_detected",
            )

    return GuardResult(
        blocked=False,
        reason="no_registered_canary_detected",
    )


def inspect_tool_arguments(
    arguments: dict[str, Any],
    canaries: set[str],
) -> GuardResult:
    """Inspect JSON-compatible tool arguments before dispatch."""
    try:
        serialized = json.dumps(
            arguments,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return GuardResult(
            blocked=True,
            reason="invalid_tool_arguments",
        )

    return inspect_text(serialized, canaries)
