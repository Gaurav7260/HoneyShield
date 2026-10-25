"""Experimental whitespace-normalized canary guard.

The original exact-match guard remains unchanged.
This candidate removes whitespace before checking registered canaries.
"""

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class GuardResult:
    blocked: bool
    reason: str


def normalize_whitespace(text: str) -> str:
    """Remove whitespace characters for experimental comparison."""
    return re.sub(r"\s+", "", text)


def inspect_text_normalized(
    text: str, canaries: set[str]
) -> GuardResult:
    """Detect exact canaries despite inserted whitespace."""
    normalized_text = normalize_whitespace(text)

    for canary in canaries:
        if not canary:
            continue

        normalized_canary = normalize_whitespace(canary)

        if normalized_canary and normalized_canary in normalized_text:
            return GuardResult(
                blocked=True,
                reason="registered_canary_detected_after_whitespace_normalization",
            )

    return GuardResult(
        blocked=False,
        reason="no_registered_canary_detected",
    )


def inspect_tool_arguments_normalized(
    arguments: dict[str, Any], canaries: set[str]
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

    return inspect_text_normalized(serialized, canaries)


def inspect_tool_arguments_normalized_v2(
    arguments: dict[str, Any], canaries: set[str]
) -> GuardResult:
    """Inspect nested tool-argument strings before JSON escaping."""

    try:
        # Validate that the arguments can be serialized as JSON.
        json.dumps(
            arguments,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return GuardResult(
            blocked=True,
            reason="invalid_tool_arguments",
        )

    def inspect_value(value: Any) -> GuardResult:
        if isinstance(value, str):
            return inspect_text_normalized(value, canaries)

        if isinstance(value, dict):
            for key, nested_value in value.items():
                key_result = inspect_text_normalized(str(key), canaries)
                if key_result.blocked:
                    return key_result

                result = inspect_value(nested_value)
                if result.blocked:
                    return result

        elif isinstance(value, list):
            for item in value:
                result = inspect_value(item)
                if result.blocked:
                    return result

        return GuardResult(
            blocked=False,
            reason="no_registered_canary_detected",
        )

    return inspect_value(arguments)
