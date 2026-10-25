"""Experimental punctuation- and whitespace-normalized canary inspection."""

import json
import re
import string
from dataclasses import dataclass
from typing import Any


@dataclass
class GuardResult:
    blocked: bool
    reason: str


def normalize_alphanumeric(text: str) -> str:
    """Keep only Unicode alphanumeric characters and remove the rest."""
    return "".join(character for character in text if character.isalnum())


def inspect_text_punctuation_normalized(
    text: str, canaries: set[str]
) -> GuardResult:
    normalized_text = normalize_alphanumeric(text)

    for canary in canaries:
        normalized_canary = normalize_alphanumeric(canary)

        if normalized_canary and normalized_canary in normalized_text:
            return GuardResult(
                blocked=True,
                reason="registered_canary_detected_after_punctuation_normalization",
            )

    return GuardResult(
        blocked=False,
        reason="no_registered_canary_detected",
    )


def inspect_tool_arguments_punctuation_normalized(
    arguments: dict[str, Any], canaries: set[str]
) -> GuardResult:
    try:
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
            return inspect_text_punctuation_normalized(value, canaries)

        if isinstance(value, dict):
            for key, nested_value in value.items():
                result = inspect_text_punctuation_normalized(str(key), canaries)
                if result.blocked:
                    return result

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
