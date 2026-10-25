"""Experimental case-insensitive, boundary-aware canary guard."""
import base64
import binascii
import json
import re
from typing import Any

from app.punctuation_guard import GuardResult, normalize_alphanumeric


def normalize(text: str) -> str:
    return normalize_alphanumeric(text).casefold()


def inspect_normalized_text(text: str, canaries: set[str]) -> GuardResult:
    normalized_text = normalize(text)

    for canary in canaries:
        normalized_canary = normalize(canary)
        if not normalized_canary:
            continue

        start = 0
        while True:
            index = normalized_text.find(normalized_canary, start)
            if index < 0:
                break

            end = index + len(normalized_canary)

            # Require token boundaries. This avoids matching a complete
            # canary merely as a prefix of a longer alphanumeric identifier.
            left_ok = index == 0 or not normalized_text[index - 1].isalnum()
            right_ok = end == len(normalized_text) or not normalized_text[end].isalnum()

            if left_ok and right_ok:
                return GuardResult(
                    blocked=True,
                    reason="registered_canary_detected_after_case_and_punctuation_normalization",
                )

            start = index + 1

    return GuardResult(blocked=False, reason="no_registered_canary_detected")


def inspect_text_with_base64_v2(text: str, canaries: set[str]) -> GuardResult:
    direct = inspect_normalized_text(text, canaries)
    if direct.blocked:
        return direct

    # Scan candidate Base64 tokens even when surrounded by JSON quotes,
    # commas, or other punctuation.
    tokens = re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])", text)

    for token in tokens:
        if len(token) % 4 != 0:
            continue

        try:
            decoded_bytes = base64.b64decode(token, validate=True)
            decoded_text = decoded_bytes.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        result = inspect_normalized_text(decoded_text, canaries)
        if result.blocked:
            return GuardResult(
                blocked=True,
                reason="registered_canary_detected_after_base64_decoding",
            )

    # If the input is JSON, inspect its decoded string values and keys too.
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        parsed = None

    if parsed is not None:
        result = inspect_tool_arguments_with_base64_v2(parsed, canaries)
        if result.blocked:
            return result

    return GuardResult(blocked=False, reason="no_registered_canary_detected")


def inspect_tool_arguments_with_base64_v2(
    arguments: Any, canaries: set[str]
) -> GuardResult:
    # Reject values that cannot be represented as strict JSON.
    try:
        json.dumps(
            arguments,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return GuardResult(blocked=True, reason="invalid_tool_arguments")

    def walk(value: Any) -> GuardResult:
        if isinstance(value, str):
            return inspect_text_with_base64_v2(value, canaries)

        if isinstance(value, dict):
            for key, nested_value in value.items():
                result = inspect_text_with_base64_v2(str(key), canaries)
                if result.blocked:
                    return result

                result = walk(nested_value)
                if result.blocked:
                    return result

        elif isinstance(value, list):
            for item in value:
                result = walk(item)
                if result.blocked:
                    return result

        return GuardResult(
            blocked=False,
            reason="no_registered_canary_detected",
        )

    return walk(arguments)
