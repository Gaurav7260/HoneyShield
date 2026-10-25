"""Experimental canary guard with bounded Base64 decoding and token checks."""
import base64
import binascii
import json
import re
from typing import Any

from app.punctuation_guard import GuardResult, normalize_alphanumeric


def inspect_normalized_text(text: str, canaries: set[str]) -> GuardResult:
    for canary in canaries:
        compact = normalize_alphanumeric(canary)
        if not compact:
            continue

        # Allow separators between canary characters, but not letters or
        # digits inserted between them.
        pattern = r"(?<![A-Za-z0-9])" + r"[^A-Za-z0-9]*".join(
            re.escape(ch) for ch in compact
        ) + r"(?![A-Za-z0-9])"

        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            end = match.end()

            # Do not treat a canary followed by "-suffix" as a complete
            # standalone token for this evaluation policy.
            if end < len(text) and text[end] == "-":
                suffix = re.match(r"-[A-Za-z0-9]+", text[end:])
                if suffix:
                    continue

            return GuardResult(
                blocked=True,
                reason="registered_canary_detected_after_case_and_separator_normalization",
            )

    return GuardResult(blocked=False, reason="no_registered_canary_detected")


def inspect_text_with_base64_v3(text: str, canaries: set[str]) -> GuardResult:
    direct = inspect_normalized_text(text, canaries)
    if direct.blocked:
        return direct

    tokens = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])",
        text,
    )

    for token in tokens:
        if len(token) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        result = inspect_normalized_text(decoded, canaries)
        if result.blocked:
            return GuardResult(
                blocked=True,
                reason="registered_canary_detected_after_base64_decoding",
            )

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        parsed = None

    if parsed is not None:
        result = inspect_tool_arguments_with_base64_v3(parsed, canaries)
        if result.blocked:
            return result

    return GuardResult(blocked=False, reason="no_registered_canary_detected")


def inspect_tool_arguments_with_base64_v3(
    arguments: Any, canaries: set[str]
) -> GuardResult:
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
            return inspect_text_with_base64_v3(value, canaries)

        if isinstance(value, dict):
            for key, nested_value in value.items():
                result = inspect_text_with_base64_v3(str(key), canaries)
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
