"""Experimental canary guard with bounded Base64 decoding."""

import base64
import binascii
import json
from typing import Any

from app.punctuation_guard import (
    GuardResult,
    inspect_text_punctuation_normalized,
)


def inspect_text_with_base64(
    text: str, canaries: set[str]
) -> GuardResult:
    # First inspect the original text using punctuation normalization.
    result = inspect_text_punctuation_normalized(text, canaries)
    if result.blocked:
        return result

    # Then try decoding whitespace-delimited tokens as strict Base64.
    for token in text.split():
        if not token or len(token) % 4 != 0:
            continue

        try:
            decoded_bytes = base64.b64decode(token, validate=True)
            decoded_text = decoded_bytes.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        result = inspect_text_punctuation_normalized(decoded_text, canaries)
        if result.blocked:
            return GuardResult(
                blocked=True,
                reason="registered_canary_detected_after_base64_decoding",
            )

    return GuardResult(
        blocked=False,
        reason="no_registered_canary_detected",
    )


def inspect_tool_arguments_with_base64(
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
            return inspect_text_with_base64(value, canaries)

        if isinstance(value, dict):
            for key, nested_value in value.items():
                result = inspect_text_with_base64(str(key), canaries)
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
