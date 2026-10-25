
"""RAG assistant with optional final-response canary filtering."""

from app.assistant import answer_question
from app.encoded_guard_v3 import inspect_text_with_base64_v3


def answer_with_guard(
    question: str,
    canaries: set[str],
    output_guard_enabled: bool = True,
) -> dict:
    result = answer_question(question)
    answer = result["answer"]

    if output_guard_enabled:
        guard_result = inspect_text_with_base64_v3(answer, canaries)

        if guard_result.blocked:
            result["answer"] = (
                "[BLOCKED] The response contained a registered "
                "synthetic canary."
            )
            result["blocked"] = True
            result["block_reason"] = guard_result.reason
            return result

    result["blocked"] = False
    result["block_reason"] = None
    return result

