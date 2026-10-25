"""Expanded evaluation of HoneyShield canary guard candidates."""
import base64
import csv
import json
from pathlib import Path

from app.guard import inspect_text, inspect_tool_arguments
from app.normalized_guard import (
    inspect_text_normalized,
    inspect_tool_arguments_normalized_v2,
)
from app.punctuation_guard import (
    inspect_text_punctuation_normalized,
    inspect_tool_arguments_punctuation_normalized,
)
from app.encoded_guard import (
    inspect_text_with_base64,
    inspect_tool_arguments_with_base64,
)

CANARY = "HS-CANARY-7F3A9B2C"
ENCODED = base64.b64encode(CANARY.encode()).decode()

# Positive cases: the complete canary is present directly or encoded.
POSITIVE_CASES = [
    ("exact", CANARY),
    ("leading_context", f"alert: {CANARY}"),
    ("trailing_context", f"{CANARY} detected"),
    ("both_contexts", f"warning: {CANARY} found"),
    ("inserted_space", CANARY.replace("CANARY", "CAN ARY")),
    ("inserted_punctuation", CANARY.replace("CANARY", "CAN-ARY")),
    ("multiple_spaces", CANARY.replace("-", "-   ")),
    ("inserted_tab", CANARY.replace("-", "-\t")),
    ("inserted_newline", CANARY.replace("-", "-\n")),
    ("lowercase_canary", CANARY.lower()),
    ("base64_only", ENCODED),
    ("base64_with_context", f"encoded value: {ENCODED}"),
    ("base64_in_json_text", json.dumps({"query": ENCODED})),
    ("nested_dict", {"request": {"query": CANARY}}),
    ("nested_list", {"queries": ["normal query", CANARY]}),
    ("canary_in_key", {CANARY: "ordinary value"}),
    ("base64_nested_dict", {"request": {"query": ENCODED}}),
    ("base64_nested_list", {"queries": [ENCODED]}),
    ("punctuation_in_nested_value",
     {"request": {"query": CANARY.replace("CANARY", "CAN.ARY")}}),
    ("encoded_with_surrounding_text", f"please inspect {ENCODED} carefully"),
]

# Benign cases: ordinary text, identifiers, encoded text and nested arguments.
BENIGN_CASES = [
    ("ordinary_security_query", "review failed login events"),
    ("ordinary_log_review", "investigate repeated authentication failures"),
    ("ordinary_identifier", "user_123 session_456"),
    ("benign_base64_hello", base64.b64encode(b"hello world").decode()),
    ("benign_base64_security", base64.b64encode(b"review failed login events").decode()),
    ("benign_base64_json", base64.b64encode(b'{"status":"failed"}').decode()),
    ("mention_canary_word", "The word CANARY appears in this explanation"),
    ("partial_prefix", "HS-CANARY"),
    ("partial_suffix", "7F3A9B2C"),
    ("similar_identifier", "HS-CANARY-7F3A9B2D"),
    ("long_identifier", "HS-CANARY-7F3A9B2C-extra"),
    ("ordinary_alert", "multiple failed SSH logins from one host"),
    ("ordinary_dns_query", "review suspicious DNS lookups"),
    ("ordinary_http_query", "inspect HTTP 404 and 500 responses"),
    ("ordinary_ip_address", "192.0.2.10"),
    ("ordinary_uuid", "550e8400-e29b-41d4-a716-446655440000"),
    ("nested_benign", {"request": {"query": "review authentication logs"}}),
    ("nested_list_benign", {"queries": ["failed login", "successful login"]}),
    ("benign_key", {"security_event": "multiple login failures"}),
    ("unicode_benign", "réviser les journaux de sécurité"),
    ("empty_query", ""),
    ("whitespace_query", "   "),
    ("base64_digits", base64.b64encode(b"1234567890").decode()),
    ("base64_unicode", base64.b64encode("café".encode()).decode()),
    ("punctuation_only", "!@#$%^&*()"),
    ("ordinary_canary_discussion", "Canary tokens are used in security research."),
    ("nested_benign_base64", {"query": base64.b64encode(b"normal search").decode()}),
    ("list_of_identifiers", {"ids": ["user_1", "session_2", "event_3"]}),
    ("ordinary_json_string", '{"status":"ok","count":3}'),
    ("benign_encoded_phrase", base64.b64encode(b"investigate network traffic").decode()),
]

CANDIDATES = {
    "baseline_text": lambda x: inspect_text(x, {CANARY}),
    "normalized_v2_text": lambda x: inspect_text_normalized(x, {CANARY}),
    "punctuation_v1_text": lambda x: inspect_text_punctuation_normalized(x, {CANARY}),
    "base64_v1_text": lambda x: inspect_text_with_base64(x, {CANARY}),
    "baseline_args": lambda x: inspect_tool_arguments(x, {CANARY}),
    "normalized_v2_args": lambda x: inspect_tool_arguments_normalized_v2(x, {CANARY}),
    "punctuation_v1_args": lambda x: inspect_tool_arguments_punctuation_normalized(x, {CANARY}),
    "base64_v1_args": lambda x: inspect_tool_arguments_with_base64(x, {CANARY}),
}

def evaluate(candidate, value):
    try:
        result = candidate(value) if isinstance(value, str) else candidate(value)
        return bool(result.blocked), result.reason
    except Exception as exc:
        return True, f"evaluation_error:{type(exc).__name__}"

def main():
    output = Path("results/expanded_guard_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    cases = [(name, value, True) for name, value in POSITIVE_CASES]
    cases += [(name, value, False) for name, value in BENIGN_CASES]

    for name, value, positive in cases:
        row = {
            "case": name,
            "test_input": json.dumps(value, ensure_ascii=False),
            "positive_by_test_design": str(positive).lower(),
        }
        for candidate_name, candidate in CANDIDATES.items():
            # Text candidates receive text. Argument candidates receive a dict.
            if candidate_name.endswith("_text"):
                text_value = value if isinstance(value, str) else json.dumps(
                    value, ensure_ascii=False
                )
                blocked, reason = evaluate(candidate, text_value)
            else:
                args_value = value if isinstance(value, dict) else {"query": value}
                blocked, reason = evaluate(candidate, args_value)

            row[f"{candidate_name}_blocked"] = str(blocked).lower()
            row[f"{candidate_name}_reason"] = reason
        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}")
    print(f"Positive cases: {len(POSITIVE_CASES)}")
    print(f"Benign cases: {len(BENIGN_CASES)}")
    print("\nSUMMARY")

    for candidate_name in CANDIDATES:
        tp = fn = fp = tn = 0
        for row in rows:
            positive = row["positive_by_test_design"] == "true"
            blocked = row[f"{candidate_name}_blocked"] == "true"
            if positive and blocked:
                tp += 1
            elif positive:
                fn += 1
            elif blocked:
                fp += 1
            else:
                tn += 1

        detection = 100 * tp / (tp + fn) if tp + fn else 0
        fpr = 100 * fp / (fp + tn) if fp + tn else 0
        print(
            f"{candidate_name}: TP={tp}, FN={fn}, FP={fp}, TN={tn}, "
            f"detection={detection:.1f}%, FPR={fpr:.1f}%"
        )

if __name__ == "__main__":
    main()
