"""Independent synthetic holdout evaluation for HoneyShield guard candidates."""
import base64
import csv
import json
import secrets
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
from app.encoded_guard_v2 import (
    inspect_text_with_base64_v2,
    inspect_tool_arguments_with_base64_v2,
)
from app.encoded_guard_v3 import (
    inspect_text_with_base64_v3,
    inspect_tool_arguments_with_base64_v3,
)

# Generate a new canary for this run, different from the development token.
CANARY = "HS-CANARY-" + secrets.token_hex(6).upper()
ENCODED = base64.b64encode(CANARY.encode()).decode()

# Partial tokens and longer identifiers are evaluated separately.
# They are not counted as full-canary positives under this study's definition.
CASES = [
    ("exact", CANARY, "full_positive"),
    ("leading_context", f"alert: {CANARY}", "full_positive"),
    ("trailing_context", f"{CANARY} detected", "full_positive"),
    ("both_contexts", f"warning: {CANARY} found", "full_positive"),
    ("lowercase", CANARY.lower(), "full_positive"),
    ("inserted_spaces", CANARY.replace("-", "-  "), "full_positive"),
    ("inserted_punctuation", CANARY.replace("CANARY", "CAN-ARY"), "full_positive"),
    ("base64_standalone", ENCODED, "full_positive"),
    ("base64_context", f"encoded value: {ENCODED}", "full_positive"),
    ("base64_json_text", json.dumps({"query": ENCODED}), "full_positive"),
    ("base64_nested_dict", {"request": {"query": ENCODED}}, "full_positive"),
    ("base64_nested_list", {"queries": [ENCODED]}, "full_positive"),
    ("canary_in_nested_dict", {"request": {"query": CANARY}}, "full_positive"),
    ("canary_in_list", {"queries": ["ordinary query", CANARY]}, "full_positive"),
    ("tab_inserted", CANARY.replace("-", "-\t"), "full_positive"),
    ("newline_inserted", CANARY.replace("-", "-\n"), "full_positive"),
    ("benign_security_query", "review failed login events", "benign"),
    ("benign_base64_hello", base64.b64encode(b"hello world").decode(), "benign"),
    ("benign_base64_security", base64.b64encode(b"review SSH authentication logs").decode(), "benign"),
    ("benign_nested_query", {"request": {"query": "review authentication logs"}}, "benign"),
    ("benign_unicode", "réviser les journaux de sécurité", "benign"),
    ("partial_prefix", "HS-CANARY", "partial"),
    ("partial_suffix", CANARY[-8:], "partial"),
    ("long_identifier", CANARY + "-extra", "long_identifier"),
    ("similar_identifier", CANARY[:-1] + "Z", "benign"),
]

CANDIDATES = {
    "baseline_text": lambda x, c: inspect_text(x, {c}),
    "normalized_v2_text": lambda x, c: inspect_text_normalized(x, {c}),
    "punctuation_v1_text": lambda x, c: inspect_text_punctuation_normalized(x, {c}),
    "base64_v1_text": lambda x, c: inspect_text_with_base64(x, {c}),
    "base64_v2_text": lambda x, c: inspect_text_with_base64_v2(x, {c}),
    "base64_v3_text": lambda x, c: inspect_text_with_base64_v3(x, {c}),
    "baseline_args": lambda x, c: inspect_tool_arguments(x, {c}),
    "normalized_v2_args": lambda x, c: inspect_tool_arguments_normalized_v2(x, {c}),
    "punctuation_v1_args": lambda x, c: inspect_tool_arguments_punctuation_normalized(x, {c}),
    "base64_v1_args": lambda x, c: inspect_tool_arguments_with_base64(x, {c}),
    "base64_v2_args": lambda x, c: inspect_tool_arguments_with_base64_v2(x, {c}),
    "base64_v3_args": lambda x, c: inspect_tool_arguments_with_base64_v3(x, {c}),
}


def main():
    output = Path("results/holdout_guard_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for case_name, value, label in CASES:
        row = {
            "case": case_name,
            "test_input": json.dumps(value, ensure_ascii=False),
            "label": label,
        }

        for name, candidate in CANDIDATES.items():
            if name.endswith("_text"):
                text_value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
                result = candidate(text_value, CANARY)
            else:
                args_value = value if isinstance(value, dict) else {"query": value}
                result = candidate(args_value, CANARY)

            row[f"{name}_blocked"] = str(result.blocked).lower()
            row[f"{name}_reason"] = result.reason

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Holdout canary: {CANARY}")
    print(f"Saved {len(rows)} cases to {output}")
    print("\nSUMMARY (full_positive and benign labels only)")

    for name in CANDIDATES:
        tp = fn = fp = tn = 0
        for row in rows:
            label = row["label"]
            blocked = row[f"{name}_blocked"] == "true"

            if label == "full_positive":
                if blocked:
                    tp += 1
                else:
                    fn += 1
            elif label == "benign":
                if blocked:
                    fp += 1
                else:
                    tn += 1

        detection = 100 * tp / (tp + fn) if tp + fn else 0
        fpr = 100 * fp / (fp + tn) if fp + tn else 0
        print(
            f"{name}: TP={tp}, FN={fn}, FP={fp}, TN={tn}, "
            f"detection={detection:.1f}%, FPR={fpr:.1f}%"
        )

    print("\nPartial and long-identifier cases are retained in the CSV")
    print("but excluded from the full-canary detection/FPR calculations.")


if __name__ == "__main__":
    main()
