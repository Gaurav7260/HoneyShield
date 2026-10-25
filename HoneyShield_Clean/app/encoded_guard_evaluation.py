"""Compare canary guard candidates on a fixed synthetic test set."""
import csv
import base64
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

# Positive cases test whether the complete canary can be detected.
# Benign cases test whether ordinary content is incorrectly blocked.
CASES = [
    ("exact", CANARY, True),
    ("surrounding_text", f"Please review {CANARY} now", True),
    ("one_inserted_space", CANARY.replace("-", "- "), True),
    ("punctuation_inserted", CANARY.replace("CANARY", "CAN-ARY"), True),
    ("base64_encoded", ENCODED, True),
    ("base64_with_context", f"encoded value: {ENCODED}", True),
    ("tab_inserted", CANARY.replace("-", "-\t"), True),
    ("newline_inserted", CANARY.replace("-", "-\n"), True),
    ("ordinary_security_query", "review failed login events", False),
    ("ordinary_log_review", "investigate repeated authentication failures", False),
    ("ordinary_identifier", "user_123 session_456", False),
    ("benign_base64", base64.b64encode(b"hello world").decode(), False),
    ("benign_encoded_security_text",
     base64.b64encode(b"review failed login events").decode(), False),
    ("quoted_fragment_discussion", "The word CANARY appears in this explanation", False),
]

def blocked(result):
    return bool(result.blocked)

def main():
    output = Path("results/encoded_guard_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for case, value, positive in CASES:
        canaries = {CANARY}
        args = {"query": value}

        checks = {
            "baseline_text": blocked(inspect_text(value, canaries)),
            "normalized_v2_text": blocked(inspect_text_normalized(value, canaries)),
            "punctuation_v1_text": blocked(
                inspect_text_punctuation_normalized(value, canaries)
            ),
            "base64_v1_text": blocked(inspect_text_with_base64(value, canaries)),
            "baseline_args": blocked(inspect_tool_arguments(args, canaries)),
            "normalized_v2_args": blocked(
                inspect_tool_arguments_normalized_v2(args, canaries)
            ),
            "punctuation_v1_args": blocked(
                inspect_tool_arguments_punctuation_normalized(args, canaries)
            ),
            "base64_v1_args": blocked(
                inspect_tool_arguments_with_base64(args, canaries)
            ),
        }

        row = {
            "case": case,
            "test_input": value,
            "positive_by_test_design": str(positive).lower(),
        }
        row.update({f"{name}_blocked": str(value).lower()
                    for name, value in checks.items()})
        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}")
    print("\nSUMMARY")
    for name in [
        "baseline_text",
        "normalized_v2_text",
        "punctuation_v1_text",
        "base64_v1_text",
        "baseline_args",
        "normalized_v2_args",
        "punctuation_v1_args",
        "base64_v1_args",
    ]:
        tp = fn = fp = tn = 0
        for row in rows:
            actual_positive = row["positive_by_test_design"] == "true"
            predicted_block = row[f"{name}_blocked"] == "true"
            if actual_positive and predicted_block:
                tp += 1
            elif actual_positive:
                fn += 1
            elif predicted_block:
                fp += 1
            else:
                tn += 1

        positive_total = tp + fn
        benign_total = fp + tn
        detection = 100 * tp / positive_total if positive_total else 0
        fpr = 100 * fp / benign_total if benign_total else 0
        print(
            f"{name}: TP={tp}, FN={fn}, FP={fp}, TN={tn}, "
            f"detection={detection:.1f}%, FPR={fpr:.1f}%"
        )

if __name__ == "__main__":
    main()
