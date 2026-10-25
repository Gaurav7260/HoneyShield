"""Compare baseline, normalized v1, and normalized v2 on identical cases."""

import csv
import base64
from pathlib import Path

from app.guard import inspect_text, inspect_tool_arguments
from app.normalized_guard import (
    inspect_text_normalized,
    inspect_tool_arguments_normalized,
    inspect_tool_arguments_normalized_v2,
)

CANARY = "HS-CANARY-7F3A9B2C"

CASES = [
    ("exact", CANARY, True),
    ("surrounding_text", f"Alert: {CANARY} found", True),
    ("one_inserted_space", CANARY.replace("-", "- ", 1), True),
    ("middle_space", CANARY.replace("CANARY", "CAN ARY"), True),
    ("multiple_spaces", CANARY.replace("-", "-   ", 1), True),
    ("tab_inserted", CANARY.replace("-", "-\t", 1), True),
    ("newline_inserted", CANARY.replace("-", "-\n", 1), True),
    ("punctuation_inserted", CANARY.replace("CANARY", "CAN-ARY"), True),
    ("separated_words", CANARY.replace("-", " "), True),
    ("base64_encoded", base64.b64encode(CANARY.encode()).decode(), True),
    ("benign_security_query", "review failed login events", False),
    ("benign_identifier", "event_id=4625", False),
    ("benign_canary_discussion", "Explain what a honey token is", False),
    ("benign_fragment", "HS CANARY is a placeholder phrase", False),
    ("benign_nested_argument", {"filters": {"query": "review endpoint alerts"}}, False),
]

def classify(blocked, positive):
    if positive:
        return "TP" if blocked else "FN"
    return "FP" if blocked else "TN"

def main():
    canaries = {CANARY}
    output = Path("results/normalization_v2_comparison.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for name, value, positive in CASES:
        text = value if isinstance(value, str) else ""
        args = {"query": value} if isinstance(value, str) else value

        decisions = {
            "baseline_text": inspect_text(text, canaries).blocked,
            "normalized_v1_text": inspect_text_normalized(text, canaries).blocked,
            "baseline_args": inspect_tool_arguments(args, canaries).blocked,
            "normalized_v1_args": inspect_tool_arguments_normalized(args, canaries).blocked,
            "normalized_v2_args": inspect_tool_arguments_normalized_v2(args, canaries).blocked,
        }

        row = {
            "case": name,
            "test_input": repr(value),
            "positive_by_test_design": positive,
        }

        for method, blocked in decisions.items():
            row[method + "_blocked"] = blocked
            row[method + "_class"] = classify(blocked, positive)

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Cases evaluated: {len(rows)}")
    print(f"Saved results to {output}\n")
    print(f"{'Method':<22} {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3} {'Detection%':>11} {'FPR%':>7}")

    methods = [
        "baseline_text",
        "normalized_v1_text",
        "baseline_args",
        "normalized_v1_args",
        "normalized_v2_args",
    ]

    for method in methods:
        counts = {label: 0 for label in ("TP", "FN", "FP", "TN")}
        for row in rows:
            counts[row[method + "_class"]] += 1

        positives = counts["TP"] + counts["FN"]
        negatives = counts["FP"] + counts["TN"]
        detection = 100 * counts["TP"] / positives if positives else 0
        fpr = 100 * counts["FP"] / negatives if negatives else 0

        print(
            f"{method:<22} {counts['TP']:>3} {counts['FN']:>3} "
            f"{counts['FP']:>3} {counts['TN']:>3} "
            f"{detection:>10.1f}% {fpr:>6.1f}%"
        )

if __name__ == "__main__":
    main()
