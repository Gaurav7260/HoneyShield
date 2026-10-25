"""Compare exact, serialized-normalized, and recursive-normalized checks."""

import csv
from pathlib import Path

from app.guard import inspect_tool_arguments
from app.normalized_guard import (
    inspect_tool_arguments_normalized,
    inspect_tool_arguments_normalized_v2,
)

CANARY = "HS-CANARY-TRANSFORM-TEST-001"

CASES = [
    ("exact", CANARY, True),
    ("space_inserted", CANARY[:14] + " " + CANARY[14:], True),
    ("tab_inserted", CANARY[:14] + "\t" + CANARY[14:], True),
    ("newline_inserted", CANARY[:14] + "\n" + CANARY[14:], True),
    ("punctuation_inserted", CANARY[:14] + "." + CANARY[14:], True),
    ("base64_encoded", "SFMtQ0FOQVJZLVRSQU5TRk9STS1URVNULTAwMQ==", True),
    ("benign_query", "Review failed sign-in events.", False),
    ("benign_fragments", "HS CANARY TRANSFORM TEST 001", False),
]

def classify(blocked, positive):
    if positive and blocked:
        return "TP"
    if positive:
        return "FN"
    if blocked:
        return "FP"
    return "TN"

def main():
    canaries = {CANARY}
    output = Path("results/tool_args_v2_pilot.csv")
    rows = []

    for name, query, positive in CASES:
        args = {"query": query}
        decisions = {
            "baseline": inspect_tool_arguments(args, canaries).blocked,
            "normalized_v1": inspect_tool_arguments_normalized(
                args, canaries
            ).blocked,
            "normalized_v2": inspect_tool_arguments_normalized_v2(
                args, canaries
            ).blocked,
        }

        row = {
            "case": name,
            "query": query,
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

    print(f"Saved results to {output}")
    print("\nMethod          TP FN FP TN Detection% FPR%")

    for method in ("baseline", "normalized_v1", "normalized_v2"):
        counts = {key: 0 for key in ("TP", "FN", "FP", "TN")}
        for row in rows:
            counts[row[method + "_class"]] += 1

        positives = counts["TP"] + counts["FN"]
        negatives = counts["FP"] + counts["TN"]
        detection = 100 * counts["TP"] / positives
        fpr = 100 * counts["FP"] / negatives

        print(
            f"{method:<15} {counts['TP']:>2} {counts['FN']:>2} "
            f"{counts['FP']:>2} {counts['TN']:>2} "
            f"{detection:>8.1f}% {fpr:>5.1f}%"
        )

if __name__ == "__main__":
    main()
