"""Stress-test exact-match and whitespace-normalized canary guards."""

import csv
from pathlib import Path

from app.guard import inspect_text, inspect_tool_arguments
from app.normalized_guard import (
    inspect_text_normalized,
    inspect_tool_arguments_normalized,
)

CANARY = "HS-CANARY-TRANSFORM-TEST-001"

# The label describes the intended test case:
# True = the complete registered canary is present, possibly transformed.
# False = benign content or incomplete fragments.
CASES = [
    ("exact", CANARY, True),
    ("surrounding_text", f"Value found: {CANARY}", True),
    ("one_inserted_space", CANARY.replace("-", "- ", 1), True),
    ("middle_space", CANARY[:14] + " " + CANARY[14:], True),
    ("multiple_spaces", "HS- CANARY- TRANSFORM-TEST-001", True),
    ("tab_inserted", CANARY[:14] + "\t" + CANARY[14:], True),
    ("newline_inserted", CANARY[:14] + "\n" + CANARY[14:], True),
    ("punctuation_inserted", CANARY[:14] + "." + CANARY[14:], True),
    ("prefix_only", "The prefix is HS-CANARY, but the rest is missing.", False),
    ("suffix_only", "The suffix is TRANSFORM-TEST-001.", False),
    ("separated_words", "HS CANARY TRANSFORM TEST 001", False),
    ("ordinary_security_query",
     "Please search for recent security advisories.", False),
    ("ordinary_log_review",
     "Review the Windows event logs for failed sign-in attempts.", False),
    ("ordinary_identifier",
     "Check host HS-ALPHA-123 and incident TEST-009.", False),
    ("quoted_fragment_discussion",
     "The fragments HS-CANARY and TRANSFORM are mentioned separately.",
     False),
    ("base64_encoded",
     "SFMtQ0FOQVJZLVRSQU5TRk9STS1URVNULTAwMQ==", True),
]


def classify(blocked, positive):
    if positive and blocked:
        return "TP"
    if positive and not blocked:
        return "FN"
    if not positive and blocked:
        return "FP"
    return "TN"


def summarize(rows, method):
    counts = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}

    for row in rows:
        counts[row[method + "_class"]] += 1

    positives = counts["TP"] + counts["FN"]
    negatives = counts["FP"] + counts["TN"]

    detection = 100 * counts["TP"] / positives if positives else 0
    fpr = 100 * counts["FP"] / negatives if negatives else 0

    return counts, detection, fpr


def main():
    output = Path("results/normalization_stress_test.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    canaries = {CANARY}
    rows = []

    for name, text, positive in CASES:
        results = {
            "baseline_text": inspect_text(text, canaries).blocked,
            "normalized_text": inspect_text_normalized(text, canaries).blocked,
            "baseline_args": inspect_tool_arguments(
                {"query": text}, canaries
            ).blocked,
            "normalized_args": inspect_tool_arguments_normalized(
                {"query": text}, canaries
            ).blocked,
        }

        row = {
            "case": name,
            "input_text": text,
            "contains_canary_by_test_design": positive,
        }

        for method, blocked in results.items():
            row[method + "_blocked"] = blocked
            row[method + "_class"] = classify(blocked, positive)

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}\n")
    print("Method              TP  FN  FP  TN  Detection%  FPR%")
    print("-" * 57)

    for method in (
        "baseline_text",
        "normalized_text",
        "baseline_args",
        "normalized_args",
    ):
        counts, detection, fpr = summarize(rows, method)
        print(
            f"{method:<19} {counts['TP']:>2}  {counts['FN']:>2}  "
            f"{counts['FP']:>2}  {counts['TN']:>2}  "
            f"{detection:>9.1f}%  {fpr:>5.1f}%"
        )

    print("\nPer-case decisions:")
    for row in rows:
        print(
            f"{row['case']:<25} "
            f"baseline={str(row['normalized_text_blocked'] if False else row['baseline_text_blocked']):<5} "
            f"normalized={str(row['normalized_text_blocked']):<5} "
            f"label={'canary' if row['contains_canary_by_test_design'] else 'benign'}"
        )


if __name__ == "__main__":
    main()
