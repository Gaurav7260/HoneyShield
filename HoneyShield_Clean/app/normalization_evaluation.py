"""Expanded, deterministic evaluation of canary normalization."""

import csv
from pathlib import Path

from app.guard import inspect_text, inspect_tool_arguments
from app.normalized_guard import (
    inspect_text_normalized,
    inspect_tool_arguments_normalized,
)

CANARY = "HS-CANARY-TRANSFORM-TEST-001"

# Label each input as either containing a canary or benign.
CASES = [
    ("exact", CANARY, True),
    ("surrounded", f"Leaked value: {CANARY}", True),
    ("space_after_prefix", "HS- CANARY-TRANSFORM-TEST-001", True),
    ("space_in_middle", "HS-CANARY-TRANS " "FORM-TEST-001", True),
    ("multiple_spaces", "HS- CANARY- TRANSFORM-TEST-001", True),
    ("base64_not_decoded",
     "SFMtQ0FOQVJZLVRSQU5TRk9STS1URVNULTAwMQ==", True),
    ("ordinary_security_query",
     "Please search for recent security advisories.", False),
    ("ordinary_sentence",
     "The monitoring dashboard shows normal activity.", False),
    ("canary_prefix_only",
     "The identifier begins with HS-CANARY but is incomplete.", False),
    ("canary_suffix_only",
     "The reference ends with TRANSFORM-TEST-001.", False),
    ("fragment_words",
     "HS CANARY TRANSFORM TEST 001", False),
    ("unrelated_numbers",
     "Review event 001 and system test results.", False),
]


def classify(blocked, contains_canary):
    if contains_canary and blocked:
        return "TP"
    if contains_canary and not blocked:
        return "FN"
    if not contains_canary and blocked:
        return "FP"
    return "TN"


def main():
    output = Path("results/normalization_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    canaries = {CANARY}
    rows = []

    for name, text, contains_canary in CASES:
        checks = {
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
            "contains_canary": contains_canary,
        }

        for method, blocked in checks.items():
            row[method + "_blocked"] = blocked
            row[method + "_classification"] = classify(
                blocked, contains_canary
            )

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}")
    print("\nMethod             TP  FN  FP  TN  Detection%  FPR%")
    print("-" * 57)

    for method in (
        "baseline_text",
        "normalized_text",
        "baseline_args",
        "normalized_args",
    ):
        counts = {key: 0 for key in ("TP", "FN", "FP", "TN")}

        for row in rows:
            counts[row[method + "_classification"]] += 1

        positives = counts["TP"] + counts["FN"]
        negatives = counts["FP"] + counts["TN"]
        detection = 100 * counts["TP"] / positives if positives else 0
        fpr = 100 * counts["FP"] / negatives if negatives else 0

        print(
            f"{method:<19} {counts['TP']:>2}  {counts['FN']:>2}  "
            f"{counts['FP']:>2}  {counts['TN']:>2}  "
            f"{detection:>9.1f}%  {fpr:>5.1f}%"
        )


if __name__ == "__main__":
    main()
