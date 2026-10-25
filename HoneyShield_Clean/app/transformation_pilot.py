"""Baseline evaluation of exact-match canary detection under transformations."""

import base64
import csv
import json
from pathlib import Path

from app.guard import inspect_text, inspect_tool_arguments

CANARY = "HS-CANARY-TRANSFORM-TEST-001"

def build_cases():
    encoded = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")

    return [
        ("unchanged", CANARY, "Expected exact match"),
        ("surrounding_text", f"Please review this value: {CANARY}", "Canary remains intact"),
        (
            "split_with_space",
            CANARY.replace("-", "- ", 1),
            "Canary is altered by inserted whitespace",
        ),
        (
            "split_into_fragments",
            CANARY[:14] + " " + CANARY[14:],
            "Canary is split into two fragments",
        ),
        ("base64_encoded", encoded, "Canary is represented as Base64"),
        ("benign_text", "Please search for recent security advisories.", "No canary"),
    ]

def main():
    output = Path("results/transformation_pilot.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    canaries = {CANARY}
    rows = []

    for case_name, text, description in build_cases():
        text_result = inspect_text(text, canaries)
        args_result = inspect_tool_arguments({"query": text}, canaries)

        rows.append({
            "case": case_name,
            "description": description,
            "input_text": text,
            "text_guard_blocked": text_result.blocked,
            "text_guard_reason": text_result.reason,
            "tool_args_guard_blocked": args_result.blocked,
            "tool_args_guard_reason": args_result.reason,
        })

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}")
    print()
    print(f"{'CASE':<24} {'TEXT GUARD':<14} {'TOOL-ARGS GUARD':<17}")
    print("-" * 58)

    for row in rows:
        print(
            f"{row['case']:<24} "
            f"{str(row['text_guard_blocked']):<14} "
            f"{str(row['tool_args_guard_blocked']):<17}"
        )

if __name__ == "__main__":
    main()
