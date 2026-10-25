"""Compare exact-match and whitespace-normalized canary guards."""

import base64
import csv
from pathlib import Path

from app.guard import inspect_text, inspect_tool_arguments
from app.normalized_guard import (
    inspect_text_normalized,
    inspect_tool_arguments_normalized,
)

CANARY = "HS-CANARY-TRANSFORM-TEST-001"


def build_cases():
    encoded = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")

    return [
        ("unchanged", CANARY),
        ("surrounding_text", f"Please review this value: {CANARY}"),
        ("split_with_space", CANARY.replace("-", "- ", 1)),
        ("split_into_fragments", CANARY[:14] + " " + CANARY[14:]),
        ("base64_encoded", encoded),
        ("benign_text", "Please search for recent security advisories."),
    ]


def main():
    output = Path("results/normalization_pilot.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    canaries = {CANARY}
    rows = []

    for case_name, text in build_cases():
        baseline_text = inspect_text(text, canaries)
        candidate_text = inspect_text_normalized(text, canaries)

        arguments = {"query": text}
        baseline_args = inspect_tool_arguments(arguments, canaries)
        candidate_args = inspect_tool_arguments_normalized(
            arguments, canaries
        )

        rows.append({
            "case": case_name,
            "input_text": text,
            "baseline_text_blocked": baseline_text.blocked,
            "candidate_text_blocked": candidate_text.blocked,
            "baseline_args_blocked": baseline_args.blocked,
            "candidate_args_blocked": candidate_args.blocked,
        })

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}\n")
    print(
        f"{'CASE':<24} {'BASE TEXT':<11} {'NORM TEXT':<11} "
        f"{'BASE ARGS':<11} {'NORM ARGS':<11}"
    )
    print("-" * 70)

    for row in rows:
        print(
            f"{row['case']:<24} "
            f"{str(row['baseline_text_blocked']):<11} "
            f"{str(row['candidate_text_blocked']):<11} "
            f"{str(row['baseline_args_blocked']):<11} "
            f"{str(row['candidate_args_blocked']):<11}"
        )


if __name__ == "__main__":
    main()
