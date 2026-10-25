"""Compare v1, v2 and v3 on the same expanded synthetic test set."""
import csv
import json
from pathlib import Path

from app.expanded_guard_evaluation import (
    POSITIVE_CASES,
    BENIGN_CASES,
    CANDIDATES,
)
from app.encoded_guard_v2 import (
    inspect_text_with_base64_v2,
    inspect_tool_arguments_with_base64_v2,
)
from app.encoded_guard_v3 import (
    inspect_text_with_base64_v3,
    inspect_tool_arguments_with_base64_v3,
)

CANARIES = {"HS-CANARY-7F3A9B2C"}

EXTRA_CANDIDATES = {
    "base64_v2_text": lambda x: inspect_text_with_base64_v2(x, CANARIES),
    "base64_v2_args": lambda x: inspect_tool_arguments_with_base64_v2(x, CANARIES),
    "base64_v3_text": lambda x: inspect_text_with_base64_v3(x, CANARIES),
    "base64_v3_args": lambda x: inspect_tool_arguments_with_base64_v3(x, CANARIES),
}

ALL_CANDIDATES = {**CANDIDATES, **EXTRA_CANDIDATES}


def main():
    output = Path("results/encoded_guard_v3_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)

    cases = (
        [(name, value, True) for name, value in POSITIVE_CASES]
        + [(name, value, False) for name, value in BENIGN_CASES]
    )
    rows = []

    for case_name, value, positive in cases:
        row = {
            "case": case_name,
            "test_input": json.dumps(value, ensure_ascii=False),
            "positive_by_test_design": str(positive).lower(),
        }

        for name, candidate in ALL_CANDIDATES.items():
            if name.endswith("_text"):
                text_value = (
                    value if isinstance(value, str)
                    else json.dumps(value, ensure_ascii=False)
                )
                result = candidate(text_value)
            else:
                args_value = value if isinstance(value, dict) else {"query": value}
                result = candidate(args_value)

            row[f"{name}_blocked"] = str(result.blocked).lower()
            row[f"{name}_reason"] = result.reason

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} cases to {output}")
    print(f"Positive cases: {len(POSITIVE_CASES)}")
    print(f"Benign cases: {len(BENIGN_CASES)}")
    print("\nSUMMARY")

    for name in ALL_CANDIDATES:
        tp = fn = fp = tn = 0

        for row in rows:
            positive = row["positive_by_test_design"] == "true"
            blocked = row[f"{name}_blocked"] == "true"

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
            f"{name}: TP={tp}, FN={fn}, FP={fp}, TN={tn}, "
            f"detection={detection:.1f}%, FPR={fpr:.1f}%"
        )


if __name__ == "__main__":
    main()
