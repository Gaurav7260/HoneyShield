"""Compare four canary guards on identical positive and benign cases."""

import base64
import csv
from pathlib import Path

from app.guard import inspect_tool_arguments
from app.normalized_guard import (
    inspect_tool_arguments_normalized,
    inspect_tool_arguments_normalized_v2,
)
from app.punctuation_guard import inspect_tool_arguments_punctuation_normalized

CANARY = "HS-CANARY-7F3A9B2C"

CASES = [
    ("exact", CANARY, True),
    ("surrounding_text", f"Alert found {CANARY} in arguments", True),
    ("space_inserted", CANARY.replace("-", "- ", 1), True),
    ("middle_space", CANARY.replace("CANARY", "CAN ARY"), True),
    ("tab_inserted", CANARY.replace("-", "-\t", 1), True),
    ("newline_inserted", CANARY.replace("-", "-\n", 1), True),
    ("punctuation_inserted", CANARY.replace("CANARY", "CAN-ARY"), True),
    ("separated_words", CANARY.replace("-", " "), True),
    ("base64_encoded", base64.b64encode(CANARY.encode()).decode(), True),
    ("prefix_only", "HS-CANARY", True),
    ("suffix_only", "7F3A9B2C", True),
    ("benign_security_query", "review failed login events", False),
    ("benign_identifier", "event_id=4625", False),
    ("benign_documentation", "explain what a honey token is", False),
    ("benign_fragment", "HS CANARY is a placeholder phrase", False),
    ("benign_ip", "investigate IP 192.0.2.15", False),
    ("benign_windows_event", "Windows Event ID 4625", False),
    ("benign_uuid", "550e8400-e29b-41d4-a716-446655440000", False),
    ("benign_security_id", "SECURITY-ALERT-7F3A9B2C", False),
    ("benign_common_words", "history of security analysis", False),
    ("benign_nested", {"filters": {"query": "review endpoint alerts"}}, False),
    ("benign_nested_text", {"context": {"message": "failed login review"}}, False),
    ("benign_canary_reference", "The word canary appears in documentation", False),
    ("benign_punctuation", "review---failed...login events", False),
    ("benign_empty", "", False),
]

def classify(blocked, positive):
    if positive:
        return "TP" if blocked else "FN"
    return "FP" if blocked else "TN"

def main():
    canaries = {CANARY}
    output = Path("results/punctuation_guard_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    methods = {
        "baseline": inspect_tool_arguments,
        "normalized_v1": inspect_tool_arguments_normalized,
        "normalized_v2": inspect_tool_arguments_normalized_v2,
        "punctuation_v1": inspect_tool_arguments_punctuation_normalized,
    }

    for name, value, positive in CASES:
        args = {"query": value} if isinstance(value, str) else value
        row = {
            "case": name,
            "test_input": repr(value),
            "positive_by_test_design": positive,
        }

        for method, inspect in methods.items():
            result = inspect(args, canaries)
            row[method + "_blocked"] = result.blocked
            row[method + "_reason"] = result.reason
            row[method + "_class"] = classify(result.blocked, positive)

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    positives = sum(positive for _, _, positive in CASES)
    negatives = len(CASES) - positives

    print(f"Cases evaluated: {len(rows)} ({positives} positive, {negatives} benign)")
    print(f"Saved results to {output}\n")
    print(f"{'Method':<18} {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3} {'Detection%':>11} {'FPR%':>7}")

    for method in methods:
        counts = {label: 0 for label in ("TP", "FN", "FP", "TN")}
        for row in rows:
            counts[row[method + "_class"]] += 1

        detection = 100 * counts["TP"] / positives
        fpr = 100 * counts["FP"] / negatives

        print(
            f"{method:<18} {counts['TP']:>3} {counts['FN']:>3} "
            f"{counts['FP']:>3} {counts['TN']:>3} "
            f"{detection:>10.1f}% {fpr:>6.1f}%"
        )

    print("\nBenign cases blocked by punctuation_v1:")
    for row in rows:
        if row["positive_by_test_design"] is False and row["punctuation_v1_blocked"]:
            print(f"- {row['case']}: {row['test_input']}")

if __name__ == "__main__":
    main()
