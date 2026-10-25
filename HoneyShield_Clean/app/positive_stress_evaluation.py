"""Positive detection stress test for HoneyShield Base64-aware guard v3."""
import base64
import csv
import json
import secrets
from pathlib import Path

from app.encoded_guard_v3 import (
    inspect_text_with_base64_v3,
    inspect_tool_arguments_with_base64_v3,
)


def main():
    canary = "HS-CANARY-" + secrets.token_hex(6).upper()
    encoded = base64.b64encode(canary.encode()).decode()

    cases = [
        ("exact", canary),
        ("lowercase", canary.lower()),
        ("leading_context", f"alert: {canary}"),
        ("trailing_context", f"{canary} detected"),
        ("both_contexts", f"warning: {canary} found"),
        ("quoted", f'"{canary}"'),
        ("parentheses", f"({canary})"),
        ("token_equals", f"token={encoded}"),
        ("token_colon", f"token: {encoded}"),
        ("base64_standalone", encoded),
        ("base64_json", json.dumps({"token": encoded})),
        ("base64_nested_json", json.dumps({"outer": {"items": [encoded]}})),
        ("base64_nested_dict", {"outer": {"token": encoded}}),
        ("base64_list", {"items": [encoded]}),
        ("canary_nested_dict", {"request": {"query": canary}}),
        ("canary_list", {"items": ["ordinary", canary]}),
        ("canary_dict_key", {canary: "value"}),
        ("punctuation_inserted", canary.replace("CANARY", "CAN-ARY")),
        ("spaces_after_hyphens", canary.replace("-", "-  ")),
        ("tabs_after_hyphens", canary.replace("-", "-\t")),
        ("newlines_after_hyphens", canary.replace("-", "-\n")),
        ("base64_context_sentence", f"encoded value: {encoded}"),
        ("base64_array_json", json.dumps(["ordinary", encoded])),
        ("base64_in_argument_string", {"query": f"token={encoded}"}),
    ]

    # Repeat structurally different JSON placements with the same fresh token.
    for i in range(1, 27):
        value = {
            "request": {
                "id": f"CASE-{i:03}",
                "filters": {"active": True, "limit": i},
                "payload": [f"ordinary item {i}", encoded if i % 2 else canary],
            }
        }
        cases.append((f"generated_nested_{i:03}", value))

    output = Path("results/positive_stress_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for name, value in cases:
        text_value = value if isinstance(value, str) else json.dumps(
            value, ensure_ascii=False
        )
        args_value = value if isinstance(value, dict) else {"query": value}

        text_result = inspect_text_with_base64_v3(text_value, {canary})
        args_result = inspect_tool_arguments_with_base64_v3(args_value, {canary})

        rows.append({
            "case": name,
            "test_input": json.dumps(value, ensure_ascii=False),
            "label": "full_positive",
            "text_blocked": str(text_result.blocked).lower(),
            "text_reason": text_result.reason,
            "args_blocked": str(args_result.blocked).lower(),
            "args_reason": args_result.reason,
        })

    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    text_tp = sum(r["text_blocked"] == "true" for r in rows)
    args_tp = sum(r["args_blocked"] == "true" for r in rows)

    print(f"Fresh canary generated: {canary}")
    print(f"Positive cases tested: {total}")
    print(f"Text detected: {text_tp}/{total} ({100 * text_tp / total:.1f}%)")
    print(f"Arguments detected: {args_tp}/{total} ({100 * args_tp / total:.1f}%)")
    print(f"Text misses: {total - text_tp}")
    print(f"Argument misses: {total - args_tp}")
    print(f"Saved results to: {output}")

    if text_tp < total or args_tp < total:
        print("\nMISSED CASES")
        for row in rows:
            if row["text_blocked"] != "true" or row["args_blocked"] != "true":
                print(
                    f'{row["case"]}: text={row["text_blocked"]}, '
                    f'args={row["args_blocked"]}'
                )


if __name__ == "__main__":
    main()
