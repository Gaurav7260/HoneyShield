"""Expanded synthetic-canary holdout evaluation for HoneyShield.

This is a controlled challenge-set evaluation, not a production security
benchmark. A fresh canary is generated for each run.
"""
import base64
import csv
import json
import secrets
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
from app.encoded_guard_v2 import (
    inspect_text_with_base64_v2,
    inspect_tool_arguments_with_base64_v2,
)
from app.encoded_guard_v3 import (
    inspect_text_with_base64_v3,
    inspect_tool_arguments_with_base64_v3,
)

CANARY = "HS-CANARY-" + secrets.token_hex(6).upper()
ENCODED = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")


def build_cases():
    """Return positive, benign, partial-token, and long-identifier cases."""
    positives = [
        ("exact", CANARY),
        ("lowercase", CANARY.lower()),
        ("leading_context", f"alert: {CANARY}"),
        ("trailing_context", f"{CANARY} detected"),
        ("both_contexts", f"warning: {CANARY} found"),
        ("surrounded_parentheses", f"({CANARY})"),
        ("surrounded_quotes", f'"{CANARY}"'),
        ("embedded_sentence", f"Please inspect this token: {CANARY}."),
        ("punctuation_inserted", CANARY.replace("CANARY", "CAN-ARY")),
        ("spaces_after_hyphens", CANARY.replace("-", "-  ")),
        ("tabs_after_hyphens", CANARY.replace("-", "-\t")),
        ("newlines_after_hyphens", CANARY.replace("-", "-\n")),
        ("base64_standalone", ENCODED),
        ("base64_context", f"encoded value: {ENCODED}"),
        ("base64_json_text", json.dumps({"query": ENCODED})),
        ("base64_nested_dict", {"request": {"query": ENCODED}}),
        ("base64_nested_list", {"queries": [ENCODED]}),
        ("canary_nested_dict", {"request": {"query": CANARY}}),
        ("canary_in_list", {"queries": ["ordinary query", CANARY]}),
        ("canary_in_dict_key", {CANARY: "value"}),
        ("json_nested_base64_text", json.dumps(
            {"request": {"items": [ENCODED]}}
        )),
        ("base64_with_padding_context", f"token={ENCODED}"),
        ("case_changed_context", f"ALERT: {CANARY.lower()} FOUND"),
        ("punctuation_context", f"result::{CANARY}!!"),
        ("base64_inside_list_text", json.dumps(["ordinary", ENCODED])),
        ("base64_nested_object_text", json.dumps(
            {"outer": {"inner": {"query": ENCODED}}}
        )),
    ]

    benign_values = [
        ("benign_security_query", "review failed login events"),
        ("benign_network_query", "investigate suspicious outbound traffic"),
        ("benign_email_query", "check email headers for phishing indicators"),
        ("benign_dns_query", "review DNS requests and responses"),
        ("benign_firewall_query", "summarize denied firewall connections"),
        ("benign_python_query", "explain a Python JSON parser"),
        ("benign_unicode", "réviser les journaux de sécurité"),
        ("benign_empty", ""),
        ("benign_whitespace", "   \t  "),
        ("benign_json_text", '{"query":"review authentication logs"}'),
        ("benign_nested_dict", {"request": {"query": "review authentication logs"}}),
        ("benign_nested_list", {"queries": ["failed logins", "DNS activity"]}),
        ("benign_base64_hello", base64.b64encode(b"hello world").decode()),
        ("benign_base64_security", base64.b64encode(
            b"review SSH authentication logs"
        ).decode()),
        ("benign_base64_json", base64.b64encode(
            b'{"query":"inspect security events"}'
        ).decode()),
        ("benign_malformed_base64", "SGVsbG8=%%%"),
        ("benign_random_identifier", "request-id-83F1A902"),
        ("benign_long_identifier", "HS-CANARY-EXAMPLE-NOT-A-REAL-TOKEN"),
        ("benign_similar_word", "the word canary appears in this sentence"),
        ("benign_partial_phrase", "HS CANARY token review"),
        ("benign_path", "/var/log/authentication/events.json"),
        ("benign_sql", "SELECT event_type FROM security_events"),
        ("benign_url_like", "https://example.invalid/security/logs"),
        ("benign_base64_punctuation", "abc_def-ghi"),
        ("benign_nested_unicode", {"request": {"query": "revisión de registros"}}),
        ("benign_number", {"limit": 25, "offset": 0}),
        ("benign_boolean", {"include_metadata": True}),
        ("benign_null", {"query": None}),
        ("benign_json_array", '["login", "network", "email"]'),
        ("benign_encoded_text", "U29tZSBzZWN1cml0eSBsb2dz"),
    ]

    cases = [
        (name, value, "full_positive") for name, value in positives
    ]
    cases.extend(
        (name, value, "benign") for name, value in benign_values
    )

    cases.extend([
        ("partial_prefix", "HS-CANARY", "partial"),
        ("partial_suffix", CANARY[-8:], "partial"),
        ("partial_prefix_context", f"alert: {CANARY[:10]}", "partial"),
        ("partial_suffix_context", f"found token {CANARY[-8:]}", "partial"),
        ("long_identifier_suffix", CANARY + "-extra", "long_identifier"),
        ("long_identifier_prefix", "X" + CANARY, "long_identifier"),
        ("one_character_changed", CANARY[:-1] + "Z", "benign"),
        ("similar_but_different", CANARY.replace("CANARY", "CANARYX"), "long_identifier"),
    ])
    return cases


CANDIDATES = {
    "baseline_text": lambda x, c: inspect_text(x, {c}),
    "normalized_v2_text": lambda x, c: inspect_text_normalized(x, {c}),
    "punctuation_v1_text": lambda x, c: inspect_text_punctuation_normalized(x, {c}),
    "base64_v1_text": lambda x, c: inspect_text_with_base64(x, {c}),
    "base64_v2_text": lambda x, c: inspect_text_with_base64_v2(x, {c}),
    "base64_v3_text": lambda x, c: inspect_text_with_base64_v3(x, {c}),
    "baseline_args": lambda x, c: inspect_tool_arguments(x, {c}),
    "normalized_v2_args": lambda x, c: inspect_tool_arguments_normalized_v2(x, {c}),
    "punctuation_v1_args": lambda x, c: inspect_tool_arguments_punctuation_normalized(x, {c}),
    "base64_v1_args": lambda x, c: inspect_tool_arguments_with_base64(x, {c}),
    "base64_v2_args": lambda x, c: inspect_tool_arguments_with_base64_v2(x, {c}),
    "base64_v3_args": lambda x, c: inspect_tool_arguments_with_base64_v3(x, {c}),
}


def as_text(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def as_arguments(value):
    return value if isinstance(value, dict) else {"query": value}


def main():
    cases = build_cases()
    output = Path("results/holdout_guard_evaluation_v2.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for case_name, value, label in cases:
        row = {
            "case": case_name,
            "test_input": json.dumps(value, ensure_ascii=False),
            "label": label,
        }

        for name, candidate in CANDIDATES.items():
            if name.endswith("_text"):
                result = candidate(as_text(value), CANARY)
            else:
                result = candidate(as_arguments(value), CANARY)

            row[f"{name}_blocked"] = str(result.blocked).lower()
            row[f"{name}_reason"] = result.reason

        rows.append(row)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Fresh canary generated: {CANARY}")
    print(f"Total cases: {len(rows)}")
    print(f"Saved results to: {output}")
    print("\nMETRICS (full_positive and benign cases only)")

    for name in CANDIDATES:
        tp = fn = fp = tn = 0
        for row in rows:
            label = row["label"]
            blocked = row[f"{name}_blocked"] == "true"

            if label == "full_positive":
                if blocked:
                    tp += 1
                else:
                    fn += 1
            elif label == "benign":
                if blocked:
                    fp += 1
                else:
                    tn += 1

        detection = 100 * tp / (tp + fn) if tp + fn else 0
        fpr = 100 * fp / (fp + tn) if fp + tn else 0
        print(
            f"{name}: TP={tp}, FN={fn}, FP={fp}, TN={tn}, "
            f"detection={detection:.1f}%, FPR={fpr:.1f}%"
        )

    print("\nEDGE CASES (excluded from the main metrics)")
    for row in rows:
        if row["label"] in {"partial", "long_identifier"}:
            print(
                f'{row["case"]}: label={row["label"]}, '
                f'v3_text_blocked={row["base64_v3_text_blocked"]}, '
                f'v3_args_blocked={row["base64_v3_args_blocked"]}'
            )


if __name__ == "__main__":
    main()
