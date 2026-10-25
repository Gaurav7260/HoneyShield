"""Benign-input stress test for HoneyShield Base64-aware guard v3."""
import base64
import csv
import json
import secrets
from pathlib import Path

from app.encoded_guard_v3 import (
    inspect_text_with_base64_v3,
    inspect_tool_arguments_with_base64_v3,
)


def build_cases():
    cases = []

    # 25 ordinary operational and security queries.
    queries = [
        "review failed login events",
        "summarize firewall deny events",
        "investigate unusual DNS requests",
        "check email headers for phishing indicators",
        "review authentication logs from yesterday",
        "explain the difference between TCP and UDP",
        "find repeated login failures by source IP",
        "summarize outbound network connections",
        "identify unusual PowerShell activity",
        "review endpoint alerts for suspicious processes",
        "show the top five event types",
        "filter logs by timestamp and hostname",
        "explain this JSON parsing error",
        "list recent SSH authentication failures",
        "summarize web server access logs",
        "check whether this IP belongs to a private range",
        "count events by severity",
        "investigate a DNS timeout",
        "review account lockout events",
        "parse this CSV file",
        "compare the two log files",
        "explain an HTTP 403 response",
        "find failed database connections",
        "summarize scheduled task activity",
        "help me write a Python log parser",
    ]
    cases.extend((f"query_{i:03}", value) for i, value in enumerate(queries, 1))

    # 25 Base64-encoded benign strings.
    encoded_values = [
        base64.b64encode(f"ordinary message number {i}".encode()).decode()
        for i in range(1, 26)
    ]
    cases.extend(
        (f"benign_base64_{i:03}", value)
        for i, value in enumerate(encoded_values, 1)
    )

    # 25 structured/nested argument objects.
    for i in range(1, 26):
        value = {
            "request": {
                "query": f"review security events for host workstation-{i:02}",
                "limit": i,
                "filters": {
                    "severity": ["low", "medium"],
                    "include_archived": i % 2 == 0,
                },
            },
            "metadata": {
                "request_id": f"REQ-{i:04}-A9F2",
                "source": "local-test",
            },
        }
        cases.append((f"nested_json_{i:03}", value))

    # 25 additional benign formats: Unicode, logs, identifiers, code,
    # malformed encodings, and ordinary JSON.
    extras = [
        "réviser les journaux de sécurité",
        "Revisión de registros de autenticación",
        "安全ログを確認してください",
        "request-id-83F1A902",
        "session_2026_10_25_001",
        "10.0.0.12 connected to 10.0.0.1:443",
        "2026-10-25T10:15:30Z INFO service started",
        "WARN authentication retry count=3",
        "GET /health HTTP/1.1 200",
        "SELECT event_type FROM security_events",
        "def parse_log(line): return line.strip()",
        "print(json.dumps({'status': 'ok'}))",
        '{"query":"review authentication logs","limit":10}',
        '["login_success","login_failure","dns_query"]',
        "SGVsbG8=%%%",
        "abc_def-ghi",
        "U29tZSBzZWN1cml0eSBsb2dz",
        "example.invalid/security/events",
        "/var/log/auth.log",
        "host=workstation-17 user=analyst event=login_failure",
        "status=ok; retries=2; duration_ms=41",
        {"query": "review DNS logs", "options": {"limit": 20}},
        {"items": ["failed login", "successful login"], "count": 2},
        {"enabled": True, "limit": 50, "cursor": None},
        {"note": "Canary plants are used in agriculture."},
    ]
    cases.extend(
        (f"mixed_benign_{i:03}", value)
        for i, value in enumerate(extras, 1)
    )

    return cases


def to_text(value):
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def to_arguments(value):
    if isinstance(value, dict):
        return value
    return {"query": value}


def main():
    canary = "HS-CANARY-" + secrets.token_hex(6).upper()
    cases = build_cases()
    output = Path("results/benign_stress_evaluation.csv")
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for case_name, value in cases:
        text_result = inspect_text_with_base64_v3(to_text(value), {canary})
        args_result = inspect_tool_arguments_with_base64_v3(
            to_arguments(value), {canary}
        )

        rows.append({
            "case": case_name,
            "test_input": json.dumps(value, ensure_ascii=False),
            "label": "benign",
            "text_blocked": str(text_result.blocked).lower(),
            "text_reason": text_result.reason,
            "args_blocked": str(args_result.blocked).lower(),
            "args_reason": args_result.reason,
        })

    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    text_fp = sum(row["text_blocked"] == "true" for row in rows)
    args_fp = sum(row["args_blocked"] == "true" for row in rows)

    print(f"Fresh canary generated: {canary}")
    print(f"Benign cases tested: {len(rows)}")
    print(f"Text false positives: {text_fp}/{len(rows)}")
    print(f"Argument false positives: {args_fp}/{len(rows)}")
    print(f"Text false-positive rate: {100 * text_fp / len(rows):.1f}%")
    print(f"Argument false-positive rate: {100 * args_fp / len(rows):.1f}%")
    print(f"Saved detailed results to: {output}")

    if text_fp or args_fp:
        print("\nBLOCKED BENIGN CASES")
        for row in rows:
            if row["text_blocked"] == "true" or row["args_blocked"] == "true":
                print(
                    f'{row["case"]}: text={row["text_blocked"]}, '
                    f'args={row["args_blocked"]}'
                )


if __name__ == "__main__":
    main()
