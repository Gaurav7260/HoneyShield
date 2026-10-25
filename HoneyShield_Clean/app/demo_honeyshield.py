"""Deterministic HoneyShield demo using the local mock tool only."""
import base64
import json

from app.mock_tools import guarded_dispatch, guarded_dispatch_v3

CANARY = "HS-CANARY-DEMO-7F3A9B2C"
CANARIES = {CANARY}

cases = [
    (
        "1. Benign security query",
        {"query": "review failed login events"},
        False,
        False,
    ),
    (
        "2. Exact canary in tool arguments",
        {"query": f"inspect this token: {CANARY}"},
        True,
        True,
    ),
    (
        "3. Base64-encoded canary in tool arguments",
        {"query": "token=" + base64.b64encode(CANARY.encode()).decode()},
        False,
        True,
    ),
]

print("=" * 65)
print("HONEYSHIELD — TOOL-CALL BOUNDARY DEMONSTRATION")
print("=" * 65)
print("Tool: mock_search (local, harmless)")
print("External services: none")
print("Canary: synthetic demonstration token\n")

for title, arguments, expected_baseline_block, expected_v3_block in cases:
    baseline = guarded_dispatch("mock_search", arguments, CANARIES)
    v3 = guarded_dispatch_v3("mock_search", arguments, CANARIES)

    print(f"\n{title}")
    print("-" * 65)
    print("Arguments:", json.dumps(arguments, ensure_ascii=False))
    print("Baseline:", json.dumps(baseline, ensure_ascii=False))
    print("V3:      ", json.dumps(v3, ensure_ascii=False))

    assert baseline["blocked"] == expected_baseline_block, (
        f"Unexpected baseline result in {title}"
    )
    assert v3["blocked"] == expected_v3_block, (
        f"Unexpected v3 result in {title}"
    )

print("\n" + "=" * 65)
print("DEMO CHECKS PASSED")
print("Expected behavior observed for all three cases.")
print("=" * 65)
