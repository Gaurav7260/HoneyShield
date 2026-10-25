
"""Validate the deterministic HoneyShield pilot dataset."""
import csv
from pathlib import Path

RESULTS_FILE = (
    Path(__file__).resolve().parent.parent
    / "results"
    / "boundary_pilot.csv"
)


def validate_results():
    with RESULTS_FILE.open(
        newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        columns = set(reader.fieldnames or [])

    required = {
        "timestamp_utc", "scenario_id", "scenario_type",
        "repetition", "configuration", "channel",
        "canary_present", "blocked", "dispatched",
        "disclosure", "reason",
    }

    assert required.issubset(columns), "Required columns missing."
    assert len(rows) == 27, f"Expected 27 rows; got {len(rows)}."

    expected_configs = {
        "A_baseline", "B_output_only", "C_boundary_output"
    }
    expected_scenarios = {"TOOL-LEAK", "FINAL-LEAK", "BENIGN"}

    assert {r["configuration"] for r in rows} == expected_configs
    assert {r["scenario_type"] for r in rows} == expected_scenarios

    for scenario in expected_scenarios:
        for config in expected_configs:
            matching = [
                r for r in rows
                if r["scenario_type"] == scenario
                and r["configuration"] == config
            ]
            assert len(matching) == 3, (
                f"Expected 3 repetitions for {scenario}/{config}."
            )

    tool_c = [
        r for r in rows
        if r["scenario_type"] == "TOOL-LEAK"
        and r["configuration"] == "C_boundary_output"
    ]
    assert all(r["blocked"] == "True" for r in tool_c)
    assert all(r["dispatched"] == "False" for r in tool_c)

    final_b = [
        r for r in rows
        if r["scenario_type"] == "FINAL-LEAK"
        and r["configuration"] == "B_output_only"
    ]
    assert all(r["blocked"] == "True" for r in final_b)

    print("CSV schema: PASS")
    print("Scenario/configuration coverage: PASS")
    print("Three repetitions per combination: PASS")
    print("Tool boundary blocks: PASS")
    print("Output-only final-response blocks: PASS")
    print(f"Total deterministic rows: {len(rows)}")
    print("Validation completed.")


if __name__ == "__main__":
    validate_results()
