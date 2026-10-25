
"""Deterministic tests for tool-call boundary enforcement."""
from app.canaries import generate_canary
from app.mock_tools import guarded_dispatch
from app.guard import inspect_text


def run_test():
    canary = generate_canary()
    arguments = {"query": f"search for {canary}"}
    canaries = {canary}

    print("Synthetic canary:", canary)

    # A: Baseline — no canary guard at the tool boundary.
    baseline_dispatched = True
    print("\nA — Baseline")
    print("Canary in tool arguments:", canary in arguments["query"])
    print("Dispatched:", baseline_dispatched)

    # B: Output-only — tool boundary is not guarded.
    # A later final-response guard cannot undo an already dispatched call.
    output_only_dispatched = True
    final_response = "The search completed successfully."
    output_result = inspect_text(final_response, canaries)

    print("\nB — Output-only")
    print("Dispatched:", output_only_dispatched)
    print("Final response blocked:", output_result.blocked)

    # C: Boundary + output — inspect arguments before mock dispatch.
    boundary_result = guarded_dispatch(
        "mock_search", arguments, canaries
    )

    print("\nC — Boundary + output")
    print("Blocked:", boundary_result["blocked"])
    print("Dispatched:", boundary_result["dispatched"])
    print("Reason:", boundary_result["reason"])

    assert baseline_dispatched is True
    assert output_only_dispatched is True
    assert boundary_result["blocked"] is True
    assert boundary_result["dispatched"] is False

    print("\nAll deterministic assertions passed.")


if __name__ == "__main__":
    run_test()
