"""Microbenchmark: baseline vs v3 guard-only latency."""
import csv
import statistics
import time
from pathlib import Path

from app.guard import inspect_tool_arguments
from app.encoded_guard_v3 import inspect_tool_arguments_with_base64_v3

RESULTS = Path("results/guard_latency_benchmark.csv")
CANARY = "HS-CANARY-3D98ED4B408D"
CANARIES = {CANARY}
ITERATIONS = 5000
WARMUP = 200

CASES = {
    "benign_short": {"query": "review failed login events"},
    "benign_nested": {
        "request": {
            "query": "review authentication logs",
            "metadata": {"source": "local_test"},
        }
    },
    "canary_exact": {"query": CANARY},
    "canary_base64": {
        "query": __import__("base64").b64encode(
            CANARY.encode()
        ).decode()
    },
}


def percentile(values, p):
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((p / 100) * len(ordered)))
    return ordered[index]


def benchmark(function, arguments):
    for _ in range(WARMUP):
        function(arguments, CANARIES)

    timings = []
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        function(arguments, CANARIES)
        timings.append((time.perf_counter_ns() - start) / 1_000_000)

    return {
        "median_ms": statistics.median(timings),
        "p95_ms": percentile(timings, 95),
        "mean_ms": statistics.mean(timings),
    }


def main():
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for case_name, arguments in CASES.items():
        for guard_name, function in [
            ("baseline", inspect_tool_arguments),
            ("v3", inspect_tool_arguments_with_base64_v3),
        ]:
            stats = benchmark(function, arguments)
            rows.append({
                "case": case_name,
                "guard": guard_name,
                "iterations": ITERATIONS,
                "median_ms": round(stats["median_ms"], 6),
                "p95_ms": round(stats["p95_ms"], 6),
                "mean_ms": round(stats["mean_ms"], 6),
            })

    with RESULTS.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved: {RESULTS}")
    print("Guard-only latency; Ollama and tool execution excluded.\n")
    for row in rows:
        print(
            f"{row['case']:16} {row['guard']:8} "
            f"median={row['median_ms']:.6f} ms  "
            f"p95={row['p95_ms']:.6f} ms  "
            f"mean={row['mean_ms']:.6f} ms"
        )


if __name__ == "__main__":
    main()
