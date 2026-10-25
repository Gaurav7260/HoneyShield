"""Final reproducibility audit for HoneyShield experiment outputs."""
import csv
import hashlib
from pathlib import Path

FILES = [
    "results/paired_live_pilot_v3_10rep.csv",
    "results/holdout_guard_evaluation_v2.csv",
    "results/benign_stress_evaluation.csv",
    "results/positive_stress_evaluation.csv",
    "results/guard_latency_benchmark.csv",
    "results/encoded_guard_v3_evaluation.csv",
]

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return reader.fieldnames or [], rows

def main():
    manifest = Path("results/reproducibility_manifest.csv")
    manifest.parent.mkdir(parents=True, exist_ok=True)

    manifest_rows = []
    failures = []

    print("HONEYSHIELD REPRODUCIBILITY AUDIT")
    print("=" * 38)

    for filename in FILES:
        path = Path(filename)

        if not path.is_file():
            print(f"MISSING: {filename}")
            failures.append(f"Missing file: {filename}")
            continue

        try:
            headers, rows = read_csv(path)
        except Exception as exc:
            print(f"READ ERROR: {filename}: {exc}")
            failures.append(f"Could not read: {filename}")
            continue

        digest = sha256_file(path)
        print(f"\nFILE: {filename}")
        print(f"Rows: {len(rows)}")
        print(f"Columns: {len(headers)}")
        print(f"SHA-256: {digest}")

        if not rows:
            failures.append(f"Empty CSV: {filename}")

        if path.name == "benign_stress_evaluation.csv":
            text_fp = sum(r.get("text_blocked") == "true" for r in rows)
            args_fp = sum(r.get("args_blocked") == "true" for r in rows)
            print(f"Text false positives: {text_fp}/{len(rows)}")
            print(f"Argument false positives: {args_fp}/{len(rows)}")
            if len(rows) != 100:
                failures.append("Benign stress test did not contain 100 rows")

        elif path.name == "positive_stress_evaluation.csv":
            text_tp = sum(r.get("text_blocked") == "true" for r in rows)
            args_tp = sum(r.get("args_blocked") == "true" for r in rows)
            print(f"Text detections: {text_tp}/{len(rows)}")
            print(f"Argument detections: {args_tp}/{len(rows)}")
            if len(rows) != 50:
                failures.append("Positive stress test did not contain 50 rows")

        elif path.name == "holdout_guard_evaluation_v2.csv":
            positives = sum(r.get("label") == "full_positive" for r in rows)
            benign = sum(r.get("label") == "benign" for r in rows)
            edge = sum(r.get("label") in {"partial", "long_identifier"} for r in rows)
            print(f"Full-positive cases: {positives}")
            print(f"Benign cases: {benign}")
            print(f"Edge cases: {edge}")

        manifest_rows.append({
            "file": filename,
            "rows": len(rows),
            "columns": len(headers),
            "sha256": digest,
        })

    with manifest.open("w", newline="", encoding="utf-8") as f:
        fields = ["file", "rows", "columns", "sha256"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"\nManifest saved to: {manifest}")

    if failures:
        print("\nAUDIT WARNINGS")
        for failure in failures:
            print(f"- {failure}")
        print("\nAudit completed with warnings; resolve missing or invalid files.")
    else:
        print("\nAll listed files were found and readable.")
        print("Review the metrics above and preserve the manifest with your results.")

if __name__ == "__main__":
    main()
