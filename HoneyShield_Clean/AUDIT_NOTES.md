# HoneyShield archive review — 25 October 2026

## Verified
- `python3 -m unittest discover -s tests -v`: 16/16 tests passed.
- `python3 -m compileall -q app tests`: passed.
- `python3 -m app.demo_honeyshield`: passed using the local harmless mock tool.
- All six entries in `results/reproducibility_manifest.csv` matched their row count, column count, and SHA-256 digest at review time.
- Paired pilot: A = 20 disclosures, B = 10, C = 0, each with 29 valid decisions out of 30; C blocked all 10 tool-canary calls before mock dispatch.
- Holdout-style challenge set: 26 full-positive, 31 benign, 4 partial, 3 long-identifier cases. v3 detected 26/26 full positives and blocked 0/31 benign cases in both text and arguments; all seven edge cases were allowed.
- Stress sets: 50/50 constructed positives detected and 0/100 constructed benign cases blocked.

## Corrected in this clean package
- `README.md` and `requirements.txt` were empty in the uploaded archive; both are now populated.
- `app/tool_agent.py` now uses the v3 boundary guard and v3 final-output guard for its guarded path. Previously, the agent's guarded path still used the earlier exact-match guard even though the v3 demo and paired experiment used v3.
- `app/guarded_assistant.py` now uses the v3 output guard.
- Added three synthetic local retrieval documents under `data/documents/` so the RAG retriever has sample content.
- The report and presentation were updated to use the 64-row holdout and the included stress-set results.

## Caveats
- The holdout and stress data are constructed challenge sets, not production attack benchmarks.
- Guard-only latency excludes model inference, retrieval, parsing outside the guard, and tool execution.
- The paired live pilot has 10 repetitions per scenario and one invalid benign decision shared across configurations.
- Exact string/canonicalized/Base64 matching does not cover semantic paraphrase, arbitrary encoding, encryption/compression, split-token, or multi-turn exfiltration attacks.
- The `final_reproducibility_audit.py` script checks file presence/readability and selected row counts but does not itself compare pre-existing manifest hashes; compare hashes separately when validating an immutable archive.
- Live model experiments require Ollama and the configured `qwen2.5:3b` model. The mock-tool demo and unit tests do not require Ollama.
