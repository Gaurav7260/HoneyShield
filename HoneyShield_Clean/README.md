# HoneyShield

**Evaluating Honey-Token Enforcement at Tool-Call Boundaries in RAG-Based LLM Applications**

HoneyShield is a local research prototype that compares synthetic-canary inspection at the final-response boundary and before a tool call is dispatched. It uses synthetic canaries and a harmless local `mock_search` tool; it does not need real credentials or external tool execution.

## Requirements

- Python 3.11+ (the project was developed with Python 3.14; other versions should be tested)
- Ollama for live-model experiments only
- Ollama model `qwen2.5:3b` for the configured live agent
- Python dependency `requests`

The unit tests, local mock-tool demo, CSV analyses, and guard-only benchmark do not require an Ollama server unless a script explicitly makes a model request.

## Setup (macOS/Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For live-model runs, install/start Ollama separately and pull the configured model:

```bash
ollama pull qwen2.5:3b
ollama serve
```

If Ollama is already running as a background service, do not start a second server. The application expects `http://localhost:11434`.

## Verify the project

From the `HoneyShield` project root:

```bash
python -m unittest discover -s tests -v
python -m compileall -q app tests
python -m app.demo_honeyshield
python app/final_reproducibility_audit.py
```

The demo exercises benign, exact-canary, and Base64-canary inputs against the local mock tool. The reproducibility audit checks the listed CSV files and rewrites `results/reproducibility_manifest.csv`; compare the resulting hashes if you need to preserve the original experiment artifacts.

## Important scripts

- `app/encoded_guard_v3.py` — case/separator normalization, bounded Base64 inspection, recursive JSON argument inspection.
- `app/mock_tools.py` — allowlisted local mock tool and pre-dispatch guards.
- `app/tool_agent.py` — local Ollama decision workflow with v3 boundary and output checks.
- `app/paired_live_pilot_v3_10rep.py` — paired A/B/C live pilot; it calls Ollama and overwrites its named output CSV when run.
- `app/holdout_guard_evaluation_v2.py` — constructs a fresh-canary challenge set and overwrites `results/holdout_guard_evaluation_v2.csv`.
- `app/benign_stress_evaluation.py`, `app/positive_stress_evaluation.py` — constructed stress evaluations.
- `app/guard_latency_benchmark.py` — guard-only timing benchmark.

## Interpretation and limitations

All included evaluations use constructed synthetic inputs. Detection rates describe these specific test cases, not real-world attack detection. The guard can miss semantic paraphrases, split canaries, unhandled encodings, encryption/compression, and multi-turn exfiltration. Base64 is encoding, not encryption. Keep tool allowlists, schema validation, authorization, and least-privilege controls even when using a canary guard.

## Data and privacy

The included `results/*.csv` files are experiment artifacts. Live-pilot scripts contact the local Ollama endpoint; no cloud API is configured in the source inspected.
