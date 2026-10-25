# SHIVALIK UNIVERSITY
## DEPARTMENT: B.TECH CSE
### PROJECT REPORT

# HONEYSHIELD
### Evaluating Honey-Token Enforcement at Tool-Call Boundaries in RAG-Based LLM Applications

**Submitted by:**
- Gourav Kumar
- Nimesh Singh Rana

**Academic Session:** 2026–2027  
**Institution:** Shivalik University  

---

## Executive Summary / Abstract

HoneyShield is a controlled security experiment for a retrieval-augmented generation (RAG)-style application that can request tool execution. It investigates whether inspecting structured tool-call arguments before dispatch, alongside filtering the final assistant response, prevents disclosure of a registered synthetic canary more effectively than output-only filtering or no canary guard. The study compares three configurations using paired model decisions, then evaluates several exact-match, normalization, punctuation-aware, and Base64-aware string guards on constructed positive and benign test cases. A local mock tool is used; no real credentials or external actions are involved.

In a 10-repetition paired live pilot, one shared model decision per scenario/repetition was replayed across the three configurations. Among valid decisions, the baseline disclosed canaries in 20/29 rows, output-only filtering in 10/29, and boundary-plus-output filtering in 0/29. In the tool-canary scenario, the boundary guard blocked 10/10 calls before mock dispatch; output-only filtering blocked final responses but did not stop the tool-call arguments from crossing the boundary. The included fresh-canary holdout-style CSV contains 26 full-positive cases, 31 benign cases, and 7 edge cases; the Base64-aware v3 candidate blocked 26/26 full positives and 0/31 benign cases in both text and argument inspection. A 50-case constructed positive stress set reported 50/50 detection and a 100-case constructed benign stress set reported 0/100 false positives. These are small, constructed evaluations, not evidence of universal protection or a real-world zero false-positive rate.

The defensible contribution is a reproducible, implementation-level comparison of enforcement placement and selected canary transformations under a paired decision design, with explicit measurement of detection, benign-call preservation, and guard-only latency. Boundary enforcement and canary-based detection are established ideas; HoneyShield does not claim to invent either.

---

## 1. Project Identity and Overview

- **Project Name:** HoneyShield
- **Full Title:** Evaluating Honey-Token Enforcement at Tool-Call Boundaries in RAG-Based LLM Applications
- **Project Type:** Implementation-oriented cybersecurity / AI application security experiment
- **Core Research Question:** Does pre-dispatch inspection of tool-call arguments plus final-output filtering reduce synthetic-canary disclosure compared with output-only filtering and no canary guard?
- **System Under Test:** Local Ollama model (`qwen2.5:3b`) producing structured tool-call or final-answer decisions; harmless local mock tool (`mock_search`).
- **Safety Boundary:** Synthetic canary strings and synthetic cases only; allowlisted mock tool; no real credentials or external network side effects.
- **Primary Outcomes:** Canary disclosure, boundary blocks, output blocks, tool dispatches, benign-call preservation, transformation detection, and guard-only latency.

---

## 2. Problem Statement and Research Questions

### 2.1 Problem Statement
RAG applications retrieve external documents and place their contents into a model's context window. Tool-using LLM applications may also let the model emit structured requests—such as a tool name and JSON arguments—that application code executes. If sensitive content or a synthetic canary is present in the context, a model may attempt to reproduce it in a final answer or place it inside tool arguments. 

A final-response filter can prevent a string from being shown to the end-user, but it cannot retroactively prevent an already-dispatched tool call from carrying that string across an API boundary or into external tool logs.

### 2.2 Research Questions
- **RQ1:** In the paired live pilot, how do the three enforcement configurations differ in synthetic-canary disclosure?
- **RQ2:** How do selected normalization and Base64-aware transformations affect canary detection on constructed test sets?
- **RQ3:** What guard-only latency overhead does the more comprehensive candidate add compared with baseline exact matching?
- **RQ4:** What can and cannot be concluded from the current controlled sample sizes and test construction?

---

## 3. Scope, Assumptions, and Threat Model

### 3.1 In Scope
- Synthetic canaries generated specifically for the experiment (e.g., `HS-CANARY-XXXXXX`).
- RAG-like context and structured tool-call arguments (JSON format).
- Pre-dispatch and final-output inspection points.
- Harmless local mock search tool and deterministic test harness.
- Selected exact, case, separator, punctuation, whitespace, and Base64 transformations.

### 3.2 Out of Scope
- Real passwords, API keys, personal data, or production secrets.
- External network tools, shell execution, email sending, file deletion, or other real side effects.
- A broad benchmark of indirect prompt injection across many commercial models.
- Semantic paraphrase detection, arbitrary encodings, multi-turn covert channels, or claims of production readiness.
- Any claim that canary matching alone solves prompt injection.

### 3.3 Threat Model and Core Definitions
- **Asset:** A registered synthetic canary string placed in test context.
- **Adversary Action:** A prompt or model decision attempts to place the canary in a final response or tool argument.
- **Tool Boundary:** The application code point after parsing a tool request but before dispatching it to the tool implementation.
- **Successful Disclosure:** The registered canary is present in a released final answer or in arguments that cross the mock dispatch boundary.
- **Exposure in Context:** The model can see a canary in its input context; this alone is not counted as a disclosure.
- **Trust Assumptions:** The guard, registry, parser, and mock dispatcher run as intended in trusted application space and are not compromised.

---

## 4. System Architecture and Data Flow

### 4.1 Enforcement Configurations

| Configuration | Boundary Check (Pre-Dispatch) | Final Output Check | Purpose |
| :--- | :--- | :--- | :--- |
| **A_baseline** | No canary guard | No canary guard | Reference baseline condition |
| **B_output_only** | No canary guard | Yes, inspects final text | Evaluates limitation of final-only filtering |
| **C_boundary_output** | Yes, inspects arguments before dispatch | Yes, inspects final text | Evaluates dual-boundary layered enforcement |

### 4.2 Application Flow
1. **Context Assembly:** Test/user prompt + retrieved synthetic context containing registered canary.
2. **Local LLM Inference:** Ollama model generates candidate completion.
3. **Structured Parser:** Extracts either a direct text answer or a tool call `{"tool": "mock_search", "arguments": {...}}`.
4. **Tool Dispatch Guard (Config C only):**
   - Serializes and recursively inspects arguments with case/separator normalization and Base64 decoding.
   - If canary detected: **BLOCK dispatch** (`dispatched=False`, `result=None`).
   - If clean: **DISPATCH** to allowlisted `mock_search`.
5. **Tool Result Loop:** Mock result is returned to model context if continuing execution.
6. **Final Output Guard (Config B & C):**
   - Inspects generated answer text for canary.
   - If canary detected: **BLOCK release** (return sanitized security notification).
   - If clean: **RELEASE** answer to user.

---

## 5. Implementation Details

- **`app/canaries.py`:** Generates synthetic canaries and supports containment checks.
- **`app/guard.py`:** Baseline exact-match string inspection for text and JSON arguments.
- **`app/normalized_guard.py`:** Whitespace normalization and recursive dictionary inspection.
- **`app/punctuation_guard.py`:** Alphanumeric normalization to tolerate separator and punctuation variations.
- **`app/encoded_guard_v3.py`:** Current best candidate:
  - Case and separator normalization with strict regex boundaries `(?<![A-Za-z0-9])` and `(?![A-Za-z0-9])`.
  - Hyphen-suffix exclusion to avoid false positives on extended tokens.
  - Bounded Base64 detection: regex `(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])`, payload decoding, and recursive inspection.
  - Recursive traversal across arbitrary nested JSON dicts and lists.
- **`app/mock_tools.py`:** Harmless mock search tool with strict allowlisting.
- **`app/tool_agent.py`:** Local Ollama integration with structured parsing and configurable enforcement paths.

---

## 6. Experimental Results

### 6.1 Paired Live Pilot (10 Repetitions × 3 Scenarios = 90 Trials)
*Evaluated on local Ollama `qwen2.5:3b`. One shared model decision per scenario/repetition is replayed across A, B, and C (29 valid decisions per configuration).*

| Scenario | Configuration | Valid Decisions | Disclosures | Boundary Blocks | Output Blocks | Tool Dispatches |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Tool-canary** | A — Baseline | 10/10 | 10 | 0 | 0 | 10 |
| **Tool-canary** | B — Output-only | 10/10 | **10 (leaked!)** | 0 | 10 | 10 |
| **Tool-canary** | C — Boundary + Output | 10/10 | **0** | **10** | 0 | **0** |
| **Final-canary** | A — Baseline | 10/10 | 10 | 0 | 0 | 0 |
| **Final-canary** | B — Output-only | 10/10 | **0** | 0 | **10** | 0 |
| **Final-canary** | C — Boundary + Output | 10/10 | **0** | 0 | **10** | 0 |
| **Benign** | A — Baseline | 9/10 | 0 | 0 | 0 | 9 |
| **Benign** | B — Output-only | 9/10 | 0 | 0 | 0 | 9 |
| **Benign** | C — Boundary + Output | 9/10 | 0 | 0 | 0 | 9 |
| **TOTAL** | **A — Baseline** | **29/30** | **20 (69.0%)** | **0** | **0** | **19** |
| **TOTAL** | **B — Output-only** | **29/30** | **10 (34.5%)** | **0** | **20** | **19** |
| **TOTAL** | **C — Boundary + Output** | **29/30** | **0 (0.0%)** | **10** | **10** | **9** |

**Key Finding:** When the model calls a tool containing the canary, **Output-only filtering (Config B) catches the final response but completely fails to stop the tool dispatch (10 disclosures)**. Dual-boundary guarding (Config C) stopped 10/10 calls before execution.

---

### 6.2 Fresh-Canary Holdout Challenge Evaluation (64 Cases)
*Evaluated on a freshly generated token `HS-CANARY-XXXXXX`.*

| Guard Candidate | Full Positives Detected | Detection Rate | Benign Blocked (FPR) | Edge Cases Blocked |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline Exact** | 11 / 26 | 42.3% | 0 / 31 (0.0%) | 0 / 7 |
| **Normalized v2** | 14 / 26 | 53.8% | 0 / 31 (0.0%) | 0 / 7 |
| **Punctuation v1** | 15 / 26 | 57.7% | 0 / 31 (0.0%) | 0 / 7 |
| **Base64 v1** | 17 / 26 | 65.4% | 0 / 31 (0.0%) | 0 / 7 |
| **Base64 v2** | 19 / 26 | 73.1% | 0 / 31 (0.0%) | 0 / 7 |
| **Base64 v3 (Text)** | **26 / 26** | **100.0%** | **0 / 31 (0.0%)** | **0 / 7** |
| **Base64 v3 (Args)** | **26 / 26** | **100.0%** | **0 / 31 (0.0%)** | **0 / 7** |

#### Why the 7 Edge Cases Were Allowed:
- **4 Partial-token cases:** Missing characters of the full 12-hex token; strict boundary matching avoids false-positive alerts on standard prefixes.
- **3 Long identifiers:** Negative lookarounds and suffix checks ignore tokens with prepended or appended alphanumeric characters.
- **Trade-off:** Prevents false positives on similar system IDs, but means truncated or token-fragmented leaks evade detection.

---

### 6.3 Stress Evaluations
- **Positive Stress Test (50 constructed positive cases):** 50/50 detected (100% recall on tested patterns).
- **Benign Stress Test (100 constructed benign cases):** 0/100 blocked (0% observed false-positive rate on tested sample).

---

### 6.4 Guard-Only Latency Microbenchmark (5,000 Iterations)

| Test Case | Baseline Median | Base64 v3 Median | Absolute Overhead |
| :--- | :--- | :--- | :--- |
| Short benign text | 0.0025 ms | 0.0167 ms | +0.0142 ms (14 µs) |
| Nested benign arguments | 0.0025 ms | 0.0466 ms | +0.0441 ms (44 µs) |
| Exact canary | 0.0020 ms | 0.0148 ms | +0.0128 ms (13 µs) |
| Base64 canary | 0.0020 ms | 0.0211 ms | +0.0191 ms (19 µs) |

**Latency Overhead:** Microsecond-level execution (15–47 µs), representing less than 0.01% of end-to-end LLM inference time.

---

## 7. Positioning and Literature Review

HoneyShield builds upon established research directions while contributing a focused, paired comparative evaluation:
1. **Canary-based detection:** Gakh & Bahsi (2026) evaluated early detection systems (LLM Guard, Vigil, Rebuff) against prompt leaks. HoneyShield focuses on the spatial placement of checks (tool boundary vs. final output).
2. **Deceptive tokens:** Ayzenshteyn et al. (*Cloak, Honey, Trap*, USENIX Security 2025) proposed proactive honeypots against agents. HoneyShield uses canaries as a narrow measurement instrument.
3. **Runtime tool enforcement:** *ClawGuard* (Zhao et al., 2026) and *SecureClaw* (Ma & Schmid, 2026) established policy enforcement and dual-boundary isolation. HoneyShield provides a minimal, open, reproducible testbed.
4. **Action auditing:** *ActGuard* (Wang et al., 2026) and *The Task Shield* (Jia et al., ACL 2025) use semantic intent reasoning. HoneyShield is deterministic and complementary.

---

## 8. Limitations and Threats to Validity

1. **Constructed Test Sets:** Metrics describe performance on synthetic challenge cases, not in-the-wild attack distributions.
2. **Tuning Bias:** The v3 detector was refined against observed failure cases; high detection rates must not be claimed as universal generalization.
3. **Encoding Scope:** Handles standard Base64 and separator variations. Does not detect arbitrary ciphers, hex/binary encoding, semantic rephrasing, or split multi-turn exfiltration.
4. **Sample Size:** 29 valid decisions per configuration in the paired pilot; zero observed false positives does not guarantee a 0% population FPR.
5. **Single Local Model:** Tested on `qwen2.5:3b` via Ollama; behavior may vary on closed-source frontier models.

---

## 9. Viva Questions & Suggested Answers

- **Q: What core problem does HoneyShield solve?**  
  *A:* It proves that filtering the assistant's final response is insufficient when tools are available. Canary-bearing arguments must be intercepted before tool execution to prevent egress.
- **Q: Does Base64 v3 detect all prompt injections?**  
  *A:* No. It is a deterministic canary matching tool, not a semantic classifier. It catches tested transformations of known markers but cannot detect attacks that do not leak the marker.
- **Q: Why were all 7 edge cases allowed?**  
  *A:* The guard requires the complete canary token bounded by non-alphanumeric characters. This prevents false alarms on normal system IDs sharing prefixes, but leaves a known gap against token truncation.
- **Q: What is the computational cost?**  
  *A:* Microbenchmark testing demonstrates a median execution time under 50 microseconds, which is imperceptible alongside second-scale LLM generation.

---

## 10. Reproduction Commands

```bash
# 1. Run unit test regression suite (16 tests)
python3 -m unittest discover -s tests -v

# 2. Run deterministic local demonstration
python3 -m app.demo_honeyshield

# 3. Verify cryptographic hashes and data integrity
python3 app/final_reproducibility_audit.py

# 4. Launch interactive research dashboard
streamlit run app/dashboard.py
```

---

## 11. Selected References

1. V. Gakh and H. Bahsi, *“Enhancing security in LLM applications: a performance evaluation of early detection systems,”* International Journal of Information Security, 2026. DOI: 10.1007/s10207-026-01338-7.
2. D. Ayzenshteyn, R. Weiss, and Y. Mirsky, *“Cloak, Honey, Trap: Proactive Defenses Against LLM Agents,”* USENIX Security Symposium 2025, pp. 8095–8114.
3. W. Zhao, Z. Li, P. Zhang, and J. Sun, *“ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection,”* arXiv:2604.11790, 2026.
4. Y. Ma and S. Schmid, *“SecureClaw: Clawing Back Control of LLM Agents,”* arXiv:2606.09549, 2026.
5. B. Wang et al., *“ActGuard: Pre-execution Action Auditing against Indirect Prompt Injection in LLM Agents,”* arXiv:2609.14987, 2026.
6. F. Jia, T. Wu, X. Qin, and A. Squicciarini, *“The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents,”* Proceedings of ACL 2025, pp. 29680–29697.
