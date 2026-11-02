# Gatekeeper.py — AI-Assisted C/C++ Static Security Scanner

Gatekeeper.py is a two-stage static application security testing (SAST) CLI tool for C and C++ compiler workflows. It combines fast regex heuristics with LLM-assisted semantic verification to detect memory safety and injection vulnerabilities before code is committed or merged.

## Features
- **Static Heuristic Engine:** Flags high-risk C/C++ constructs including buffer overflows (CWE-120), uncontrolled format strings (CWE-134), OS command injection (CWE-78), and pointer sizeof miscalculations (CWE-467).
- **AI Output Validation & Remediation:** Extracts surrounding source context and queries Gemini or OpenAI with strict JSON schema validation to filter false positives and suggest safe C++ patches.
- **Git Pre-Commit Integration:** Automatically inspects staged C/C++ files and aborts commits that violate the configured severity threshold.
- **Automated Testing & CI/CD:** Validated with Pytest unit tests and integrated into GitHub Actions workflows.

## Usage
Scan specific C/C++ files:
```bash
python gatekeeper.py tests/fixtures/vulnerable.cpp --fail-on HIGH
```

Scan staged Git changes (used by the pre-commit hook):
```bash
python gatekeeper.py --staged --fail-on HIGH
```

Run in offline heuristic-only mode:
```bash
python gatekeeper.py tests/fixtures/vulnerable.cpp --offline
```

## Running Tests
```bash
python -m pytest -v
```
