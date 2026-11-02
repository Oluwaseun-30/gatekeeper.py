#!/usr/bin/env python3
"""
Gatekeeper.py - AI-Assisted Static Security Scanner for C/C++
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests

# Enable ANSI terminal colors on Windows PowerShell
if sys.platform == "win32":
    os.system("")

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

HEURISTIC_RULES = [
    {
        "id": "CWE-120",
        "name": "Buffer Copy Without Checking Size",
        "pattern": r"\b(strcpy|strcat|gets|sprintf|vsprintf)\s*\(",
        "severity": "HIGH",
        "description": "Unbounded memory copy susceptible to buffer overflows.",
    },
    {
        "id": "CWE-134",
        "name": "Uncontrolled Format String",
        "pattern": r"\b(printf|fprintf|sprintf|snprintf)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)",
        "severity": "HIGH",
        "description": "Format function called with a variable instead of a string literal.",
    },
    {
        "id": "CWE-78",
        "name": "OS Command Injection",
        "pattern": r"\b(system|popen)\s*\(",
        "severity": "CRITICAL",
        "description": "Direct execution of raw system shell commands.",
    },
    {
        "id": "CWE-467",
        "name": "Use of sizeof() on a Pointer Type",
        "pattern": r"sizeof\s*\(\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "severity": "MEDIUM",
        "description": "Potential incorrect buffer size calculation on a pointer.",
    },
]

SUPPORTED_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}


def run_heuristic_scan(filepath: str, content: str) -> List[Dict[str, Any]]:
    """Scan C/C++ source lines against static security rules, ignoring comments."""
    findings = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        for rule in HEURISTIC_RULES:
            if re.search(rule["pattern"], line):
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "file": filepath,
                    "line": line_idx,
                    "code_snippet": stripped,
                    "description": rule["description"],
                })
    return findings


def validate_ai_output(raw_payload: Any) -> Optional[Dict[str, Any]]:
    """Validate LLM JSON output schema and sanitize fields before deployment."""
    if not isinstance(raw_payload, dict):
        return None

    required_keys = {"is_vulnerable", "cwe", "severity", "explanation", "suggested_fix"}
    if not required_keys.issubset(raw_payload.keys()):
        return None

    if not isinstance(raw_payload["is_vulnerable"], bool):
        return None

    severity = str(raw_payload["severity"]).upper()
    if severity not in VALID_SEVERITIES:
        return None

    cwe = str(raw_payload["cwe"]).strip()
    if not re.match(r"^CWE-\d+$", cwe):
        cwe = "CWE-Unknown"

    return {
        "is_vulnerable": raw_payload["is_vulnerable"],
        "cwe": cwe,
        "severity": severity,
        "explanation": str(raw_payload["explanation"]).strip(),
        "suggested_fix": str(raw_payload["suggested_fix"]).strip(),
    }


def analyze_with_llm(
    filepath: str, code_snippet: str, heuristic_hits: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Query Gemini or OpenAI to verify exploitability and suggest a C++ patch."""
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")

    if not gemini_key and not openai_key:
        return None

    prompt = (
        f"You are a C/C++ static security analyzer.\n"
        f"Evaluate the following C/C++ code snippet from {filepath} and its static heuristic alerts.\n"
        f"Determine if the vulnerability is a true positive or false positive.\n\n"
        f"Alerts:\n{json.dumps(heuristic_hits, indent=2)}\n\n"
        f"Code Snippet:\n{code_snippet}\n\n"
        f"Return ONLY a valid JSON object with keys: "
        f"is_vulnerable (bool), cwe (string), severity (CRITICAL|HIGH|MEDIUM|LOW), "
        f"explanation (string), and suggested_fix (string)."
    )

    try:
        if gemini_key:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1},
            }
            resp = requests.post(url, json=payload, timeout=15)
            resp.raise_for_status()
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        else:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=15)
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]

        parsed = json.loads(text)
        return validate_ai_output(parsed)
    except Exception as err:
        print(f"[-] LLM validation unavailable ({err}). Falling back to static heuristics.", file=sys.stderr)
        return None


def get_staged_files() -> List[str]:
    """Retrieve staged C/C++ files from Git."""
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        return []

    files = result.stdout.strip().splitlines()
    return [f for f in files if Path(f).suffix.lower() in SUPPORTED_EXTENSIONS]


def scan_target(file_path: str, offline: bool = False) -> List[Dict[str, Any]]:
    """Run static heuristic pre-filter followed by optional LLM verification."""
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}", file=sys.stderr)
        return []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    heuristic_results = run_heuristic_scan(file_path, content)
    if not heuristic_results or offline:
        return heuristic_results

    lines = content.splitlines()
    target_lines = {hit["line"] for hit in heuristic_results}
    start_line = max(1, min(target_lines) - 5)
    end_line = min(len(lines), max(target_lines) + 5)
    snippet = "\n".join(lines[start_line - 1 : end_line])

    ai_result = analyze_with_llm(file_path, snippet, heuristic_results)
    if ai_result is not None:
        if not ai_result["is_vulnerable"]:
            return []
        return [{
            "rule_id": ai_result["cwe"],
            "name": "AI-Verified Vulnerability",
            "severity": ai_result["severity"],
            "file": file_path,
            "line": min(target_lines),
            "code_snippet": lines[min(target_lines) - 1].strip(),
            "description": ai_result["explanation"],
            "fix": ai_result["suggested_fix"],
        }]

    return heuristic_results


def main():
    parser = argparse.ArgumentParser(description="Gatekeeper.py - C/C++ Static Security Analyzer")
    parser.add_argument("files", nargs="*", help="C/C++ file paths to scan")
    parser.add_argument("--staged", action="store_true", help="Scan Git staged C/C++ files")
    parser.add_argument("--offline", action="store_true", help="Run static heuristics only (skip LLM)")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="HIGH")
    args = parser.parse_args()

    files_to_scan = list(args.files)
    if args.staged:
        files_to_scan.extend(get_staged_files())

    files_to_scan = sorted(list(set(files_to_scan)))
    if not files_to_scan:
        sys.exit(0)

    severity_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    threshold = severity_weight[args.fail_on]
    violations = []

    for path in files_to_scan:
        findings = scan_target(path, offline=args.offline)
        for issue in findings:
            if severity_weight.get(issue.get("severity", "LOW"), 1) >= threshold:
                violations.append(issue)

    if violations:
        print("\n\033[91m[!] SECURITY GATE CHECK FAILED\033[0m")
        for v in violations:
            print(f"- [{v['severity']}] {v['rule_id']}: {v['name']} at {v['file']}:{v['line']}")
            print(f"  Snippet : {v['code_snippet']}")
            print(f"  Details : {v['description']}")
            if v.get("fix"):
                print(f"  Fix     : {v['fix']}")
            print()
        sys.exit(1)

    print("\033[92m[+] Gatekeeper scan clean. Zero policy violations.\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()