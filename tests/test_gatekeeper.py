import pytest
from unittest.mock import patch
from gatekeeper import run_heuristic_scan, validate_ai_output, scan_target


def test_heuristic_detects_buffer_overflow():
    code = 'void copy_data(const char* src) { char buf[16]; strcpy(buf, src); }'
    findings = run_heuristic_scan("sample.cpp", code)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CWE-120"
    assert findings[0]["severity"] == "HIGH"


def test_heuristic_detects_command_injection():
    code = 'int run() { return system("ls -la"); }'
    findings = run_heuristic_scan("sample.cpp", code)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CWE-78"
    assert findings[0]["severity"] == "CRITICAL"


def test_heuristic_ignores_comments():
    code = '// strcpy(buf, src);\n/* system("rm -rf /"); */'
    findings = run_heuristic_scan("sample.cpp", code)
    assert len(findings) == 0


def test_validate_ai_output_accepts_valid_schema():
    valid_payload = {
        "is_vulnerable": True,
        "cwe": "CWE-120",
        "severity": "high",
        "explanation": "Unbounded strcpy call allows stack buffer overflow.",
        "suggested_fix": "snprintf(buf, sizeof(buf), \"%s\", src);",
    }
    validated = validate_ai_output(valid_payload)
    assert validated is not None
    assert validated["severity"] == "HIGH"
    assert validated["cwe"] == "CWE-120"


def test_validate_ai_output_rejects_malformed_schema():
    invalid_payload = {
        "is_vulnerable": "yes",  # Must be boolean
        "severity": "EXTREME",   # Invalid severity level
    }
    assert validate_ai_output(invalid_payload) is None


@patch("gatekeeper.analyze_with_llm")
def test_scan_target_with_ai_verification(mock_llm, tmp_path):
    mock_llm.return_value = {
        "is_vulnerable": True,
        "cwe": "CWE-120",
        "severity": "CRITICAL",
        "explanation": "gets() never checks buffer bounds.",
        "suggested_fix": "fgets(buf, sizeof(buf), stdin);",
    }
    cpp_file = tmp_path / "vuln.cpp"
    cpp_file.write_text("void read_input() { char buf[32]; gets(buf); }")

    results = scan_target(str(cpp_file), offline=False)
    assert len(results) == 1
    assert results[0]["severity"] == "CRITICAL"
    assert "fgets" in results[0]["fix"]
