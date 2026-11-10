import json
import os
import subprocess
import sys
from pathlib import Path

from aws_baseline_evidence.cli import main
from tests.fixture_factory import compliant_document, dumps, noncompliant_document, unknown_document


def test_cli_text_and_json(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_bytes(dumps(compliant_document()))
    out = tmp_path / "evidence.json"
    code = main(["assess", str(plan), "--json-out", str(out)])
    assert code == 0
    text = out.read_text(encoding="utf-8")
    parsed = json.loads(text)
    assert parsed["summary"]["result"] == "pass"
    assert parsed["input"]["deployed_aws_verified"] is False


def test_cli_exit_codes(tmp_path: Path, capsys) -> None:
    unknown = tmp_path / "unknown.json"
    unknown.write_bytes(dumps(unknown_document()))
    assert main(["assess", str(unknown), "--format", "json"]) == 3
    bad = tmp_path / "bad.json"
    bad.write_bytes(dumps(noncompliant_document()))
    assert main(["assess", str(bad), "--format", "text"]) == 1
    capsys.readouterr()
    missing = tmp_path / "missing.json"
    missing.write_text("{", encoding="utf-8")
    assert main(["assess", str(missing)]) == 2


def test_cli_rejects_oversized_input(tmp_path: Path) -> None:
    plan = tmp_path / "large.json"
    plan.write_bytes(b"{" + b" " * 50 + b"}")
    assert main(["assess", str(plan), "--max-bytes", "20"]) == 2


def test_module_entrypoint() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [sys.executable, "-m", "aws_baseline_evidence", "--version"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 0
    assert "aws-baseline-evidence" in completed.stdout
