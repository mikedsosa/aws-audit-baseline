import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "aws_baseline_evidence"
FORBIDDEN = {
    "boto3",
    "botocore",
    "pickle",
    "requests",
    "socket",
    "subprocess",
    "urllib",
}


def test_checker_source_does_not_import_execution_or_network_modules() -> None:
    for path in ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".", 1)[0]]
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "__import__"}
                continue
            else:
                continue
            assert FORBIDDEN.isdisjoint(names), f"{path.name} imports {names}"
