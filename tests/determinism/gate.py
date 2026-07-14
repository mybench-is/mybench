"""Two-process byte comparison and ambient-state audit for MYB-10.3."""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from tests.determinism.stages import STAGES, Stage

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"

# Scorers and deterministic pipeline stages get configuration, time, locale,
# currency/version snapshots, and all other variability as explicit inputs.
# Importing these modules is therefore a gate failure even if a particular
# synthetic fixture happens not to exercise the impure branch.
FORBIDDEN_IMPORTS = {
    "aiohttp": "network",
    "asyncio": "network/clock",
    "ftplib": "network",
    "getpass": "environment",
    "http": "network",
    "httpx": "network",
    "locale": "locale/environment",
    "os": "environment",
    "platform": "environment",
    "random": "ambient randomness",
    "requests": "network",
    "secrets": "ambient randomness",
    "smtplib": "network",
    "socket": "network",
    "subprocess": "subprocess/ambient state",
    "sys": "environment",
    "tempfile": "environment",
    "time": "clock",
    "urllib": "network",
    "uuid": "ambient randomness",
    "zoneinfo": "host time-zone database",
}

FORBIDDEN_CALLS = {
    "datetime.date.today": "wall clock",
    "datetime.datetime.now": "wall clock",
    "datetime.datetime.today": "wall clock",
    "datetime.datetime.utcnow": "wall clock",
    "pathlib.Path.cwd": "process working directory",
    "pathlib.Path.home": "environment home directory",
}


class GateError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditIssue:
    path: Path
    line: int
    column: int
    message: str

    def __str__(self) -> str:
        try:
            display_path = self.path.relative_to(REPO_ROOT)
        except ValueError:
            display_path = self.path
        return f"{display_path}:{self.line}:{self.column}: {self.message}"


@dataclass(frozen=True)
class StageResult:
    name: str
    size: int
    sha256: str


class _AmbientStateVisitor(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.aliases: dict[str, str] = {}
        self.issues: list[AuditIssue] = []

    def _issue(self, node: ast.AST, message: str) -> None:
        self.issues.append(
            AuditIssue(
                self.path,
                getattr(node, "lineno", 1),
                getattr(node, "col_offset", 0) + 1,
                message,
            )
        )

    def _check_import(self, node: ast.AST, module: str) -> None:
        root = module.split(".", 1)[0]
        if root in FORBIDDEN_IMPORTS:
            self._issue(
                node,
                f"forbidden {FORBIDDEN_IMPORTS[root]} import {module!r}; pass it as input",
            )

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 - ast API
        for alias in node.names:
            self._check_import(node, alias.name)
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802 - ast API
        if node.module:
            self._check_import(node, node.module)
            for alias in node.names:
                local = alias.asname or alias.name
                self.aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def _qualified_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._qualified_name(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        name = self._qualified_name(node.func)
        if name in FORBIDDEN_CALLS:
            self._issue(node, f"forbidden {FORBIDDEN_CALLS[name]} call {name!r}; pass it as input")
        self.generic_visit(node)


def audit_source(path: Path) -> list[AuditIssue]:
    """Return all ambient-state violations in one Python source file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [
            AuditIssue(path, exc.lineno or 1, exc.offset or 1, f"cannot audit invalid syntax: {exc.msg}")
        ]
    visitor = _AmbientStateVisitor(path)
    visitor.visit(tree)
    return visitor.issues


def module_path(module_name: str) -> Path:
    """Resolve a first-party module name without importing it."""
    parts = module_name.split(".")
    path = SOURCE_ROOT.joinpath(*parts)
    package = path / "__init__.py"
    module = path.with_suffix(".py")
    if package.is_file():
        return package
    if module.is_file():
        return module
    raise GateError(f"determinism manifest names missing module {module_name!r}")


def scorer_modules() -> set[str]:
    """Discover every scorer implementation module, excluding only I/O wrappers."""
    root = SOURCE_ROOT / "mybench" / "scorer"
    modules = set()
    for path in root.rglob("*.py"):
        if path.name in {"__init__.py", "__main__.py"}:
            continue
        rel = path.relative_to(SOURCE_ROOT).with_suffix("")
        modules.add(".".join(rel.parts))
    return modules


def validate_manifest_and_audit() -> None:
    """Fail closed on missing/duplicate stages, uncovered scorers, or ambient state."""
    names = [stage.name for stage in STAGES]
    if len(names) != len(set(names)):
        raise GateError("determinism stage names must be unique")

    audited_modules = {module for stage in STAGES for module in stage.module_names}
    missing_scorers = sorted(scorer_modules() - audited_modules)
    if missing_scorers:
        raise GateError(
            "scorer modules missing from the determinism manifest: " + ", ".join(missing_scorers)
        )

    issues = []
    for module_name in sorted(audited_modules):
        issues.extend(audit_source(module_path(module_name)))
    if issues:
        raise GateError("ambient-state audit failed:\n" + "\n".join(str(issue) for issue in issues))


_RUN_PROFILES = (
    {
        "PYTHONHASHSEED": "101",
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
        "MYBENCH_DETERMINISM_SENTINEL": "first-run",
    },
    {
        "PYTHONHASHSEED": "202",
        "TZ": "America/Los_Angeles",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "MYBENCH_DETERMINISM_SENTINEL": "second-run",
    },
)


def _run_once(stage: Stage, profile: dict[str, str], root: Path, run_number: int) -> bytes:
    private_root = root / stage.name / f"run-{run_number}"
    for name in ("home", "data", "config", "tmp"):
        (private_root / name).mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env.update(profile)
    env.update(
        {
            "HOME": str(private_root / "home"),
            "XDG_DATA_HOME": str(private_root / "data"),
            "XDG_CONFIG_HOME": str(private_root / "config"),
            "TMPDIR": str(private_root / "tmp"),
        }
    )
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SOURCE_ROOT) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    artifact = private_root / "artifact.bin"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.determinism.runner",
            stage.name,
            "--out",
            str(artifact),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise GateError(
            f"determinism stage {stage.name!r} run {run_number} failed "
            f"with exit {completed.returncode}:\n{stderr}"
        )
    if completed.stdout or completed.stderr:
        raise GateError(
            f"determinism stage {stage.name!r} run {run_number} wrote to stdout/stderr; "
            "stages must return bytes without logging"
        )
    if not artifact.is_file():
        raise GateError(
            f"determinism stage {stage.name!r} run {run_number} produced no artifact"
        )
    return artifact.read_bytes()


def assert_byte_identical(stage_name: str, first: bytes, second: bytes) -> StageResult:
    """Compare exact artifacts and return the safe-to-log digest on success."""
    first_digest = hashlib.sha256(first).hexdigest()
    second_digest = hashlib.sha256(second).hexdigest()
    if first != second:
        raise GateError(
            f"determinism divergence in {stage_name!r}: "
            f"run 1={len(first)} bytes sha256:{first_digest}; "
            f"run 2={len(second)} bytes sha256:{second_digest}"
        )
    return StageResult(stage_name, len(first), first_digest)


def run_gate() -> list[StageResult]:
    """Audit and run every stage twice in independent, perturbed processes."""
    validate_manifest_and_audit()
    results = []
    with tempfile.TemporaryDirectory(prefix="mybench-determinism-") as temp:
        root = Path(temp)
        for stage in STAGES:
            outputs = [
                _run_once(stage, profile, root, run_number)
                for run_number, profile in enumerate(_RUN_PROFILES, start=1)
            ]
            results.append(assert_byte_identical(stage.name, *outputs))
    return results


def main() -> int:
    try:
        results = run_gate()
    except GateError as exc:
        print(f"determinism gate failed: {exc}", file=sys.stderr)
        return 1
    for result in results:
        print(f"{result.name}: {result.size} bytes sha256:{result.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
