"""Two-process byte comparison and transitive ambient-state audit (MYB-10.3)."""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from packaging.utils import canonicalize_name

from tests.determinism.stages import (
    RUNNERS,
    STAGES,
    Stage,
    validate_registration,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"
LOCK_PATH = REPO_ROOT / "requirements-ci.lock"


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
class AuditClosure:
    modules: frozenset[str]
    issues: tuple[AuditIssue, ...]


@dataclass(frozen=True)
class StageResult:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PipelineRoot:
    module: str
    required: bool = False


@dataclass(frozen=True)
class ReviewedCall:
    reason: str
    expected_count: int


# Required roots exist today; optional roots reserve the fail-closed package
# contract for the parser/normalizer/publication stories that have not landed.
PIPELINE_ROOTS = (
    PipelineRoot("mybench.scorer", required=True),
    PipelineRoot("mybench.report", required=True),
    PipelineRoot("mybench.parser"),
    PipelineRoot("mybench.parsers"),
    PipelineRoot("mybench.normalizer"),
    PipelineRoot("mybench.normalizers"),
    PipelineRoot("mybench.normalize"),
    PipelineRoot("mybench.publication"),
    PipelineRoot("mybench.publish"),
    PipelineRoot("mybench.preview"),
)

# Package/CLI shells are never compute stages.  Other helpers under a pipeline
# root must be reviewed and named here rather than silently skipped by a broad
# filename convention.
WRAPPER_BASENAMES = frozenset({"__init__", "__main__", "cli"})
REVIEWED_NON_STAGE_MODULES = frozenset(
    {
        # Copy-only constants consumed transitively by report.page.
        "mybench.report.descriptions",
        # Source-neutral re-export facade; the executable implementation and
        # audit root remain mybench.normalizer.claude.
        "mybench.normalizer.contract",
        # Trusted A2/A3/A9 filesystem boundary. It supplies explicit verified
        # inputs to the pure Claude stage and is not itself compute/render.
        "mybench.normalizer.loader",
    }
)

# Scorers and deterministic compute/render modules get configuration, time,
# locale, and all other variability as explicit inputs.  An import is rejected
# even when the current synthetic fixture would not exercise the impure branch.
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
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate": (
        "ambient randomness"
    ),
    "datetime.date.today": "wall clock",
    "datetime.datetime.now": "wall clock",
    "datetime.datetime.today": "wall clock",
    "datetime.datetime.utcnow": "wall clock",
    "mybench.claims.envelope.local_device_pub": "device/environment helper",
    "mybench.claims.envelope.sign_with_device_key": "device/environment helper",
    "mybench.claims.local_device_pub": "device/environment helper",
    "mybench.claims.sign_with_device_key": "device/environment helper",
    "mybench.commitments.generate_nonce": "ambient randomness",
    "mybench.nonce_generation.generate_nonce": "ambient randomness",
    "pathlib.Path.cwd": "process working directory",
    "pathlib.Path.home": "environment home directory",
}

FILESYSTEM_METHODS = frozenset(
    {
        "exists",
        "glob",
        "is_dir",
        "is_file",
        "iterdir",
        "lstat",
        "open",
        "read_bytes",
        "read_text",
        "resolve",
        "rglob",
        "stat",
    }
)

# These exceptions are deliberately exact module+call pairs, not module-wide
# exemptions.  Package resources are committed inputs.  The registry's
# explicit-path loader and claim envelope's device/ephemeral-key conveniences
# are dormant in these fixed runners; their call sites remain visible here and
# any pipeline caller invoking the re-exported helpers is rejected above.
REVIEWED_CALLS: Mapping[tuple[str, str], ReviewedCall] = {
    (
        "mybench.schemas",
        "importlib.resources.files().joinpath().read_text",
    ): ReviewedCall("committed packaged JSON schema", 1),
    (
        "mybench.registry",
        "importlib.resources.files().joinpath().read_bytes",
    ): ReviewedCall("committed packaged descriptor registry", 1),
    (
        "mybench.registry",
        "pathlib.Path().read_bytes",
    ): ReviewedCall(
        "optional caller-supplied registry path; unused by the fixed manifest runner", 1
    ),
    (
        "mybench.claims.envelope",
        "importlib.resources.files().joinpath().read_text",
    ): ReviewedCall("committed packaged claim schema", 1),
    (
        "mybench.claims.envelope",
        "mybench.paths.load_device_key",
    ): ReviewedCall(
        "dormant device-signing convenience; fixed runner supplies a synthetic dev seed", 2
    ),
    (
        "mybench.claims.envelope",
        "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate",
    ): ReviewedCall(
        "dormant ephemeral dev-key convenience; fixed runner supplies a synthetic seed", 1
    ),
}

# These exact edges isolate deliberately impure helpers that deterministic
# stage entry points never call. Pure commitment/Merkle code remains visible
# transitively through the commitments compatibility facade.
REVIEWED_IMPORT_BOUNDARIES: Mapping[tuple[str, str], str] = {
    (
        "mybench.claims.envelope",
        "mybench.paths",
    ): "dormant device-key convenience functions; fixed claim runner uses dev seed",
    (
        "mybench.commitments",
        "mybench.nonce_generation",
    ): "CSPRNG-only capture helper; deterministic callers use commitment_tree re-exports",
}


class _AmbientStateVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, module_name: str | None):
        self.path = path
        self.module_name = module_name
        self.aliases: dict[str, str] = {}
        self.issues: list[AuditIssue] = []
        self.reviewed_hits: dict[tuple[str, str], int] = {}

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
        if isinstance(node, ast.Call):
            function = self._qualified_name(node.func)
            return f"{function}()" if function else None
        return None

    def _is_reviewed_call(self, name: str) -> bool:
        if self.module_name is None:
            return False
        key = (self.module_name, name)
        if key not in REVIEWED_CALLS:
            return False
        self.reviewed_hits[key] = self.reviewed_hits.get(key, 0) + 1
        return True

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        name = self._qualified_name(node.func)
        if name in {"__import__", "builtins.__import__", "importlib.import_module"}:
            target = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else "?"
            self._issue(node, f"forbidden dynamic import {target!r}; use a static audited import")
        elif name and not self._is_reviewed_call(name):
            if name in FORBIDDEN_CALLS:
                self._issue(
                    node,
                    f"forbidden {FORBIDDEN_CALLS[name]} call {name!r}; pass it as input",
                )
            elif name.startswith("mybench.paths."):
                self._issue(node, f"forbidden environment/filesystem helper call {name!r}")
            elif name == "open" or name.rsplit(".", 1)[-1] in FILESYSTEM_METHODS:
                self._issue(node, f"forbidden filesystem call {name!r}; pass bytes as input")
        self.generic_visit(node)


def audit_source(
    path: Path,
    *,
    module_name: str | None = None,
    reviewed_hits: dict[tuple[str, str], int] | None = None,
) -> list[AuditIssue]:
    """Return direct ambient-state violations in one Python source file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [
            AuditIssue(
                path,
                exc.lineno or 1,
                exc.offset or 1,
                f"cannot audit invalid syntax: {exc.msg}",
            )
        ]
    visitor = _AmbientStateVisitor(path, module_name)
    visitor.visit(tree)
    if reviewed_hits is not None:
        for key, count in visitor.reviewed_hits.items():
            reviewed_hits[key] = reviewed_hits.get(key, 0) + count
    return visitor.issues


def module_path(module_name: str, *, source_root: Path = SOURCE_ROOT) -> Path:
    """Resolve a first-party module name without importing it."""
    path = source_root.joinpath(*module_name.split("."))
    package = path / "__init__.py"
    module = path.with_suffix(".py")
    if package.is_file():
        return package
    if module.is_file():
        return module
    raise GateError(f"determinism configuration names missing module {module_name!r}")


def _module_path_or_none(module_name: str, source_root: Path) -> Path | None:
    try:
        return module_path(module_name, source_root=source_root)
    except GateError:
        return None


def _relative_import_base(
    current_module: str,
    current_path: Path,
    imported_module: str | None,
    level: int,
) -> str:
    package = current_module if current_path.name == "__init__.py" else current_module.rsplit(".", 1)[0]
    parts = package.split(".")
    if level > len(parts):
        return ""
    base_parts = parts[: len(parts) - (level - 1)]
    if imported_module:
        base_parts.extend(imported_module.split("."))
    return ".".join(base_parts)


def first_party_imports(
    module_name: str,
    path: Path,
    *,
    source_root: Path = SOURCE_ROOT,
) -> set[str]:
    """Resolve statically imported ``mybench`` modules for closure auditing."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            candidates = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _relative_import_base(module_name, path, node.module, node.level)
            else:
                base = node.module or ""
            candidates = [base]
            candidates.extend(f"{base}.{alias.name}" for alias in node.names if base)
        else:
            continue
        for candidate in candidates:
            if candidate == "mybench" or candidate.startswith("mybench."):
                if _module_path_or_none(candidate, source_root):
                    imports.add(candidate)
    return imports


def audit_module_closure(
    roots: Sequence[str],
    *,
    source_root: Path = SOURCE_ROOT,
) -> AuditClosure:
    """Audit roots plus every relevant statically imported first-party helper."""
    pending = list(roots)
    visited = set()
    issues = []
    reviewed_hits: dict[tuple[str, str], int] = {}
    skipped_boundaries = set()
    while pending:
        module_name = pending.pop()
        if module_name in visited:
            continue
        path = module_path(module_name, source_root=source_root)
        visited.add(module_name)
        issues.extend(
            audit_source(path, module_name=module_name, reviewed_hits=reviewed_hits)
        )
        for imported in first_party_imports(module_name, path, source_root=source_root):
            if (module_name, imported) in REVIEWED_IMPORT_BOUNDARIES:
                skipped_boundaries.add((module_name, imported))
                continue
            if imported not in visited:
                pending.append(imported)
    for key, allowance in REVIEWED_CALLS.items():
        module_name, call_name = key
        if module_name not in visited:
            continue
        actual = reviewed_hits.get(key, 0)
        if actual != allowance.expected_count:
            issues.append(
                AuditIssue(
                    module_path(module_name, source_root=source_root),
                    1,
                    1,
                    f"reviewed call count drift for {call_name!r}: "
                    f"expected {allowance.expected_count}, found {actual}",
                )
            )
    for parent, imported in REVIEWED_IMPORT_BOUNDARIES:
        if parent in visited and (parent, imported) not in skipped_boundaries:
            issues.append(
                AuditIssue(
                    module_path(parent, source_root=source_root),
                    1,
                    1,
                    f"reviewed import boundary is stale: {parent} -> {imported}",
                )
            )
    return AuditClosure(frozenset(visited), tuple(issues))


def discover_pipeline_modules(
    *,
    source_root: Path = SOURCE_ROOT,
    roots: Sequence[PipelineRoot] = PIPELINE_ROOTS,
    reviewed_non_stages: frozenset[str] = REVIEWED_NON_STAGE_MODULES,
) -> set[str]:
    """Discover compute/render modules while excluding only reviewed wrappers/helpers."""
    discovered = set()
    for root in roots:
        path = source_root.joinpath(*root.module.split("."))
        module_file = path.with_suffix(".py")
        if module_file.is_file():
            if root.module not in reviewed_non_stages:
                discovered.add(root.module)
            continue
        if not path.is_dir():
            if root.required:
                raise GateError(f"required pipeline package root is missing: {root.module}")
            continue
        for source in path.rglob("*.py"):
            if source.stem in WRAPPER_BASENAMES:
                continue
            module_name = ".".join(source.relative_to(source_root).with_suffix("").parts)
            if module_name in reviewed_non_stages:
                continue
            discovered.add(module_name)
    return discovered


def validate_pipeline_coverage(
    stages: Sequence[Stage],
    *,
    source_root: Path = SOURCE_ROOT,
    roots: Sequence[PipelineRoot] = PIPELINE_ROOTS,
    reviewed_non_stages: frozenset[str] = REVIEWED_NON_STAGE_MODULES,
) -> None:
    """Require exact discovered-module coverage by executable stage entries."""
    discovered = discover_pipeline_modules(
        source_root=source_root,
        roots=roots,
        reviewed_non_stages=reviewed_non_stages,
    )
    registered = {
        stage.entrypoint.module for stage in stages if stage.discovery_entry
    }
    missing = sorted(discovered - registered)
    extra = sorted(registered - discovered)
    if missing or extra:
        raise GateError(
            f"pipeline discovery/registration drift: missing={missing}, extra={extra}; "
            "every compute/render module needs its own executable stage runner"
        )


def validate_manifest_and_audit(
    stages: Sequence[Stage] = STAGES,
    runners: Mapping[str, object] = RUNNERS,
    *,
    source_root: Path = SOURCE_ROOT,
    roots: Sequence[PipelineRoot] = PIPELINE_ROOTS,
    reviewed_non_stages: frozenset[str] = REVIEWED_NON_STAGE_MODULES,
) -> AuditClosure:
    """Fail closed on registration drift, uncovered modules, or ambient state."""
    try:
        validate_registration(stages, runners)
    except ValueError as exc:
        raise GateError(str(exc)) from exc
    validate_pipeline_coverage(
        stages,
        source_root=source_root,
        roots=roots,
        reviewed_non_stages=reviewed_non_stages,
    )
    audit_roots = tuple(dict.fromkeys(root for stage in stages for root in stage.audit_roots))
    closure = audit_module_closure(audit_roots, source_root=source_root)
    if closure.issues:
        raise GateError(
            "ambient-state audit failed:\n" + "\n".join(str(issue) for issue in closure.issues)
        )
    return closure


def load_lock_pins(path: Path = LOCK_PATH) -> dict[str, str]:
    """Read the exact runtime/test dependency pins used by CI."""
    pins = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.count("==") != 1:
            raise GateError(f"unlocked CI dependency: {line}")
        name, version = line.split("==")
        normalized = canonicalize_name(name)
        if not version or normalized in pins:
            raise GateError(f"invalid or duplicate CI dependency pin: {line}")
        pins[normalized] = version
    return pins


def verify_installed_dependency_versions(path: Path = LOCK_PATH) -> None:
    """Prove pip left every locked runtime/test distribution at its exact pin."""
    mismatches = []
    for package, expected in sorted(load_lock_pins(path).items()):
        try:
            actual = metadata.version(package)
        except metadata.PackageNotFoundError:
            actual = "missing"
        if actual != expected:
            mismatches.append(f"{package}: expected {expected}, installed {actual}")
    if mismatches:
        raise GateError("installed dependencies do not match requirements-ci.lock: " + "; ".join(mismatches))


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


def _stream_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value.encode("utf-8", errors="replace") if isinstance(value, str) else value


def _stream_fingerprint(value: bytes | str | None) -> str:
    data = _stream_bytes(value)
    return f"{len(data)} bytes sha256:{hashlib.sha256(data).hexdigest()}"


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
    try:
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
    except subprocess.TimeoutExpired as exc:
        raise GateError(
            f"determinism stage {stage.name!r} run {run_number} timed out; "
            f"stderr={_stream_fingerprint(exc.stderr)}"
        ) from None
    if completed.returncode:
        raise GateError(
            f"determinism stage {stage.name!r} run {run_number} failed with "
            f"exit {completed.returncode}; stderr={_stream_fingerprint(completed.stderr)}"
        )
    if completed.stdout or completed.stderr:
        raise GateError(
            f"determinism stage {stage.name!r} run {run_number} wrote to process streams; "
            f"stdout={_stream_fingerprint(completed.stdout)}, "
            f"stderr={_stream_fingerprint(completed.stderr)}"
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
    """Validate dependencies, audit, then run every stage in two fresh processes."""
    verify_installed_dependency_versions()
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
