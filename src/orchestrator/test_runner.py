"""Resolve mandatory-test commands as data; local execution is prohibited.

Logical IDs require both global permission and an exact project mapping.
Resolution never authorizes execution. Backends are supplied only by the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

# Mismo patrón que task_packet._IDENTIFIER_RE / config_loader._LOGICAL_ID_RE:
# letra inicial, luego letras/dígitos/guion/guion bajo. Por construcción
# rechaza espacios, "&&", "|", ";", rutas y cualquier metacarácter de shell.
_LOGICAL_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


ISOLATED_BACKEND_UNAVAILABLE = "isolated mandatory-test execution backend unavailable"


class TestRunnerError(Exception):
    """Fallo de resolución/validación como datos o rechazo de ejecución.
    El backend aislado es obligatorio; la ejecución local está prohibida.
    Nunca se convierte el bloqueo en un TestResult de éxito."""


@dataclass(frozen=True)
class TestResult:
    test_id: str
    argv: tuple[str, ...]
    success: bool
    exit_code: int
    stdout: str
    stderr: str


def _validate_test_id(test_id: Any) -> str:
    if not isinstance(test_id, str) or not test_id:
        raise TestRunnerError("test_id must be a non-empty string")
    if "\x00" in test_id:
        raise TestRunnerError("test_id must not contain NUL characters")
    if not _LOGICAL_ID_RE.fullmatch(test_id):
        raise TestRunnerError(
            f"test_id must be a simple logical identifier, not a shell command: {test_id!r}"
        )
    return test_id


def _validate_resolved_argv(argv: Any, test_id: str) -> tuple[str, ...]:
    """Revalida defensivamente el argv resuelto (además de config_loader):
    lista no vacía de strings no vacíos, sin listas anidadas, sin null."""
    if not isinstance(argv, list) or not argv:
        raise TestRunnerError(
            f"resolved argv for test_id {test_id!r} must be a non-empty list"
        )
    for idx, item in enumerate(argv):
        if not isinstance(item, str) or not item:
            raise TestRunnerError(
                f"resolved argv[{idx}] for test_id {test_id!r} must be a non-empty string"
            )
    return tuple(argv)


@dataclass(frozen=True)
class ResolvedMandatoryTest:
    test_id: str
    argv: tuple[str, ...]


def resolve_mandatory_test(
    test_id: str,
    *,
    project_commands: Mapping[str, Any],
    globally_allowed_ids: Sequence[str],
) -> ResolvedMandatoryTest:
    """Validate the exact mapping and return immutable data, never execute it."""
    validated_id = _validate_test_id(test_id)

    allowed_set = frozenset(globally_allowed_ids)
    if validated_id not in allowed_set:
        raise TestRunnerError(f"mandatory test {validated_id!r} is not globally allowed")
    if validated_id not in project_commands:
        raise TestRunnerError(
            f"mandatory test {validated_id!r} has no command mapping for this project"
        )

    argv = _validate_resolved_argv(project_commands[validated_id], validated_id)

    return ResolvedMandatoryTest(test_id=validated_id, argv=argv)


@dataclass(frozen=True)
class ExternalTestOutcome:
    """Untrusted backend data, never technical or security approval."""

    test_id: str
    argv: tuple[str, ...]
    success: bool
    exit_code: int
    stdout: str
    stderr: str


class IsolatedTestBackend(Protocol):
    """Engine-owned injection boundary; no provider or local executor here."""

    def execute(
        self, resolved: ResolvedMandatoryTest, *, cwd: Path | str, timeout: int,
    ) -> ExternalTestOutcome: ...


def require_isolated_mandatory_test_backend(
    backend: IsolatedTestBackend | None = None,
) -> None:
    """Check availability without invoking the backend or authorizing any ID."""
    if backend is None:
        raise TestRunnerError(ISOLATED_BACKEND_UNAVAILABLE)
    try:
        valid = callable(getattr(backend, "execute", None))
    except Exception:
        valid = False
    if not valid:
        raise TestRunnerError("invalid isolated mandatory-test backend")


def run_mandatory_test(
    test_id: str,
    *,
    project_commands: Mapping[str, Any],
    globally_allowed_ids: Sequence[str],
    cwd: Path | str,
    timeout: int,
    backend: IsolatedTestBackend | None = None,
) -> TestResult:
    """Resolve authorized data, delegate externally, then validate the outcome.

    cwd and timeout remain API metadata; neither causes host access or execution.
    No backend is selected from project rules or task input. No local fallback.
    """
    resolved = resolve_mandatory_test(
        test_id, project_commands=project_commands,
        globally_allowed_ids=globally_allowed_ids,
    )
    require_isolated_mandatory_test_backend(backend)
    try:
        outcome = backend.execute(resolved, cwd=cwd, timeout=timeout)
        valid = (
            type(outcome) is ExternalTestOutcome
            and type(outcome.test_id) is str
            and outcome.test_id == resolved.test_id
            and type(outcome.argv) is tuple
            and all(type(arg) is str for arg in outcome.argv)
            and outcome.argv == resolved.argv
            and type(outcome.success) is bool
            and type(outcome.exit_code) is int
            and outcome.success == (outcome.exit_code == 0)
            and type(outcome.stdout) is str
            and type(outcome.stderr) is str
        )
    except Exception:
        # Backend messages/tracebacks may contain secrets: do not expose them.
        raise TestRunnerError("isolated mandatory-test backend failed") from None
    if not valid:
        raise TestRunnerError("invalid isolated mandatory-test outcome")
    return TestResult(
        test_id=resolved.test_id, argv=resolved.argv, success=outcome.success,
        exit_code=outcome.exit_code, stdout=outcome.stdout, stderr=outcome.stderr,
    )
