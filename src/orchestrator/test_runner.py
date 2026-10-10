"""Resolve mandatory-test commands as data; local execution is prohibited.

Logical IDs require both global permission and an exact project mapping.
Resolution never authorizes execution. No isolated backend is integrated yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, NoReturn, Sequence

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


def require_isolated_mandatory_test_backend() -> NoReturn:
    """Fail closed until an isolated backend is separately admitted/integrated."""
    raise TestRunnerError(ISOLATED_BACKEND_UNAVAILABLE)


def run_mandatory_test(
    test_id: str,
    *,
    project_commands: Mapping[str, Any],
    globally_allowed_ids: Sequence[str],
    cwd: Path | str,
    timeout: int,
) -> NoReturn:
    """Compatibility boundary: resolve, then reject every execution attempt.

    cwd and timeout remain API metadata; neither causes host access or execution.
    TestResult remains a reporting data contract, not a local execution backend.
    """
    resolve_mandatory_test(
        test_id, project_commands=project_commands,
        globally_allowed_ids=globally_allowed_ids,
    )
    raise TestRunnerError(ISOLATED_BACKEND_UNAVAILABLE)
