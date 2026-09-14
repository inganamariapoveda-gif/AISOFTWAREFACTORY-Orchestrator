"""Test runner — TASK-EXECUTION-002.

Responsabilidad única: resolver y ejecutar mandatory_test IDs autorizados.
NUNCA ejecuta un test_id como comando: solo un lookup EXACTO en
`project_commands` (ya validado como argv por config_loader) produce el
argv preautorizado a ejecutar (INVARIANTE TÉCNICO de task_packet.py:
UNKNOWN ID = FAIL CLOSED, nunca subprocess([test_id])/shell(test_id)/
os.system(test_id), nunca shlex sobre valores del Task Packet).

La autorización efectiva exige la INTERSECCIÓN obligatoria (D-EXEC-001,
PERMISSIONS §6):

    test_id IN globally_allowed_ids  Y  test_id IN project_commands

en ese orden -- ambas condiciones se comprueban ANTES de tocar
project_commands[test_id]. Falta cualquiera de las dos: FAIL CLOSED.

subprocess siempre con lista de argumentos, shell=False, cwd explícito,
timeout acotado -- mismo patrón que evidence.py/adapters/claude_code.py.
Los mensajes de excepción nunca incluyen stdout/stderr crudo ni ilimitado
(mismo patrón que evidence._run_git); el TestResult devuelto en éxito o en
fallo controlado (exit code != 0) sí conserva stdout/stderr completos, para
que capas superiores puedan mostrarlos como evidencia.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

# Mismo patrón que task_packet._IDENTIFIER_RE / config_loader._LOGICAL_ID_RE:
# letra inicial, luego letras/dígitos/guion/guion bajo. Por construcción
# rechaza espacios, "&&", "|", ";", rutas y cualquier metacarácter de shell.
_LOGICAL_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class TestRunnerError(Exception):
    """Fallo controlado de resolución/ejecución de un mandatory test. Falla
    cerrado: nunca se traduce en un TestResult "de éxito" sintético."""


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


def run_mandatory_test(
    test_id: str,
    *,
    project_commands: Mapping[str, Any],
    globally_allowed_ids: Sequence[str],
    cwd: Path | str,
    timeout: int,
) -> TestResult:
    """Resuelve y ejecuta un único mandatory_test ID autorizado.

    Proceso obligatorio (fail closed en cada paso):
    1. valida la forma de test_id (identificador lógico, nunca comando);
    2. exige test_id EN globally_allowed_ids (PERMISSIONS.allowed_commands);
    3. exige test_id EN project_commands (PROJECT_RULES.commands), con
       lookup EXACTO -- ambas condiciones, nunca solo una;
    4. revalida el argv resuelto;
    5. subprocess.run(argv, shell=False, cwd=cwd, timeout=timeout, ...).

    Un exit code != 0 NO lanza excepción: se devuelve como
    TestResult(success=False, ...), evidencia ejecutable para la capa que
    decide. Solo lo estructural/de autorización (ID desconocido, no
    autorizado, argv inválido, timeout, ejecutable ausente) es
    TestRunnerError."""
    validated_id = _validate_test_id(test_id)

    allowed_set = frozenset(globally_allowed_ids)
    if validated_id not in allowed_set:
        raise TestRunnerError(f"mandatory test {validated_id!r} is not globally allowed")
    if validated_id not in project_commands:
        raise TestRunnerError(
            f"mandatory test {validated_id!r} has no command mapping for this project"
        )

    argv = _validate_resolved_argv(project_commands[validated_id], validated_id)

    resolved_cwd = Path(cwd).resolve()
    if not resolved_cwd.is_dir():
        raise TestRunnerError(f"cwd is not a directory: {resolved_cwd}")

    try:
        completed = subprocess.run(
            list(argv),
            shell=False,
            cwd=str(resolved_cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise TestRunnerError(
            f"mandatory test {validated_id!r} executable could not be launched: "
            f"{type(exc).__name__}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TestRunnerError(
            f"mandatory test {validated_id!r} timed out after {timeout}s"
        ) from exc

    return TestResult(
        test_id=validated_id,
        argv=argv,
        success=completed.returncode == 0,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
