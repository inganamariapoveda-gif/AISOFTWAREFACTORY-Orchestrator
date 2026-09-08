"""ClaudeCodeAdapter — adaptador programático DeveloperPort -> Claude Code CLI.

CLAUDE-EXECUTION-001: HANDSHAKE seguro únicamente. Invoca `claude` en modo no
interactivo (`-p`/`--print`), con `--permission-mode plan` (sin autorización
de edición ni Bash) y valida defensivamente la salida JSON. Este adaptador NO
ejecuta tareas de desarrollo reales ni recibe un Task Packet: esa capacidad
es alcance de un incremento posterior (§17 roadmap, CLAUDE EXECUTION).

Reglas de seguridad aplicadas aquí (Master Spec §10, §11):
- subprocess siempre con lista de argumentos, con el intérprete de shell
  deshabilitado explícitamente, sin `os.system` ni invocación vía shell;
- el prompt se envía por stdin (`input=`), nunca como argumento de línea de
  comandos, para no exponerlo en listados de procesos;
- el ejecutable se resuelve con `shutil.which()` a partir de configuración,
  nunca una ruta hardcodeada específica del usuario;
- el directorio de trabajo se resuelve a ruta canónica y se verifica que
  esté dentro de una raíz autorizada antes de usarse como `cwd`;
- `--dangerously-skip-permissions` / `--allow-dangerously-skip-permissions`
  están prohibidos incondicionalmente;
- cualquier anomalía (ejecutable ausente, timeout, exit code != 0, JSON
  inválido, `is_error` verdadero o de tipo inesperado, formato inesperado)
  se traduce en un fallo controlado (`DeveloperExecutionError`); nunca se
  convierte silenciosamente en éxito;
- los mensajes de error son sanitizados: tipo de error, exit code, duración
  si se conoce — nunca el prompt completo ni stdout/stderr crudos.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Handshake determinista (CORRECTION-001, hallazgo 1): el texto exacto que
# debe devolver Claude. No se acepta coincidencia parcial, startswith, ni
# ninguna normalización que convierta una respuesta distinta en válida.
EXPECTED_HANDSHAKE_RESULT = "CLAUDE_EXECUTION_OK - analysis mode, no changes made."

# Prompt de handshake fijo: no contiene secretos ni datos de negocio, no
# pide lectura/modificación de AIP/FOA, y pide explícitamente confirmar modo
# de análisis sin cambios. Reutiliza EXPECTED_HANDSHAKE_RESULT para no
# duplicar el valor exacto exigido en la respuesta.
HANDSHAKE_PROMPT = (
    "This is a safe, read-only handshake check running in plan/analysis "
    "mode. Do not read, write, or modify any files, and do not run any "
    "shell commands. Reply with exactly one line and nothing else: "
    f"{EXPECTED_HANDSHAKE_RESULT}"
)

_ALLOWED_PERMISSION_MODES = frozenset({"plan"})

_FORBIDDEN_FLAGS = frozenset(
    {
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
    }
)


class DeveloperExecutionError(Exception):
    """Fallo controlado del adaptador Developer. Nunca se traduce en éxito."""


@dataclass(frozen=True)
class DeveloperResult:
    success: bool
    result_text: str
    session_id: str | None
    num_turns: int | None
    duration_ms: int | None
    is_error: bool
    exit_code: int


def _validate_developer_config(developer_config: dict[str, Any]) -> tuple[str, str, int, int, str]:
    executable = developer_config.get("executable")
    output_format = developer_config.get("output_format")
    max_turns = developer_config.get("max_turns")
    timeout_seconds = developer_config.get("timeout_seconds")
    permission_mode = developer_config.get("permission_mode")
    restricted = developer_config.get("restricted")

    if not isinstance(executable, str) or not executable:
        raise DeveloperExecutionError("developer.executable must be a non-empty string")
    if output_format != "json":
        raise DeveloperExecutionError("developer.output_format must be 'json'")
    if not isinstance(max_turns, int) or isinstance(max_turns, bool) or max_turns < 1:
        raise DeveloperExecutionError("developer.max_turns must be a positive integer")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
    ):
        raise DeveloperExecutionError("developer.timeout_seconds must be a positive integer")
    if permission_mode not in _ALLOWED_PERMISSION_MODES:
        raise DeveloperExecutionError(
            f"developer.permission_mode must be one of {sorted(_ALLOWED_PERMISSION_MODES)}"
        )
    # Defensa en profundidad (CORRECTION-001, hallazgo 2): permission-mode
    # plan no es la única barrera; --restricted quita las herramientas que
    # ejecutan comandos/código. Validado aquí también, independientemente
    # de config_loader, por si el adaptador se invoca directamente.
    if restricted is not True:
        raise DeveloperExecutionError("developer.restricted must be true")

    return executable, output_format, max_turns, timeout_seconds, permission_mode


def _resolve_executable(executable_name: str) -> str:
    """Resuelve el ejecutable vía shutil.which(); nunca inventa una ruta."""
    resolved = shutil.which(executable_name)
    if resolved is None:
        raise DeveloperExecutionError(
            f"executable {executable_name!r} not found on PATH"
        )
    return resolved


def _resolve_cwd(cwd: Path | str, authorized_root: Path | str) -> Path:
    """Confina la ejecución a authorized_root (nunca AIP/FOA/directorios padre)."""
    authorized_root_resolved = Path(authorized_root).resolve()
    resolved = Path(cwd).resolve()
    if not resolved.exists():
        raise DeveloperExecutionError(f"cwd does not exist: {resolved}")
    if not resolved.is_dir():
        raise DeveloperExecutionError(f"cwd is not a directory: {resolved}")
    if authorized_root_resolved not in (resolved, *resolved.parents):
        raise DeveloperExecutionError(
            "cwd is outside the authorized root for this increment"
        )
    return resolved


def _build_args(
    executable_path: str,
    *,
    output_format: str,
    max_turns: int,
    permission_mode: str,
) -> list[str]:
    """Construye la lista de argumentos. El prompt NUNCA se incluye aquí:
    se envía por stdin en run_handshake(). --restricted es obligatorio en
    este incremento (CORRECTION-001, hallazgo 2): defensa en profundidad
    además de --permission-mode plan, quita las herramientas que ejecutan
    comandos/código."""
    return [
        executable_path,
        "-p",
        "--output-format",
        output_format,
        "--max-turns",
        str(max_turns),
        "--permission-mode",
        permission_mode,
        "--restricted",
    ]


def _parse_completed_process(
    completed: "subprocess.CompletedProcess[str]",
) -> DeveloperResult:
    if completed.returncode != 0:
        raise DeveloperExecutionError(
            f"developer execution failed: exit_code={completed.returncode}"
        )

    try:
        data = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise DeveloperExecutionError("developer output is not valid JSON") from exc

    if not isinstance(data, dict):
        raise DeveloperExecutionError("developer JSON output is not a JSON object")

    # Handshake determinista (CORRECTION-001, hallazgo 1): se exige la forma
    # exacta de una respuesta de éxito de `claude -p --output-format json`.
    # Ninguna coincidencia parcial, startswith, ni normalización puede
    # convertir una respuesta distinta en válida.
    if data.get("type") != "result":
        raise DeveloperExecutionError("developer JSON 'type' is missing or is not 'result'")

    if data.get("subtype") != "success":
        raise DeveloperExecutionError("developer JSON 'subtype' is missing or is not 'success'")

    is_error = data.get("is_error")
    if not isinstance(is_error, bool) or is_error:
        raise DeveloperExecutionError(f"developer reported is_error={is_error!r}")

    result_text = data.get("result")
    if not isinstance(result_text, str):
        raise DeveloperExecutionError("developer JSON missing string 'result' field")
    if result_text != EXPECTED_HANDSHAKE_RESULT:
        # No se registra el valor recibido: podría contener contenido
        # arbitrario devuelto por el modelo (§ sanitización de logs).
        raise DeveloperExecutionError(
            "developer handshake 'result' did not match the expected exact text"
        )

    session_id = data.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        raise DeveloperExecutionError("developer JSON 'session_id' has unexpected type")

    num_turns = data.get("num_turns")
    if num_turns is not None and (not isinstance(num_turns, int) or isinstance(num_turns, bool)):
        raise DeveloperExecutionError("developer JSON 'num_turns' has unexpected type")

    duration_ms = data.get("duration_ms")
    if duration_ms is not None and (
        not isinstance(duration_ms, int) or isinstance(duration_ms, bool)
    ):
        raise DeveloperExecutionError("developer JSON 'duration_ms' has unexpected type")

    return DeveloperResult(
        success=True,
        result_text=result_text,
        session_id=session_id,
        num_turns=num_turns,
        duration_ms=duration_ms,
        is_error=False,
        exit_code=completed.returncode,
    )


def run_handshake(
    *,
    developer_config: dict[str, Any],
    prompt: str,
    cwd: Path | str,
    authorized_root: Path | str,
) -> DeveloperResult:
    """Ejecuta un único handshake no interactivo con Claude Code CLI.

    Falla cerrado (DeveloperExecutionError) ante cualquier anomalía:
    configuración incompleta, ejecutable ausente, cwd no autorizado,
    timeout, exit code != 0, JSON inválido, is_error verdadero o formato
    inesperado. Nunca convierte un fallo en éxito.
    """
    executable_name, output_format, max_turns, timeout_seconds, permission_mode = (
        _validate_developer_config(developer_config)
    )
    executable_path = _resolve_executable(executable_name)
    resolved_cwd = _resolve_cwd(cwd, authorized_root)

    args = _build_args(
        executable_path,
        output_format=output_format,
        max_turns=max_turns,
        permission_mode=permission_mode,
    )

    for arg in args:
        if arg in _FORBIDDEN_FLAGS:
            raise DeveloperExecutionError("forbidden flag present in constructed command")

    try:
        completed = subprocess.run(
            args,
            input=prompt,
            cwd=str(resolved_cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise DeveloperExecutionError(
            f"executable could not be launched: {type(exc).__name__}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DeveloperExecutionError(
            f"developer execution timed out after {timeout_seconds}s"
        ) from exc

    return _parse_completed_process(completed)
