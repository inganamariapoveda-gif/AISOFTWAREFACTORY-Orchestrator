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

import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import sandbox as sandbox_mod

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

# ============================================================
# CLAUDE-EXECUTION-002: write-probe determinista en sandbox efímero.
#
# permission_mode propio ("acceptEdits"), separado por completo del
# handshake read-only anterior (que sigue exclusivamente en "plan"). Nunca
# se reutiliza ni se debilita _ALLOWED_PERMISSION_MODES.
# ============================================================
_WRITE_PROBE_PERMISSION_MODE = "acceptEdits"

# ============================================================
# TASK-EXECUTION-005: presupuesto de la ejecución genérica de un Developer
# Task Packet (run_developer_task), separado por completo del write-probe
# de arriba y del handshake read-only. Mismo permission_mode que el
# write-probe (ambos autorizan edición real), pero max_turns/timeout_seconds
# son PROPIOS y no se comparten (ver developer.task_execution en AGENTS.yaml).
# ============================================================
_TASK_EXECUTION_PERMISSION_MODE = "acceptEdits"

WRITE_PROBE_TARGET_FILENAME = "TARGET.txt"
WRITE_PROBE_DO_NOT_TOUCH_FILENAME = "DO_NOT_TOUCH.txt"
WRITE_PROBE_BEFORE_CONTENT = "BEFORE"
WRITE_PROBE_AFTER_CONTENT = "AFTER"
WRITE_PROBE_DO_NOT_TOUCH_CONTENT = "DO_NOT_TOUCH"
EXPECTED_WRITE_RESULT = "CLAUDE_WRITE_OK"

_EXPECTED_TARGET_AFTER_BYTES = WRITE_PROBE_AFTER_CONTENT.encode("utf-8")
_EXPECTED_TARGET_AFTER_SHA256 = hashlib.sha256(_EXPECTED_TARGET_AFTER_BYTES).hexdigest()
_EXPECTED_TARGET_AFTER_SIZE = len(_EXPECTED_TARGET_AFTER_BYTES)

# Prompt construido enteramente a partir de las constantes anteriores, para
# no duplicar los valores exactos exigidos en ningún otro lugar. No
# contiene rutas personales ni secretos.
WRITE_PROBE_PROMPT = (
    "You are working ONLY inside the current working directory (a disposable "
    "sandbox). "
    f"Modify EXCLUSIVELY the file {WRITE_PROBE_TARGET_FILENAME}: it currently "
    f"contains exactly \"{WRITE_PROBE_BEFORE_CONTENT}\"; replace its entire "
    f"content with exactly \"{WRITE_PROBE_AFTER_CONTENT}\" and nothing else. "
    f"Do not modify {WRITE_PROBE_DO_NOT_TOUCH_FILENAME}. Do not create, "
    "delete, or rename any file. Do not read or write anything outside this "
    "directory. Do not run Bash, PowerShell, or any other command. When "
    "done, reply with exactly one line and nothing else: "
    f"{EXPECTED_WRITE_RESULT}"
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


@dataclass(frozen=True)
class DeveloperWriteResult:
    success: bool
    result_text: str
    changed_paths: tuple[str, ...]
    created_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    target_before_hash: str | None
    target_after_hash: str | None
    session_id: str | None
    num_turns: int | None
    duration_ms: int | None
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


# ============================================================
# CLAUDE-EXECUTION-002: write-probe (sandbox efímero)
# ============================================================


def prepare_sandbox_files(sandbox: Path | str) -> None:
    """Crea TARGET.txt y DO_NOT_TOUCH.txt con contenido EXACTO dentro del
    sandbox, ANTES de invocar a Claude. No copia archivos del orquestador
    ni crea symlinks; no contiene secretos ni datos reales."""
    sandbox_path = Path(sandbox)
    (sandbox_path / WRITE_PROBE_TARGET_FILENAME).write_text(
        WRITE_PROBE_BEFORE_CONTENT, encoding="utf-8"
    )
    (sandbox_path / WRITE_PROBE_DO_NOT_TOUCH_FILENAME).write_text(
        WRITE_PROBE_DO_NOT_TOUCH_CONTENT, encoding="utf-8"
    )


def _validate_write_probe_config(
    developer_config: dict[str, Any],
) -> tuple[str, str, int, int, str]:
    """Valida developer.executable/output_format (compartidos con el
    handshake read-only) y developer.write_probe.* (independientes:
    permission_mode/restricted/max_turns/timeout_seconds propios)."""
    executable = developer_config.get("executable")
    output_format = developer_config.get("output_format")

    if not isinstance(executable, str) or not executable:
        raise DeveloperExecutionError("developer.executable must be a non-empty string")
    if output_format != "json":
        raise DeveloperExecutionError("developer.output_format must be 'json'")

    write_probe = developer_config.get("write_probe")
    if not isinstance(write_probe, dict):
        raise DeveloperExecutionError("developer.write_probe must be a mapping")

    max_turns = write_probe.get("max_turns")
    timeout_seconds = write_probe.get("timeout_seconds")
    permission_mode = write_probe.get("permission_mode")
    restricted = write_probe.get("restricted")

    if not isinstance(max_turns, int) or isinstance(max_turns, bool) or max_turns < 1:
        raise DeveloperExecutionError("developer.write_probe.max_turns must be a positive integer")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
    ):
        raise DeveloperExecutionError(
            "developer.write_probe.timeout_seconds must be a positive integer"
        )
    if permission_mode != _WRITE_PROBE_PERMISSION_MODE:
        raise DeveloperExecutionError(
            f"developer.write_probe.permission_mode must be {_WRITE_PROBE_PERMISSION_MODE!r}"
        )
    # Defensa en profundidad, independiente de config_loader (mismo patrón
    # que _validate_developer_config para el handshake read-only).
    if restricted is not True:
        raise DeveloperExecutionError("developer.write_probe.restricted must be true")

    return executable, output_format, max_turns, timeout_seconds, permission_mode


def run_write_probe(
    *,
    developer_config: dict[str, Any],
    cwd: Path | str,
    authorized_root: Path | str,
) -> DeveloperWriteResult:
    """Ejecuta un único write-probe determinista dentro de un sandbox ya
    preparado (ver prepare_sandbox_files()). No crea ni elimina el sandbox:
    esa responsabilidad es de orchestrator.sandbox y de quien orquesta la
    llamada (app.py).

    Falla cerrado ante cualquier anomalía: configuración incompleta,
    ejecutable ausente, cwd fuera de authorized_root, timeout, exit code
    != 0, JSON inválido/inesperado, o evidencia de filesystem que no
    coincide EXACTAMENTE con el contrato (solo TARGET.txt cambia, a
    exactamente AFTER; ningún archivo nuevo, eliminado o renombrado;
    DO_NOT_TOUCH.txt intacto). La evidencia de filesystem tiene prioridad
    sobre la narrativa de Claude: nunca se convierte un fallo en éxito.
    """
    executable_name, output_format, max_turns, timeout_seconds, permission_mode = (
        _validate_write_probe_config(developer_config)
    )
    executable_path = _resolve_executable(executable_name)
    resolved_cwd = _resolve_cwd(cwd, authorized_root)

    # Snapshot PRE: producido directamente por Python, antes de invocar a
    # Claude. Nunca se confía en su respuesta narrativa para saber qué
    # cambió realmente.
    pre_snapshot = sandbox_mod.snapshot(resolved_cwd)

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
            input=WRITE_PROBE_PROMPT,
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

    # Snapshot POST: independiente de si Claude "dice" haber terminado
    # correctamente.
    post_snapshot = sandbox_mod.snapshot(resolved_cwd)

    return _evaluate_write_probe(completed, pre_snapshot, post_snapshot)


def _evaluate_write_probe(
    completed: "subprocess.CompletedProcess[str]",
    pre_snapshot: dict[str, sandbox_mod.EntrySnapshot],
    post_snapshot: dict[str, sandbox_mod.EntrySnapshot],
) -> DeveloperWriteResult:
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

    # Handshake determinista (mismo criterio que el read-only, hallazgo 1 de
    # CORRECTION-001): sin coincidencia parcial ni normalización.
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
    if result_text != EXPECTED_WRITE_RESULT:
        raise DeveloperExecutionError(
            "developer write-probe 'result' did not match the expected exact text"
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

    # Evidencia de filesystem, independiente de la narrativa de Claude: la
    # respuesta JSON validada arriba NUNCA es suficiente por sí sola.
    target_pre = pre_snapshot.get(WRITE_PROBE_TARGET_FILENAME)
    if target_pre is None or target_pre.kind != "file":
        raise DeveloperExecutionError("TARGET.txt did not exist as a file before the probe")

    pre_paths = set(pre_snapshot)
    post_paths = set(post_snapshot)
    created = sorted(post_paths - pre_paths)
    deleted = sorted(pre_paths - post_paths)
    changed = sorted(
        path for path in (pre_paths & post_paths) if pre_snapshot[path] != post_snapshot[path]
    )

    if created:
        raise DeveloperExecutionError("write probe created unexpected path(s)")
    if deleted:
        raise DeveloperExecutionError("write probe deleted unexpected path(s)")
    if changed != [WRITE_PROBE_TARGET_FILENAME]:
        raise DeveloperExecutionError("write probe modified an unexpected set of paths")

    target_post = post_snapshot[WRITE_PROBE_TARGET_FILENAME]
    if (
        target_post.kind != "file"
        or target_post.sha256 != _EXPECTED_TARGET_AFTER_SHA256
        or target_post.size != _EXPECTED_TARGET_AFTER_SIZE
    ):
        raise DeveloperExecutionError("TARGET.txt content after the probe did not match exactly")

    return DeveloperWriteResult(
        success=True,
        result_text=result_text,
        changed_paths=tuple(changed),
        created_paths=tuple(created),
        deleted_paths=tuple(deleted),
        target_before_hash=target_pre.sha256,
        target_after_hash=target_post.sha256,
        session_id=session_id,
        num_turns=num_turns,
        duration_ms=duration_ms,
        exit_code=completed.returncode,
    )


# ============================================================
# TASK-EXECUTION-002/005: run_developer_task (adaptador genérico de tarea de
# desarrollo, D-EXEC-002).
#
# Reutiliza EXCLUSIVAMENTE helpers ya existentes (_resolve_executable,
# _resolve_cwd, _build_args, _FORBIDDEN_FLAGS, DeveloperResult): las MISMAS
# garantías de seguridad que el write-probe (CLAUDE-EXECUTION-002) --
# permission-mode acceptEdits, --restricted, shell=False, prompt por stdin,
# cwd confinado -- sin duplicar esa lógica ni tocar
# run_handshake()/run_write_probe(). TASK-EXECUTION-005: run_developer_task
# ya NO reutiliza developer.write_probe como configuración operacional --
# EXECUTION-DIAG-002 mostró que 3 turnos (presupuesto del write-probe,
# pensado para una única escritura mínima determinista) no es un
# presupuesto fiable para una instrucción de desarrollo genérica arbitraria.
# Usa exclusivamente developer.task_execution (_validate_task_execution_config),
# un bloque de configuración separado e independiente: cambiar
# write_probe.max_turns nunca afecta a run_developer_task, y viceversa.
#
# A diferencia del handshake/write-probe (deterministas, con un texto de
# 'result' exacto exigido), run_developer_task recibe un prompt ARBITRARIO
# (la developer instruction de un Task Packet) y por tanto NUNCA puede
# exigir un texto de respuesta específico. Solo valida la ESTRUCTURA del
# JSON (type/subtype/is_error/result). Claude nunca es autoridad sobre
# éxito (D-EXEC-002): ese juicio pertenece a capas posteriores (Git
# Evidence + mandatory tests), fuera de este adaptador.
# ============================================================


def _validate_task_execution_config(
    developer_config: dict[str, Any],
) -> tuple[str, str, int, int, str]:
    """TASK-EXECUTION-005: valida developer.executable/output_format
    (compartidos con el handshake/write-probe) y developer.task_execution.*
    (presupuesto PROPIO e independiente de write_probe: max_turns/
    timeout_seconds/permission_mode/restricted propios). Falla cerrado sin
    fallback a write_probe: si task_execution falta o es inválido, esto
    lanza DeveloperExecutionError -- run_developer_task nunca ejecuta con un
    presupuesto ajeno al declarado explícitamente para este propósito."""
    executable = developer_config.get("executable")
    output_format = developer_config.get("output_format")

    if not isinstance(executable, str) or not executable:
        raise DeveloperExecutionError("developer.executable must be a non-empty string")
    if output_format != "json":
        raise DeveloperExecutionError("developer.output_format must be 'json'")

    task_execution = developer_config.get("task_execution")
    if not isinstance(task_execution, dict):
        raise DeveloperExecutionError("developer.task_execution must be a mapping")

    if task_execution.get("enabled") is not True:
        raise DeveloperExecutionError("developer.task_execution.enabled must be true")

    max_turns = task_execution.get("max_turns")
    timeout_seconds = task_execution.get("timeout_seconds")
    permission_mode = task_execution.get("permission_mode")
    restricted = task_execution.get("restricted")

    if not isinstance(max_turns, int) or isinstance(max_turns, bool) or max_turns < 1:
        raise DeveloperExecutionError("developer.task_execution.max_turns must be a positive integer")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
    ):
        raise DeveloperExecutionError(
            "developer.task_execution.timeout_seconds must be a positive integer"
        )
    if permission_mode != _TASK_EXECUTION_PERMISSION_MODE:
        raise DeveloperExecutionError(
            f"developer.task_execution.permission_mode must be {_TASK_EXECUTION_PERMISSION_MODE!r}"
        )
    if restricted is not True:
        raise DeveloperExecutionError("developer.task_execution.restricted must be true")

    return executable, output_format, max_turns, timeout_seconds, permission_mode


def run_developer_task(
    *,
    developer_config: dict[str, Any],
    prompt: str,
    cwd: Path | str,
    authorized_root: Path | str,
) -> DeveloperResult:
    """Ejecuta una única instrucción de desarrollo estructurada (Task
    Packet) con Claude Code CLI, dentro de authorized_root.

    Falla cerrado (DeveloperExecutionError) ante cualquier anomalía:
    configuración incompleta, ejecutable ausente, cwd fuera de
    authorized_root, timeout, exit code != 0, JSON inválido, is_error
    verdadero, o forma inesperada. Nunca convierte un fallo en éxito y
    nunca exige un texto exacto de 'result' (no PASS/SUCCESS/DONE ni
    equivalente): solo su forma estructural. TASK-EXECUTION-005: usa
    EXCLUSIVAMENTE developer.task_execution, nunca developer.write_probe."""
    executable_name, output_format, max_turns, timeout_seconds, permission_mode = (
        _validate_task_execution_config(developer_config)
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

    return _parse_generic_task_result(completed)


# TASK-EXECUTION-003: diagnóstico seguro y acotado de un fallo de
# run_developer_task (exit_code != 0). Nunca expone el prompt (enviado por
# stdin, ni siquiera visible aquí) ni el stdout/stderr crudos completos;
# nunca expone el campo JSON `result` (puede contener contenido arbitrario
# del modelo). Solo campos ESTRUCTURALES allowlisted de un stdout JSON, y un
# fragmento acotado/saneado de stderr.
_FAILURE_DIAGNOSTIC_ALLOWED_STDOUT_FIELDS: tuple[str, ...] = (
    "type",
    "subtype",
    "is_error",
    "api_error_status",
    "stop_reason",
    "permission_denials",
)

_FAILURE_DIAGNOSTIC_MAX_STDERR_CHARS = 500

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_stderr_diagnostic(stderr: str) -> str:
    """Convierte stderr en un fragmento de diagnóstico ACOTADO Y SANEADO:
    saltos de línea -> espacio, caracteres de control eliminados, espacios
    colapsados/trim, y recortado a lo sumo a
    _FAILURE_DIAGNOSTIC_MAX_STDERR_CHARS caracteres. Nunca intenta
    interpretar credenciales; simplemente acota el texto crudo."""
    if not stderr:
        return ""
    no_newlines = stderr.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    no_control = _CONTROL_CHARS_RE.sub(" ", no_newlines)
    collapsed = " ".join(no_control.split())
    return collapsed[:_FAILURE_DIAGNOSTIC_MAX_STDERR_CHARS]


def _build_failure_diagnostic(completed: "subprocess.CompletedProcess[str]") -> str:
    """Construye el diagnóstico saneado y acotado para exit_code != 0.
    Conserva SIEMPRE exit_code. Si stdout es JSON válido (objeto), extrae
    ÚNICAMENTE los campos allowlisted presentes (nunca `result`, nunca
    session/usage/transcript). Si stdout no es JSON válido y stderr está
    vacío, reporta solamente `stdout_present=true` sin reproducir su
    contenido. stderr, si no está vacío, se añade saneado y acotado."""
    parts = [f"exit_code={completed.returncode}"]

    stdout = completed.stdout or ""
    parsed: dict[str, Any] | None = None
    if stdout:
        try:
            candidate = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            candidate = None
        if isinstance(candidate, dict):
            parsed = candidate

    if parsed is not None:
        for field in _FAILURE_DIAGNOSTIC_ALLOWED_STDOUT_FIELDS:
            if field in parsed:
                parts.append(f"{field}={parsed[field]!r}")

    sanitized_stderr = _sanitize_stderr_diagnostic(completed.stderr or "")
    if sanitized_stderr:
        parts.append(f"stderr={sanitized_stderr!r}")
    elif parsed is None and stdout:
        parts.append("stdout_present=true")

    return "; ".join(parts)


def _parse_generic_task_result(
    completed: "subprocess.CompletedProcess[str]",
) -> DeveloperResult:
    """Validación PURAMENTE estructural (D-EXEC-002): nunca exige un texto
    de 'result' específico. Mismo criterio de tipos que
    _parse_completed_process()/_evaluate_write_probe() para type/subtype/
    is_error/session_id/num_turns/duration_ms; la única diferencia
    deliberada es que aquí NO se compara result_text contra ningún valor
    fijo (a diferencia del handshake/write-probe, deterministas)."""
    if completed.returncode != 0:
        raise DeveloperExecutionError(
            f"developer execution failed: {_build_failure_diagnostic(completed)}"
        )

    try:
        data = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise DeveloperExecutionError("developer output is not valid JSON") from exc

    if not isinstance(data, dict):
        raise DeveloperExecutionError("developer JSON output is not a JSON object")

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
