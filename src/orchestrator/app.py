"""CLI mínima del orquestador (BOOTSTRAP) — §17.

Demuestra, sin conectar Director/Claude Code: inicializar almacenamiento,
registrar el proyecto SAMPLE, crear una tarea, consultarla, solicitar una
transición de estado y consultar su historial.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import evidence as evidence_mod
from . import sandbox as sandbox_mod
from . import task_packet as task_packet_mod
from . import test_runner as test_runner_mod
from .adapters.claude_code import (
    HANDSHAKE_PROMPT,
    DeveloperExecutionError,
    prepare_sandbox_files,
    run_developer_task,
    run_handshake,
    run_write_probe,
)
from .config_loader import (
    ConfigError,
    OrchestratorConfig,
    load_core_config,
    load_project_rules,
    resolve_project_root,
)
from .evidence import EvidenceError
from .sandbox import SandboxError
from .state_machine import StateMachineError
from .store import InvalidIdError, Store, StoreError, validate_id
from .task_packet import TaskPacket, TaskPacketError

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"
PROJECTS_DIR = REPO_ROOT / "projects"
TASKS_DIR = REPO_ROOT / "tasks"
SAMPLE_TASK_PACKET_PATH = TASKS_DIR / "SAMPLE_TASK.yaml"
DEFAULT_DB_PATH = REPO_ROOT / "orchestrator.db"

# TASK-EXECUTION-002: timeout fijo (segundos) para cada mandatory_test
# resuelto/ejecutado por test_runner.run_mandatory_test(). No es específico
# de PILOT-001 ni de ningún proyecto; un valor razonable de orquestador.
MANDATORY_TEST_TIMEOUT_SECONDS = 300

# Estados deterministas del resultado de task-execution-probe (D-EXEC-002):
# nunca "éxito narrativo" de Claude, siempre evidencia ejecutable. No se
# modifica la definición de HUMAN_GATE/HUMAN_FUNCTIONAL_TEST de GATES.yaml;
# estas son solo las etiquetas literales que ya declara ese archivo.
STATE_HUMAN_GATE = "HUMAN_GATE"
STATE_BLOCKED = "BLOCKED"
HUMAN_GATE_FUNCTIONAL_TEST = "HUMAN_FUNCTIONAL_TEST"


class CliError(Exception):
    """Error de uso de la CLI (rutas fuera del directorio del orquestador, etc.)."""


def _ensure_within_repo(path: Path) -> Path:
    resolved = path.resolve()
    if REPO_ROOT not in (resolved, *resolved.parents):
        raise CliError(
            f"refusing to write outside the orchestrator directory: {resolved}"
        )
    return resolved


def _resolve_project_rules_path(project_id: str) -> Path:
    validate_id(project_id, "project_id")
    return PROJECTS_DIR / project_id / "PROJECT_RULES.yaml"


def _require_core_config() -> OrchestratorConfig:
    """Falla cerrado: ninguna operación de la CLI procede sin config core válida."""
    return load_core_config(CONFIG_DIR)


def _require_project_rules(project_id: str) -> dict:
    """Falla cerrado: ninguna operación sobre un proyecto procede sin sus
    PROJECT_RULES.yaml válidas, y sin que rules['project_id'] coincida
    exactamente con el project_id solicitado. Sin esta comprobación,
    PROJECT_RULES.yaml de un proyecto podría reescribirse para declarar el
    project_id de otro y seguir siendo estructuralmente válido, permitiendo
    que un proyecto opere con las reglas de otro (CORRECTION-002)."""
    rules_path = _resolve_project_rules_path(project_id)
    rules = load_project_rules(rules_path)
    if rules["project_id"] != project_id:
        raise ConfigError(
            f"PROJECT_RULES.yaml project_id ({rules['project_id']!r}) does not "
            f"match requested project {project_id!r} ({rules_path})"
        )
    return rules


def cmd_init_storage(args: argparse.Namespace) -> int:
    _require_core_config()
    db_path = _ensure_within_repo(Path(args.db_path))
    with Store(db_path):
        pass
    print(f"storage initialized at {db_path}")
    return 0


def cmd_register_project(args: argparse.Namespace) -> int:
    _require_core_config()
    rules = _require_project_rules(args.project_id)
    db_path = _ensure_within_repo(Path(args.db_path))
    rules_path = _resolve_project_rules_path(args.project_id)
    with Store(db_path) as store:
        store.register_project(
            project_id=args.project_id,
            name=rules.get("name", args.project_id),
            repo_path=rules["repo_path"],
            rules_ref=str(rules_path),
        )
    print(f"project {args.project_id} registered")
    return 0


def cmd_create_task(args: argparse.Namespace) -> int:
    _require_core_config()
    _require_project_rules(args.project_id)
    db_path = _ensure_within_repo(Path(args.db_path))
    with Store(db_path) as store:
        store.create_task(args.task_id, args.project_id, args.title, args.need)
    print(f"task {args.task_id} created in BACKLOG")
    return 0


def cmd_get_task(args: argparse.Namespace) -> int:
    _require_core_config()
    db_path = _ensure_within_repo(Path(args.db_path))
    with Store(db_path) as store:
        task = store.get_task(args.task_id)
    if task is None:
        print(f"error: task {args.task_id!r} not found", file=sys.stderr)
        return 1
    print(json.dumps(task, indent=2))
    return 0


def cmd_transition(args: argparse.Namespace) -> int:
    _require_core_config()
    db_path = _ensure_within_repo(Path(args.db_path))
    with Store(db_path) as store:
        # Lectura únicamente: identificar el proyecto de la tarea no muta
        # estado y permite validar sus PROJECT_RULES ANTES de transicionar.
        task = store.get_task(args.task_id)
        if task is None:
            print(f"error: task {args.task_id!r} not found", file=sys.stderr)
            return 1
        _require_project_rules(task["project_id"])
        updated = store.transition_task(args.task_id, args.to_status, args.reason, args.actor)
    print(json.dumps(updated, indent=2))
    return 0


def cmd_developer_probe(args: argparse.Namespace) -> int:
    """CLAUDE-EXECUTION-001: handshake seguro y no interactivo con Claude
    Code CLI. No autoriza edición ni Bash; no recibe Task Packet; no ejecuta
    tareas de desarrollo reales (§17 roadmap: eso es un incremento futuro).
    cwd y authorized_root quedan fijos en REPO_ROOT: en este incremento la
    ejecución se limita exclusivamente a este repositorio."""
    config = _require_core_config()
    developer_config = config.agents.get("agents", {}).get("developer", {})
    if developer_config.get("enabled") is not True:
        print("error: developer is not enabled in AGENTS.yaml", file=sys.stderr)
        return 1

    result = run_handshake(
        developer_config=developer_config,
        prompt=HANDSHAKE_PROMPT,
        cwd=REPO_ROOT,
        authorized_root=REPO_ROOT,
    )

    summary = {
        "success": result.success,
        "is_error": result.is_error,
        "exit_code": result.exit_code,
        "session_id": result.session_id,
        "num_turns": result.num_turns,
        "duration_ms": result.duration_ms,
        "result_text": result.result_text,
    }
    print(json.dumps(summary, indent=2))
    return 0


def cmd_developer_write_probe(args: argparse.Namespace) -> int:
    """CLAUDE-EXECUTION-002: autoriza una única escritura determinista
    (TARGET.txt: BEFORE -> AFTER) dentro de un sandbox efímero DENTRO de
    REPO_ROOT. El sandbox es el único lugar que Claude puede leer/escribir;
    nunca AIP, FOA, projects/SAMPLE, src/, tests/ ni config/. Se elimina
    siempre al finalizar (éxito o fallo controlado), vía finally."""
    config = _require_core_config()
    developer_config = config.agents.get("agents", {}).get("developer", {})
    write_probe_config = developer_config.get("write_probe", {})
    if write_probe_config.get("enabled") is not True:
        print("error: write_probe is not enabled in AGENTS.yaml", file=sys.stderr)
        return 1

    sandbox_path = sandbox_mod.create_sandbox(REPO_ROOT)
    try:
        prepare_sandbox_files(sandbox_path)
        result = run_write_probe(
            developer_config=developer_config,
            cwd=sandbox_path,
            authorized_root=sandbox_path,
        )
    finally:
        sandbox_mod.cleanup_sandbox(sandbox_path, repo_root=REPO_ROOT)

    summary = {
        "success": result.success,
        "changed_paths": list(result.changed_paths),
        "created_paths": list(result.created_paths),
        "deleted_paths": list(result.deleted_paths),
        "result_text": result.result_text,
    }
    print(json.dumps(summary, indent=2))
    return 0


def _setup_fake_evidence_repo(repo_path: Path) -> None:
    """Configura un repositorio Git ficticio y desechable para
    evidence-probe. Esto es setup de la DEMOSTRACIÓN (código de
    probe/CLI), no una capacidad genérica del recolector de evidencia
    (orchestrator/evidence.py es READ-ONLY por diseño). Identidad LOCAL y
    claramente ficticia; NUNCA se toca `git config --global`. Sin remote,
    sin push."""
    (repo_path / "allowed.txt").write_text("BEFORE", encoding="utf-8")
    (repo_path / "untouched.txt").write_text("UNCHANGED", encoding="utf-8")

    git_exe = shutil.which("git")
    if git_exe is None:
        raise CliError("git executable not found on PATH")

    def _git(*args: str) -> None:
        try:
            subprocess.run(
                [git_exe, *args],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise CliError(
                f"git {args[0]} failed while setting up the evidence probe repo "
                f"(exit_code={exc.returncode})"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CliError(f"git {args[0]} timed out while setting up the evidence probe repo") from exc

    _git("init")
    _git("config", "user.name", "Evidence Probe")
    _git("config", "user.email", "evidence-probe@localhost")
    _git("add", "allowed.txt", "untouched.txt")
    _git("commit", "-m", "baseline")


def cmd_evidence_probe(args: argparse.Namespace) -> int:
    """EVIDENCE-001: demuestra el recolector reutilizable de evidencia Git
    sobre un repositorio Git ficticio y desechable, DENTRO de REPO_ROOT.
    No conecta AIP ni FOA; no invoca Claude Code (no gasta llamada de
    modelo). El sandbox se crea y elimina con los mismos controles de
    seguridad que developer-write-probe (prefijo propio, confinado a
    REPO_ROOT, verificación de identidad antes de seguir cualquier
    enlace)."""
    _require_core_config()
    repo_path = sandbox_mod.create_sandbox(
        REPO_ROOT, prefix=evidence_mod.GIT_EVIDENCE_PROBE_PREFIX
    )
    try:
        _setup_fake_evidence_repo(repo_path)

        before = evidence_mod.capture_snapshot(repo_path, authorized_root=REPO_ROOT)

        # Modificación EXCLUSIVAMENTE vía Python directo (no Claude, no
        # subprocess): BEFORE -> AFTER en allowed.txt.
        (repo_path / "allowed.txt").write_text("AFTER", encoding="utf-8")

        change_evidence = evidence_mod.capture_change_evidence(before, ["allowed.txt"])
        result = evidence_mod.evaluate(change_evidence, expected_head_unchanged=True)
    finally:
        sandbox_mod.cleanup_sandbox(
            repo_path, repo_root=REPO_ROOT, prefix=evidence_mod.GIT_EVIDENCE_PROBE_PREFIX
        )

    summary = {
        "success": result.success,
        "base_sha": result.base_sha,
        "current_head_sha": result.current_head_sha,
        "head_changed": result.head_changed,
        "changed_paths": list(result.changed_paths),
        "created_paths": list(result.created_paths),
        "deleted_paths": list(result.deleted_paths),
        "renamed_paths": [list(pair) for pair in result.renamed_paths],
        "untracked_paths": list(result.untracked_paths),
        "out_of_scope_paths": list(result.out_of_scope_paths),
        "reason": result.reason,
    }
    print(json.dumps(summary, indent=2))
    return 0 if result.success else 1


def cmd_task_packet_probe(args: argparse.Namespace) -> int:
    """TASK-PACKET-001: demuestra el contrato Task Packet definition ->
    validation -> deterministic developer instruction sobre
    tasks/SAMPLE_TASK.yaml (completamente ficticio). NUNCA invoca Claude
    Code, NUNCA ejecuta comandos/tests del proyecto, NUNCA modifica
    ningún archivo: es exclusivamente carga + validación + construcción
    determinista de texto en memoria."""
    _require_core_config()
    packet = task_packet_mod.load_task_packet_from_yaml_file(SAMPLE_TASK_PACKET_PATH)

    instruction_1 = task_packet_mod.build_developer_instruction(packet)
    instruction_2 = task_packet_mod.build_developer_instruction(packet)
    instruction_deterministic = instruction_1 == instruction_2

    summary = {
        "valid": True,
        "task_id": packet.task_id,
        "project_id": packet.project_id,
        "authorized_files": list(packet.authorized_files),
        "forbidden_files": list(packet.forbidden_files),
        "mandatory_tests": list(packet.mandatory_tests),
        "instruction_deterministic": instruction_deterministic,
    }
    print(json.dumps(summary, indent=2))
    return 0 if instruction_deterministic else 1


def _evaluate_scope_security(
    change_evidence: evidence_mod.GitChangeEvidence,
    *,
    forbidden_files: tuple[str, ...],
) -> tuple[bool, str]:
    """TASK-EXECUTION-002/CORRECTION-001: evalúa (HEAD unchanged + scope) +
    forbidden_files a partir de una captura de evidencia dada. Reutilizada
    TAL CUAL para la evidencia PRE-TEST y para la evidencia POST-TEST
    (misma lógica, sin duplicarla): AMBAS deben pasar (PRE_TEST_EVIDENCE ==
    PASS Y POST_TEST_EVIDENCE == PASS). Devuelve (security_review, reason);
    reason es "all checks passed" cuando security_review es True."""
    evidence_result = evidence_mod.evaluate(change_evidence, expected_head_unchanged=True)
    touched_paths = sorted(
        set(change_evidence.changed_paths)
        | set(change_evidence.created_paths)
        | set(change_evidence.deleted_paths)
        | set(change_evidence.untracked_paths)
        | {p for pair in change_evidence.renamed_paths for p in pair}
    )
    forbidden_violations = [p for p in touched_paths if p in set(forbidden_files)]
    if not evidence_result.success:
        return False, evidence_result.reason
    if forbidden_violations:
        return False, f"forbidden file(s) modified: {forbidden_violations}"
    return True, "all checks passed"


def execute_task_packet(
    packet: TaskPacket,
    *,
    project_rules: dict[str, Any],
    developer_config: dict[str, Any],
    permissions: dict[str, Any],
    orchestrator_repo_root: Path,
    mandatory_test_timeout: int,
) -> dict[str, Any]:
    """TASK-EXECUTION-002: compone el flujo mínimo seguro --

        TaskPacket -> project authorization -> developer instruction ->
        generic Claude adapter -> Git Evidence -> scope verification ->
        mandatory test resolver/runner -> deterministic technical/security
        gate -> HUMAN_FUNCTIONAL_TEST -> STOP

    -- SIN commit automático. Función determinista dado el mismo estado
    externo (Git real, subprocess mockeado en pruebas); NUNCA invoca
    git add/commit/reset/checkout/clean, NUNCA revierte nada. Claude nunca
    es autoridad sobre éxito (D-EXEC-002): éxito real = Git Evidence +
    scope validation + mandatory tests, evaluados aquí exclusivamente a
    partir de evidencia ejecutable (evidence_mod/test_runner_mod), nunca de
    la narrativa de run_developer_task().

    Cualquier fallo (repo sucio, developer con timeout/resultado
    malformado, cambio fuera de alcance, HEAD modificado, mandatory test
    desconocido/no autorizado/fallido) se traduce en un resultado
    estructurado con state=BLOCKED -- nunca en una excepción sin controlar
    ni en un éxito silencioso. Solo si TODAS las capas pasan se alcanza
    state=HUMAN_GATE/human_gate=HUMAN_FUNCTIONAL_TEST, siempre con
    commit_performed=False."""

    def _blocked(reason: str, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "task_id": packet.task_id,
            "project_id": packet.project_id,
            "state": STATE_BLOCKED,
            "human_gate": None,
            "developer_completed": False,
            "head_unchanged": True,
            "changed_paths": [],
            "out_of_scope_paths": [],
            "mandatory_tests": list(packet.mandatory_tests),
            "tests_passed": False,
            "technical_review": False,
            "security_review": False,
            "pre_test_evidence_passed": False,
            "post_test_evidence_passed": False,
            "commit_performed": False,
            "reason": reason,
        }
        base.update(overrides)
        return base

    # 2-4. project authorization + project root resolution (D-EXEC-003):
    # repo_path viene EXCLUSIVAMENTE de PROJECT_RULES, nunca del Task Packet.
    try:
        project_root = resolve_project_root(
            project_rules,
            project_id=packet.project_id,
            orchestrator_repo_root=orchestrator_repo_root,
        )
    except ConfigError as exc:
        return _blocked(f"project root resolution failed: {exc}")

    # 5-6. Git BEFORE (snapshot ORIGINAL); el working tree debe estar
    # limpio antes de invocar al developer, o STOP inmediato (nunca se
    # invoca Claude sobre un repo sucio). CORRECTION-001: este mismo
    # snapshot `before` -- nunca uno nuevo capturado después de Claude o
    # después de los mandatory tests -- es la base de AMBAS evaluaciones
    # de evidencia (PRE-TEST y POST-TEST) más abajo.
    try:
        before = evidence_mod.capture_snapshot(project_root, authorized_root=project_root)
    except EvidenceError as exc:
        return _blocked(f"git BEFORE snapshot failed: {exc}")

    if not before.is_clean:
        return _blocked("working tree is not clean before developer execution")

    # 7-8. developer instruction determinista + adaptador genérico de Claude.
    instruction = task_packet_mod.build_developer_instruction(packet)
    try:
        run_developer_task(
            developer_config=developer_config,
            prompt=instruction,
            cwd=project_root,
            authorized_root=project_root,
        )
    except DeveloperExecutionError as exc:
        return _blocked(f"developer execution failed: {exc}")

    # 9-11. Git evidence PRE-TEST (contra el BEFORE original) + evaluación
    # (HEAD unchanged, scope, forbidden_files). Debe pasar ANTES de
    # ejecutar ningún mandatory test.
    try:
        pre_test_change_evidence = evidence_mod.capture_change_evidence(
            before, packet.authorized_files
        )
    except EvidenceError as exc:
        return _blocked(f"git PRE-TEST evidence failed: {exc}", developer_completed=True)

    pre_test_security_review, pre_test_reason = _evaluate_scope_security(
        pre_test_change_evidence, forbidden_files=packet.forbidden_files
    )

    common_fields = {
        "developer_completed": True,
        "head_unchanged": not pre_test_change_evidence.head_changed,
        "changed_paths": list(pre_test_change_evidence.changed_paths),
        "out_of_scope_paths": list(pre_test_change_evidence.out_of_scope_paths),
    }

    if not pre_test_security_review:
        return _blocked(
            pre_test_reason,
            security_review=False,
            pre_test_evidence_passed=False,
            **common_fields,
        )

    # 12-14. mandatory tests: resolver/ejecutar cada uno; cualquier fallo ->
    # STOP. La evidencia PRE-TEST ya pasó en este punto (pre_test_evidence_
    # passed=True), pero POST-TEST todavía no se ha comprobado.
    for test_id in packet.mandatory_tests:
        try:
            test_result = test_runner_mod.run_mandatory_test(
                test_id,
                project_commands=project_rules["commands"],
                globally_allowed_ids=permissions["allowed_commands"],
                cwd=project_root,
                timeout=mandatory_test_timeout,
            )
        except test_runner_mod.TestRunnerError as exc:
            return _blocked(
                f"mandatory test resolution/execution failed: {exc}",
                security_review=pre_test_security_review,
                pre_test_evidence_passed=True,
                **common_fields,
            )
        if not test_result.success:
            return _blocked(
                f"mandatory test {test_id!r} failed",
                security_review=pre_test_security_review,
                pre_test_evidence_passed=True,
                **common_fields,
            )

    # CORRECTION-001 (SECURITY_REVIEW: CHANGES_REQUESTED): un mandatory
    # test preautorizado puede retornar exit code 0 y aun así mutar el
    # repositorio (modificar forbidden_files, tocar un archivo fuera de
    # alcance, crear un untracked inesperado, o incluso mover HEAD). El
    # exit code del test NUNCA es autoridad suficiente por sí solo: se
    # vuelve a capturar y evaluar evidencia -- SIEMPRE contra el mismo
    # `before` original, nunca un nuevo baseline post-Claude/post-test --
    # y debe pasar TAMBIÉN, o STOP. Sin rollback automático: nunca
    # git reset/checkout/clean, solo BLOCK.
    try:
        post_test_change_evidence = evidence_mod.capture_change_evidence(
            before, packet.authorized_files
        )
    except EvidenceError as exc:
        return _blocked(
            f"git POST-TEST evidence failed: {exc}",
            developer_completed=True,
            pre_test_evidence_passed=True,
        )

    post_test_security_review, post_test_reason = _evaluate_scope_security(
        post_test_change_evidence, forbidden_files=packet.forbidden_files
    )

    # El resultado final (changed_paths/out_of_scope_paths/head_unchanged)
    # SIEMPRE representa el estado POST-TEST, nunca el PRE-TEST ya
    # obsoleto: es la evidencia más reciente y por tanto la única
    # autoritativa sobre el estado final del repositorio.
    common_fields = {
        "developer_completed": True,
        "head_unchanged": not post_test_change_evidence.head_changed,
        "changed_paths": list(post_test_change_evidence.changed_paths),
        "out_of_scope_paths": list(post_test_change_evidence.out_of_scope_paths),
    }

    if not post_test_security_review:
        return _blocked(
            post_test_reason,
            security_review=False,
            pre_test_evidence_passed=True,
            post_test_evidence_passed=False,
            **common_fields,
        )

    # 15-18. deterministic technical/security gate: PRE-TEST PASS + tests
    # PASS + POST-TEST PASS -> HUMAN_GATE/HUMAN_FUNCTIONAL_TEST -> STOP.
    # Nunca commit.
    return {
        "task_id": packet.task_id,
        "project_id": packet.project_id,
        "state": STATE_HUMAN_GATE,
        "human_gate": HUMAN_GATE_FUNCTIONAL_TEST,
        "mandatory_tests": list(packet.mandatory_tests),
        "tests_passed": True,
        "technical_review": True,
        "security_review": True,
        "pre_test_evidence_passed": True,
        "post_test_evidence_passed": True,
        "commit_performed": False,
        "reason": "all checks passed",
        **common_fields,
    }


def cmd_task_execution_probe(args: argparse.Namespace) -> int:
    """TASK-EXECUTION-002: probe genérico (no ligado a ningún proyecto ni
    Task Packet específico -- no hardcodea PILOT-001) del flujo mínimo
    seguro de ejecución de un Task Packet. Nunca hace commit; se detiene
    siempre en HUMAN_GATE/HUMAN_FUNCTIONAL_TEST si todas las capas pasan, o
    en BLOCKED estructurado si alguna falla. No se ejecuta contra ningún
    proyecto real en esta tarea (mocks/temp repos exclusivamente en
    pruebas)."""
    config = _require_core_config()
    packet_path = _ensure_within_repo(Path(args.task_packet_path))
    packet = task_packet_mod.load_task_packet_from_yaml_file(packet_path)
    project_rules = _require_project_rules(packet.project_id)
    developer_config = config.agents.get("agents", {}).get("developer", {})

    result = execute_task_packet(
        packet,
        project_rules=project_rules,
        developer_config=developer_config,
        permissions=config.permissions,
        orchestrator_repo_root=REPO_ROOT,
        mandatory_test_timeout=MANDATORY_TEST_TIMEOUT_SECONDS,
    )

    print(json.dumps(result, indent=2))
    return 0 if result["state"] == STATE_HUMAN_GATE else 1


def cmd_history(args: argparse.Namespace) -> int:
    _require_core_config()
    db_path = _ensure_within_repo(Path(args.db_path))
    with Store(db_path) as store:
        history = store.get_history(args.task_id)
    print(json.dumps(history, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description="AISOFTWAREFACTORY Development Orchestrator — BOOTSTRAP CLI",
    )
    parser.add_argument(
        "--db-path", default=str(DEFAULT_DB_PATH), help="Ruta del archivo SQLite"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-storage", help="Inicializar el almacenamiento SQLite")
    p.set_defaults(func=cmd_init_storage)

    p = sub.add_parser(
        "register-project", help="Registrar un proyecto desde PROJECT_RULES.yaml"
    )
    p.add_argument("project_id")
    p.set_defaults(func=cmd_register_project)

    p = sub.add_parser("create-task", help="Crear una tarea en BACKLOG")
    p.add_argument("task_id")
    p.add_argument("project_id")
    p.add_argument("title")
    p.add_argument("need")
    p.set_defaults(func=cmd_create_task)

    p = sub.add_parser("get-task", help="Consultar una tarea")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_get_task)

    p = sub.add_parser("transition", help="Solicitar una transición de estado")
    p.add_argument("task_id")
    p.add_argument("to_status")
    p.add_argument("--reason", default="")
    # No existe rol de "operador técnico humano" en el proyecto (Master Spec
    # §2, §8): quien ejecuta la transición debe identificarse explícitamente,
    # sin actor implícito por defecto.
    p.add_argument("--actor", required=True)
    p.set_defaults(func=cmd_transition)

    p = sub.add_parser("history", help="Consultar el historial de estados")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser(
        "developer-probe",
        help="Handshake seguro y no interactivo con Claude Code CLI (sin edición, sin Bash)",
    )
    p.set_defaults(func=cmd_developer_probe)

    p = sub.add_parser(
        "developer-write-probe",
        help="Escritura determinista controlada en un sandbox efímero (TARGET.txt: BEFORE -> AFTER)",
    )
    p.set_defaults(func=cmd_developer_write_probe)

    p = sub.add_parser(
        "evidence-probe",
        help="Demuestra el recolector de evidencia Git sobre un repositorio ficticio desechable",
    )
    p.set_defaults(func=cmd_evidence_probe)

    p = sub.add_parser(
        "task-packet-probe",
        help="Demuestra Task Packet definition -> validation -> deterministic developer instruction",
    )
    p.set_defaults(func=cmd_task_packet_probe)

    p = sub.add_parser(
        "task-execution-probe",
        help=(
            "Compone TaskPacket -> project authorization -> developer instruction -> "
            "generic Claude adapter -> Git Evidence -> mandatory tests -> Human Gate (STOP, sin commit)"
        ),
    )
    p.add_argument("task_packet_path")
    p.set_defaults(func=cmd_task_execution_probe)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (
        ConfigError,
        StateMachineError,
        InvalidIdError,
        StoreError,
        CliError,
        DeveloperExecutionError,
        SandboxError,
        EvidenceError,
        TaskPacketError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
