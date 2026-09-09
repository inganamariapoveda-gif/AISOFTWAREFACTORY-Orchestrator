"""CLI mínima del orquestador (BOOTSTRAP) — §17.

Demuestra, sin conectar Director/Claude Code: inicializar almacenamiento,
registrar el proyecto SAMPLE, crear una tarea, consultarla, solicitar una
transición de estado y consultar su historial.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import sandbox as sandbox_mod
from .adapters.claude_code import (
    HANDSHAKE_PROMPT,
    DeveloperExecutionError,
    prepare_sandbox_files,
    run_handshake,
    run_write_probe,
)
from .config_loader import ConfigError, OrchestratorConfig, load_core_config, load_project_rules
from .sandbox import SandboxError
from .state_machine import StateMachineError
from .store import InvalidIdError, Store, StoreError, validate_id

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"
PROJECTS_DIR = REPO_ROOT / "projects"
DEFAULT_DB_PATH = REPO_ROOT / "orchestrator.db"


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
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
