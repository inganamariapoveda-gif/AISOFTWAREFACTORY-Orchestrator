"""Config loader — lee y valida los cinco archivos YAML de configuración.

Fuente de verdad: 01_MASTER_SPEC.md §7, §10, §13.

Reglas de seguridad aplicadas aquí:
- carga segura de YAML (yaml.safe_load), nunca constructores arbitrarios;
- ninguna clave con forma de secreto (api_key, secret, token, password,
  credential) puede aparecer en ninguna configuración;
- toda configuración obligatoria ausente o inválida falla cerrado, sin
  aplicar valores por defecto que debiliten una política de seguridad.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|credential)", re.IGNORECASE
)

REQUIRED_CLASSIFICATION_LEVELS = frozenset({"VERDE", "AMARILLO", "ROJO"})
REQUIRED_ON_UNCLASSIFIED = "BLOCKED"
REQUIRED_HUMAN_GATES = frozenset(
    {
        "HUMAN_UI_REVIEW",
        "HUMAN_FUNCTIONAL_TEST",
        "HUMAN_BUSINESS_DECISION",
        "HUMAN_CRITICAL_APPROVAL",
    }
)
# CLAUDE-EXECUTION-001: modos de permiso admitidos para agents.developer
# cuando enabled: true (handshake seguro con Claude Code CLI, §17 roadmap).
ALLOWED_DEVELOPER_PERMISSION_MODES = frozenset({"plan"})

# CLAUDE-EXECUTION-002: permission_mode propio y separado para el
# write-probe en sandbox efímero. Nunca se reutiliza para el handshake
# read-only, que permanece exclusivamente en "plan".
WRITE_PROBE_PERMISSION_MODE = "acceptEdits"
REQUIRED_PERMISSION_DENY_KEYS = (
    "deny.production",
    "deny.git_push",
    "deny.git_merge",
    "deny.irreversible_actions",
    "deny.env_files",
    "deny.secret_files",
)


class ConfigError(Exception):
    """Configuración faltante, inválida o insegura. Falla cerrado."""


@dataclass(frozen=True)
class OrchestratorConfig:
    policies: dict[str, Any]
    agents: dict[str, Any]
    gates: dict[str, Any]
    permissions: dict[str, Any]


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"required configuration file missing: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(
            f"configuration file {path} must contain a YAML mapping at top level"
        )
    _reject_secrets(data, path)
    return data


def _reject_secrets(node: Any, path: Path, trail: str = "") -> None:
    # Un valor booleano bajo una clave con forma de "secreto" (p. ej.
    # deny.secret_files: true) es una política declarativa, no un secreto;
    # cualquier otro valor bajo esa misma forma de clave se rechaza.
    if isinstance(node, dict):
        for key, value in node.items():
            key_str = str(key)
            location = f"{trail}.{key_str}" if trail else key_str
            if SECRET_KEY_PATTERN.search(key_str) and not isinstance(value, bool):
                raise ConfigError(
                    f"potential secret key '{location}' found in {path}; "
                    "secrets must never appear in configuration"
                )
            _reject_secrets(value, path, location)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _reject_secrets(item, path, f"{trail}[{idx}]")


def _require(data: dict[str, Any], dotted_path: str, path: Path) -> Any:
    node: Any = data
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise ConfigError(f"missing required key '{dotted_path}' in {path}")
        node = node[part]
    return node


def _require_true(data: dict[str, Any], dotted_path: str, path: Path) -> None:
    value = _require(data, dotted_path, path)
    if value is not True:
        raise ConfigError(f"'{dotted_path}' must be true in {path}")


def _validate_policies(data: dict[str, Any], path: Path) -> None:
    _require_true(data, "prohibitions.production", path)
    _require_true(data, "prohibitions.git_push", path)
    _require_true(data, "prohibitions.git_merge", path)
    _require_true(data, "prohibitions.irreversible_actions", path)
    _require_true(data, "fail_closed", path)

    max_attempts = _require(data, "attempts.max_correction_attempts", path)
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ConfigError(
            f"'attempts.max_correction_attempts' must be a positive integer in {path}"
        )

    levels = _require(data, "classification.levels", path)
    if not isinstance(levels, list) or set(levels) != REQUIRED_CLASSIFICATION_LEVELS:
        raise ConfigError(
            f"'classification.levels' must be exactly {sorted(REQUIRED_CLASSIFICATION_LEVELS)} "
            f"in {path}"
        )

    # Una acción no clasificada nunca hereda silenciosamente un nivel que el
    # Director pudiera aprobar más adelante: debe detenerse y escalar (§0, §8).
    on_unclassified = _require(data, "classification.on_unclassified", path)
    if on_unclassified != REQUIRED_ON_UNCLASSIFIED:
        raise ConfigError(
            f"'classification.on_unclassified' must be {REQUIRED_ON_UNCLASSIFIED!r} "
            f"in {path}"
        )


def _validate_agents(data: dict[str, Any], path: Path) -> None:
    # Director permanece con enabled: false de forma inamovible en este
    # incremento (CLAUDE-EXECUTION-001 solo autoriza al Developer, §0 D1/D2).
    director = _require(data, "agents.director", path)
    if not isinstance(director, dict):
        raise ConfigError(f"'agents.director' must be a mapping in {path}")
    if director.get("enabled") is not False:
        raise ConfigError(f"agent 'director' must have enabled: false ({path})")

    developer = _require(data, "agents.developer", path)
    if not isinstance(developer, dict):
        raise ConfigError(f"'agents.developer' must be a mapping in {path}")
    developer_enabled = developer.get("enabled")
    if not isinstance(developer_enabled, bool):
        raise ConfigError(
            f"agent 'developer' must declare a boolean 'enabled' ({path})"
        )
    if developer_enabled:
        _validate_developer_handshake_config(developer, path)
    # Independiente de developer_enabled: si alguien declara write_probe
    # habilitado, sus campos deben ser válidos de todos modos (fail closed,
    # sin defaults silenciosos).
    _validate_write_probe_config(developer, path)


def _validate_developer_handshake_config(developer: dict[str, Any], path: Path) -> None:
    """CLAUDE-EXECUTION-001: si developer.enabled es true, exige declarar
    todos los campos del handshake seguro con Claude Code CLI. Falla cerrado
    si falta cualquiera o tiene un valor inválido."""
    executable = developer.get("executable")
    if not isinstance(executable, str) or not executable:
        raise ConfigError(
            f"'agents.developer.executable' must be a non-empty string when enabled ({path})"
        )
    if developer.get("output_format") != "json":
        raise ConfigError(
            f"'agents.developer.output_format' must be 'json' when enabled ({path})"
        )
    max_turns = developer.get("max_turns")
    if not isinstance(max_turns, int) or isinstance(max_turns, bool) or max_turns < 1:
        raise ConfigError(
            f"'agents.developer.max_turns' must be a positive integer when enabled ({path})"
        )
    timeout_seconds = developer.get("timeout_seconds")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
    ):
        raise ConfigError(
            f"'agents.developer.timeout_seconds' must be a positive integer when enabled ({path})"
        )
    if developer.get("permission_mode") not in ALLOWED_DEVELOPER_PERMISSION_MODES:
        raise ConfigError(
            "'agents.developer.permission_mode' must be one of "
            f"{sorted(ALLOWED_DEVELOPER_PERMISSION_MODES)} when enabled ({path})"
        )
    # CORRECTION-001, hallazgo 2: defensa en profundidad — permission_mode
    # plan no es la única barrera; --restricted quita las herramientas que
    # ejecutan comandos/código. No se permite un default silencioso.
    if developer.get("restricted") is not True:
        raise ConfigError(
            f"'agents.developer.restricted' must be true when enabled ({path})"
        )


def _validate_write_probe_config(developer: dict[str, Any], path: Path) -> None:
    """CLAUDE-EXECUTION-002: agents.developer.write_probe es opt-in y
    separado del handshake read-only. Si está ausente, no se exige nada
    (compatibilidad retroactiva). Si está presente, 'enabled' debe ser un
    booleano explícito; si es true, exige permission_mode=='acceptEdits',
    restricted==true, max_turns y timeout_seconds válidos. Falla cerrado
    sin defaults silenciosos que debiliten el control."""
    write_probe = developer.get("write_probe")
    if write_probe is None:
        return
    if not isinstance(write_probe, dict):
        raise ConfigError(f"'agents.developer.write_probe' must be a mapping in {path}")

    enabled = write_probe.get("enabled")
    if not isinstance(enabled, bool):
        raise ConfigError(
            f"'agents.developer.write_probe.enabled' must be a boolean when declared ({path})"
        )
    if not enabled:
        return

    if write_probe.get("permission_mode") != WRITE_PROBE_PERMISSION_MODE:
        raise ConfigError(
            "'agents.developer.write_probe.permission_mode' must be "
            f"{WRITE_PROBE_PERMISSION_MODE!r} when enabled ({path})"
        )
    if write_probe.get("restricted") is not True:
        raise ConfigError(
            f"'agents.developer.write_probe.restricted' must be true when enabled ({path})"
        )
    max_turns = write_probe.get("max_turns")
    if not isinstance(max_turns, int) or isinstance(max_turns, bool) or max_turns < 1:
        raise ConfigError(
            f"'agents.developer.write_probe.max_turns' must be a positive integer when enabled ({path})"
        )
    timeout_seconds = write_probe.get("timeout_seconds")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
    ):
        raise ConfigError(
            "'agents.developer.write_probe.timeout_seconds' must be a positive integer "
            f"when enabled ({path})"
        )


def _validate_gates(data: dict[str, Any], path: Path) -> None:
    _require_true(data, "automatic_approval.verde", path)
    _require_true(data, "director_internal_gate.amarillo_contemplado", path)

    human_gates = _require(data, "human_gates", path)
    if not isinstance(human_gates, list) or not human_gates:
        raise ConfigError(f"'human_gates' must be a non-empty list in {path}")
    names = {gate.get("name") for gate in human_gates if isinstance(gate, dict)}
    missing = REQUIRED_HUMAN_GATES - names
    if missing:
        raise ConfigError(
            f"'human_gates' missing required gates {sorted(missing)} in {path}"
        )

    _require(data, "escalation.decision_material_no_contemplada", path)


def _validate_permissions(data: dict[str, Any], path: Path) -> None:
    for key in REQUIRED_PERMISSION_DENY_KEYS:
        _require_true(data, key, path)
    allowed_commands = _require(data, "allowed_commands", path)
    if not isinstance(allowed_commands, list):
        raise ConfigError(f"'allowed_commands' must be a list in {path}")


def _validate_project_rules(data: dict[str, Any], path: Path) -> None:
    for key in ("project_id", "repo_path", "commands", "protected_paths"):
        _require(data, key, path)
    if not isinstance(data["project_id"], str) or not data["project_id"]:
        raise ConfigError(f"'project_id' must be a non-empty string in {path}")
    if not isinstance(data["commands"], dict):
        raise ConfigError(f"'commands' must be a mapping in {path}")
    if not isinstance(data["protected_paths"], list):
        raise ConfigError(f"'protected_paths' must be a list in {path}")


def load_core_config(config_dir: Path | str) -> OrchestratorConfig:
    """Carga y valida POLICIES/AGENTS/GATES/PERMISSIONS. Falla cerrado."""
    config_dir = Path(config_dir)

    policies_path = config_dir / "POLICIES.yaml"
    agents_path = config_dir / "AGENTS.yaml"
    gates_path = config_dir / "GATES.yaml"
    permissions_path = config_dir / "PERMISSIONS.yaml"

    policies = _load_yaml_mapping(policies_path)
    agents = _load_yaml_mapping(agents_path)
    gates = _load_yaml_mapping(gates_path)
    permissions = _load_yaml_mapping(permissions_path)

    _validate_policies(policies, policies_path)
    _validate_agents(agents, agents_path)
    _validate_gates(gates, gates_path)
    _validate_permissions(permissions, permissions_path)

    return OrchestratorConfig(
        policies=policies, agents=agents, gates=gates, permissions=permissions
    )


def load_project_rules(rules_path: Path | str) -> dict[str, Any]:
    """Carga y valida PROJECT_RULES.yaml de un proyecto. Falla cerrado."""
    rules_path = Path(rules_path)
    data = _load_yaml_mapping(rules_path)
    _validate_project_rules(data, rules_path)
    return data
