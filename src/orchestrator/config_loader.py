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
# CAPACITY-RESUME-FOUNDATION-001: developer.capacity_wait (espera automática
# ante una señal estructurada de capacidad de Claude). Bloque OPCIONAL; si
# falta, equivale a auto_wait desactivado. Si existe, sus cuatro claves son
# obligatorias (sin defaults silenciosos) y no se admiten claves extra.
CAPACITY_WAIT_KEYS = frozenset(
    {"auto_wait", "retry_interval_seconds", "max_attempts", "max_wait_seconds"}
)
CAPACITY_WAIT_RETRY_INTERVAL_MIN_SECONDS = 60
CAPACITY_WAIT_RETRY_INTERVAL_MAX_SECONDS = 86400
CAPACITY_WAIT_MAX_ATTEMPTS_MIN = 1
CAPACITY_WAIT_MAX_ATTEMPTS_MAX = 100
CAPACITY_WAIT_MAX_WAIT_MAX_SECONDS = 604800

REQUIRED_PERMISSION_DENY_KEYS = (
    "deny.production",
    "deny.git_push",
    "deny.git_merge",
    "deny.irreversible_actions",
    "deny.env_files",
    "deny.secret_files",
)

# TASK-EXECUTION-002 (D-EXEC-001): mismo patrón de identificador simple que
# task_packet._IDENTIFIER_RE (letra inicial, luego letras/dígitos/guion/guion
# bajo). Usado tanto para las claves de PROJECT_RULES.commands como para las
# entradas de PERMISSIONS.allowed_commands: ambas son IDs lógicos, nunca
# comandos de shell.
_LOGICAL_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


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
    validate_resource_budget(data)
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


RESOURCE_LIMIT_KEYS = frozenset({
    "max_builder_invocations", "max_verifier_invocations",
    "max_correction_attempts", "max_total_model_invocations",
})


def validate_resource_budget(policies: dict[str, Any]) -> dict[str, Any]:
    """Closed policy schema; numeric limits belong exclusively to YAML."""
    if not isinstance(policies, dict):
        raise ConfigError("policies must be a mapping")
    block = policies.get("resource_budget")
    if not isinstance(block, dict) or set(block) != {
        "default_profile", "exhaustion_behavior", "profiles"
    }:
        raise ConfigError("invalid resource_budget keys")
    if block["exhaustion_behavior"] != "BLOCKED":
        raise ConfigError("unsupported resource budget exhaustion behavior")
    profiles = block["profiles"]
    if not isinstance(profiles, dict) or not profiles:
        raise ConfigError("invalid resource budget profiles")
    if any(not isinstance(name, str) or not name.strip() for name in profiles):
        raise ConfigError("resource profile names must be non-empty strings")
    default_profile = block["default_profile"]
    if not isinstance(default_profile, str) or default_profile not in profiles:
        raise ConfigError("default_profile must reference a configured profile")
    attempts = policies.get("attempts")
    if not isinstance(attempts, dict):
        raise ConfigError("attempts must be a mapping")
    ceiling = attempts.get("max_correction_attempts")
    if type(ceiling) is not int or ceiling < 1:
        raise ConfigError("invalid global correction ceiling")
    for limits in profiles.values():
        if not isinstance(limits, dict) or set(limits) != RESOURCE_LIMIT_KEYS:
            raise ConfigError("invalid resource profile keys")
        if any(type(value) is not int or value < 1 for value in limits.values()):
            raise ConfigError("resource limits must be positive integers")
        if limits["max_correction_attempts"] > ceiling:
            raise ConfigError("profile correction limit exceeds global ceiling")
        if max(limits["max_builder_invocations"], limits["max_verifier_invocations"]) > limits["max_total_model_invocations"]:
            raise ConfigError("role limit exceeds total model limit")
    return block


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
    # Igual que write_probe: independiente de developer_enabled, un bloque
    # capacity_wait declarado debe ser válido de todos modos.
    _validate_capacity_wait_config(developer, path)


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


def _require_bounded_int(
    block: dict[str, Any], key: str, minimum: int, maximum: int, path: Path
) -> int:
    """Entero REAL (nunca bool) dentro de [minimum, maximum]. Falla cerrado."""
    value = block.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(
            f"'agents.developer.capacity_wait.{key}' must be an integer "
            f"(not a boolean) in {path}"
        )
    if value < minimum or value > maximum:
        raise ConfigError(
            f"'agents.developer.capacity_wait.{key}' must be between {minimum} "
            f"and {maximum} in {path}"
        )
    return value


def _validate_capacity_wait_config(developer: dict[str, Any], path: Path) -> None:
    """CAPACITY-RESUME-FOUNDATION-001: valida el bloque OPCIONAL
    agents.developer.capacity_wait. Ausente -> no se exige nada (equivale a
    auto_wait desactivado, el comportamiento actual). Presente -> debe ser un
    mapping con EXACTAMENTE las claves auto_wait (bool real),
    retry_interval_seconds (60..86400), max_attempts (1..100) y
    max_wait_seconds (>= retry_interval_seconds, <= 604800); enteros reales,
    nunca bool. Cualquier clave desconocida, tipo incorrecto o valor fuera de
    límites falla cerrado."""
    if "capacity_wait" not in developer:
        return
    block = developer["capacity_wait"]
    if not isinstance(block, dict):
        raise ConfigError(f"'agents.developer.capacity_wait' must be a mapping in {path}")

    unknown = sorted(str(key) for key in block if key not in CAPACITY_WAIT_KEYS)
    if unknown:
        raise ConfigError(
            f"'agents.developer.capacity_wait' has unknown key(s) {unknown} in {path}"
        )
    missing = sorted(CAPACITY_WAIT_KEYS - set(block))
    if missing:
        raise ConfigError(
            f"'agents.developer.capacity_wait' is missing required key(s) {missing} in {path}"
        )

    if not isinstance(block["auto_wait"], bool):
        raise ConfigError(
            f"'agents.developer.capacity_wait.auto_wait' must be a boolean in {path}"
        )
    retry_interval = _require_bounded_int(
        block,
        "retry_interval_seconds",
        CAPACITY_WAIT_RETRY_INTERVAL_MIN_SECONDS,
        CAPACITY_WAIT_RETRY_INTERVAL_MAX_SECONDS,
        path,
    )
    _require_bounded_int(
        block, "max_attempts", CAPACITY_WAIT_MAX_ATTEMPTS_MIN, CAPACITY_WAIT_MAX_ATTEMPTS_MAX, path
    )
    _require_bounded_int(
        block, "max_wait_seconds", retry_interval, CAPACITY_WAIT_MAX_WAIT_MAX_SECONDS, path
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
    # D-EXEC-001/PERMISSIONS §6: allowed_commands es una lista CERRADA de IDs
    # lógicos globalmente autorizados -- nunca argv, nunca un string de shell.
    for idx, item in enumerate(allowed_commands):
        if not isinstance(item, str) or not item:
            raise ConfigError(
                f"'allowed_commands[{idx}]' must be a non-empty string in {path}"
            )
        if not _LOGICAL_ID_RE.fullmatch(item):
            raise ConfigError(
                f"'allowed_commands[{idx}]' must be a simple logical identifier, "
                f"not a shell command: {item!r} ({path})"
            )


def _validate_commands(commands: dict[str, Any], path: Path) -> None:
    """D-EXEC-001: PROJECT_RULES.commands es un mapping ABIERTO
    logical_id -> argv (lista de strings); no existen slots semánticos fijos
    (test/lint/tsc/build) en el motor. `commands: {}` es válido. Cada argv se
    valida aquí SOLO como estructura (lista no vacía de strings no vacíos,
    sin listas anidadas, sin null, sin string de shell): nunca se interpreta
    ni se divide un string. Falla cerrado ante cualquier forma inesperada."""
    for key, value in commands.items():
        if not isinstance(key, str) or not key:
            raise ConfigError(f"'commands' key must be a non-empty string in {path}: {key!r}")
        if "\x00" in key:
            raise ConfigError(f"'commands' key must not contain NUL characters in {path}: {key!r}")
        if not _LOGICAL_ID_RE.fullmatch(key):
            raise ConfigError(
                f"'commands' key {key!r} must be a simple logical identifier "
                f"(letters/digits/'-'/'_' only, starting with a letter) in {path}"
            )
        if not isinstance(value, list) or not value:
            raise ConfigError(f"'commands.{key}' must be a non-empty list (argv) in {path}")
        for idx, item in enumerate(value):
            if not isinstance(item, str) or not item:
                raise ConfigError(
                    f"'commands.{key}[{idx}]' must be a non-empty string in {path}"
                )
            if "\x00" in item:
                raise ConfigError(
                    f"'commands.{key}[{idx}]' must not contain NUL characters in {path}"
                )


def _validate_project_rules(data: dict[str, Any], path: Path) -> None:
    for key in ("project_id", "repo_path", "commands", "protected_paths"):
        _require(data, key, path)
    if not isinstance(data["project_id"], str) or not data["project_id"]:
        raise ConfigError(f"'project_id' must be a non-empty string in {path}")
    if not isinstance(data["commands"], dict):
        raise ConfigError(f"'commands' must be a mapping in {path}")
    _validate_commands(data["commands"], path)
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


# HUMAN-GATE-NOTIFY-001: config OPCIONAL de notificaciones salientes. Vive
# fuera de load_core_config: si NOTIFICATIONS.yaml no existe, las
# notificaciones están desactivadas y ninguna config/prueba existente se rompe.
# El YAML nunca contiene el secreto: solo el NOMBRE de la variable de entorno
# que lo contiene.
NOTIFICATIONS_FILENAME = "NOTIFICATIONS.yaml"
ALLOWED_NOTIFICATION_PROVIDERS = frozenset({"slack"})
ALLOWED_NOTIFICATION_EVENTS = frozenset({"human_gate"})
_NOTIFICATION_KEYS = frozenset({"enabled", "provider", "webhook_env_var", "events"})
_ENV_VAR_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class NotificationsConfig:
    enabled: bool
    provider: str | None
    webhook_env_var: str | None
    human_gate: bool


DISABLED_NOTIFICATIONS = NotificationsConfig(
    enabled=False, provider=None, webhook_env_var=None, human_gate=False
)


def load_notifications_config(config_dir: Path | str) -> NotificationsConfig:
    """Carga config/NOTIFICATIONS.yaml. Ausente -> desactivado. Presente e
    inválido -> ConfigError (el llamador lo traduce a config_invalid sin
    afectar a ninguna tarea). Validación estricta: sin claves desconocidas."""
    path = Path(config_dir) / NOTIFICATIONS_FILENAME
    if not path.exists():
        return DISABLED_NOTIFICATIONS
    data = _load_yaml_mapping(path)
    if set(data) != {"notifications"}:
        raise ConfigError(f"unexpected top-level keys in {path}")
    block = data["notifications"]
    if not isinstance(block, dict) or set(block) != _NOTIFICATION_KEYS:
        raise ConfigError(f"'notifications' in {path} must contain exactly {sorted(_NOTIFICATION_KEYS)}")
    enabled = block["enabled"]
    if not isinstance(enabled, bool):
        raise ConfigError(f"notifications.enabled in {path} must be a boolean")
    provider = block["provider"]
    if not isinstance(provider, str) or provider not in ALLOWED_NOTIFICATION_PROVIDERS:
        raise ConfigError(f"notifications.provider in {path} is not an allowed provider")
    env_var = block["webhook_env_var"]
    if not isinstance(env_var, str) or not _ENV_VAR_NAME_RE.match(env_var):
        raise ConfigError(
            f"notifications.webhook_env_var in {path} must match {_ENV_VAR_NAME_RE.pattern}"
        )
    events = block["events"]
    if not isinstance(events, dict) or not events or not set(events) <= ALLOWED_NOTIFICATION_EVENTS:
        raise ConfigError(f"notifications.events in {path} has unknown or missing events")
    human_gate = events.get("human_gate")
    if not isinstance(human_gate, bool):
        raise ConfigError(f"notifications.events.human_gate in {path} must be a boolean")
    return NotificationsConfig(
        enabled=enabled, provider=provider, webhook_env_var=env_var, human_gate=human_gate
    )


def load_project_rules(rules_path: Path | str) -> dict[str, Any]:
    """Carga y valida PROJECT_RULES.yaml de un proyecto. Falla cerrado."""
    rules_path = Path(rules_path)
    data = _load_yaml_mapping(rules_path)
    _validate_project_rules(data, rules_path)
    return data


def resolve_project_root(
    project_rules: dict[str, Any],
    *,
    project_id: str,
    orchestrator_repo_root: Path | str,
) -> Path:
    """TASK-EXECUTION-002 (D-EXEC-003): PROJECT_RULES.repo_path es la ÚNICA
    fuente configurable de autorización del root de un proyecto. El Task
    Packet nunca define ni amplía este root: aquí solo se usa su
    `project_id`, exigiendo que coincida EXACTAMENTE con
    PROJECT_RULES.project_id (misma comprobación que app._require_project_rules,
    reaplicada aquí porque esta función puede invocarse independientemente).

    repo_path puede ser relativo (se resuelve respecto a
    orchestrator_repo_root, el root del propio orquestador) o absoluto;
    siempre se canonicaliza (resolve()). Falla cerrado si el resultado no
    existe o no es un directorio. Nunca crea el directorio ni corrige la
    ruta; la validación profunda de que sea un repositorio Git confinado y
    seguro sigue siendo responsabilidad de orchestrator.evidence."""
    rules_project_id = project_rules.get("project_id")
    if rules_project_id != project_id:
        raise ConfigError(
            f"PROJECT_RULES project_id {rules_project_id!r} does not match "
            f"requested project_id {project_id!r}"
        )

    repo_path = project_rules.get("repo_path")
    if not isinstance(repo_path, str) or not repo_path:
        raise ConfigError("'repo_path' must be a non-empty string in PROJECT_RULES")

    orchestrator_root_resolved = Path(orchestrator_repo_root).resolve()
    candidate = Path(repo_path)
    if not candidate.is_absolute():
        candidate = orchestrator_root_resolved / candidate
    resolved = candidate.resolve()

    if not resolved.exists():
        raise ConfigError(f"resolved project root does not exist: {resolved}")
    if not resolved.is_dir():
        raise ConfigError(f"resolved project root is not a directory: {resolved}")

    return resolved
