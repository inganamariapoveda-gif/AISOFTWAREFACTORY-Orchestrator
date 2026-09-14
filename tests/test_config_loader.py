import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.config_loader import (  # noqa: E402
    ConfigError,
    load_core_config,
    load_project_rules,
    resolve_project_root,
)

CONFIG_DIR = REPO_ROOT / "config"
SAMPLE_RULES_PATH = REPO_ROOT / "projects" / "SAMPLE" / "PROJECT_RULES.yaml"


def _baseline_policies() -> dict:
    return {
        "version": 1,
        "prohibitions": {
            "production": True,
            "git_push": True,
            "git_merge": True,
            "irreversible_actions": True,
        },
        "attempts": {"max_correction_attempts": 3},
        "classification": {
            "levels": ["VERDE", "AMARILLO", "ROJO"],
            "on_unclassified": "BLOCKED",
        },
        "fail_closed": True,
    }


def _baseline_agents() -> dict:
    return {
        "version": 1,
        "agents": {
            "director": {"role": "director", "enabled": False},
            "developer": {"role": "developer", "enabled": False},
        },
    }


def _baseline_gates() -> dict:
    return {
        "version": 1,
        "automatic_approval": {"verde": True},
        "director_internal_gate": {"amarillo_contemplado": True},
        "human_gates": [
            {"name": "HUMAN_UI_REVIEW"},
            {"name": "HUMAN_FUNCTIONAL_TEST"},
            {"name": "HUMAN_BUSINESS_DECISION"},
            {"name": "HUMAN_CRITICAL_APPROVAL"},
        ],
        "escalation": {"decision_material_no_contemplada": "x"},
    }


def _baseline_permissions() -> dict:
    return {
        "version": 1,
        "deny": {
            "production": True,
            "git_push": True,
            "git_merge": True,
            "irreversible_actions": True,
            "env_files": True,
            "secret_files": True,
        },
        "allowed_commands": [],
    }


def _write_core_config(
    tmp: Path,
    *,
    policies: dict | None = None,
    agents: dict | None = None,
    gates: dict | None = None,
    permissions: dict | None = None,
) -> Path:
    """Escribe un conjunto COMPLETO y por defecto VÁLIDO de los 4 YAML core,
    permitiendo sobreescribir uno de ellos para forzar un escenario inválido
    puntual. Así una prueba que rompe un solo campo alcanza realmente el
    validador correspondiente, en vez de fallar por otra causa incidental."""
    (tmp / "POLICIES.yaml").write_text(
        yaml.safe_dump(policies if policies is not None else _baseline_policies()),
        encoding="utf-8",
    )
    (tmp / "AGENTS.yaml").write_text(
        yaml.safe_dump(agents if agents is not None else _baseline_agents()),
        encoding="utf-8",
    )
    (tmp / "GATES.yaml").write_text(
        yaml.safe_dump(gates if gates is not None else _baseline_gates()),
        encoding="utf-8",
    )
    (tmp / "PERMISSIONS.yaml").write_text(
        yaml.safe_dump(permissions if permissions is not None else _baseline_permissions()),
        encoding="utf-8",
    )
    return tmp


class LoadRealConfigTests(unittest.TestCase):
    """La configuración real del repositorio debe cargar y validar."""

    def test_core_config_loads(self) -> None:
        config = load_core_config(CONFIG_DIR)
        self.assertTrue(config.policies["fail_closed"])
        # Director permanece deshabilitado (D1/D2, §0); Developer se habilita
        # a partir de CLAUDE-EXECUTION-001 exclusivamente para el handshake
        # seguro con Claude Code CLI (--permission-mode plan, sin edición).
        self.assertFalse(config.agents["agents"]["director"]["enabled"])
        self.assertTrue(config.agents["agents"]["developer"]["enabled"])
        self.assertEqual(config.agents["agents"]["developer"]["permission_mode"], "plan")
        self.assertTrue(config.agents["agents"]["developer"]["restricted"])

    def test_sample_project_rules_load(self) -> None:
        rules = load_project_rules(SAMPLE_RULES_PATH)
        self.assertEqual(rules["project_id"], "SAMPLE")


class InvalidYamlTests(unittest.TestCase):
    def test_invalid_yaml_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "POLICIES.yaml"
            bad_path.write_text("prohibitions: [unterminated", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_project_rules(bad_path)


class MissingFileTests(unittest.TestCase):
    def test_missing_required_core_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                load_core_config(Path(tmp))

    def test_missing_project_rules_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "PROJECT_RULES.yaml"
            with self.assertRaises(ConfigError):
                load_project_rules(missing)


class MissingSecurityKeyTests(unittest.TestCase):
    def _write(self, tmp: Path, name: str, content: str) -> Path:
        path = tmp / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_policies_missing_git_push_prohibition_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            self._write(
                tmp,
                "POLICIES.yaml",
                """
version: 1
prohibitions:
  production: true
  git_merge: true
  irreversible_actions: true
attempts:
  max_correction_attempts: 3
classification:
  levels: ["VERDE", "AMARILLO", "ROJO"]
fail_closed: true
""",
            )
            self._write(
                tmp,
                "AGENTS.yaml",
                """
agents:
  director:
    enabled: false
  developer:
    enabled: false
""",
            )
            self._write(
                tmp,
                "GATES.yaml",
                """
automatic_approval:
  verde: true
director_internal_gate:
  amarillo_contemplado: true
human_gates:
  - name: HUMAN_UI_REVIEW
  - name: HUMAN_FUNCTIONAL_TEST
  - name: HUMAN_BUSINESS_DECISION
  - name: HUMAN_CRITICAL_APPROVAL
escalation:
  decision_material_no_contemplada: "x"
""",
            )
            self._write(
                tmp,
                "PERMISSIONS.yaml",
                """
deny:
  production: true
  git_push: true
  git_merge: true
  irreversible_actions: true
  env_files: true
  secret_files: true
allowed_commands: []
""",
            )
            with self.assertRaises(ConfigError):
                load_core_config(tmp)

    def test_production_prohibition_false_fails_closed(self) -> None:
        # Corrección BOOTSTRAP-001/CORRECTION-001 hallazgo 2: se construye un
        # core config COMPLETO y válido salvo el campo bajo prueba, y se llama
        # a load_core_config() (no load_project_rules()) para demostrar que
        # el ConfigError proviene realmente del validador de policies por
        # 'prohibitions.production', no de una clave de PROJECT_RULES ausente.
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            policies["prohibitions"]["production"] = False
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("prohibitions.production", str(ctx.exception))

    def test_git_push_prohibition_false_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            policies["prohibitions"]["git_push"] = False
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("prohibitions.git_push", str(ctx.exception))

    def test_git_merge_prohibition_false_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            policies["prohibitions"]["git_merge"] = False
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("prohibitions.git_merge", str(ctx.exception))

    def test_irreversible_actions_prohibition_false_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            policies["prohibitions"]["irreversible_actions"] = False
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("prohibitions.irreversible_actions", str(ctx.exception))

    def test_director_enabled_true_rejected(self) -> None:
        # Demuestra que el ConfigError proviene del validador de agents por
        # 'director', no de otra causa incidental.
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["director"]["enabled"] = True
            _write_core_config(tmp, agents=agents)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("director", str(ctx.exception))

    def test_developer_enabled_true_without_handshake_config_rejected(self) -> None:
        # A partir de CLAUDE-EXECUTION-001, developer.enabled: true está
        # permitido, pero SOLO si declara el handshake completo (executable,
        # output_format, max_turns, timeout_seconds, permission_mode). Aquí
        # se habilita sin ninguno de esos campos: debe seguir fallando
        # cerrado (ConfigError), por 'developer.executable' ausente.
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["developer"]["enabled"] = True
            _write_core_config(tmp, agents=agents)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("developer", str(ctx.exception))


def _valid_developer_handshake() -> dict:
    return {
        "role": "developer",
        "enabled": True,
        "executable": "claude",
        "output_format": "json",
        "max_turns": 1,
        "timeout_seconds": 60,
        "permission_mode": "plan",
        "restricted": True,
    }


class DeveloperHandshakeConfigTests(unittest.TestCase):
    """CLAUDE-EXECUTION-001: developer.enabled: true exige el handshake
    completo; cada campo ausente o inválido falla cerrado."""

    def _load_with_developer(self, developer: dict) -> None:
        """`developer` debe ser el diccionario COMPLETO a escribir (no un
        parche): permite tanto sobreescribir un valor como eliminar una
        clave para simular un campo ausente."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["developer"] = developer
            _write_core_config(tmp, agents=agents)
            load_core_config(tmp)

    def _load_with_developer_override(self, **overrides) -> None:
        developer = _valid_developer_handshake()
        developer.update(overrides)
        self._load_with_developer(developer)

    def test_complete_valid_handshake_config_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["developer"] = _valid_developer_handshake()
            _write_core_config(tmp, agents=agents)
            config = load_core_config(tmp)
            self.assertTrue(config.agents["agents"]["developer"]["enabled"])
            self.assertEqual(
                config.agents["agents"]["developer"]["permission_mode"], "plan"
            )

    def test_missing_executable_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            developer = _valid_developer_handshake()
            del developer["executable"]
            self._load_with_developer(developer)
        self.assertIn("developer.executable", str(ctx.exception))

    def test_output_format_not_json_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_developer_override(output_format="text")
        self.assertIn("developer.output_format", str(ctx.exception))

    def test_max_turns_not_positive_int_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_developer_override(max_turns=0)
        self.assertIn("developer.max_turns", str(ctx.exception))

    def test_timeout_seconds_missing_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            developer = _valid_developer_handshake()
            del developer["timeout_seconds"]
            self._load_with_developer(developer)
        self.assertIn("developer.timeout_seconds", str(ctx.exception))

    def test_permission_mode_other_than_plan_rejected(self) -> None:
        # Ningún modo de bypass ni edición está autorizado en este incremento.
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_developer_override(permission_mode="bypassPermissions")
        self.assertIn("developer.permission_mode", str(ctx.exception))

    def test_restricted_missing_rejected(self) -> None:
        # 8. restricted ausente en AGENTS config -> ConfigError
        # (CORRECTION-001, hallazgo 2: defensa en profundidad).
        with self.assertRaises(ConfigError) as ctx:
            developer = _valid_developer_handshake()
            del developer["restricted"]
            self._load_with_developer(developer)
        self.assertIn("developer.restricted", str(ctx.exception))

    def test_restricted_false_rejected(self) -> None:
        # 9. restricted: false -> ConfigError.
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_developer_override(restricted=False)
        self.assertIn("developer.restricted", str(ctx.exception))

    def test_restricted_non_boolean_rejected(self) -> None:
        # 10. restricted con tipo no booleano -> ConfigError.
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_developer_override(restricted="true")
        self.assertIn("developer.restricted", str(ctx.exception))

    def test_developer_disabled_does_not_require_handshake_fields(self) -> None:
        # Compatibilidad con BOOTSTRAP: developer.enabled: false sigue
        # aceptándose sin declarar ningún campo de handshake.
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _write_core_config(tmp)  # baseline: developer.enabled = False
            config = load_core_config(tmp)
            self.assertFalse(config.agents["agents"]["developer"]["enabled"])


def _valid_write_probe() -> dict:
    return {
        "enabled": True,
        "permission_mode": "acceptEdits",
        "restricted": True,
        "max_turns": 3,
        "timeout_seconds": 90,
    }


class WriteProbeConfigTests(unittest.TestCase):
    """CLAUDE-EXECUTION-002: agents.developer.write_probe es opt-in; si se
    declara enabled: true, exige permission_mode==acceptEdits,
    restricted==true, max_turns y timeout_seconds válidos. Independiente
    del handshake read-only (developer.permission_mode sigue en "plan")."""

    def _load_with_write_probe(self, write_probe: dict) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            developer = _valid_developer_handshake()
            developer["write_probe"] = write_probe
            agents["agents"]["developer"] = developer
            _write_core_config(tmp, agents=agents)
            load_core_config(tmp)

    def _load_with_write_probe_override(self, **overrides) -> None:
        write_probe = _valid_write_probe()
        write_probe.update(overrides)
        self._load_with_write_probe(write_probe)

    def test_complete_valid_write_probe_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            developer = _valid_developer_handshake()
            developer["write_probe"] = _valid_write_probe()
            agents["agents"]["developer"] = developer
            _write_core_config(tmp, agents=agents)
            config = load_core_config(tmp)
            write_probe = config.agents["agents"]["developer"]["write_probe"]
            self.assertTrue(write_probe["enabled"])
            self.assertEqual(write_probe["permission_mode"], "acceptEdits")
            # El handshake read-only NO se debilita: sigue en "plan".
            self.assertEqual(
                config.agents["agents"]["developer"]["permission_mode"], "plan"
            )

    def test_write_probe_absent_is_accepted(self) -> None:
        # write_probe es opt-in: su ausencia no debe fallar.
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["developer"] = _valid_developer_handshake()
            _write_core_config(tmp, agents=agents)
            config = load_core_config(tmp)
            self.assertNotIn("write_probe", config.agents["agents"]["developer"])

    def test_write_probe_disabled_does_not_require_other_fields(self) -> None:
        self._load_with_write_probe({"enabled": False})

    def test_permission_mode_other_than_accept_edits_rejected(self) -> None:
        # 23. permission_mode diferente de acceptEdits -> ConfigError.
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_write_probe_override(permission_mode="plan")
        self.assertIn("write_probe.permission_mode", str(ctx.exception))

    def test_permission_mode_bypass_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_write_probe_override(permission_mode="bypassPermissions")
        self.assertIn("write_probe.permission_mode", str(ctx.exception))

    def test_restricted_false_rejected(self) -> None:
        # 24. restricted != true -> ConfigError.
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_write_probe_override(restricted=False)
        self.assertIn("write_probe.restricted", str(ctx.exception))

    def test_restricted_missing_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            write_probe = _valid_write_probe()
            del write_probe["restricted"]
            self._load_with_write_probe(write_probe)
        self.assertIn("write_probe.restricted", str(ctx.exception))

    def test_max_turns_invalid_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_write_probe_override(max_turns=0)
        self.assertIn("write_probe.max_turns", str(ctx.exception))

    def test_timeout_seconds_invalid_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_write_probe_override(timeout_seconds=-1)
        self.assertIn("write_probe.timeout_seconds", str(ctx.exception))

    def test_enabled_non_boolean_rejected(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load_with_write_probe({"enabled": "yes"})
        self.assertIn("write_probe.enabled", str(ctx.exception))


class OnUnclassifiedTests(unittest.TestCase):
    """Hallazgo 3: una acción no clasificada debe fallar cerrado (BLOCKED),
    nunca heredar silenciosamente un nivel aprobable."""

    def test_missing_on_unclassified_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            del policies["classification"]["on_unclassified"]
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("on_unclassified", str(ctx.exception))

    def test_on_unclassified_wrong_value_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            policies["classification"]["on_unclassified"] = "AMARILLO"
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("on_unclassified", str(ctx.exception))

    def test_on_unclassified_blocked_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            _write_core_config(tmp)
            config = load_core_config(tmp)
            self.assertEqual(
                config.policies["classification"]["on_unclassified"], "BLOCKED"
            )


class SecretRejectionTests(unittest.TestCase):
    def test_secret_key_in_yaml_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "AGENTS.yaml"
            path.write_text(
                """
agents:
  director:
    enabled: false
    api_key: "should-not-be-here"
""",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_project_rules(path)

    def test_no_hardcoded_secret_keys_in_real_config_files(self) -> None:
        pattern = re.compile(
            r"(api[_-]?key|secret|token|password|passwd|credential)\s*:", re.IGNORECASE
        )
        yaml_files = list(CONFIG_DIR.glob("*.yaml")) + [SAMPLE_RULES_PATH]
        for path in yaml_files:
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(
                pattern.search(text), f"secret-looking key found in {path}"
            )


class NoShellTrueTests(unittest.TestCase):
    def test_no_shell_true_in_source(self) -> None:
        # Recursivo: cubre también src/orchestrator/adapters/** (CLAUDE-EXECUTION-001).
        src_dir = REPO_ROOT / "src" / "orchestrator"
        for path in src_dir.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text, f"shell=True found in {path}")


# ============================================================
# TASK-EXECUTION-002: PROJECT_RULES.commands (D-EXEC-001, mapping abierto
# logical_id -> argv) y PERMISSIONS.allowed_commands (D-EXEC-001, lista
# cerrada de IDs lógicos).
# ============================================================


class ProjectRulesCommandsTests(unittest.TestCase):
    """Cada prueba escribe un PROJECT_RULES.yaml mínimo, válido salvo el
    campo 'commands' bajo prueba."""

    def _write_rules(self, tmp: Path, commands) -> Path:
        path = tmp / "PROJECT_RULES.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "project_id": "X",
                    "repo_path": ".",
                    "commands": commands,
                    "protected_paths": [],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_empty_commands_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {})
            rules = load_project_rules(path)
            self.assertEqual(rules["commands"], {})

    def test_valid_logical_id_to_argv_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {"unit": ["python", "verify_task.py"]})
            rules = load_project_rules(path)
            self.assertEqual(rules["commands"]["unit"], ["python", "verify_task.py"])

    def test_string_command_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {"unit": "python verify_task.py"})
            with self.assertRaises(ConfigError):
                load_project_rules(path)

    def test_null_command_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {"unit": None})
            with self.assertRaises(ConfigError):
                load_project_rules(path)

    def test_empty_argv_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {"unit": []})
            with self.assertRaises(ConfigError):
                load_project_rules(path)

    def test_invalid_logical_id_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(
                Path(tmp_str), {"unit && evil": ["python", "verify_task.py"]}
            )
            with self.assertRaises(ConfigError):
                load_project_rules(path)

    def test_nested_argv_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {"unit": [["python"]]})
            with self.assertRaises(ConfigError):
                load_project_rules(path)

    def test_argv_with_empty_string_element_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = self._write_rules(Path(tmp_str), {"unit": ["python", ""]})
            with self.assertRaises(ConfigError):
                load_project_rules(path)


class AllowedCommandsValidationTests(unittest.TestCase):
    def test_allowed_commands_entry_must_be_logical_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            permissions = _baseline_permissions()
            permissions["allowed_commands"] = ["unit && evil"]
            _write_core_config(tmp, permissions=permissions)
            with self.assertRaises(ConfigError):
                load_core_config(tmp)

    def test_allowed_commands_valid_logical_id_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            permissions = _baseline_permissions()
            permissions["allowed_commands"] = ["unit"]
            _write_core_config(tmp, permissions=permissions)
            config = load_core_config(tmp)
            self.assertEqual(config.permissions["allowed_commands"], ["unit"])


class ProjectRootResolutionTests(unittest.TestCase):
    """Sección 7: resolve_project_root() -- repo_path SOLO desde
    PROJECT_RULES, nunca del Task Packet; relativo resuelto contra el repo
    root del orquestador; canonicalizado; debe existir y ser directorio;
    project_id debe coincidir. No crea nada, no corrige rutas."""

    def test_relative_repo_path_resolves_against_orchestrator_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            orchestrator_root = Path(tmp_str)
            project_dir = orchestrator_root / "projects" / "X"
            project_dir.mkdir(parents=True)
            rules = {
                "project_id": "X",
                "repo_path": "./projects/X",
                "commands": {},
                "protected_paths": [],
            }
            resolved = resolve_project_root(
                rules, project_id="X", orchestrator_repo_root=orchestrator_root
            )
            self.assertEqual(resolved, project_dir.resolve())

    def test_project_id_mismatch_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            orchestrator_root = Path(tmp_str)
            rules = {
                "project_id": "X",
                "repo_path": ".",
                "commands": {},
                "protected_paths": [],
            }
            with self.assertRaises(ConfigError):
                resolve_project_root(
                    rules, project_id="OTHER", orchestrator_repo_root=orchestrator_root
                )

    def test_nonexistent_repo_path_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            orchestrator_root = Path(tmp_str)
            rules = {
                "project_id": "X",
                "repo_path": "./does/not/exist",
                "commands": {},
                "protected_paths": [],
            }
            with self.assertRaises(ConfigError):
                resolve_project_root(
                    rules, project_id="X", orchestrator_repo_root=orchestrator_root
                )

    def test_repo_path_pointing_to_a_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            orchestrator_root = Path(tmp_str)
            a_file = orchestrator_root / "a_file.txt"
            a_file.write_text("x", encoding="utf-8")
            rules = {
                "project_id": "X",
                "repo_path": "./a_file.txt",
                "commands": {},
                "protected_paths": [],
            }
            with self.assertRaises(ConfigError):
                resolve_project_root(
                    rules, project_id="X", orchestrator_repo_root=orchestrator_root
                )

    def test_missing_repo_path_field_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            orchestrator_root = Path(tmp_str)
            rules = {"project_id": "X", "commands": {}, "protected_paths": []}
            with self.assertRaises(ConfigError):
                resolve_project_root(
                    rules, project_id="X", orchestrator_repo_root=orchestrator_root
                )


if __name__ == "__main__":
    unittest.main()
