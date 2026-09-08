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
        self.assertFalse(config.agents["agents"]["director"]["enabled"])
        self.assertFalse(config.agents["agents"]["developer"]["enabled"])

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

    def test_developer_enabled_true_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["developer"]["enabled"] = True
            _write_core_config(tmp, agents=agents)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("developer", str(ctx.exception))


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
        src_dir = REPO_ROOT / "src" / "orchestrator"
        for path in src_dir.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text, f"shell=True found in {path}")


if __name__ == "__main__":
    unittest.main()
