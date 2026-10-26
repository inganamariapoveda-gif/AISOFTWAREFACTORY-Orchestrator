import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.config_loader import (  # noqa: E402
    DISABLED_NOTIFICATIONS,
    ConfigError,
    NotificationsConfig,
    load_core_config,
    load_core_config_from_permissions_bytes,
    load_permissions_from_yaml_bytes,
    load_notifications_config,
    load_project_rules,
    load_project_rules_from_yaml_bytes,
    resolve_project_root,
)

CONFIG_DIR = REPO_ROOT / "config"
SAMPLE_RULES_PATH = REPO_ROOT / "projects" / "SAMPLE" / "PROJECT_RULES.yaml"


def _baseline_policies() -> dict:
    return {
        "version": 1,
        "prohibitions": {
            "production": True,
            "uncontrolled_git_push": True,
            "git_merge": True,
            "irreversible_actions": True,
        },
        "controlled_actions": {"git_publish_task_branch": {
            "enabled": True, "classification": "AMARILLO",
            "approval": "DIRECTOR_INTERNAL_GATE", "on_violation": "BLOCKED",
        }},
        "attempts": {"max_correction_attempts": 3},
        "classification": {
            "levels": ["VERDE", "AMARILLO", "ROJO"],
            "on_unclassified": "BLOCKED",
        },
        "fail_closed": True,
        "resource_budget": yaml.safe_load((CONFIG_DIR / "POLICIES.yaml").read_text(encoding="utf-8"))["resource_budget"],
    }


class ResourceBudgetConfigTests(unittest.TestCase):
    def test_alternate_profiles_and_default_from_yaml(self):
        policies = _baseline_policies()
        budget = policies["resource_budget"]
        budget["profiles"] = {"custom_review": budget["profiles"]["economy"]}
        budget["default_profile"] = "custom_review"
        with tempfile.TemporaryDirectory() as directory:
            _write_core_config(Path(directory), policies=policies)
            loaded = load_core_config(Path(directory)).policies["resource_budget"]
        self.assertEqual(loaded["default_profile"], "custom_review")
        self.assertEqual(set(loaded["profiles"]), {"custom_review"})

    def test_malformed_attempts_raise_config_error(self):
        from orchestrator.config_loader import validate_resource_budget
        for attempts in (None, [], "invalid", 3, True):
            with self.subTest(attempts=attempts), tempfile.TemporaryDirectory() as directory:
                policies = _baseline_policies()
                policies["attempts"] = attempts
                with self.assertRaises(ConfigError):
                    validate_resource_budget(policies)
                _write_core_config(Path(directory), policies=policies)
                with self.assertRaises(ConfigError):
                    load_core_config(Path(directory))

    def test_invalid_profile_mapping_and_default(self):
        from orchestrator.config_loader import validate_resource_budget
        for profiles, default in (({}, "x"), ([], "x"), ({1: {}}, 1), ({"": {}}, ""), ({"x": {}}, [])):
            policies = _baseline_policies()
            policies["resource_budget"].update(profiles=profiles, default_profile=default)
            with self.subTest(profiles=profiles), self.assertRaises(ConfigError):
                validate_resource_budget(policies)

    def test_profiles_and_default(self):
        from orchestrator.config_loader import validate_resource_budget
        block = validate_resource_budget(_baseline_policies())
        self.assertEqual(block["default_profile"], "standard")
        self.assertEqual(set(block["profiles"]), {"economy", "standard", "high_assurance"})
        self.assertEqual([block["profiles"][p]["max_builder_invocations"] for p in ("economy", "standard", "high_assurance")], [2, 3, 4])

    def test_invalid_policies_fail_closed(self):
        from orchestrator.config_loader import validate_resource_budget
        import copy
        baseline = _baseline_policies()
        mutations = [
            lambda p: p.pop("resource_budget"),
            lambda p: p["resource_budget"].update(extra=True),
            lambda p: p["resource_budget"].update(default_profile="unknown"),
            lambda p: p["resource_budget"].update(exhaustion_behavior="CONTINUE"),
            lambda p: p["resource_budget"]["profiles"].update(unknown={}),
            lambda p: p["resource_budget"]["profiles"]["standard"].update(extra=1),
            lambda p: p["resource_budget"]["profiles"]["standard"].update(max_correction_attempts=4),
            lambda p: p["resource_budget"]["profiles"]["standard"].update(max_total_model_invocations=1),
        ]
        for value in (0, -1, True, "3", None, 1.5):
            mutations.append(lambda p, v=value: p["resource_budget"]["profiles"]["standard"].update(max_builder_invocations=v))
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = copy.deepcopy(baseline)
                mutate(data)
                with self.assertRaises(ConfigError):
                    validate_resource_budget(data)


def _baseline_agents() -> dict:
    return {
        "version": 1,
        "agents": {
            "director": {"role": "director", "enabled": False},
            "developer": {"role": "builder", "provider": "claude_code_cli", "adapter": "claude_code_cli", "enabled": False},
        },
    }


def _baseline_gates() -> dict:
    return {
        "version": 1,
        "automatic_approval": {"verde": True},
        "director_internal_gate": {"amarillo_contemplado": True, "git_publish_task_branch": True},
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
            "uncontrolled_git_push": True,
            "git_merge": True,
            "irreversible_actions": True,
            "env_files": True,
            "secret_files": True,
        },
        "git_publish": {
            "enabled": True,
            "remote_name": "origin",
            "allowed_remote_urls": ["https://github.com/inganamariapoveda-gif/AISOFTWAREFACTORY-Orchestrator.git"],
            "branch_prefix": "task/", "forbidden_branches": ["main", "master"],
            "allow_force": False, "allow_tags": False, "allow_delete": False,
            "require_explicit_task_packet": True, "require_director_approval": True,
            "require_clean_worktree": True, "refspec_mode": "current_branch_only",
        },
        "execution_controls": {"local_project_commands": False},
        "allowed_commands": [],
        "role_capabilities": {"builder": ["implement_authorized_changes", "publish_authorized_task_branch"]},
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

    def test_policies_missing_uncontrolled_push_prohibition_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policies = _baseline_policies()
            del policies["prohibitions"]["uncontrolled_git_push"]
            _write_core_config(Path(directory), policies=policies)
            with self.assertRaisesRegex(ConfigError, "prohibitions.uncontrolled_git_push"):
                load_core_config(directory)

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

    def test_uncontrolled_git_push_prohibition_false_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            policies = _baseline_policies()
            policies["prohibitions"]["uncontrolled_git_push"] = False
            _write_core_config(tmp, policies=policies)
            with self.assertRaises(ConfigError) as ctx:
                load_core_config(tmp)
            self.assertIn("prohibitions.uncontrolled_git_push", str(ctx.exception))

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
        "role": "builder", "provider": "claude_code_cli", "adapter": "claude_code_cli",
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


def _valid_capacity_wait(**overrides) -> dict:
    block = {
        "auto_wait": True,
        "retry_interval_seconds": 1800,
        "max_attempts": 12,
        "max_wait_seconds": 28800,
    }
    block.update(overrides)
    return block


class CapacityWaitConfigTests(unittest.TestCase):
    """CAPACITY-RESUME-FOUNDATION-001: agents.developer.capacity_wait es un
    bloque OPCIONAL (ausente == auto_wait desactivado). Si existe, sus cuatro
    claves son obligatorias, sin claves extra, con enteros REALES (nunca
    bool) dentro de límites. Solo configuración: el motor todavía no
    suspende ni reanuda."""

    def _load(self, block, *, developer_enabled: bool = True):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            developer = (
                _valid_developer_handshake() if developer_enabled else {"role": "builder", "enabled": False}
            )
            developer["capacity_wait"] = block
            agents["agents"]["developer"] = developer
            _write_core_config(tmp, agents=agents)
            return load_core_config(tmp)

    def _assert_rejected(self, block, expected_fragment: str) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load(block)
        self.assertIn(expected_fragment, str(ctx.exception))

    # ---- válido / ausente ----

    def test_approved_block_is_accepted_exactly(self) -> None:
        config = self._load(_valid_capacity_wait())
        block = config.agents["agents"]["developer"]["capacity_wait"]
        self.assertEqual(
            block,
            {
                "auto_wait": True,
                "retry_interval_seconds": 1800,
                "max_attempts": 12,
                "max_wait_seconds": 28800,
            },
        )

    def test_real_repository_config_has_the_approved_block(self) -> None:
        block = load_core_config(CONFIG_DIR).agents["agents"]["developer"]["capacity_wait"]
        self.assertIs(block["auto_wait"], True)
        self.assertEqual(block["retry_interval_seconds"], 1800)
        self.assertEqual(block["max_attempts"], 12)
        self.assertEqual(block["max_wait_seconds"], 28800)

    def test_absent_block_is_accepted_and_means_auto_wait_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = _baseline_agents()
            agents["agents"]["developer"] = _valid_developer_handshake()
            _write_core_config(tmp, agents=agents)
            config = load_core_config(tmp)
        developer = config.agents["agents"]["developer"]
        self.assertNotIn("capacity_wait", developer)
        # Sin bloque no hay espera automática: ningún default silencioso.
        self.assertFalse(developer.get("capacity_wait", {}).get("auto_wait", False))

    def test_auto_wait_false_is_a_valid_explicit_disable(self) -> None:
        config = self._load(_valid_capacity_wait(auto_wait=False))
        self.assertIs(config.agents["agents"]["developer"]["capacity_wait"]["auto_wait"], False)

    def test_block_is_validated_even_when_developer_is_disabled(self) -> None:
        self._load(_valid_capacity_wait(), developer_enabled=False)
        with self.assertRaises(ConfigError):
            self._load(_valid_capacity_wait(max_attempts=0), developer_enabled=False)

    # ---- forma ----

    def test_block_must_be_a_mapping(self) -> None:
        for bogus in (None, True, [], "on", 5):
            with self.subTest(block=bogus):
                self._assert_rejected(bogus, "capacity_wait' must be a mapping")

    def test_unknown_keys_are_rejected(self) -> None:
        for extra in ("auto_retry", "max_turns", "retry_interval", "notes"):
            with self.subTest(extra=extra):
                self._assert_rejected(_valid_capacity_wait(**{extra: 1}), "unknown key")

    def test_every_key_is_required(self) -> None:
        for key in ("auto_wait", "retry_interval_seconds", "max_attempts", "max_wait_seconds"):
            with self.subTest(missing=key):
                block = _valid_capacity_wait()
                del block[key]
                self._assert_rejected(block, "missing required key")

    # ---- auto_wait ----

    def test_auto_wait_must_be_a_real_boolean(self) -> None:
        for bogus in (1, 0, "true", "yes", None, [], 1.0):
            with self.subTest(auto_wait=bogus):
                self._assert_rejected(
                    _valid_capacity_wait(auto_wait=bogus), "capacity_wait.auto_wait"
                )

    # ---- enteros reales, nunca bool ----

    def test_integers_must_not_be_booleans(self) -> None:
        for key in ("retry_interval_seconds", "max_attempts", "max_wait_seconds"):
            for bogus in (True, False):
                with self.subTest(key=key, value=bogus):
                    self._assert_rejected(
                        _valid_capacity_wait(**{key: bogus}), f"capacity_wait.{key}"
                    )

    def test_integers_must_not_be_floats_or_strings(self) -> None:
        for key in ("retry_interval_seconds", "max_attempts", "max_wait_seconds"):
            for bogus in (1800.0, "1800", None, [1800]):
                with self.subTest(key=key, value=bogus):
                    self._assert_rejected(
                        _valid_capacity_wait(**{key: bogus}), f"capacity_wait.{key}"
                    )

    # ---- límites ----

    def test_retry_interval_bounds(self) -> None:
        for bad in (59, 30, 0, -1, 86401):
            with self.subTest(retry=bad):
                self._assert_rejected(
                    _valid_capacity_wait(retry_interval_seconds=bad, max_wait_seconds=604800),
                    "capacity_wait.retry_interval_seconds",
                )
        for good in (60, 86400):
            with self.subTest(retry=good):
                self._load(
                    _valid_capacity_wait(retry_interval_seconds=good, max_wait_seconds=604800)
                )

    def test_max_attempts_bounds(self) -> None:
        for bad in (0, -1, 101):
            with self.subTest(attempts=bad):
                self._assert_rejected(
                    _valid_capacity_wait(max_attempts=bad), "capacity_wait.max_attempts"
                )
        for good in (1, 100):
            with self.subTest(attempts=good):
                self._load(_valid_capacity_wait(max_attempts=good))

    def test_max_wait_must_not_be_below_retry_interval(self) -> None:
        self._assert_rejected(
            _valid_capacity_wait(retry_interval_seconds=1800, max_wait_seconds=1799),
            "capacity_wait.max_wait_seconds",
        )
        # Igual al intervalo: válido (mínimo permitido).
        self._load(_valid_capacity_wait(retry_interval_seconds=1800, max_wait_seconds=1800))

    def test_max_wait_upper_bound(self) -> None:
        self._assert_rejected(
            _valid_capacity_wait(max_wait_seconds=604801), "capacity_wait.max_wait_seconds"
        )
        self._load(_valid_capacity_wait(max_wait_seconds=604800))

    def test_capacity_wait_keys_do_not_trigger_the_secret_key_filter(self) -> None:
        # Ningún nombre del bloque coincide con el patrón de "secretos" del
        # loader: el bloque aprobado carga sin tocar ese filtro.
        self._load(_valid_capacity_wait())


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
                    "name": "Fixture",
                    "autonomy_overrides": {},
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


class NotificationsConfigTests(unittest.TestCase):
    """HUMAN-GATE-NOTIFY-001: NOTIFICATIONS.yaml es OPCIONAL y estricto."""

    VALID = {
        "notifications": {
            "enabled": True,
            "provider": "slack",
            "webhook_env_var": "AISOFTWAREFACTORY_SLACK_WEBHOOK_URL",
            "events": {"human_gate": True},
        }
    }

    def load(self, data) -> NotificationsConfig:
        with tempfile.TemporaryDirectory() as tmp:
            if data is not None:
                (Path(tmp) / "NOTIFICATIONS.yaml").write_text(
                    yaml.safe_dump(data), encoding="utf-8"
                )
            return load_notifications_config(tmp)

    def mutated(self, **changes) -> dict:
        data = yaml.safe_load(yaml.safe_dump(self.VALID))
        data["notifications"].update(changes)
        return data

    def test_absent_file_means_disabled(self) -> None:
        config = self.load(None)
        self.assertEqual(config, DISABLED_NOTIFICATIONS)
        self.assertFalse(config.enabled)

    def test_valid_enabled(self) -> None:
        config = self.load(self.VALID)
        self.assertEqual(
            config,
            NotificationsConfig(
                enabled=True,
                provider="slack",
                webhook_env_var="AISOFTWAREFACTORY_SLACK_WEBHOOK_URL",
                human_gate=True,
            ),
        )

    def test_valid_disabled_and_event_disabled(self) -> None:
        self.assertFalse(self.load(self.mutated(enabled=False)).enabled)
        config = self.load(self.mutated(events={"human_gate": False}))
        self.assertTrue(config.enabled)
        self.assertFalse(config.human_gate)

    def test_invalid_variants_are_rejected(self) -> None:
        bad = {
            "unknown key": self.mutated(extra=True),
            "unknown top-level key": {**self.VALID, "other": 1},
            "missing key": {"notifications": {"enabled": True, "provider": "slack"}},
            "enabled not a bool": self.mutated(enabled="yes"),
            "provider invalid": self.mutated(provider="email"),
            "provider not a string": self.mutated(provider=1),
            "event unknown": self.mutated(events={"human_gate": True, "other": True}),
            "event not a bool": self.mutated(events={"human_gate": "yes"}),
            "events empty": self.mutated(events={}),
            "env var lowercase": self.mutated(webhook_env_var="my_webhook"),
            "env var with a url": self.mutated(webhook_env_var="https://hooks.slack.com/services/T/B/X"),
            "env var with a space": self.mutated(webhook_env_var="A B"),
            "env var empty": self.mutated(webhook_env_var=""),
            "env var starts with a digit": self.mutated(webhook_env_var="1ABC"),
            "not a mapping": ["notifications"],
        }
        for label, data in bad.items():
            with self.subTest(label):
                with self.assertRaises(ConfigError):
                    self.load(data)

    def test_secret_shaped_keys_are_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            self.load(self.mutated(webhook_token="x"))

    def test_invalid_yaml_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "NOTIFICATIONS.yaml").write_text("notifications: [unclosed", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_notifications_config(tmp)

    def test_the_real_yaml_is_valid_and_holds_no_secret(self) -> None:
        path = CONFIG_DIR / "NOTIFICATIONS.yaml"
        config = load_notifications_config(CONFIG_DIR)
        self.assertEqual(config.provider, "slack")
        self.assertEqual(config.webhook_env_var, "AISOFTWAREFACTORY_SLACK_WEBHOOK_URL")
        text = path.read_text(encoding="utf-8")
        for needle in ("https://", "http://", "hooks.slack.com", "xoxb-", "xoxp-"):
            self.assertNotIn(needle, text)

    def test_load_core_config_does_not_require_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("POLICIES.yaml", "AGENTS.yaml", "GATES.yaml", "PERMISSIONS.yaml"):
                (Path(tmp) / name).write_text(
                    (CONFIG_DIR / name).read_text(encoding="utf-8"), encoding="utf-8"
                )
            load_core_config(tmp)  # sin NOTIFICATIONS.yaml: no falla


class GitPublishGovernanceTests(unittest.TestCase):
    """Declarative validation only; no Git/network execution."""

    def load(self, mutate=None):
        policies = _baseline_policies()
        permissions = _baseline_permissions()
        gates = _baseline_gates()
        if mutate:
            mutate(policies, permissions, gates)
        with tempfile.TemporaryDirectory() as tmp:
            _write_core_config(Path(tmp), policies=policies, permissions=permissions, gates=gates)
            return load_core_config(tmp)

    def reject(self, mutate):
        with self.assertRaises(ConfigError):
            self.load(mutate)

    def test_canonical_publication_policy(self):
        config = load_core_config(CONFIG_DIR)
        self.assertEqual(config.policies["controlled_actions"], {
            "git_publish_safe_test_source_tag": {"enabled": True, "classification": "AMARILLO",
                                                 "approval": "DIRECTOR_INTERNAL_GATE", "on_violation": "BLOCKED"},
            "git_publish_task_branch": {"enabled": True, "classification": "AMARILLO",
                                       "approval": "DIRECTOR_INTERNAL_GATE", "on_violation": "BLOCKED"}})
        self.assertEqual(config.permissions["git_publish"], _baseline_permissions()["git_publish"])
        self.assertTrue(config.gates["director_internal_gate"]["git_publish_task_branch"])

    def test_required_push_denials_missing(self):
        self.reject(lambda p, r, g: p["prohibitions"].pop("uncontrolled_git_push"))
        self.reject(lambda p, r, g: r["deny"].pop("uncontrolled_git_push"))

    def test_required_denials_must_be_true(self):
        for section, keys in (("policies", ("production", "uncontrolled_git_push", "git_merge", "irreversible_actions")),
                              ("permissions", ("production", "uncontrolled_git_push", "git_merge",
                                               "irreversible_actions", "env_files", "secret_files"))):
            for key in keys:
                for value in (False, 1, "true", None):
                    with self.subTest(section=section, key=key, value=value):
                        self.reject(lambda p, r, g: (p["prohibitions"] if section == "policies" else r["deny"]).update({key: value}))

    def test_legacy_policy_cannot_replace_new_schema(self):
        def legacy(p, r, g):
            p["prohibitions"].pop("uncontrolled_git_push")
            p["prohibitions"]["git_push"] = True
            p.pop("controlled_actions")
        self.reject(legacy)

    def test_legacy_permission_cannot_replace_new_schema(self):
        def legacy(p, r, g):
            r["deny"].pop("uncontrolled_git_push")
            r["deny"]["git_push"] = True
            r.pop("git_publish")
        self.reject(legacy)

    def test_mixed_legacy_and_new_schema_rejected(self):
        self.reject(lambda p, r, g: p["prohibitions"].update(git_push=True))
        self.reject(lambda p, r, g: r["deny"].update(git_push=True))

    def test_controlled_actions_missing_or_wrong_shape(self):
        self.reject(lambda p, r, g: p.pop("controlled_actions"))
        for value in (None, [], {}, {"another_action": {}}):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: p.update(controlled_actions=value))

    def test_controlled_action_keys_closed(self):
        self.reject(lambda p, r, g: p["controlled_actions"].update(other={}))
        self.reject(lambda p, r, g: p["controlled_actions"]["git_publish_task_branch"].update(extra=True))
        for key in ("enabled", "classification", "approval", "on_violation"):
            with self.subTest(key=key):
                self.reject(lambda p, r, g: p["controlled_actions"]["git_publish_task_branch"].pop(key))

    def test_controlled_action_values_exact(self):
        for key, value in (("classification", "VERDE"), ("approval", "AUTOMATIC"),
                           ("on_violation", "ALLOW"), ("enabled", 1), ("enabled", "true")):
            with self.subTest(key=key, value=value):
                self.reject(lambda p, r, g: p["controlled_actions"]["git_publish_task_branch"].update({key: value}))

    def test_git_publish_missing_or_wrong_shape(self):
        self.reject(lambda p, r, g: r.pop("git_publish"))
        for value in (None, [], True, "enabled"):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r.update(git_publish=value))

    def test_git_publish_keys_closed(self):
        self.reject(lambda p, r, g: r["git_publish"].update(extra=True))
        for key in _baseline_permissions()["git_publish"]:
            with self.subTest(key=key):
                self.reject(lambda p, r, g: r["git_publish"].pop(key))

    def test_enabled_requires_real_boolean(self):
        for value in (1, 0, "true", None, []):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r["git_publish"].update(enabled=value))

    def test_disabled_blocks_still_validate_and_do_not_default(self):
        result = self.load(lambda p, r, g: (
            p["controlled_actions"]["git_publish_task_branch"].update(enabled=False),
            r["git_publish"].update(enabled=False)))
        self.assertIs(result.permissions["git_publish"]["enabled"], False)
        self.reject(lambda p, r, g: r["git_publish"].update(enabled=False, allow_force=True))

    def test_force_tags_delete_always_false(self):
        for key in ("allow_force", "allow_tags", "allow_delete"):
            for value in (True, 0, "false", None):
                with self.subTest(key=key, value=value):
                    self.reject(lambda p, r, g: r["git_publish"].update({key: value}))

    def test_approval_packet_and_clean_worktree_always_required(self):
        for key in ("require_explicit_task_packet", "require_director_approval", "require_clean_worktree"):
            for value in (False, 1, "true", None):
                with self.subTest(key=key, value=value):
                    self.reject(lambda p, r, g: r["git_publish"].update({key: value}))

    def test_refspec_mode_cannot_expand(self):
        for value in ("all", "matching", "*", None):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r["git_publish"].update(refspec_mode=value))

    def test_remote_name_is_simple_identifier(self):
        for value in ("", " ", "-origin", "origin x", "https://host", "*", [], None):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r["git_publish"].update(remote_name=value))

    def test_remote_urls_nonempty_unique_strings(self):
        url = _baseline_permissions()["git_publish"]["allowed_remote_urls"][0]
        for value in ([], "", None, [""], [1], [url, url], [[]]):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r["git_publish"].update(allowed_remote_urls=value))

    def test_remote_credentials_rejected_without_echo(self):
        url = "https://synthetic-user:synthetic-password@github.com/example/repo.git"
        with self.assertRaises(ConfigError) as caught:
            self.load(lambda p, r, g: r["git_publish"].update(allowed_remote_urls=[url]))
        self.assertNotIn(url, str(caught.exception))
        self.assertNotIn("synthetic-password", str(caught.exception))

    def test_remote_query_fragment_ssh_and_wildcards_rejected(self):
        base = "https://github.com/example/repo.git"
        for url in (base + "?x=1", base + "#ref", base + "?", base + "#",
                    "git@github.com:example/repo.git", "ssh://github.com/example/repo.git",
                    "https://*.github.com/example/repo.git", base + "\n",
                    "https://github.com/example/*.git", "https://github.com:443/example/repo.git"):
            with self.subTest(url=url):
                self.reject(lambda p, r, g: r["git_publish"].update(allowed_remote_urls=[url]))

    def test_branch_prefix_rejects_unsafe_values(self):
        for value in ("", "/", "task", "../", "task/../", "task\\/", "task /", "task\n/",
                      "task\x00/", "task/*/", "task/?/", "task//", "-task/", None, []):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r["git_publish"].update(branch_prefix=value))

    def test_forbidden_branches_are_explicit_unique_and_include_main_master(self):
        for value in ([], "main", ["main"], ["master"], ["main", "master", "main"],
                      ["main", "master", ""], ["main", "master", 1],
                      ["main", "master", "*"], ["main", "master", "../x"], None):
            with self.subTest(value=value):
                self.reject(lambda p, r, g: r["git_publish"].update(forbidden_branches=value))

    def test_publish_capability_builder_only(self):
        from orchestrator.config_loader import require_builder_publish_capability, require_builder_capability
        permissions = self.load().permissions
        require_builder_publish_capability(permissions)
        require_builder_capability(permissions)
        for role in ("director", "verifier"):
            with self.subTest(role=role):
                self.reject(lambda p, r, g: r["role_capabilities"].update({role: ["publish_authorized_task_branch"]}))

    def test_missing_publish_capability_is_not_inferred(self):
        from orchestrator.config_loader import require_builder_publish_capability
        permissions = _baseline_permissions()
        permissions["role_capabilities"]["builder"] = ["implement_authorized_changes"]
        with self.assertRaises(ConfigError):
            require_builder_publish_capability(permissions)

    def test_unknown_capability_rejected(self):
        self.reject(lambda p, r, g: r["role_capabilities"]["builder"].append("publish_anything"))

    def test_both_director_gates_required_true(self):
        for key in ("amarillo_contemplado", "git_publish_task_branch"):
            with self.subTest(key=key):
                self.reject(lambda p, r, g: g["director_internal_gate"].pop(key))
                for value in (False, 1, "true", None):
                    self.reject(lambda p, r, g: g["director_internal_gate"].update({key: value}))

    def test_concrete_destinations_live_in_yaml_not_loader(self):
        config = self.load(lambda p, r, g: r["git_publish"].update(
            remote_name="review", allowed_remote_urls=["https://example.org/team/review.git"],
            branch_prefix="review/"))
        self.assertEqual(config.permissions["git_publish"]["remote_name"], "review")
        self.assertEqual(config.permissions["git_publish"]["branch_prefix"], "review/")
        # Validation is not approval of these destinations for operational use.



class RoleCapabilityConfigTests(unittest.TestCase):
    def roster(self):
        agents = _baseline_agents()
        agents["agents"]["developer"] = _valid_developer_handshake()
        return agents

    def resolve(self, agents):
        from orchestrator.config_loader import resolve_builder
        return resolve_builder(agents)

    def test_current_assignment(self):
        identity, agent = self.resolve(yaml.safe_load((CONFIG_DIR / "AGENTS.yaml").read_text(encoding="utf-8")))
        self.assertEqual(identity, "developer")
        self.assertEqual((agent["role"], agent["provider"], agent["adapter"], agent["enabled"]),
                         ("builder", "claude_code_cli", "claude_code_cli", True))
        self.assertNotEqual(identity, agent["role"])
        self.assertNotEqual(agent["role"], agent["provider"])

    def test_alternate_identity(self):
        agents = self.roster()
        agents["agents"]["implementation_agent"] = agents["agents"].pop("developer")
        self.assertEqual(self.resolve(agents)[0], "implementation_agent")

    def test_zero_builders(self):
        agents = self.roster()
        del agents["agents"]["developer"]
        with self.assertRaises(ConfigError):
            self.resolve(agents)

    def test_disabled_builder_not_selected(self):
        with self.assertRaises(ConfigError):
            self.resolve(_baseline_agents())

    def test_two_builders(self):
        agents = self.roster()
        agents["agents"]["second"] = dict(agents["agents"]["developer"])
        with self.assertRaises(ConfigError):
            self.resolve(agents)

    def test_unknown_role(self):
        agents = self.roster()
        agents["agents"]["developer"]["role"] = "developer"
        with self.assertRaises(ConfigError):
            self.resolve(agents)

    def test_adapter_and_provider_fail_closed(self):
        for key, value in [("adapter", "unknown"), ("adapter", "os.system"),
                           ("provider", "openai_api"), ("provider", None), ("adapter", None)]:
            with self.subTest(key=key, value=value):
                agents = self.roster()
                agents["agents"]["developer"][key] = value
                with self.assertRaises(ConfigError):
                    self.resolve(agents)

    def test_disabled_verifier_without_invented_provider(self):
        agents = self.roster()
        agents["agents"]["independent_review"] = {"role": "verifier", "enabled": False}
        self.assertEqual(self.resolve(agents)[0], "developer")
        with tempfile.TemporaryDirectory() as tmp:
            _write_core_config(Path(tmp), agents=agents)
            self.assertFalse(load_core_config(Path(tmp)).agents["agents"]["independent_review"]["enabled"])

    def test_director_and_verifier_cannot_be_enabled(self):
        for role in ("director", "verifier"):
            agents = self.roster()
            agents["agents"][role] = {"role": role, "enabled": True}
            with self.assertRaises(ConfigError):
                self.resolve(agents)

    def test_capability_is_explicit_not_inferred_from_role(self):
        from orchestrator.config_loader import require_builder_capability
        permissions = _baseline_permissions()
        require_builder_capability(permissions)
        permissions["role_capabilities"]["builder"] = []
        with self.assertRaises(ConfigError):
            require_builder_capability(permissions)
        del permissions["role_capabilities"]
        with self.assertRaises(ConfigError):
            require_builder_capability(permissions)

    def test_unknown_and_nonoperational_grants_fail_configuration(self):
        for grants in ({"builder": ["arbitrary_execution"]}, {"unknown": []},
                       {"director": ["implement_authorized_changes"]},
                       {"verifier": ["implement_authorized_changes"]}):
            with self.subTest(grants=grants), tempfile.TemporaryDirectory() as tmp:
                permissions = _baseline_permissions()
                permissions["role_capabilities"] = grants
                _write_core_config(Path(tmp), permissions=permissions)
                with self.assertRaises(ConfigError):
                    load_core_config(Path(tmp))

    def test_capability_cannot_override_denials_or_command_validation(self):
        from orchestrator.config_loader import require_builder_capability
        for field in ("deny", "allowed_commands"):
            permissions = _baseline_permissions()
            if field == "deny":
                permissions["deny"]["production"] = False
            else:
                permissions["allowed_commands"] = ["python -c arbitrary"]
            with self.assertRaises(ConfigError):
                require_builder_capability(permissions)


class CodexConfigTests(unittest.TestCase):
    def load(self, mutate=None):
        from tests.test_codex_adapter import codex_agent
        agents = _baseline_agents()
        agents["agents"]["codex_builder"] = codex_agent()
        if mutate:
            mutate(agents["agents"]["codex_builder"])
        with tempfile.TemporaryDirectory() as tmp:
            _write_core_config(Path(tmp), agents=agents)
            return load_core_config(Path(tmp))

    def test_canonical_claude_only_and_disabled_codex(self):
        from orchestrator.config_loader import resolve_builder
        config = load_core_config(CONFIG_DIR)
        self.assertEqual(resolve_builder(config.agents)[0], "developer")
        agent = config.agents["agents"]["codex_builder"]
        self.assertIs(agent["enabled"], False)
        self.assertEqual((agent["role"], agent["provider"], agent["adapter"]),
                         ("builder", "openai_codex", "codex_cli"))
        self.assertEqual(agent["executable"], "codex")

    def test_temporary_codex_builder_resolves(self):
        from orchestrator.config_loader import resolve_builder
        self.assertEqual(resolve_builder(self.load().agents)[0], "codex_builder")

    def test_pairing_and_module_paths_rejected(self):
        for key, value in (("provider", "claude_code_cli"), ("provider", "unknown"),
                           ("adapter", "claude_code_cli"), ("adapter", "os.system"),
                           ("adapter", "unknown"), ("executable", "C:/version/codex.exe")):
            with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                self.load(lambda a: a.update({key: value}))

    def test_execution_settings_closed_and_exact(self):
        cases = [("timeout_seconds", 0), ("timeout_seconds", True), ("timeout_seconds", 1.5),
                 ("sandbox", "danger-full-access"), ("approval_policy", "on-request"),
                 ("structured_output", "text"), ("ephemeral", False), ("ephemeral", 1),
                 ("ignore_user_config", False), ("ignore_user_config", "true"),
                 ("network_access", True), ("network_access", 0), ("max_turns", 8)]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                self.load(lambda a: a["task_execution"].update({key: value}))

    def test_unknown_or_missing_agent_keys_denied_even_disabled(self):
        for mutation in (lambda a: a.update(enabled=False, arbitrary=True),
                         lambda a: a["task_execution"].pop("sandbox"),
                         lambda a: a.update(task_execution=[])):
            with self.assertRaises(ConfigError):
                self.load(mutation)


class LocalProjectCommandControlsTests(unittest.TestCase):
    def load(self, permissions):
        with tempfile.TemporaryDirectory() as tmp:
            _write_core_config(Path(tmp), permissions=permissions)
            return load_core_config(tmp)

    def test_exact_false_accepted(self):
        config = self.load(_baseline_permissions())
        self.assertIs(config.permissions["execution_controls"]["local_project_commands"], False)

    def test_missing_block_rejected(self):
        permissions = _baseline_permissions()
        del permissions["execution_controls"]
        with self.assertRaises(ConfigError):
            self.load(permissions)

    def test_block_requires_mapping(self):
        for value in (None, False, [], "false", 0):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                permissions = _baseline_permissions()
                permissions["execution_controls"] = value
                self.load(permissions)

    def test_keys_closed_and_required(self):
        for value in ({}, {"local_project_commands": False, "extra": False}):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                permissions = _baseline_permissions()
                permissions["execution_controls"] = value
                self.load(permissions)

    def test_non_false_values_rejected_without_coercion(self):
        for value in (True, 1, 0, "false", None):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                permissions = _baseline_permissions()
                permissions["execution_controls"]["local_project_commands"] = value
                self.load(permissions)


class ProjectRulesAdmissionTests(unittest.TestCase):
    def canonical(self):
        return {"version": 1, "project_id": "X", "name": "Fixture", "repo_path": ".",
                "commands": {"unit": ["python", "-B", "verify.py"]},
                "protected_paths": ["**/.env*"], "autonomy_overrides": {}}

    def parse(self, data):
        return load_project_rules_from_yaml_bytes(
            yaml.safe_dump(data).encode("utf-8"), Path("PROJECT_RULES.yaml")
        )

    def test_canonical_and_current_real_rules_are_valid(self):
        self.assertEqual(self.parse(self.canonical()), self.canonical())
        for project_id in ("SAMPLE", "DISPOSABLE", "AIP_ISO"):
            with self.subTest(project_id=project_id):
                rules = load_project_rules(REPO_ROOT / "projects" / project_id / "PROJECT_RULES.yaml")
                self.assertEqual(rules["project_id"], project_id)
                self.assertEqual(rules["autonomy_overrides"], {})

    def test_closed_schema_rejects_missing_and_unknown_keys(self):
        for key in self.canonical():
            data = self.canonical()
            del data[key]
            with self.subTest(missing=key), self.assertRaises(ConfigError):
                self.parse(data)
        data = self.canonical()
        data["unknown"] = True
        with self.assertRaises(ConfigError):
            self.parse(data)

    def test_version_requires_real_integer_one(self):
        for value in (True, False, 1.0, "1", 0, 2, None):
            data = self.canonical()
            data["version"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.parse(data)

    def test_project_identity_name_and_path_validation(self):
        for key in ("project_id", "name", "repo_path"):
            for value in ("", None, 42, [], "bad\x00value"):
                data = self.canonical()
                data[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                    self.parse(data)
        for value in ("../X", "bad id", "/X", "X" * 65, "X\n"):
            data = self.canonical()
            data["project_id"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.parse(data)

    def test_duplicate_top_level_keys_rejected(self):
        raw = yaml.safe_dump(self.canonical())
        for key, value in self.canonical().items():
            duplicate = raw + yaml.safe_dump({key: value})
            with self.subTest(key=key), self.assertRaises(ConfigError):
                load_project_rules_from_yaml_bytes(duplicate.encode(), "fixture")

    def test_duplicate_nested_keys_and_merge_collisions_rejected(self):
        for raw in (
            "commands: {unit: [a], unit: [b]}",
            "autonomy_overrides: {a: {x: 1, x: 2}}",
            "base: &base {x: 1}\nother: {<<: *base, x: 2}",
        ):
            with self.subTest(raw=raw), self.assertRaisesRegex(ConfigError, "duplicate"):
                load_project_rules_from_yaml_bytes(raw.encode(), "fixture")
        # No global mutation of the general-purpose SafeLoader.
        self.assertEqual(yaml.safe_load("x: 1\nx: 2"), {"x": 2})

    def test_protected_paths_structure_and_duplicates_rejected(self):
        for value in ({}, None, "x", [1], [""], ["a\x00b"], ["x", "x"]):
            data = self.canonical()
            data["protected_paths"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.parse(data)

    def test_autonomy_overrides_must_be_empty_mapping(self):
        for value in (None, [], "", True, {"level": "VERDE"}):
            data = self.canonical()
            data["autonomy_overrides"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.parse(data)
        self.assertEqual(self.parse(self.canonical())["autonomy_overrides"], {})

    def test_invalid_encoding_unsafe_tags_and_non_mapping_rejected(self):
        for raw in (b"\xff", b"!!python/object/apply:os.system ['echo forbidden']",
                    b"[]", b"null", b"", b"autonomy_overrides: &a {loop: *a}"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                load_project_rules_from_yaml_bytes(raw, "fixture")

    def test_secret_keys_still_rejected(self):
        raw = b"commands: {api_key: ['placeholder']}"
        with self.assertRaisesRegex(ConfigError, "potential secret"):
            load_project_rules_from_yaml_bytes(raw, "fixture")

    def test_path_loader_reads_bytes_once_and_parser_never_opens_path(self):
        raw = yaml.safe_dump(self.canonical()).encode()
        with mock.patch.object(Path, "read_bytes", return_value=raw) as read:
            self.assertEqual(load_project_rules("fixture"), self.canonical())
        read.assert_called_once_with()
        with mock.patch.object(Path, "open", side_effect=AssertionError("unexpected reopen")):
            self.assertEqual(load_project_rules_from_yaml_bytes(raw, "fixture"), self.canonical())


class PermissionsAdmissionTests(unittest.TestCase):
    def parse(self, raw):
        return load_permissions_from_yaml_bytes(raw, "PERMISSIONS.yaml")

    def test_current_permissions_and_exact_byte_parser_valid(self):
        raw = (CONFIG_DIR / "PERMISSIONS.yaml").read_bytes()
        self.assertEqual(self.parse(raw), yaml.safe_load(raw))
        self.assertIs(self.parse(raw)["execution_controls"]["local_project_commands"], False)

    def test_invalid_encoding_tags_and_nonmapping_rejected(self):
        for raw in (b"\xff", b"!!python/object/apply:os.system ['forbidden']", b"[]", b"null"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                self.parse(raw)

    def test_duplicate_authority_keys_rejected_recursively(self):
        for raw in (
            b"version: 1\nversion: 1",
            b"deny: {production: true, production: false}",
            b"execution_controls: {local_project_commands: false, local_project_commands: true}",
            b"git_publish: {allow_force: false, allow_force: true}",
            b"role_capabilities: {builder: [], builder: [publish_authorized_task_branch]}",
            b"nested: {inner: {value: 1, value: 2}}",
        ):
            with self.subTest(raw=raw), self.assertRaisesRegex(ConfigError, "duplicate"):
                self.parse(raw)

    def test_alias_merge_collision_and_recursive_alias_rejected(self):
        for raw in (
            b"base: &base {x: 1}\nother: {<<: *base, x: 2}",
            b"deny: &d {loop: *d}",
        ):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                self.parse(raw)
        self.assertEqual(yaml.safe_load("x: 1\nx: 2"), {"x": 2})

    def test_unambiguous_alias_preserves_safe_yaml_semantics(self):
        data = _baseline_permissions()
        data["role_capabilities"]["verifier"] = []
        data["role_capabilities"]["director"] = data["role_capabilities"]["verifier"]
        raw = yaml.safe_dump(data).encode()
        self.assertEqual(self.parse(raw), data)

    def test_parser_does_not_reopen_source(self):
        raw = yaml.safe_dump(_baseline_permissions()).encode()
        with mock.patch.object(Path, "open", side_effect=AssertionError("unexpected reopen")):
            self.assertEqual(self.parse(raw), _baseline_permissions())

    def test_existing_validators_preserved(self):
        for mutate in (
            lambda p: p["deny"].update(production=False),
            lambda p: p["execution_controls"].update(local_project_commands=True),
            lambda p: p["git_publish"].update(allow_force=True),
            lambda p: p["role_capabilities"].update(builder=["unknown"]),
            lambda p: p.update(allowed_commands=["shell command"]),
            lambda p: p.update(api_key="placeholder"),
        ):
            data = _baseline_permissions()
            mutate(data)
            with self.subTest(mutate=mutate), self.assertRaises(ConfigError):
                self.parse(yaml.safe_dump(data).encode())

    def test_core_config_uses_supplied_snapshot_without_permissions_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_core_config(root)
            path = root / "PERMISSIONS.yaml"
            raw = path.read_bytes()
            path.unlink()
            config = load_core_config_from_permissions_bytes(root, raw)
            self.assertEqual(config.permissions, yaml.safe_load(raw))
            with self.assertRaises(ConfigError):
                load_core_config(root)


class PublicationAuthorityFoundationTests(unittest.TestCase):
    def parsers(self):
        from orchestrator.config_loader import load_policies_from_yaml_bytes, load_gates_from_yaml_bytes
        return (("POLICIES", load_policies_from_yaml_bytes), ("GATES", load_gates_from_yaml_bytes))

    def test_current_bytes_without_open_and_global_loader_unchanged(self):
        from unittest import mock
        constructors = dict(yaml.SafeLoader.yaml_constructors)
        mapping = yaml.SafeLoader.construct_mapping
        for name, parser in self.parsers():
            raw = (REPO_ROOT / "config" / (name + ".yaml")).read_bytes()
            expected = yaml.safe_load(raw)
            with self.subTest(name=name), mock.patch.object(Path, "open", side_effect=AssertionError("reopen")):
                self.assertEqual(parser(raw, "absent.yaml"), expected)
        self.assertEqual(yaml.SafeLoader.yaml_constructors, constructors)
        self.assertIs(yaml.SafeLoader.construct_mapping, mapping)
        self.assertEqual(yaml.safe_load("x: 1\nx: 2"), {"x": 2})

    def test_encoding_tags_duplicates_merges_types_and_secrets(self):
        for name, parser in self.parsers():
            raw = (REPO_ROOT / "config" / (name + ".yaml")).read_bytes()
            nested = (b"prohibitions: {production: true, production: true}\n" if name == "POLICIES"
                      else b"director_internal_gate: {amarillo_contemplado: true, amarillo_contemplado: true}\n")
            cases = [b"\xff", b"!!python/object:builtins.object {}", b"[]", b"null",
                     raw + b"\nversion: 1\n", nested,
                     b"x: &x {enabled: true}\ny: {<<: *x, enabled: false}\n",
                     raw + b"\napi_key: forbidden\n", "not bytes", bytearray(raw)]
            for invalid in cases:
                with self.subTest(name=name, invalid=repr(invalid)[:80]), self.assertRaises(ConfigError):
                    parser(invalid, "unused.yaml")

    def test_existing_validator_semantics_and_alias_policy(self):
        from orchestrator import config_loader as loader
        for name, parser in self.parsers():
            data = yaml.safe_load((REPO_ROOT / "config" / (name + ".yaml")).read_bytes())
            validator = loader._validate_policies if name == "POLICIES" else loader._validate_gates
            for key in tuple(data):
                altered = dict(data)
                del altered[key]
                with self.subTest(name=name, removed=key):
                    try:
                        validator(altered, Path("unused.yaml"))
                    except ConfigError:
                        with self.assertRaises(ConfigError):
                            parser(yaml.safe_dump(altered).encode(), "unused.yaml")
                    else:
                        self.assertEqual(parser(yaml.safe_dump(altered).encode(), "unused.yaml"), altered)
            raw = yaml.safe_dump(data).encode()
            self.assertIn("alias", parser(raw + b"\nbase: &base {ordinary: true}\nalias: *base\n", "unused.yaml"))
            with self.assertRaises(ConfigError):
                parser(raw + b"\ncycle: &cycle {child: *cycle}\n", "unused.yaml")

    def test_duplicates_are_rejected_by_shared_mapping_loader(self):
        for name, parser in self.parsers():
            for raw in (
                b"version: 1\nversion: 1\n",
                b"controlled_actions: {git_publish_task_branch: {enabled: true, enabled: false}}\n",
                b"director_internal_gate: {git_publish_task_branch: true, git_publish_task_branch: false}\n",
                b"base: &base {enabled: true}\naction: {<<: *base, enabled: false}\n",
            ):
                with self.subTest(name=name, raw=raw), self.assertRaisesRegex(ConfigError, "duplicate"):
                    parser(raw, "unused.yaml")

    def test_intersection_requires_every_declarative_condition(self):
        import copy
        from orchestrator.config_loader import OrchestratorConfig, require_controlled_publication_authority
        baseline = load_core_config(REPO_ROOT / "config")
        before = copy.deepcopy(baseline)
        self.assertIsNone(require_controlled_publication_authority(baseline))
        self.assertEqual(baseline, before)
        mutations = [
            lambda c: c.permissions["git_publish"].update(enabled=False),
            lambda c: c.permissions["role_capabilities"].update(builder=[]),
            lambda c: c.policies["controlled_actions"]["git_publish_task_branch"].update(enabled=False),
            lambda c: c.policies["controlled_actions"]["git_publish_task_branch"].update(classification="VERDE"),
            lambda c: c.policies["controlled_actions"]["git_publish_task_branch"].update(approval="OTHER"),
            lambda c: c.policies["controlled_actions"]["git_publish_task_branch"].update(on_violation="ALLOW"),
            lambda c: c.gates["director_internal_gate"].update(amarillo_contemplado=False),
            lambda c: c.gates["director_internal_gate"].update(git_publish_task_branch=False),
            lambda c: c.permissions.pop("git_publish"),
            lambda c: c.policies.pop("controlled_actions"),
            lambda c: c.gates.pop("director_internal_gate"),
            lambda c: c.permissions["git_publish"].update(enabled="true"),
        ]
        for index, mutate in enumerate(mutations):
            config = copy.deepcopy(baseline)
            mutate(config)
            with self.subTest(index=index), self.assertRaises(ConfigError):
                require_controlled_publication_authority(config)
        for invalid in (None, {}, OrchestratorConfig({}, {}, {}, None)):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                require_controlled_publication_authority(invalid)


class SafeTestBackendPolicyTests(unittest.TestCase):
    def load_policy(self, data):
        from orchestrator.config_loader import load_policies_from_yaml_bytes
        return load_policies_from_yaml_bytes(yaml.safe_dump(data).encode("utf-8"), "POLICIES.yaml")

    def test_canonical_policy_and_legacy_absence(self):
        from orchestrator.config_loader import validate_safe_test_backend
        policy = yaml.safe_load((CONFIG_DIR / "POLICIES.yaml").read_text(encoding="utf-8"))
        self.assertEqual(self.load_policy(policy)["safe_test_backend"]["activation"], "disabled")
        del policy["safe_test_backend"]
        self.assertIsNone(validate_safe_test_backend(self.load_policy(policy)))

    def test_migration_must_cannot_be_weakened(self):
        for key, value in (("mvp", "other"), ("production_required", "optional"),
                           ("github_app_required_before", []), ("token", "SENTINEL")):
            data = yaml.safe_load((CONFIG_DIR / "POLICIES.yaml").read_text(encoding="utf-8"))
            data["safe_test_backend"]["credential_strategy"][key] = value
            with self.subTest(key=key), self.assertRaises(ConfigError):
                self.load_policy(data)

    def test_closed_policy_rejects_partial_enabled_and_extra_fields(self):
        for block in (None, {}, {"activation": "enabled"}):
            data = _baseline_policies()
            data["safe_test_backend"] = block
            with self.subTest(block=block), self.assertRaises(ConfigError):
                self.load_policy(data)
        data = yaml.safe_load((CONFIG_DIR / "POLICIES.yaml").read_text(encoding="utf-8"))
        data["safe_test_backend"]["activation"] = "enabled"
        with self.assertRaises(ConfigError):
            self.load_policy(data)

    def test_credential_exception_is_exact_path_only(self):
        data = _baseline_policies()
        data["credential_strategy"] = {"mvp": "fine_grained_pat_dpapi"}
        with self.assertRaises(ConfigError):
            self.load_policy(data)


class SafeTestSourceTagAuthorityTests(unittest.TestCase):
    def setUp(self):
        from orchestrator.config_loader import require_controlled_source_tag_authority
        self.require_authority = require_controlled_source_tag_authority
        self.config = load_core_config(CONFIG_DIR)

    def reject_permission(self, key, value):
        import copy
        from orchestrator.config_loader import load_permissions_from_yaml_bytes
        permissions = copy.deepcopy(self.config.permissions)
        permissions["git_tag_publish"][key] = value
        with self.assertRaises(ConfigError):
            load_permissions_from_yaml_bytes(yaml.safe_dump(permissions).encode(), "unused.yaml")

    def test_exact_canonical_authority_and_ordinary_contract(self):
        import copy
        from orchestrator.config_loader import require_controlled_publication_authority
        before = copy.deepcopy(self.config)
        self.assertIsNone(self.require_authority(self.config))
        self.assertIsNone(require_controlled_publication_authority(self.config))
        self.assertEqual(self.config, before)
        self.assertEqual(self.config.permissions["git_publish"], _baseline_permissions()["git_publish"])
        self.assertIs(self.config.permissions["git_publish"]["allow_tags"], False)
        self.assertEqual(set(self.config.permissions["role_capabilities"]["builder"]), {
            "implement_authorized_changes", "publish_authorized_task_branch",
            "publish_authorized_safe_test_source_tag"})
        for role in ("director", "verifier"):
            self.assertEqual(self.config.permissions["role_capabilities"][role], [])

    def test_exact_destination_and_object(self):
        cases = {
            "remote_name": ["other", "Origin", None],
            "allowed_repository_url": ["https://evil.invalid/repo.git", "https://github.com/other/repo.git"],
            "allowed_tag_ref": ["refs/tags/other", "refs/heads/main", "refs/tags/*", "../main"],
            "allowed_target_sha": ["a" * 40, "DB38EF6E6CBC73D8E54B591D4F0EB747073D500B", "db38ef6", "g" * 40, None],
            "allowed_target_tree": ["a" * 40, "short"],
            "tag_type": ["annotated", "signed", None],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.reject_permission(key, value)

    def test_all_boolean_constraints_without_coercion(self):
        block = self.config.permissions["git_tag_publish"]
        for key, value in block.items():
            if type(value) is bool:
                for invalid in (not value, int(value), str(value), None):
                    with self.subTest(key=key, invalid=invalid):
                        self.reject_permission(key, invalid)

    def test_closed_permission_and_ruleset_schema(self):
        import copy
        from orchestrator.config_loader import load_permissions_from_yaml_bytes
        baseline = self.config.permissions
        for key in baseline["git_tag_publish"]:
            permissions = copy.deepcopy(baseline)
            del permissions["git_tag_publish"][key]
            with self.subTest(missing=key), self.assertRaises(ConfigError):
                load_permissions_from_yaml_bytes(yaml.safe_dump(permissions).encode(), "unused.yaml")
        self.reject_permission("extra", True)
        ruleset = baseline["git_tag_publish"]["protective_ruleset"]
        for key in ruleset:
            missing = dict(ruleset)
            del missing[key]
            with self.subTest(missing_ruleset=key):
                self.reject_permission("protective_ruleset", missing)
            altered = dict(ruleset)
            altered[key] = None
            with self.subTest(changed_ruleset=key):
                self.reject_permission("protective_ruleset", altered)
        for key, value in (("extra", True), ("bypass_actors", ["actor"]),
                           ("rules", ["update"]), ("enforcement", "disabled"),
                           ("creation_restricted", 0)):
            with self.subTest(key=key):
                self.reject_permission("protective_ruleset", dict(ruleset, **{key: value}))

    def test_intersection_missing_disabled_wrong_or_unauthorized(self):
        import copy
        action = "git_publish_safe_test_source_tag"
        mutations = [
            lambda c: c.permissions.pop("git_tag_publish"),
            lambda c: c.policies["controlled_actions"].pop(action),
            lambda c: c.policies["controlled_actions"][action].update(enabled=False),
            lambda c: c.policies["controlled_actions"][action].update(enabled=1),
            lambda c: c.policies["controlled_actions"][action].update(classification="VERDE"),
            lambda c: c.policies["controlled_actions"][action].update(approval="OTHER"),
            lambda c: c.policies["controlled_actions"][action].update(on_violation="ALLOW"),
            lambda c: c.policies["controlled_actions"][action].update(extra=True),
            lambda c: c.gates["director_internal_gate"].pop(action),
            lambda c: c.gates["director_internal_gate"].update({action: False}),
            lambda c: c.gates["director_internal_gate"].update({action: 1}),
            lambda c: c.permissions["role_capabilities"]["builder"].remove("publish_authorized_safe_test_source_tag"),
            lambda c: c.permissions["role_capabilities"]["builder"].append("publish_any_tag"),
            lambda c: c.permissions["role_capabilities"]["director"].append("publish_authorized_safe_test_source_tag"),
            lambda c: c.permissions["role_capabilities"]["verifier"].append("publish_authorized_safe_test_source_tag"),
        ]
        for mutate in mutations:
            altered = copy.deepcopy(self.config)
            mutate(altered)
            with self.subTest(mutation=mutate), self.assertRaises(ConfigError):
                self.require_authority(altered)
        for invalid in (None, {}):
            with self.assertRaises(ConfigError):
                self.require_authority(invalid)


if __name__ == "__main__":
    unittest.main()
