"""Pruebas de CLI — demuestran el bypass de fail-closed corregido en
BOOTSTRAP-001/CORRECTION-001 (hallazgo 1), la eliminación del actor
implícito ("operator") en `transition` (trazabilidad), y el rechazo de un
PROJECT_RULES.yaml cuyo project_id no coincide con el proyecto solicitado
(CORRECTION-002).

Cada prueba parchea app.REPO_ROOT / app.CONFIG_DIR / app.PROJECTS_DIR para
operar sobre una configuración de fixture aislada bajo un directorio
temporal, sin tocar la configuración real del repositorio ni invocar
subprocesos: se llama directamente a orchestrator.app.main().
"""

import contextlib
import io
import json
import shutil
import sqlite3
import subprocess
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

from orchestrator import app  # noqa: E402
from orchestrator.adapters.claude_code import (  # noqa: E402
    EXPECTED_HANDSHAKE_RESULT,
    EXPECTED_WRITE_RESULT,
    WRITE_PROBE_AFTER_CONTENT,
    WRITE_PROBE_TARGET_FILENAME,
)
from orchestrator.sandbox import SANDBOX_PREFIX  # noqa: E402
from orchestrator.store import Store  # noqa: E402


def _valid_core_config() -> dict[str, dict]:
    return {
        "POLICIES.yaml": {
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
        },
        "AGENTS.yaml": {
            "version": 1,
            "agents": {
                "director": {"role": "director", "enabled": False},
                "developer": {"role": "developer", "enabled": False},
            },
        },
        "GATES.yaml": {
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
        },
        "PERMISSIONS.yaml": {
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
        },
    }


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _project_row_exists(db_path: Path, project_id: str) -> bool:
    """Lectura directa de solo verificación (fuera de Store) para confirmar,
    en las pruebas de CORRECTION-002, que un register-project/create-task
    rechazado no dejó ninguna fila en la tabla project/task."""
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT 1 FROM project WHERE id = ?", (project_id,))
        return cur.fetchone() is not None
    finally:
        conn.close()


class CliFixtureTestCase(unittest.TestCase):
    """Fixture aislada: config/ + projects/SAMPLE/ + orchestrator.db bajo un
    directorio temporal, con app.REPO_ROOT/CONFIG_DIR/PROJECTS_DIR parcheados
    para que la CLI real opere exclusivamente sobre ella."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config_dir = self.root / "config"
        self.projects_dir = self.root / "projects"
        self.config_dir.mkdir()
        self.projects_dir.mkdir()
        (self.projects_dir / "SAMPLE").mkdir()

        for name, data in _valid_core_config().items():
            _write_yaml(self.config_dir / name, data)

        _write_yaml(
            self.projects_dir / "SAMPLE" / "PROJECT_RULES.yaml",
            {
                "version": 1,
                "project_id": "SAMPLE",
                "name": "Sample",
                "repo_path": "./projects/SAMPLE",
                "commands": {"test": None, "lint": None, "tsc": None, "build": None},
                "protected_paths": ["**/.env*"],
            },
        )

        self.db_path = self.root / "orchestrator.db"

        self._patches = [
            mock.patch.object(app, "REPO_ROOT", self.root),
            mock.patch.object(app, "CONFIG_DIR", self.config_dir),
            mock.patch.object(app, "PROJECTS_DIR", self.projects_dir),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def run_cli(self, *argv: str) -> int:
        return app.main(["--db-path", str(self.db_path), *argv])

    def corrupt_core_config(self) -> None:
        """Simula 'config ausente' retirando el directorio config/ completo."""
        shutil.rmtree(self.config_dir)

    def weaken_policy(self) -> None:
        """Simula una política insegura: production ya no está prohibida."""
        data = _valid_core_config()["POLICIES.yaml"]
        data["prohibitions"]["production"] = False
        _write_yaml(self.config_dir / "POLICIES.yaml", data)

    def remove_project_rules(self, project_id: str = "SAMPLE") -> None:
        (self.projects_dir / project_id / "PROJECT_RULES.yaml").unlink()

    def set_project_rules_project_id(
        self, new_project_id: str, project_id: str = "SAMPLE"
    ) -> None:
        """Reescribe PROJECT_RULES.yaml de `project_id` para que declare
        `new_project_id`, dejando el archivo estructuralmente válido pero
        con un project_id que ya no corresponde al directorio/proyecto
        solicitado (escenario del hallazgo de CORRECTION-002)."""
        rules_path = self.projects_dir / project_id / "PROJECT_RULES.yaml"
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        data["project_id"] = new_project_id
        _write_yaml(rules_path, data)

    def enable_developer(self, **overrides) -> None:
        """CLAUDE-EXECUTION-001: habilita developer con un handshake válido
        (o el override indicado) reescribiendo AGENTS.yaml de la fixture."""
        data = yaml.safe_load((self.config_dir / "AGENTS.yaml").read_text(encoding="utf-8"))
        developer = {
            "role": "developer",
            "enabled": True,
            "executable": "claude",
            "output_format": "json",
            "max_turns": 1,
            "timeout_seconds": 60,
            "permission_mode": "plan",
            "restricted": True,
        }
        developer.update(overrides)
        data["agents"]["developer"] = developer
        _write_yaml(self.config_dir / "AGENTS.yaml", data)

    def enable_write_probe(self, **write_probe_overrides) -> None:
        """CLAUDE-EXECUTION-002: habilita developer + write_probe con una
        configuración válida (permission_mode/restricted/max_turns/
        timeout_seconds propios, independientes del handshake read-only,
        que permanece en "plan")."""
        data = yaml.safe_load((self.config_dir / "AGENTS.yaml").read_text(encoding="utf-8"))
        write_probe = {
            "enabled": True,
            "permission_mode": "acceptEdits",
            "restricted": True,
            "max_turns": 3,
            "timeout_seconds": 90,
        }
        write_probe.update(write_probe_overrides)
        developer = {
            "role": "developer",
            "enabled": True,
            "executable": "claude",
            "output_format": "json",
            "max_turns": 1,
            "timeout_seconds": 60,
            "permission_mode": "plan",
            "restricted": True,
            "write_probe": write_probe,
        }
        data["agents"]["developer"] = developer
        _write_yaml(self.config_dir / "AGENTS.yaml", data)


class InitAndRegisterTests(CliFixtureTestCase):
    def test_happy_path_setup_succeeds(self) -> None:
        self.assertEqual(self.run_cli("init-storage"), 0)
        self.assertEqual(self.run_cli("register-project", "SAMPLE"), 0)


class ConfigAbsentBlocksCreateTaskTests(CliFixtureTestCase):
    """Escenario obligatorio 1: config ausente -> create-task rechazada y
    la base de datos queda sin cambios."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")

    def test_create_task_rejected_and_db_unchanged_when_config_missing(self) -> None:
        self.corrupt_core_config()
        rc = self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")
        self.assertNotEqual(rc, 0)
        with Store(self.db_path) as store:
            self.assertIsNone(store.get_task("T-1"))


class ConfigAbsentBlocksTransitionTests(CliFixtureTestCase):
    """Escenario obligatorio 2: config ausente -> transition rechazada y el
    estado/historial de la tarea quedan intactos."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")
        self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")

    def test_transition_rejected_and_state_history_intact_when_config_missing(self) -> None:
        with Store(self.db_path) as store:
            before_task = store.get_task("T-1")
            before_history = store.get_history("T-1")

        self.corrupt_core_config()
        rc = self.run_cli(
            "transition", "T-1", "SPECIFICATION", "--reason", "r", "--actor", "director"
        )
        self.assertNotEqual(rc, 0)

        with Store(self.db_path) as store:
            after_task = store.get_task("T-1")
            after_history = store.get_history("T-1")
        self.assertEqual(before_task, after_task)
        self.assertEqual(before_history, after_history)


class InsecurePolicyBlocksTransitionTests(CliFixtureTestCase):
    """Escenario obligatorio 3: política insegura (production ya no
    prohibida) -> transition rechazada."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")
        self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")

    def test_transition_rejected_when_policy_is_weakened(self) -> None:
        with Store(self.db_path) as store:
            before_task = store.get_task("T-1")

        self.weaken_policy()
        rc = self.run_cli(
            "transition", "T-1", "SPECIFICATION", "--reason", "r", "--actor", "director"
        )
        self.assertNotEqual(rc, 0)

        with Store(self.db_path) as store:
            after_task = store.get_task("T-1")
        self.assertEqual(before_task, after_task)


class ProjectRulesAbsentBlocksCreateTaskTests(CliFixtureTestCase):
    """Escenario obligatorio 4: PROJECT_RULES ausente -> create-task
    rechazada (config core sigue válida)."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")

    def test_create_task_rejected_when_project_rules_missing(self) -> None:
        self.remove_project_rules("SAMPLE")
        rc = self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")
        self.assertNotEqual(rc, 0)
        with Store(self.db_path) as store:
            self.assertIsNone(store.get_task("T-1"))


class ConfigAbsentBlocksReadOperationsTests(CliFixtureTestCase):
    """Hallazgo 1, mínimo para get-task/history: también deben validar la
    config core antes de operar."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")
        self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")

    def test_get_task_rejected_when_config_missing(self) -> None:
        self.corrupt_core_config()
        rc = self.run_cli("get-task", "T-1")
        self.assertNotEqual(rc, 0)

    def test_history_rejected_when_config_missing(self) -> None:
        self.corrupt_core_config()
        rc = self.run_cli("history", "T-1")
        self.assertNotEqual(rc, 0)


class ActorRequiredTests(CliFixtureTestCase):
    """Trazabilidad: no debe existir un actor implícito ("operator") por
    defecto en `transition`; --actor es obligatorio."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")
        self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")

    def test_transition_without_actor_is_rejected_by_argument_parsing(self) -> None:
        with self.assertRaises(SystemExit):
            self.run_cli("transition", "T-1", "SPECIFICATION", "--reason", "r")

    def test_transition_with_explicit_actor_succeeds(self) -> None:
        rc = self.run_cli(
            "transition", "T-1", "SPECIFICATION", "--reason", "r", "--actor", "director"
        )
        self.assertEqual(rc, 0)
        with Store(self.db_path) as store:
            task = store.get_task("T-1")
            history = store.get_history("T-1")
        self.assertEqual(task["status"], "SPECIFICATION")
        self.assertEqual(history[-1]["actor"], "director")


class ProjectIdMismatchOnRegisterTests(CliFixtureTestCase):
    """Escenario obligatorio 1 (CORRECTION-002): PROJECT_RULES.project_id
    distinto del proyecto solicitado -> register-project rechazado, sin
    dejar fila en la tabla project."""

    def test_register_project_rejected_when_project_id_mismatches(self) -> None:
        self.run_cli("init-storage")
        self.set_project_rules_project_id("OTHER", project_id="SAMPLE")

        rc = self.run_cli("register-project", "SAMPLE")

        self.assertNotEqual(rc, 0)
        self.assertFalse(_project_row_exists(self.db_path, "SAMPLE"))


class ProjectIdMismatchBlocksCreateTaskTests(CliFixtureTestCase):
    """Escenario obligatorio 2 (CORRECTION-002): SAMPLE registrado con
    reglas válidas; luego PROJECT_RULES.yaml de SAMPLE cambia a
    project_id: OTHER -> create-task sobre SAMPLE rechazada y la tarea no
    se crea."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")

    def test_create_task_rejected_after_project_rules_project_id_changed(self) -> None:
        self.set_project_rules_project_id("OTHER", project_id="SAMPLE")

        rc = self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")

        self.assertNotEqual(rc, 0)
        with Store(self.db_path) as store:
            self.assertIsNone(store.get_task("T-1"))


class ProjectIdMismatchBlocksTransitionTests(CliFixtureTestCase):
    """Escenario obligatorio 3 (CORRECTION-002): SAMPLE registrado + tarea
    existente; luego PROJECT_RULES.yaml de SAMPLE cambia a
    project_id: OTHER -> transition sobre la tarea rechazada, con estado e
    historial intactos."""

    def setUp(self) -> None:
        super().setUp()
        self.run_cli("init-storage")
        self.run_cli("register-project", "SAMPLE")
        self.run_cli("create-task", "T-1", "SAMPLE", "Title", "Need")

    def test_transition_rejected_after_project_rules_project_id_changed(self) -> None:
        with Store(self.db_path) as store:
            before_task = store.get_task("T-1")
            before_history = store.get_history("T-1")

        self.set_project_rules_project_id("OTHER", project_id="SAMPLE")
        rc = self.run_cli(
            "transition", "T-1", "SPECIFICATION", "--reason", "r", "--actor", "director"
        )

        self.assertNotEqual(rc, 0)
        with Store(self.db_path) as store:
            after_task = store.get_task("T-1")
            after_history = store.get_history("T-1")
        self.assertEqual(before_task, after_task)
        self.assertEqual(before_history, after_history)


class DeveloperProbeDisabledTests(CliFixtureTestCase):
    """Escenario obligatorio 16 (CLAUDE-EXECUTION-001): developer
    deshabilitado (default de la fixture) -> developer-probe rechazado."""

    def test_developer_probe_rejected_when_developer_disabled(self) -> None:
        with mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run"
        ) as mock_run:
            rc = self.run_cli("developer-probe")
        self.assertNotEqual(rc, 0)
        mock_run.assert_not_called()


class DeveloperProbeEnabledTests(CliFixtureTestCase):
    """Verifica el wiring end-to-end de `developer-probe`: config core ->
    AGENTS.yaml -> ClaudeCodeAdapter, con subprocess mockeado (sin invocar
    Claude Code real)."""

    def setUp(self) -> None:
        super().setUp()
        self.enable_developer()

    def test_developer_probe_success_prints_summary(self) -> None:
        # CORRECTION-001: representa el JSON de éxito EXACTO exigido por el
        # handshake determinista (type/subtype/is_error/result).
        payload = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": EXPECTED_HANDSHAKE_RESULT,
                "session_id": "sess-1",
                "num_turns": 1,
                "duration_ms": 500,
            }
        )
        completed = subprocess.CompletedProcess(
            args=["claude"], returncode=0, stdout=payload, stderr=""
        )
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ) as mock_run:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.run_cli("developer-probe")

        self.assertEqual(rc, 0)
        mock_run.assert_called_once()
        _, call_kwargs = mock_run.call_args
        self.assertIs(call_kwargs["shell"], False)
        self.assertIn(EXPECTED_HANDSHAKE_RESULT, stdout.getvalue())

    def test_developer_probe_fails_closed_on_is_error_true(self) -> None:
        payload = '{"is_error": true, "result": "something went wrong"}'
        completed = subprocess.CompletedProcess(
            args=["claude"], returncode=0, stdout=payload, stderr=""
        )
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            rc = self.run_cli("developer-probe")
        self.assertNotEqual(rc, 0)


def _sandbox_dirs(root: Path) -> list[str]:
    return [p.name for p in root.iterdir() if p.name.startswith(SANDBOX_PREFIX)]


class DeveloperWriteProbeDisabledTests(CliFixtureTestCase):
    """Escenario obligatorio 22 (CLAUDE-EXECUTION-002): write_probe
    deshabilitado/ausente -> CLI rechaza sin invocar subprocess."""

    def test_write_probe_rejected_when_not_declared(self) -> None:
        self.enable_developer()  # developer habilitado, sin write_probe
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            rc = self.run_cli("developer-write-probe")
        self.assertNotEqual(rc, 0)
        mock_run.assert_not_called()
        self.assertEqual(_sandbox_dirs(self.root), [])

    def test_write_probe_rejected_when_explicitly_disabled(self) -> None:
        self.enable_write_probe(enabled=False)
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            rc = self.run_cli("developer-write-probe")
        self.assertNotEqual(rc, 0)
        mock_run.assert_not_called()


class DeveloperWriteProbeEnabledTests(CliFixtureTestCase):
    """Verifica el wiring end-to-end de `developer-write-probe`: creación
    del sandbox, invocación del adaptador (subprocess mockeado) y limpieza
    del sandbox tanto en éxito como en fallo controlado."""

    def setUp(self) -> None:
        super().setUp()
        self.enable_write_probe()

    def test_write_probe_success_cleans_sandbox_and_prints_summary(self) -> None:
        payload = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": EXPECTED_WRITE_RESULT,
                "session_id": "s1",
                "num_turns": 2,
                "duration_ms": 321,
            }
        )

        def fake_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / WRITE_PROBE_TARGET_FILENAME).write_text(
                WRITE_PROBE_AFTER_CONTENT, encoding="utf-8"
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout=payload, stderr="")

        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", side_effect=fake_run
        ) as mock_run:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.run_cli("developer-write-probe")

        self.assertEqual(rc, 0)
        mock_run.assert_called_once()
        self.assertIn(EXPECTED_WRITE_RESULT, stdout.getvalue())

        # 25. sandbox se limpia después de éxito.
        self.assertEqual(_sandbox_dirs(self.root), [])

    def test_write_probe_controlled_failure_still_cleans_sandbox(self) -> None:
        payload = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "NOT_THE_RIGHT_TEXT",
                "session_id": "s1",
                "num_turns": 1,
                "duration_ms": 10,
            }
        )

        def fake_run(args, **kwargs):
            # No modifica TARGET.txt: la evaluación fallará por evidencia
            # de filesystem, además de por el texto de 'result' incorrecto.
            return subprocess.CompletedProcess(args=args, returncode=0, stdout=payload, stderr="")

        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", side_effect=fake_run
        ):
            rc = self.run_cli("developer-write-probe")

        self.assertNotEqual(rc, 0)

        # 26. sandbox se limpia después de fallo controlado (finally).
        self.assertEqual(_sandbox_dirs(self.root), [])


if __name__ == "__main__":
    unittest.main()
