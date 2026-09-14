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
from orchestrator.evidence import EvidenceError, GIT_EVIDENCE_PROBE_PREFIX  # noqa: E402
from orchestrator.sandbox import SANDBOX_PREFIX  # noqa: E402
from orchestrator.store import Store  # noqa: E402
from orchestrator.task_packet import TaskPacketError  # noqa: E402


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
                "commands": {},
                "protected_paths": ["**/.env*"],
            },
        )

        self.db_path = self.root / "orchestrator.db"

        self.tasks_dir = self.root / "tasks"
        self.tasks_dir.mkdir()
        self.sample_task_path = self.tasks_dir / "SAMPLE_TASK.yaml"
        _write_yaml(
            self.sample_task_path,
            {
                "task_id": "SAMPLE-001",
                "project_id": "SAMPLE",
                "objective": "Change the content of allowed.txt",
                "scope": ["Modify allowed.txt"],
                "out_of_scope": ["Modify any other file"],
                "authorized_files": ["allowed.txt"],
                "forbidden_files": ["untouched.txt"],
                "constraints": ["No new dependencies"],
                "acceptance_criteria": ["allowed.txt contains AFTER"],
                "security_criteria": ["No secrets in code"],
                "mandatory_tests": ["unit"],
                "stop_rules": ["Unauthorized file modified"],
                "required_evidence": ["git_diff", "test_output"],
            },
        )

        self._patches = [
            mock.patch.object(app, "REPO_ROOT", self.root),
            mock.patch.object(app, "CONFIG_DIR", self.config_dir),
            mock.patch.object(app, "PROJECTS_DIR", self.projects_dir),
            mock.patch.object(app, "TASKS_DIR", self.tasks_dir),
            mock.patch.object(app, "SAMPLE_TASK_PACKET_PATH", self.sample_task_path),
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


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=15,
        shell=False,
        check=True,
    )


def _evidence_repo_dirs(root: Path) -> list[str]:
    return [p.name for p in root.iterdir() if p.name.startswith(GIT_EVIDENCE_PROBE_PREFIX)]


class EvidenceProbeTests(CliFixtureTestCase):
    """Grupo G (EVIDENCE-001): evidence-probe usa git real (sin Claude,
    sin llamada al modelo) sobre un repositorio ficticio desechable
    DENTRO de REPO_ROOT (patchado a self.root en esta fixture)."""

    def test_evidence_probe_success_modifies_only_allowed_file(self) -> None:
        # 33/34: éxito produce exclusivamente el cambio autorizado;
        # untouched.txt queda implícitamente intacto (out_of_scope vacío).
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.run_cli("evidence-probe")

        self.assertEqual(rc, 0)
        output = json.loads(stdout.getvalue())
        self.assertTrue(output["success"])
        self.assertEqual(output["changed_paths"], ["allowed.txt"])
        self.assertEqual(output["created_paths"], [])
        self.assertEqual(output["deleted_paths"], [])
        self.assertEqual(output["renamed_paths"], [])
        self.assertEqual(output["untracked_paths"], [])
        self.assertEqual(output["out_of_scope_paths"], [])
        self.assertFalse(output["head_changed"])

        # 35. repo temporal se elimina tras éxito.
        self.assertEqual(_evidence_repo_dirs(self.root), [])

    def test_evidence_probe_cleans_up_repo_after_controlled_failure(self) -> None:
        # 36. repo temporal se elimina tras fallo controlado, vía finally,
        # incluso si la evaluación de evidencia falla internamente.
        with mock.patch(
            "orchestrator.app.evidence_mod.capture_change_evidence",
            side_effect=EvidenceError("simulated failure"),
        ):
            rc = self.run_cli("evidence-probe")

        self.assertNotEqual(rc, 0)
        self.assertEqual(_evidence_repo_dirs(self.root), [])


class TaskPacketProbeTests(CliFixtureTestCase):
    """Grupo H (TASK-PACKET-001): task-packet-probe carga
    tasks/SAMPLE_TASK.yaml (fixture), valida, construye la developer
    instruction dos veces, y demuestra determinismo -- sin invocar Claude
    Code, sin modificar ningún archivo, sin ejecutar comandos."""

    def test_task_packet_probe_passes_and_prints_expected_summary(self) -> None:
        # 41. task-packet-probe PASS.
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.run_cli("task-packet-probe")

        self.assertEqual(rc, 0)
        output = json.loads(stdout.getvalue())
        self.assertTrue(output["valid"])
        self.assertEqual(output["task_id"], "SAMPLE-001")
        self.assertEqual(output["project_id"], "SAMPLE")
        self.assertEqual(output["authorized_files"], ["allowed.txt"])
        self.assertEqual(output["forbidden_files"], ["untouched.txt"])
        self.assertEqual(output["mandatory_tests"], ["unit"])
        self.assertTrue(output["instruction_deterministic"])

    def test_task_packet_probe_does_not_modify_parent_git_or_fixture_files(self) -> None:
        # 42. no modifica parent Git (ni ningún otro archivo): es
        # exclusivamente lectura + validación + construcción de texto en
        # memoria. Se compara el estado completo del árbol patcheado
        # (REPO_ROOT/config/projects/tasks) antes y después.
        def _snapshot() -> set[str]:
            return {
                str(p.relative_to(self.root))
                for p in self.root.rglob("*")
                if p.is_file()
            }

        before = _snapshot()
        rc = self.run_cli("task-packet-probe")
        after = _snapshot()

        self.assertEqual(rc, 0)
        self.assertEqual(before, after)

        # El repositorio Git REAL del orquestador (no la fixture) tampoco
        # se toca: task-packet-probe no invoca git en absoluto.
        real_repo_status_before = subprocess.run(
            ["git", "status", "--short", "--branch"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
            check=True,
        ).stdout
        self.run_cli("task-packet-probe")
        real_repo_status_after = subprocess.run(
            ["git", "status", "--short", "--branch"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
            check=True,
        ).stdout
        self.assertEqual(real_repo_status_before, real_repo_status_after)


# ============================================================
# TASK-EXECUTION-002: task-execution-probe. Compone TaskPacket -> project
# authorization -> developer instruction -> generic Claude adapter -> Git
# Evidence -> mandatory tests -> Human Gate, sobre un repositorio Git
# TEMPORAL real (nunca disposable-001/AIP).
#
# `subprocess` y `shutil` son módulos stdlib compartidos: parchear
# "orchestrator.adapters.claude_code.subprocess.run" parchea el MISMO
# objeto módulo que usa orchestrator.evidence internamente (git real). Por
# eso aquí se parchea "subprocess.run"/"shutil.which" UNA sola vez con un
# despachador que distingue por el ejecutable invocado: las llamadas a
# Claude ("/resolved/claude") y al mandatory test ("python") se simulan;
# CUALQUIER otra invocación (git, usado por Git Evidence) se delega a la
# implementación REAL guardada antes de parchear. Así el repositorio Git
# temporal sigue siendo la fuente de verdad ejecutable, y Claude nunca se
# invoca de verdad.
# ============================================================

_REAL_SUBPROCESS_RUN = subprocess.run
_REAL_SHUTIL_WHICH = shutil.which


def _init_taskexec_repo(repo_root: Path) -> None:
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "allowed.txt").write_text("BEFORE", encoding="utf-8")
    (repo_root / "untouched.txt").write_text("UNCHANGED", encoding="utf-8")
    _git("init", cwd=repo_root)
    _git("config", "user.name", "Task Execution Test", cwd=repo_root)
    _git("config", "user.email", "task-execution-test@localhost", cwd=repo_root)
    _git("add", "allowed.txt", "untouched.txt", cwd=repo_root)
    _git("commit", "-m", "baseline", cwd=repo_root)


class TaskExecutionProbeTestCase(CliFixtureTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.taskexec_repo = self.root / "taskexec_repo"
        _init_taskexec_repo(self.taskexec_repo)

        (self.projects_dir / "TASKEXEC").mkdir()
        _write_yaml(
            self.projects_dir / "TASKEXEC" / "PROJECT_RULES.yaml",
            {
                "version": 1,
                "project_id": "TASKEXEC",
                "name": "Task execution test project",
                "repo_path": "./taskexec_repo",
                "commands": {"unit": ["python", "-c", "pass"]},
                "protected_paths": [],
            },
        )

        self.taskexec_packet_path = self.tasks_dir / "TASKEXEC_TASK.yaml"
        self._write_taskexec_packet(mandatory_tests=["unit"])

        self.enable_write_probe()  # developer + write_probe válidos
        self._set_allowed_commands(["unit"])

    def _write_taskexec_packet(self, *, mandatory_tests: list[str]) -> None:
        _write_yaml(
            self.taskexec_packet_path,
            {
                "task_id": "TASKEXEC-001",
                "project_id": "TASKEXEC",
                "objective": "Change the content of allowed.txt",
                "scope": ["Modify allowed.txt"],
                "out_of_scope": ["Modify any other file"],
                "authorized_files": ["allowed.txt"],
                "forbidden_files": ["untouched.txt"],
                "constraints": ["No new dependencies"],
                "acceptance_criteria": ["allowed.txt contains AFTER"],
                "security_criteria": ["No secrets in code"],
                "mandatory_tests": mandatory_tests,
                "stop_rules": ["Unauthorized file modified"],
                "required_evidence": ["git_diff", "test_output"],
            },
        )

    def _set_allowed_commands(self, allowed: list[str]) -> None:
        data = yaml.safe_load((self.config_dir / "PERMISSIONS.yaml").read_text(encoding="utf-8"))
        data["allowed_commands"] = allowed
        _write_yaml(self.config_dir / "PERMISSIONS.yaml", data)

    def _developer_success_payload(self) -> str:
        return json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "developer says whatever, never checked verbatim",
                "session_id": "s1",
                "num_turns": 1,
                "duration_ms": 100,
            }
        )

    def _developer_writes_allowed_only(self, args, **kwargs):
        cwd = Path(kwargs["cwd"])
        (cwd / "allowed.txt").write_text("AFTER", encoding="utf-8")
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout=self._developer_success_payload(), stderr=""
        )

    def _test_passes(self, args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    @contextlib.contextmanager
    def patched_subprocess(self, *, developer=None, test=None):
        """Despachador único: delega a git REAL cualquier invocación que no
        sea Claude ("/resolved/claude") ni el mandatory test ("python").
        `developer`/`test`, si se dan, deben ser mock.MagicMock(side_effect=...)
        para poder aserir después cuántas veces se invocaron; si son None,
        una invocación inesperada de ese tipo hace fallar la prueba."""

        def fake_which(name, *a, **kw):
            if name == "claude":
                return "/resolved/claude"
            return _REAL_SHUTIL_WHICH(name, *a, **kw)

        def fake_run(args, **kwargs):
            exe = args[0] if args else ""
            if exe == "/resolved/claude":
                if developer is None:
                    raise AssertionError("unexpected Claude invocation in this test")
                return developer(args, **kwargs)
            if exe == "python":
                if test is None:
                    raise AssertionError("unexpected mandatory test invocation in this test")
                return test(args, **kwargs)
            return _REAL_SUBPROCESS_RUN(args, **kwargs)

        with mock.patch("shutil.which", side_effect=fake_which), mock.patch(
            "subprocess.run", side_effect=fake_run
        ):
            yield

    def run_task_execution_probe(self) -> tuple[int, str]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.run_cli("task-execution-probe", str(self.taskexec_packet_path))
        return rc, stdout.getvalue()

    def _assert_head_unchanged_on_disk(self, head_before: str) -> None:
        head_after = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()
        self.assertEqual(head_before, head_after)


class TaskExecutionProbeSuccessTests(TaskExecutionProbeTestCase):
    def test_success_path_reaches_human_gate_without_commit(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        developer_mock = mock.MagicMock(side_effect=self._developer_writes_allowed_only)
        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(developer=developer_mock, test=test_mock):
            rc, stdout = self.run_task_execution_probe()

        self.assertEqual(rc, 0)
        output = json.loads(stdout)
        self.assertEqual(output["task_id"], "TASKEXEC-001")
        self.assertEqual(output["project_id"], "TASKEXEC")
        self.assertEqual(output["state"], "HUMAN_GATE")
        self.assertEqual(output["human_gate"], "HUMAN_FUNCTIONAL_TEST")
        self.assertTrue(output["developer_completed"])
        self.assertTrue(output["head_unchanged"])
        self.assertEqual(output["changed_paths"], ["allowed.txt"])
        self.assertEqual(output["out_of_scope_paths"], [])
        self.assertEqual(output["mandatory_tests"], ["unit"])
        self.assertTrue(output["tests_passed"])
        self.assertTrue(output["technical_review"])
        self.assertTrue(output["security_review"])
        # CORRECTION-001: la doble validación Git (PRE-TEST y POST-TEST,
        # ambas contra el mismo BEFORE original) debe haber pasado.
        self.assertTrue(output["pre_test_evidence_passed"])
        self.assertTrue(output["post_test_evidence_passed"])
        self.assertFalse(output["commit_performed"])

        developer_mock.assert_called_once()
        test_mock.assert_called_once()

        # HEAD del repo REAL nunca cambia (el orquestador nunca hace
        # commit/add/reset/checkout/clean): allowed.txt queda modificado en
        # el working tree, pero sin stage ni commit.
        head_after = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()
        self.assertEqual(head_before, head_after)
        status_after = _git("status", "--porcelain", cwd=self.taskexec_repo).stdout
        self.assertIn("allowed.txt", status_after)


class TaskExecutionProbeFailureTests(TaskExecutionProbeTestCase):
    def test_dirty_before_blocks_without_invoking_claude_or_tests(self) -> None:
        (self.taskexec_repo / "untracked_before.txt").write_text("x", encoding="utf-8")
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        with self.patched_subprocess():
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertFalse(output["developer_completed"])
        self.assertFalse(output["commit_performed"])
        self._assert_head_unchanged_on_disk(head_before)

    def test_developer_touches_unauthorized_file_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_developer_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / "allowed.txt").write_text("AFTER", encoding="utf-8")
            (cwd / "extra_unauthorized.txt").write_text("surprise", encoding="utf-8")
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout=self._developer_success_payload(), stderr=""
            )

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=fake_developer_run), test=test_mock
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertIn("extra_unauthorized.txt", output["out_of_scope_paths"])
        self.assertFalse(output["commit_performed"])
        test_mock.assert_not_called()
        self._assert_head_unchanged_on_disk(head_before)

    def test_developer_touches_forbidden_file_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_developer_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / "allowed.txt").write_text("AFTER", encoding="utf-8")
            (cwd / "untouched.txt").write_text("MODIFIED", encoding="utf-8")
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout=self._developer_success_payload(), stderr=""
            )

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=fake_developer_run), test=test_mock
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertIn("untouched.txt", output["out_of_scope_paths"])
        test_mock.assert_not_called()
        self._assert_head_unchanged_on_disk(head_before)

    def test_developer_creates_unexpected_untracked_file_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_developer_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / "allowed.txt").write_text("AFTER", encoding="utf-8")
            (cwd / "unexpected_new.txt").write_text("new", encoding="utf-8")
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout=self._developer_success_payload(), stderr=""
            )

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=fake_developer_run), test=test_mock
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertIn("unexpected_new.txt", output["out_of_scope_paths"])
        test_mock.assert_not_called()
        self._assert_head_unchanged_on_disk(head_before)

    def test_head_changes_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_developer_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / "allowed.txt").write_text("AFTER", encoding="utf-8")
            _git("add", "allowed.txt", cwd=cwd)
            _git("commit", "-m", "unauthorized commit", cwd=cwd)
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout=self._developer_success_payload(), stderr=""
            )

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=fake_developer_run), test=test_mock
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertFalse(output["head_unchanged"])
        self.assertFalse(output["commit_performed"])
        test_mock.assert_not_called()
        # Este HEAD SÍ cambió, pero por el "developer" simulado (fuera de
        # banda), nunca por el orquestador: se detecta y se bloquea, no se
        # revierte.
        head_after = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()
        self.assertNotEqual(head_before, head_after)

    def test_unknown_mandatory_test_blocks(self) -> None:
        self._write_taskexec_packet(mandatory_tests=["nonexistent"])
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=self._developer_writes_allowed_only),
            test=test_mock,
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertFalse(output["commit_performed"])
        test_mock.assert_not_called()
        self._assert_head_unchanged_on_disk(head_before)

    def test_mandatory_test_failure_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_test_run(args, **kwargs):
            return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="FAIL")

        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=self._developer_writes_allowed_only),
            test=mock.MagicMock(side_effect=fake_test_run),
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertFalse(output["tests_passed"])
        self.assertFalse(output["commit_performed"])
        self._assert_head_unchanged_on_disk(head_before)

    def test_developer_malformed_result_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_developer_run(args, **kwargs):
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="not json", stderr="")

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=fake_developer_run), test=test_mock
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertFalse(output["developer_completed"])
        self.assertFalse(output["commit_performed"])
        test_mock.assert_not_called()
        self._assert_head_unchanged_on_disk(head_before)

    def test_developer_timeout_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_developer_run(args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args, timeout=90)

        test_mock = mock.MagicMock(side_effect=self._test_passes)
        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=fake_developer_run), test=test_mock
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertFalse(output["developer_completed"])
        self.assertFalse(output["commit_performed"])
        test_mock.assert_not_called()
        self._assert_head_unchanged_on_disk(head_before)


class TaskExecutionProbePostTestMutationTests(TaskExecutionProbeTestCase):
    """CORRECTION-001 (SECURITY_REVIEW: CHANGES_REQUESTED): un mandatory
    test preautorizado que retorna exit code 0 pero muta el repositorio
    DURANTE su ejecución debe bloquear igualmente, nunca alcanzar
    HUMAN_GATE. El developer en los tres casos es correcto (modifica
    únicamente allowed.txt, PRE-TEST evidence PASS); la mutación ocurre
    exclusivamente dentro del propio proceso del mandatory test simulado.
    Sin rollback automático en ningún caso: el repo temporal queda como
    quedó, y se limpia únicamente por el teardown normal de
    tempfile.TemporaryDirectory()."""

    def test_case_a_forbidden_mutation_after_test_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_test_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / "untouched.txt").write_text("MUTATED_BY_TEST", encoding="utf-8")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=self._developer_writes_allowed_only),
            test=mock.MagicMock(side_effect=fake_test_run),
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertIsNone(output["human_gate"])
        self.assertTrue(output["pre_test_evidence_passed"])
        self.assertFalse(output["post_test_evidence_passed"])
        self.assertIn("untouched.txt", output["out_of_scope_paths"])
        self.assertFalse(output["security_review"])
        self.assertFalse(output["commit_performed"])
        # Estado real del repo temporal: untouched.txt SÍ quedó mutado (el
        # orquestador no revierte nada); solo se detecta y se bloquea.
        self.assertEqual(
            (self.taskexec_repo / "untouched.txt").read_text(encoding="utf-8"),
            "MUTATED_BY_TEST",
        )
        self._assert_head_unchanged_on_disk(head_before)

    def test_case_b_untracked_after_test_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_test_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            (cwd / "unexpected_from_test.txt").write_text("surprise", encoding="utf-8")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=self._developer_writes_allowed_only),
            test=mock.MagicMock(side_effect=fake_test_run),
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertTrue(output["pre_test_evidence_passed"])
        self.assertFalse(output["post_test_evidence_passed"])
        self.assertIn("unexpected_from_test.txt", output["out_of_scope_paths"])
        self.assertFalse(output["security_review"])
        self.assertFalse(output["commit_performed"])
        self.assertTrue((self.taskexec_repo / "unexpected_from_test.txt").exists())
        self._assert_head_unchanged_on_disk(head_before)

    def test_case_c_head_change_after_test_blocks(self) -> None:
        head_before = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()

        def fake_test_run(args, **kwargs):
            cwd = Path(kwargs["cwd"])
            _git("add", "allowed.txt", cwd=cwd)
            _git("commit", "-m", "unauthorized commit by test", cwd=cwd)
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        with self.patched_subprocess(
            developer=mock.MagicMock(side_effect=self._developer_writes_allowed_only),
            test=mock.MagicMock(side_effect=fake_test_run),
        ):
            rc, stdout = self.run_task_execution_probe()

        output = json.loads(stdout)
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(output["state"], "HUMAN_GATE")
        self.assertFalse(output["head_unchanged"])
        self.assertTrue(output["pre_test_evidence_passed"])
        self.assertFalse(output["post_test_evidence_passed"])
        self.assertFalse(output["security_review"])
        self.assertFalse(output["commit_performed"])
        # Este HEAD SÍ cambió -- por el mandatory test simulado, nunca por
        # el orquestador -- y NO se revierte: solo se detecta y se bloquea.
        head_after = _git("rev-parse", "HEAD", cwd=self.taskexec_repo).stdout.strip()
        self.assertNotEqual(head_before, head_after)


if __name__ == "__main__":
    unittest.main()
