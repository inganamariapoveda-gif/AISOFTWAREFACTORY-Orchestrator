"""Pruebas de orchestrator.test_runner — TASK-EXECUTION-002.

Cubren la resolución y ejecución de mandatory_test IDs autorizados:
intersección obligatoria (test_id IN globally_allowed_ids Y test_id IN
project_commands), argv preservado EXACTAMENTE (nunca derivado de
test_id), shell=False, cwd correcto, y fail-closed ante ID desconocido/no
autorizado/argv inválido/timeout. subprocess.run se mockea siempre; no se
ejecuta ningún proceso externo real ni disposable-001/AIP.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.test_runner import (  # noqa: E402
    TestResult,
    TestRunnerError,
    run_mandatory_test,
)


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["python"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class RunMandatoryTestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_exact_argv_preserved_shell_false_and_cwd_correct(self) -> None:
        project_commands = {"unit": ["python", "verify_task.py"]}
        with mock.patch(
            "orchestrator.test_runner.subprocess.run", return_value=_completed(returncode=0)
        ) as mock_run:
            result = run_mandatory_test(
                "unit",
                project_commands=project_commands,
                globally_allowed_ids=["unit"],
                cwd=self.cwd,
                timeout=30,
            )

        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        self.assertEqual(call_args[0], ["python", "verify_task.py"])
        self.assertIs(call_kwargs["shell"], False)
        self.assertEqual(call_kwargs["cwd"], str(self.cwd))
        self.assertEqual(call_kwargs["timeout"], 30)

        self.assertIsInstance(result, TestResult)
        self.assertEqual(result.test_id, "unit")
        self.assertEqual(result.argv, ("python", "verify_task.py"))
        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)

    def test_nonzero_exit_code_is_reported_as_failure_not_exception(self) -> None:
        project_commands = {"unit": ["python", "verify_task.py"]}
        with mock.patch(
            "orchestrator.test_runner.subprocess.run",
            return_value=_completed(returncode=1, stderr="boom"),
        ):
            result = run_mandatory_test(
                "unit",
                project_commands=project_commands,
                globally_allowed_ids=["unit"],
                cwd=self.cwd,
                timeout=30,
            )
        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.stderr, "boom")

    def test_timeout_fails_closed(self) -> None:
        project_commands = {"unit": ["python", "verify_task.py"]}
        with mock.patch(
            "orchestrator.test_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["python", "verify_task.py"], timeout=30),
        ):
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unit",
                    project_commands=project_commands,
                    globally_allowed_ids=["unit"],
                    cwd=self.cwd,
                    timeout=30,
                )

    def test_unknown_test_id_fails_closed_without_subprocess(self) -> None:
        with mock.patch("orchestrator.test_runner.subprocess.run") as mock_run:
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unknown",
                    project_commands={"unit": ["python", "verify_task.py"]},
                    globally_allowed_ids=["unit"],
                    cwd=self.cwd,
                    timeout=30,
                )
        mock_run.assert_not_called()

    def test_project_known_but_globally_forbidden_fails_closed(self) -> None:
        # test_id existe en PROJECT_RULES.commands pero NO en
        # PERMISSIONS.allowed_commands.
        with mock.patch("orchestrator.test_runner.subprocess.run") as mock_run:
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unit",
                    project_commands={"unit": ["python", "verify_task.py"]},
                    globally_allowed_ids=[],
                    cwd=self.cwd,
                    timeout=30,
                )
        mock_run.assert_not_called()

    def test_globally_allowed_but_project_unknown_fails_closed(self) -> None:
        # test_id está en PERMISSIONS.allowed_commands pero el proyecto no
        # lo mapea en PROJECT_RULES.commands.
        with mock.patch("orchestrator.test_runner.subprocess.run") as mock_run:
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unit",
                    project_commands={},
                    globally_allowed_ids=["unit"],
                    cwd=self.cwd,
                    timeout=30,
                )
        mock_run.assert_not_called()

    def test_argv_never_derived_from_test_id(self) -> None:
        # El argv ejecutado es EXCLUSIVAMENTE project_commands[test_id];
        # nunca [test_id] ni ninguna derivación del propio identificador.
        project_commands = {"unit": ["python", "verify_task.py", "--flag"]}
        with mock.patch(
            "orchestrator.test_runner.subprocess.run", return_value=_completed(returncode=0)
        ) as mock_run:
            run_mandatory_test(
                "unit",
                project_commands=project_commands,
                globally_allowed_ids=["unit"],
                cwd=self.cwd,
                timeout=30,
            )
        call_args, _ = mock_run.call_args
        self.assertNotEqual(call_args[0], ["unit"])
        self.assertEqual(call_args[0], ["python", "verify_task.py", "--flag"])

    def test_invalid_test_id_shape_rejected(self) -> None:
        with mock.patch("orchestrator.test_runner.subprocess.run") as mock_run:
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unit && evil",
                    project_commands={"unit && evil": ["python", "verify_task.py"]},
                    globally_allowed_ids=["unit && evil"],
                    cwd=self.cwd,
                    timeout=30,
                )
        mock_run.assert_not_called()

    def test_resolved_argv_invalid_shape_rejected(self) -> None:
        # Defensa en profundidad: incluso si project_commands llega con una
        # forma inválida (bypaseando config_loader), test_runner nunca
        # ejecuta un string como si fuera argv.
        with mock.patch("orchestrator.test_runner.subprocess.run") as mock_run:
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unit",
                    project_commands={"unit": "python verify_task.py"},
                    globally_allowed_ids=["unit"],
                    cwd=self.cwd,
                    timeout=30,
                )
        mock_run.assert_not_called()

    def test_cwd_nonexistent_rejected(self) -> None:
        missing = self.cwd / "does_not_exist"
        with mock.patch("orchestrator.test_runner.subprocess.run") as mock_run:
            with self.assertRaises(TestRunnerError):
                run_mandatory_test(
                    "unit",
                    project_commands={"unit": ["python", "verify_task.py"]},
                    globally_allowed_ids=["unit"],
                    cwd=missing,
                    timeout=30,
                )
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
