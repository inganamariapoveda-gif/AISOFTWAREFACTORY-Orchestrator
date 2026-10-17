"""Resolution-only contract: project argv never becomes a host subprocess."""

import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator import test_runner  # noqa: E402
from orchestrator.test_runner import (  # noqa: E402
    ISOLATED_BACKEND_UNAVAILABLE,
    ResolvedMandatoryTest,
    TestRunnerError,
    resolve_mandatory_test,
    run_mandatory_test,
)


class ResolveMandatoryTestTests(unittest.TestCase):
    def resolve(self, test_id="unit", commands=None, allowed=("unit",)):
        return resolve_mandatory_test(
            test_id,
            project_commands={"unit": ["python", "verify_task.py"]} if commands is None else commands,
            globally_allowed_ids=allowed,
        )

    def test_valid_id_and_exact_argv_preserved_as_immutable_data(self):
        argv = ["python", "verify_task.py", "--flag", "value with spaces", "; literal"]
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
            result = self.resolve(commands={"unit": argv})
        self.assertIsInstance(result, ResolvedMandatoryTest)
        self.assertEqual(result.test_id, "unit")
        self.assertEqual(result.argv, tuple(argv))
        argv.append("later mutation")
        self.assertEqual(result.argv[-1], "; literal")
        run.assert_not_called()
        popen.assert_not_called()

    def test_unknown_test_id_fails_closed_without_subprocess(self):
        with mock.patch("subprocess.run") as run, self.assertRaises(TestRunnerError):
            self.resolve("unknown")
        run.assert_not_called()

    def test_project_known_but_globally_forbidden_fails_closed(self):
        with self.assertRaises(TestRunnerError):
            self.resolve(allowed=())

    def test_globally_allowed_but_project_unknown_fails_closed(self):
        with self.assertRaises(TestRunnerError):
            self.resolve(commands={})

    def test_argv_never_derived_from_test_id(self):
        result = self.resolve(commands={"unit": ["python", "verify_task.py", "--flag"]})
        self.assertNotEqual(result.argv, ("unit",))
        self.assertEqual(result.argv, ("python", "verify_task.py", "--flag"))
        with self.assertRaises(TestRunnerError):
            self.resolve("uni", allowed=("uni",))

    def test_invalid_test_id_shape_rejected(self):
        for value in ("unit && evil", "", None, 1, "unit/name", "unit\x00"):
            with self.subTest(value=value), self.assertRaises(TestRunnerError):
                self.resolve(value)

    def test_resolved_argv_invalid_shape_rejected(self):
        for value in ("python verify_task.py", [], None, [""], [1], [None], [["python"]]):
            with self.subTest(value=value), self.assertRaises(TestRunnerError):
                self.resolve(commands={"unit": value})

    def test_all_project_commands_resolve_but_cannot_execute(self):
        for argv in (
            ["git", "push", "origin", "task/x"],
            ["git", "reset", "--hard"],
            ["powershell", "-Command", "..."],
            ["python", "-c", "..."],
            ["python", "verify_task.py"],
            ["pnpm.cmd", "test"],
        ):
            with self.subTest(argv=argv), mock.patch("subprocess.run") as run, \
                    mock.patch("subprocess.Popen") as popen:
                self.assertEqual(self.resolve(commands={"unit": argv}).argv, tuple(argv))
                with self.assertRaises(TestRunnerError) as error:
                    run_mandatory_test(
                        "unit", project_commands={"unit": argv},
                        globally_allowed_ids=["unit"], cwd=REPO_ROOT, timeout=30,
                    )
                self.assertEqual(str(error.exception), ISOLATED_BACKEND_UNAVAILABLE)
                run.assert_not_called()
                popen.assert_not_called()

    def test_cwd_and_timeout_metadata_cannot_enable_execution(self):
        for cwd, timeout in ((REPO_ROOT, 30), (REPO_ROOT / "does_not_exist", 0)):
            with self.subTest(cwd=cwd), mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(TestRunnerError, ISOLATED_BACKEND_UNAVAILABLE):
                    run_mandatory_test(
                        "unit", project_commands={"unit": ["python", "verify_task.py"]},
                        globally_allowed_ids=["unit"], cwd=cwd, timeout=timeout,
                    )
                run.assert_not_called()

    def test_no_execution_import_or_permissive_switch(self):
        self.assertFalse(hasattr(test_runner, "subprocess"))
        for function in (resolve_mandatory_test, run_mandatory_test):
            self.assertNotIn("allow_local", inspect.signature(function).parameters)
        with self.assertRaisesRegex(TestRunnerError, ISOLATED_BACKEND_UNAVAILABLE):
            test_runner.require_isolated_mandatory_test_backend()


if __name__ == "__main__":
    unittest.main()
