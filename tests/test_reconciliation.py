"""Pruebas de orchestrator.reconciliation — STATE-RECONCILIATION-001.

Cubren: reconciliación Git (reutilizando evidence.py, sin segundo motor),
reconciliación de Windows Scheduled Task (solo lectura, shell=False, sin
operaciones mutantes), y la clasificación global (MATCH / DRIFT_MATERIAL /
UNKNOWN). No invocan Claude Code ni tocan el orquestador real.
"""

from __future__ import annotations

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

from orchestrator import reconciliation  # noqa: E402
from orchestrator.evidence import EvidenceError  # noqa: E402
from orchestrator.task_packet import (  # noqa: E402
    ExternalResourcePrecondition,
    GitPreconditions,
    Preconditions,
)

_VALID_HEAD_SHA = "a" * 40


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


def _init_repo(repo_root: Path) -> tuple[str, str]:
    """Repo real y desechable. Devuelve (branch, head_sha) reales tras el
    commit inicial."""
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "tracked.txt").write_text("BEFORE", encoding="utf-8")
    _git("init", cwd=repo_root)
    _git("config", "user.name", "Reconciliation Test", cwd=repo_root)
    _git("config", "user.email", "reconciliation-test@localhost", cwd=repo_root)
    _git("checkout", "-b", "main", cwd=repo_root)
    _git("add", "tracked.txt", cwd=repo_root)
    _git("commit", "-m", "baseline", cwd=repo_root)
    branch = _git("branch", "--show-current", cwd=repo_root).stdout.strip()
    head = _git("rev-parse", "HEAD", cwd=repo_root).stdout.strip()
    return branch, head


def _preconditions(
    *, branch: str, head: str, external_resources: tuple = ()
) -> Preconditions:
    return Preconditions(
        git=GitPreconditions(expected_branch=branch, expected_head=head, require_clean=True),
        external_resources=external_resources,
    )


# ================================================================
# A. GIT RECONCILIATION
# ================================================================


class GitReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo_root = Path(self._tmp.name)
        self.branch, self.head = _init_repo(self.repo_root)

    def test_branch_head_clean_match(self) -> None:
        # 11. branch + HEAD + clean coinciden -> MATCH.
        report = reconciliation.reconcile_preconditions(
            self.repo_root, _preconditions(branch=self.branch, head=self.head)
        )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_MATCH)
        for check in report.checks:
            self.assertEqual(check.classification, reconciliation.CLASSIFICATION_MATCH)

    def test_head_mismatch_is_drift_material(self) -> None:
        # 12. HEAD distinto -> DRIFT_MATERIAL.
        other_head = "b" * 40
        report = reconciliation.reconcile_preconditions(
            self.repo_root, _preconditions(branch=self.branch, head=other_head)
        )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)
        head_check = next(c for c in report.checks if c.check_type == "git_head")
        self.assertEqual(head_check.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)
        self.assertEqual(head_check.expected, other_head)
        self.assertEqual(head_check.observed, self.head)

    def test_branch_mismatch_is_drift_material(self) -> None:
        # 13. branch distinta -> DRIFT_MATERIAL.
        report = reconciliation.reconcile_preconditions(
            self.repo_root, _preconditions(branch="some-other-branch", head=self.head)
        )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)
        branch_check = next(c for c in report.checks if c.check_type == "git_branch")
        self.assertEqual(branch_check.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)

    def test_dirty_working_tree_is_drift_material(self) -> None:
        # 14. working tree sucio -> DRIFT_MATERIAL.
        (self.repo_root / "stray.txt").write_text("dirty", encoding="utf-8")
        report = reconciliation.reconcile_preconditions(
            self.repo_root, _preconditions(branch=self.branch, head=self.head)
        )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)
        clean_check = next(c for c in report.checks if c.check_type == "git_working_tree_clean")
        self.assertEqual(clean_check.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)
        self.assertFalse(clean_check.observed)

    def test_git_unavailable_is_unknown(self) -> None:
        # 15. git no disponible/falla -> UNKNOWN.
        with mock.patch.object(
            reconciliation.evidence_mod,
            "capture_snapshot",
            side_effect=EvidenceError("git executable not found on PATH"),
        ):
            report = reconciliation.reconcile_preconditions(
                self.repo_root, _preconditions(branch=self.branch, head=self.head)
            )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_UNKNOWN)
        self.assertEqual(len(report.checks), 1)
        self.assertEqual(report.checks[0].check_type, "git")
        self.assertEqual(report.checks[0].evidence_code, "git_unavailable")

    def test_no_mutating_git_operation_is_ever_performed(self) -> None:
        # 16. no se ejecuta ninguna operación Git mutante: el repo queda
        # exactamente igual (HEAD, branch y árbol de trabajo) después de
        # reconciliar contra expectativas EQUIVOCADAS a propósito.
        before_head = _git("rev-parse", "HEAD", cwd=self.repo_root).stdout.strip()
        before_branch = _git("branch", "--show-current", cwd=self.repo_root).stdout.strip()
        before_status = _git("status", "--porcelain", cwd=self.repo_root).stdout

        reconciliation.reconcile_preconditions(
            self.repo_root,
            _preconditions(branch="totally-different-branch", head="c" * 40),
        )

        self.assertEqual(
            _git("rev-parse", "HEAD", cwd=self.repo_root).stdout.strip(), before_head
        )
        self.assertEqual(
            _git("branch", "--show-current", cwd=self.repo_root).stdout.strip(), before_branch
        )
        self.assertEqual(
            _git("status", "--porcelain", cwd=self.repo_root).stdout, before_status
        )


# ================================================================
# B. WINDOWS SCHEDULED TASK RECONCILIATION
# ================================================================


def _fake_completed(returncode: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["schtasks.exe"], returncode=returncode)


class WindowsScheduledTaskReconciliationTests(unittest.TestCase):
    def _resource(self, *, expected_present: bool) -> ExternalResourcePrecondition:
        return ExternalResourcePrecondition(
            type="windows_scheduled_task",
            name="AISOFTWAREFACTORY-Orchestrator-ResumeDue",
            expected_present=expected_present,
        )

    def test_expected_present_and_present_is_match(self) -> None:
        # 17. expected present + present -> MATCH.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(0)) as run_mock:
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=True)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_MATCH)
        self.assertEqual(check.observed, {"observed_present": True})
        run_mock.assert_called_once()

    def test_expected_present_and_absent_is_drift_material(self) -> None:
        # 18. expected present + absent -> DRIFT_MATERIAL.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(0x80070002)):
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=True)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)
        self.assertEqual(check.observed, {"observed_present": False})

    def test_expected_absent_and_absent_is_match(self) -> None:
        # 19. expected absent + absent -> MATCH.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(0x80070002)):
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=False)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_MATCH)

    def test_expected_absent_and_present_is_drift_material(self) -> None:
        # 20. expected absent + present -> DRIFT_MATERIAL.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(0)):
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=False)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)

    def test_schtasks_not_found_is_unknown(self) -> None:
        # 21. schtasks falla (ejecutable no encontrado) -> UNKNOWN.
        with mock.patch("shutil.which", return_value=None):
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=True)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_UNKNOWN)
        self.assertEqual(check.observed, {"observed_present": None})

    def test_schtasks_timeout_is_unknown(self) -> None:
        # 22. timeout -> UNKNOWN.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="schtasks", timeout=15),
            ):
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=True)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_UNKNOWN)

    def test_ambiguous_exit_code_is_unknown(self) -> None:
        # Resultado ambiguo (código no documentado, p. ej. acceso denegado)
        # -> UNKNOWN, nunca interpretado como presente/ausente.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(5)):
            check = reconciliation._reconcile_external_resource(
                self._resource(expected_present=True)
            )
        self.assertEqual(check.classification, reconciliation.CLASSIFICATION_UNKNOWN)

    def test_query_uses_shell_false_with_separate_argv(self) -> None:
        # 23. shell=False, argv separado.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(0)) as run_mock:
            reconciliation._query_windows_scheduled_task_presence("SomeTask")
        args, kwargs = run_mock.call_args
        self.assertFalse(kwargs.get("shell", False))
        self.assertIsInstance(args[0], list)
        self.assertIn("timeout", kwargs)
        self.assertIn("/HRESULT", args[0])

    def test_generic_one_and_query_errors_never_confirm_absence(self) -> None:
        for code in (1, 0x80070005, 0x80070057, 0x80070003):
            for expected in (True, False):
                with self.subTest(code=code, expected=expected), \
                    mock.patch("shutil.which", return_value="schtasks.exe"), \
                    mock.patch("subprocess.run", return_value=_fake_completed(code)):
                    check = reconciliation._reconcile_external_resource(
                        self._resource(expected_present=expected)
                    )
                self.assertEqual(check.classification, reconciliation.CLASSIFICATION_UNKNOWN)
                self.assertEqual(check.observed, {"observed_present": None})

    def test_signed_file_not_found_hresult_confirms_absence(self) -> None:
        with mock.patch("shutil.which", return_value="schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(-2147024894)):
            self.assertIs(reconciliation._query_windows_scheduled_task_presence("Missing"), False)

    def test_shell_metacharacters_remain_one_literal_argument(self) -> None:
        name = "Task & echo marker | other; $(command) > output"
        with mock.patch("shutil.which", return_value="schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(1)) as run_mock:
            self.assertIsNone(reconciliation._query_windows_scheduled_task_presence(name))
        run_mock.assert_called_once_with(
            ["schtasks.exe", "/Query", "/TN", name, "/HRESULT"],
            capture_output=True, timeout=15, shell=False,
        )

    def test_never_uses_create_delete_change_run_or_end(self) -> None:
        # 24. jamás usa /Create, /Delete, /Change, /Run o /End; siempre
        # /Query, nunca PowerShell ni cmd.exe.
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\schtasks.exe"), \
            mock.patch("subprocess.run", return_value=_fake_completed(0)) as run_mock:
            reconciliation._query_windows_scheduled_task_presence("SomeTask")
        argv = run_mock.call_args[0][0]
        forbidden = {"/Create", "/Delete", "/Change", "/Run", "/End"}
        self.assertFalse(forbidden & set(argv))
        self.assertIn("/Query", argv)
        joined = " ".join(argv).lower()
        self.assertNotIn("powershell", joined)
        self.assertNotIn("cmd.exe", joined)


# ================================================================
# C. GLOBAL CLASSIFICATION
# ================================================================


class GlobalClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo_root = Path(self._tmp.name)
        self.branch, self.head = _init_repo(self.repo_root)

    def test_all_match_is_global_match(self) -> None:
        # 25. todos MATCH -> global MATCH.
        resource = ExternalResourcePrecondition(
            type="windows_scheduled_task", name="SomeTask", expected_present=True
        )
        # Patchea SOLO la consulta de recursos externos (no subprocess.run
        # global, que evidence.py también usa para git real): así el
        # bloque Git de este test sigue usando git de verdad.
        with mock.patch.object(
            reconciliation, "_query_windows_scheduled_task_presence", return_value=True
        ):
            report = reconciliation.reconcile_preconditions(
                self.repo_root,
                _preconditions(
                    branch=self.branch, head=self.head, external_resources=(resource,)
                ),
            )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_MATCH)

    def test_one_drift_material_makes_global_drift_material(self) -> None:
        # 26. un DRIFT_MATERIAL -> global DRIFT_MATERIAL.
        resource = ExternalResourcePrecondition(
            type="windows_scheduled_task", name="SomeTask", expected_present=False
        )
        with mock.patch.object(
            reconciliation,
            "_query_windows_scheduled_task_presence",
            return_value=True,  # existe, se esperaba ausente
        ):
            report = reconciliation.reconcile_preconditions(
                self.repo_root,
                _preconditions(
                    branch=self.branch, head=self.head, external_resources=(resource,)
                ),
            )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_DRIFT_MATERIAL)

    def test_one_unknown_makes_global_unknown_even_with_a_drift(self) -> None:
        # 27. un UNKNOWN -> global UNKNOWN (prioridad sobre DRIFT_MATERIAL).
        resource = ExternalResourcePrecondition(
            type="windows_scheduled_task", name="SomeTask", expected_present=True
        )
        with mock.patch.object(
            reconciliation, "_query_windows_scheduled_task_presence", return_value=None
        ):
            report = reconciliation.reconcile_preconditions(
                # branch equivocada a propósito: produciría DRIFT_MATERIAL
                # si no hubiera un UNKNOWN con más prioridad.
                self.repo_root,
                _preconditions(
                    branch="wrong-branch",
                    head=self.head,
                    external_resources=(resource,),
                ),
            )
        self.assertEqual(report.classification, reconciliation.CLASSIFICATION_UNKNOWN)


if __name__ == "__main__":
    unittest.main()
