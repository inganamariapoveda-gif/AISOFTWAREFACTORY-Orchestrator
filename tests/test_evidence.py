"""Pruebas de orchestrator.evidence — EVIDENCE-001 / CORRECTION-001.

Cubren el recolector reutilizable de evidencia Git: validación segura de
repo_root (incluido el confinamiento de .git), parseo NUL-terminated
robusto de status/diff (sin quoting humano, preservando espacios/Unicode/
tabs reales), política conservadora de renombres (solo lo que Git reporta
explícitamente), validación estricta de allowed_paths (incluye rutas
estilo Windows) y evaluación de política (expected_head_unchanged). No
invocan Claude Code ni dependen de sandbox/write-probe.

Los repositorios Git de prueba se crean con `git` real vía subprocess
directo (setup de prueba, no la capacidad del recolector), siempre en
directorios temporales fuera del árbol del repositorio del orquestador.
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

from orchestrator.evidence import (  # noqa: E402
    EvidenceError,
    GitChangeEvidence,
    _iter_status_records_z,
    _normalize_allowed_paths,
    _parse_diff_name_status_z,
    _run_git,
    _split_nul_terminated,
    _union_touched_paths,
    capture_change_evidence,
    capture_snapshot,
    evaluate,
)


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


def _init_fake_repo(repo_root: Path) -> None:
    (repo_root / "allowed.txt").write_text("BEFORE", encoding="utf-8")
    (repo_root / "untouched.txt").write_text("UNCHANGED", encoding="utf-8")
    _git("init", cwd=repo_root)
    _git("config", "user.name", "Evidence Test", cwd=repo_root)
    _git("config", "user.email", "evidence-test@localhost", cwd=repo_root)
    _git("add", "allowed.txt", "untouched.txt", cwd=repo_root)
    _git("commit", "-m", "baseline", cwd=repo_root)


def _add_and_commit(repo_root: Path, name: str, content: str, message: str) -> None:
    (repo_root / name).write_text(content, encoding="utf-8")
    _git("add", name, cwd=repo_root)
    _git("commit", "-m", message, cwd=repo_root)


def _try_make_symlink(link_path: Path, target: Path, *, target_is_directory: bool) -> bool:
    try:
        import os

        os.symlink(str(target), str(link_path), target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


class EvidenceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.authorized_root = Path(self._tmp.name).resolve()
        self.repo_root = self.authorized_root / "repo"
        self.repo_root.mkdir()
        _init_fake_repo(self.repo_root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def real_head(self) -> str:
        return _git("rev-parse", "HEAD", cwd=self.repo_root).stdout.strip()

    def real_branch(self) -> str:
        return _git("branch", "--show-current", cwd=self.repo_root).stdout.strip()

    def make_mixed_changes(self):
        """REPORTING-001: un working tree con las cuatro categorías a la vez
        -- modified (tracked), untracked (nunca 'git add'eado), deleted y un
        rename confirmado por Git (git mv) -- y devuelve el snapshot BEFORE
        capturado justo antes. Los contenidos de old.txt y before.txt son
        deliberadamente disímiles para que Git no empareje old.txt (delete)
        con after.txt (destino del rename) por similitud."""
        _add_and_commit(self.repo_root, "old.txt", "zzz\n" * 40, "add old")
        _add_and_commit(self.repo_root, "before.txt", "alpha bravo charlie\n" * 40, "add before")
        before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")  # modified
        (self.repo_root / "new.txt").write_text("brand new", encoding="utf-8")  # untracked
        (self.repo_root / "old.txt").unlink()  # deleted
        _git("mv", "before.txt", "after.txt", cwd=self.repo_root)  # renamed
        return before


# ================================================================
# A. REPOSITORY VALIDATION
# ================================================================


class RepositoryValidationTests(EvidenceTestCase):
    def test_valid_repo_is_accepted(self) -> None:
        # 27. repo normal continúa aceptado.
        snapshot = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertEqual(snapshot.repo_root, self.repo_root.resolve())

    def test_missing_path_rejected(self) -> None:
        missing = self.authorized_root / "does_not_exist"
        with self.assertRaises(EvidenceError):
            capture_snapshot(missing, authorized_root=self.authorized_root)

    def test_non_directory_path_rejected(self) -> None:
        a_file = self.authorized_root / "a_file.txt"
        a_file.write_text("x", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            capture_snapshot(a_file, authorized_root=self.authorized_root)

    def test_path_outside_authorized_root_rejected(self) -> None:
        other_root = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=other_root)
        finally:
            import shutil

            shutil.rmtree(other_root, ignore_errors=True)

    def test_directory_without_git_rejected(self) -> None:
        plain_dir = self.authorized_root / "plain"
        plain_dir.mkdir()
        with self.assertRaises(EvidenceError):
            capture_snapshot(plain_dir, authorized_root=self.authorized_root)

    def test_symlink_repo_root_rejected_real(self) -> None:
        link_path = self.authorized_root / "link_to_repo"
        if not _try_make_symlink(link_path, self.repo_root, target_is_directory=True):
            self.skipTest("symlink creation not permitted in this environment")
        with self.assertRaises(EvidenceError):
            capture_snapshot(link_path, authorized_root=self.authorized_root)

    def test_symlink_repo_root_rejected_mocked(self) -> None:
        # Equivalente determinista, sin depender de privilegios de symlink.
        with mock.patch("orchestrator.evidence._is_link_like", return_value=True):
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)


# ================================================================
# A2. .GIT CONFINEMENT (CORRECTION-001, hallazgo 6)
# ================================================================


class GitDirConfinementTests(EvidenceTestCase):
    def test_git_dir_symlink_rejected_real(self) -> None:
        # 23. .git symlink rechazado (intento real; skip si no se permite).
        real_git = self.repo_root / ".git"
        moved = self.authorized_root / "real_git_dir"
        real_git.rename(moved)
        if not _try_make_symlink(real_git, moved, target_is_directory=True):
            moved.rename(real_git)
            self.skipTest("symlink creation not permitted in this environment")
        try:
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        finally:
            if real_git.is_symlink():
                real_git.unlink()
            if moved.exists() and not real_git.exists():
                moved.rename(real_git)

    def test_git_dir_symlink_rejected_mocked(self) -> None:
        # 23 (equivalente determinista). _is_link_like es el mecanismo
        # unificado de detección para symlink Y junction; se simula que
        # detecta un enlace específicamente en el path ".git".
        with mock.patch(
            "orchestrator.evidence._is_link_like",
            side_effect=lambda p: p.name == ".git",
        ):
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_git_dir_junction_rejected_mocked(self) -> None:
        # 24. .git junction rechazado. No se crea un junction real (no se
        # usa mklink, prohibido explícitamente); se simula mediante el
        # mismo mecanismo _is_link_like (que en sandbox.py sí distingue
        # symlink de junction vía Path.is_junction(), probado por
        # separado en tests/test_sandbox.py).
        with mock.patch(
            "orchestrator.evidence._is_link_like",
            side_effect=lambda p: p.name == ".git",
        ):
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_git_as_file_rejected(self) -> None:
        # 25. .git file (redirección "gitdir:") rechazado -- sin soporte
        # de worktrees externos en este MVP.
        real_git = self.repo_root / ".git"
        moved = self.authorized_root / "real_git_dir"
        real_git.rename(moved)
        (self.repo_root / ".git").write_text(f"gitdir: {moved}\n", encoding="utf-8")
        try:
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        finally:
            (self.repo_root / ".git").unlink()
            moved.rename(real_git)

    def test_show_toplevel_mismatch_rejected(self) -> None:
        # 26. git rev-parse --show-toplevel diferente del repo_root
        # autorizado -> rechazado.
        real_run_git = _run_git

        def fake_run_git(git_executable, args, *, cwd, timeout=15):
            if args[:2] == ["rev-parse", "--show-toplevel"]:
                return subprocess.CompletedProcess(
                    args=["git"],
                    returncode=0,
                    stdout=str(self.authorized_root) + "\n",
                    stderr="",
                )
            return real_run_git(git_executable, args, cwd=cwd, timeout=timeout)

        with mock.patch("orchestrator.evidence._run_git", side_effect=fake_run_git):
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_normal_repo_confinement_still_accepted(self) -> None:
        # 27 (repetido con foco en confinamiento .git): un repo normal
        # sigue siendo aceptado tras agregar las comprobaciones de .git.
        snapshot = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertFalse(snapshot.is_clean is None)  # snapshot construido con éxito


# ================================================================
# B. BEFORE SNAPSHOT
# ================================================================


class BeforeSnapshotTests(EvidenceTestCase):
    def test_captures_correct_head(self) -> None:
        snapshot = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertEqual(snapshot.head_sha, self.real_head())

    def test_captures_branch(self) -> None:
        snapshot = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertEqual(snapshot.branch, self.real_branch())

    def test_clean_repo_is_clean(self) -> None:
        snapshot = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertTrue(snapshot.is_clean)
        self.assertEqual(snapshot.status_entries, ())

    def test_dirty_repo_is_not_clean(self) -> None:
        (self.repo_root / "allowed.txt").write_text("DIRTY", encoding="utf-8")
        snapshot = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertFalse(snapshot.is_clean)
        self.assertTrue(len(snapshot.status_entries) >= 1)


# ================================================================
# C. CHANGE DETECTION
# ================================================================


class ChangeDetectionTests(EvidenceTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_modified_tracked_file_detected(self) -> None:
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        self.assertEqual(evidence.changed_paths, ("allowed.txt",))
        self.assertEqual(evidence.created_paths, ())
        self.assertEqual(evidence.deleted_paths, ())

    def test_new_untracked_file_detected(self) -> None:
        (self.repo_root / "new.txt").write_text("new content", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt", "new.txt"])
        self.assertIn("new.txt", evidence.untracked_paths)

    def test_deleted_tracked_file_detected(self) -> None:
        (self.repo_root / "untouched.txt").unlink()
        evidence = capture_change_evidence(self.before, ["allowed.txt", "untouched.txt"])
        self.assertEqual(evidence.deleted_paths, ("untouched.txt",))

    def test_multiple_changes_detected(self) -> None:
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        (self.repo_root / "untouched.txt").unlink()
        (self.repo_root / "extra.txt").write_text("extra", encoding="utf-8")
        evidence = capture_change_evidence(
            self.before, ["allowed.txt", "untouched.txt", "extra.txt"]
        )
        self.assertEqual(evidence.changed_paths, ("allowed.txt",))
        self.assertEqual(evidence.deleted_paths, ("untouched.txt",))
        self.assertIn("extra.txt", evidence.untracked_paths)

    def test_no_changes_yields_empty_lists(self) -> None:
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        self.assertEqual(evidence.changed_paths, ())
        self.assertEqual(evidence.created_paths, ())
        self.assertEqual(evidence.deleted_paths, ())
        self.assertEqual(evidence.renamed_paths, ())
        self.assertEqual(evidence.untracked_paths, ())
        self.assertEqual(evidence.touched_paths, ())
        self.assertFalse(evidence.has_out_of_scope_changes)
        self.assertFalse(evidence.head_changed)
        self.assertTrue(evidence.working_tree_clean)

    # ---- REPORTING-001: touched_paths (única fuente de verdad) ----

    def test_touched_paths_unions_modified_untracked_deleted_and_rename(self) -> None:
        before = self.make_mixed_changes()
        evidence = capture_change_evidence(
            before, ["allowed.txt", "new.txt", "old.txt", "before.txt", "after.txt"]
        )
        # changed_paths conserva su semántica histórica: SOLO tracked
        # clasificados como modificados; no es exhaustivo.
        self.assertEqual(evidence.changed_paths, ("allowed.txt",))
        self.assertEqual(evidence.untracked_paths, ("new.txt",))
        self.assertEqual(evidence.deleted_paths, ("old.txt",))
        self.assertEqual(evidence.renamed_paths, (("before.txt", "after.txt"),))
        self.assertEqual(
            evidence.touched_paths,
            ("after.txt", "allowed.txt", "before.txt", "new.txt", "old.txt"),
        )

    def test_touched_paths_includes_both_rename_endpoints(self) -> None:
        _git("mv", "untouched.txt", "moved.txt", cwd=self.repo_root)
        evidence = capture_change_evidence(self.before, ["untouched.txt", "moved.txt"])
        self.assertEqual(evidence.renamed_paths, (("untouched.txt", "moved.txt"),))
        self.assertEqual(evidence.changed_paths, ())
        self.assertEqual(evidence.touched_paths, ("moved.txt", "untouched.txt"))

    def test_touched_paths_deterministic_across_captures(self) -> None:
        before = self.make_mixed_changes()
        allowed = ["allowed.txt", "new.txt", "old.txt", "before.txt", "after.txt"]
        first = capture_change_evidence(before, allowed)
        second = capture_change_evidence(before, allowed)
        self.assertEqual(first.touched_paths, second.touched_paths)
        self.assertEqual(list(first.touched_paths), sorted(first.touched_paths))

    def test_touched_paths_has_no_duplicates(self) -> None:
        # Un mismo path presente en varias colecciones (y ambos extremos de
        # un rename que además aparecen en otra colección) se reporta una
        # sola vez, ordenado.
        evidence = GitChangeEvidence(
            base_sha="a" * 40,
            current_head_sha="a" * 40,
            head_changed=False,
            changed_paths=("b.txt", "a.txt"),
            created_paths=("a.txt",),
            deleted_paths=("c.txt", "b.txt"),
            renamed_paths=(("c.txt", "d.txt"), ("d.txt", "e.txt")),
            untracked_paths=("e.txt", "a.txt"),
            out_of_scope_paths=(),
            has_out_of_scope_changes=False,
            working_tree_clean=False,
            diff_available=True,
        )
        self.assertEqual(
            evidence.touched_paths, ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt")
        )
        self.assertEqual(
            evidence.touched_paths,
            _union_touched_paths(
                evidence.changed_paths,
                evidence.created_paths,
                evidence.deleted_paths,
                evidence.untracked_paths,
                evidence.renamed_paths,
            ),
        )


# ================================================================
# C2. PARSER ROBUSTNESS (CORRECTION-001, hallazgo 1)
# ================================================================


class ParserRobustnessSyntheticTests(unittest.TestCase):
    """Pruebas sintéticas directas de los parsers -z (sin invocar git):
    demuestran que el parseo se hace por delimitador NUL, nunca por
    líneas/tabs, y que ningún carácter del nombre real se pierde."""

    def test_diff_parser_preserves_tab_inside_filename(self) -> None:
        # 3. Un TAB real dentro del nombre no debe fragmentar el campo:
        # con -z, el delimitador es EXCLUSIVAMENTE NUL.
        raw = "M\x00weird\tname.txt\x00"
        changed, created, deleted, renamed = _parse_diff_name_status_z(raw)
        self.assertEqual(changed, ["weird\tname.txt"])
        self.assertEqual(created, [])
        self.assertEqual(deleted, [])
        self.assertEqual(renamed, [])

    def test_diff_parser_preserves_non_ascii_filename(self) -> None:
        # 4. Caracteres no ASCII preservados exactamente (sin quoting).
        raw = "M\x00café ñ.txt\x00"
        changed, _, _, _ = _parse_diff_name_status_z(raw)
        self.assertEqual(changed, ["café ñ.txt"])

    def test_diff_parser_preserves_spaces(self) -> None:
        raw = "A\x00file with spaces.txt\x00"
        _, created, _, _ = _parse_diff_name_status_z(raw)
        self.assertEqual(created, ["file with spaces.txt"])

    def test_diff_parser_rename_record(self) -> None:
        raw = "R100\x00old name.txt\x00new café.txt\x00"
        _, _, _, renamed = _parse_diff_name_status_z(raw)
        self.assertEqual(renamed, [("old name.txt", "new café.txt")])

    def test_status_parser_preserves_tab_inside_filename(self) -> None:
        raw = "?? weird\tname.txt\x00"
        records = _iter_status_records_z(raw)
        self.assertEqual(records, [("??", "weird\tname.txt", None)])

    def test_status_parser_preserves_non_ascii_filename(self) -> None:
        raw = "?? café ñ.txt\x00"
        records = _iter_status_records_z(raw)
        self.assertEqual(records, [("??", "café ñ.txt", None)])

    def test_status_parser_rename_record(self) -> None:
        raw = "R  new name.txt\x00old café.txt\x00"
        records = _iter_status_records_z(raw)
        self.assertEqual(records, [("R ", "new name.txt", "old café.txt")])

    def test_status_parser_multiple_entries(self) -> None:
        raw = " M a.txt\x00?? b.txt\x00 D c.txt\x00"
        records = _iter_status_records_z(raw)
        self.assertEqual(
            records,
            [(" M", "a.txt", None), ("??", "b.txt", None), (" D", "c.txt", None)],
        )


# ================================================================
# C2b. PARSER FAIL-CLOSED (CORRECTION-002, hallazgo 1)
# ================================================================


class ParserFailClosedTests(unittest.TestCase):
    """CORRECTION-002: formato -z incompleto/inesperado SIEMPRE es
    EvidenceError; nunca break/continue silencioso devolviendo evidencia
    parcial."""

    def test_non_empty_output_without_trailing_nul_rejected(self) -> None:
        # 1. salida -z no vacía sin NUL terminal -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _split_nul_terminated("M\x00allowed.txt")

    def test_diff_status_without_path_rejected(self) -> None:
        # 2. diff status sin path -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("M\x00")

    def test_diff_rename_truncated_rejected(self) -> None:
        # 3. diff rename R100 truncado (falta el new_path) -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("R100\x00old.txt\x00")

    def test_diff_copy_truncated_rejected(self) -> None:
        # 4. diff copy truncado (falta el new_path) -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("C100\x00old.txt\x00")

    def test_diff_empty_path_rejected(self) -> None:
        # path vacío en un registro ordinario -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("M\x00\x00")

    def test_diff_rename_with_empty_path_rejected(self) -> None:
        # path vacío en uno de los dos extremos de un rename -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("R100\x00\x00new.txt\x00")

    def test_diff_empty_status_code_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("\x00allowed.txt\x00")

    def test_status_record_shorter_than_three_chars_rejected(self) -> None:
        # 5. status record de menos de 3 chars -> EvidenceError.
        with self.assertRaises(EvidenceError):
            _iter_status_records_z("M\x00")

    def test_status_record_missing_separator_rejected(self) -> None:
        # estructura "XY path" exige el separador exactamente en la
        # posición esperada (índice 2).
        with self.assertRaises(EvidenceError):
            _iter_status_records_z("MXpath.txt\x00")

    def test_status_rename_without_second_path_rejected(self) -> None:
        # 6. status rename sin segundo path -> EvidenceError. Sin este
        # chequeo, el parser desincronizaría el resto del stream.
        with self.assertRaises(EvidenceError):
            _iter_status_records_z("R  new.txt\x00")

    def test_status_rename_in_y_position_without_second_path_rejected(self) -> None:
        # R/C en la posición Y de XY también exige el segundo path.
        with self.assertRaises(EvidenceError):
            _iter_status_records_z(" R new.txt\x00")

    def test_status_empty_path_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            _iter_status_records_z("?? \x00")

    def test_status_rename_with_empty_old_path_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            _iter_status_records_z("R  new.txt\x00\x00")

    def test_malformed_diff_record_does_not_yield_partial_evidence(self) -> None:
        # 7. Un campo malformado NO produce evidencia parcial: la
        # excepción se propaga antes de devolver cualquier lista, ni
        # siquiera los registros válidos que precedían al malformado.
        with self.assertRaises(EvidenceError):
            _parse_diff_name_status_z("M\x00good.txt\x00A\x00")

    def test_malformed_status_record_does_not_yield_partial_evidence(self) -> None:
        with self.assertRaises(EvidenceError):
            _iter_status_records_z("?? good.txt\x00M\x00")

    def test_diff_parser_names_with_tab_newline_unicode_still_preserved(self) -> None:
        # 8. nombres con tab/newline/Unicode siguen preservándose bajo el
        # parseo estricto (el fail-closed no afecta el caso bien formado).
        raw = "M\x00weird\tname\nwith\nnewlines café.txt\x00"
        changed, _, _, _ = _parse_diff_name_status_z(raw)
        self.assertEqual(changed, ["weird\tname\nwith\nnewlines café.txt"])

    def test_diff_parser_multiple_valid_streams_still_work(self) -> None:
        # 9. streams válidos múltiples siguen funcionando.
        raw = "M\x00a.txt\x00A\x00b.txt\x00D\x00c.txt\x00"
        changed, created, deleted, renamed = _parse_diff_name_status_z(raw)
        self.assertEqual(changed, ["a.txt"])
        self.assertEqual(created, ["b.txt"])
        self.assertEqual(deleted, ["c.txt"])
        self.assertEqual(renamed, [])

    def test_status_parser_multiple_valid_streams_still_work(self) -> None:
        # 9 (status). streams válidos múltiples siguen funcionando.
        raw = " M a.txt\x00?? b.txt\x00 D c.txt\x00"
        records = _iter_status_records_z(raw)
        self.assertEqual(
            records,
            [(" M", "a.txt", None), ("??", "b.txt", None), (" D", "c.txt", None)],
        )

    def test_diff_rename_valid_still_works(self) -> None:
        # 10. rename/copy válido sigue funcionando.
        raw = "R100\x00old name.txt\x00new café.txt\x00"
        _, _, _, renamed = _parse_diff_name_status_z(raw)
        self.assertEqual(renamed, [("old name.txt", "new café.txt")])

    def test_status_rename_valid_still_works(self) -> None:
        # 10 (status). rename/copy válido sigue funcionando.
        raw = "R  new name.txt\x00old café.txt\x00"
        records = _iter_status_records_z(raw)
        self.assertEqual(records, [("R ", "new name.txt", "old café.txt")])

    def test_empty_output_is_valid_empty_list(self) -> None:
        self.assertEqual(_split_nul_terminated(""), [])
        self.assertEqual(_parse_diff_name_status_z(""), ([], [], [], []))
        self.assertEqual(_iter_status_records_z(""), [])


class UnicodeAndSpacesIntegrationTests(EvidenceTestCase):
    """Regresión end-to-end contra git REAL (no sintética): demuestra que
    el hallazgo 1 (quoting/escapes de git) queda corregido."""

    def setUp(self) -> None:
        super().setUp()
        self.before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_unicode_untracked_authorized_is_not_out_of_scope(self) -> None:
        # 1. unicode untracked autorizado -> NO out_of_scope.
        (self.repo_root / "café ñ.txt").write_text("nuevo", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt", "café ñ.txt"])
        self.assertIn("café ñ.txt", evidence.untracked_paths)
        self.assertNotIn("café ñ.txt", evidence.out_of_scope_paths)
        self.assertTrue(evaluate(evidence).success)

    def test_filename_with_spaces_authorized_is_not_out_of_scope(self) -> None:
        # 2. filename con espacios autorizado -> NO out_of_scope.
        (self.repo_root / "file with spaces.txt").write_text("nuevo", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt", "file with spaces.txt"])
        self.assertIn("file with spaces.txt", evidence.untracked_paths)
        self.assertNotIn("file with spaces.txt", evidence.out_of_scope_paths)
        self.assertTrue(evaluate(evidence).success)

    def test_unicode_modified_tracked_file_detected_via_diff(self) -> None:
        _add_and_commit(self.repo_root, "café ñ.txt", "BEFORE", "add unicode file")
        before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        (self.repo_root / "café ñ.txt").write_text("AFTER", encoding="utf-8")
        evidence = capture_change_evidence(before, ["allowed.txt", "café ñ.txt"])
        self.assertEqual(evidence.changed_paths, ("café ñ.txt",))
        self.assertNotIn("café ñ.txt", evidence.out_of_scope_paths)

    def test_spaced_modified_tracked_file_detected_via_diff(self) -> None:
        _add_and_commit(self.repo_root, "spaced name.txt", "BEFORE", "add spaced file")
        before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        (self.repo_root / "spaced name.txt").write_text("AFTER", encoding="utf-8")
        evidence = capture_change_evidence(before, ["allowed.txt", "spaced name.txt"])
        self.assertEqual(evidence.changed_paths, ("spaced name.txt",))
        self.assertNotIn("spaced name.txt", evidence.out_of_scope_paths)


# ================================================================
# C3. RENAME POLICY (CORRECTION-001, hallazgo 2 -- solo Git-detectable)
# ================================================================


class RenamePolicyTests(EvidenceTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_git_detectable_rename_is_interpreted_correctly(self) -> None:
        # 5. Git rename R100/R### se interpreta correctamente. El fixture
        # de PRUEBA usa `git mv` (staging) para producirlo; esto NO
        # convierte git mv/add en una capacidad del recolector.
        _git("mv", "allowed.txt", "renamed.txt", cwd=self.repo_root)
        evidence = capture_change_evidence(self.before, ["renamed.txt"])
        self.assertIn(("allowed.txt", "renamed.txt"), evidence.renamed_paths)
        self.assertEqual(evidence.deleted_paths, ())
        self.assertNotIn("allowed.txt", evidence.untracked_paths)
        self.assertNotIn("renamed.txt", evidence.untracked_paths)

    def test_filesystem_only_rename_not_confirmed_by_git_reports_delete_and_untracked(
        self,
    ) -> None:
        # 6. filesystem rename NO confirmado por Git (sin stage) -> se
        # reporta CONSERVADORAMENTE como delete + untracked, nunca como
        # rename inventado. Este es el comportamiento CORRECTO.
        (self.repo_root / "allowed.txt").rename(self.repo_root / "renamed.txt")
        evidence = capture_change_evidence(self.before, ["allowed.txt", "renamed.txt"])
        self.assertEqual(evidence.renamed_paths, ())
        self.assertEqual(evidence.deleted_paths, ("allowed.txt",))
        self.assertIn("renamed.txt", evidence.untracked_paths)
        # REPORTING-001: ambos extremos siguen entrando en touched_paths.
        self.assertEqual(evidence.touched_paths, ("allowed.txt", "renamed.txt"))
        # La evaluación de alcance sigue cubriendo ambos paths por
        # separado: si alguno no estuviera autorizado, seguiría fallando.
        evidence_missing_scope = capture_change_evidence(self.before, ["allowed.txt"])
        self.assertIn("renamed.txt", evidence_missing_scope.out_of_scope_paths)

    def test_multiple_identical_files_do_not_produce_invented_renames(self) -> None:
        # 7. múltiples archivos idénticos NO producen renames inventados
        # (a.txt/b.txt eliminados, x.txt/y.txt nuevos, TODOS con el mismo
        # contenido: sin heurística de hash, jamás se infiere un rename).
        (self.repo_root / "a.txt").write_text("SAME", encoding="utf-8")
        (self.repo_root / "b.txt").write_text("SAME", encoding="utf-8")
        _git("add", "a.txt", "b.txt", cwd=self.repo_root)
        _git("commit", "-m", "add a and b", cwd=self.repo_root)
        before2 = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

        (self.repo_root / "a.txt").unlink()
        (self.repo_root / "b.txt").unlink()
        (self.repo_root / "x.txt").write_text("SAME", encoding="utf-8")
        (self.repo_root / "y.txt").write_text("SAME", encoding="utf-8")

        evidence = capture_change_evidence(before2, ["a.txt", "b.txt", "x.txt", "y.txt"])
        self.assertEqual(evidence.renamed_paths, ())
        self.assertEqual(set(evidence.deleted_paths), {"a.txt", "b.txt"})
        self.assertEqual(set(evidence.untracked_paths), {"x.txt", "y.txt"})


# ================================================================
# C4. AFTER REVALIDATION (CORRECTION-002, hallazgo 2)
# ================================================================


class AfterRevalidationTests(EvidenceTestCase):
    """capture_change_evidence() vuelve a validar repo_root/authorized_root
    ANTES de ejecutar cualquier comando git sobre el AFTER. Si el
    repositorio dejó de ser confinado/seguro entre BEFORE y AFTER, la
    revalidación falla cerrado y ningún diff/status se ejecuta sobre el
    destino inseguro."""

    def setUp(self) -> None:
        super().setUp()
        self.before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_normal_repo_before_to_after_still_passes(self) -> None:
        # 11. repo normal BEFORE->AFTER continúa PASS.
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        self.assertEqual(evidence.changed_paths, ("allowed.txt",))
        self.assertTrue(evaluate(evidence).success)

    def test_repo_root_replaced_by_symlink_after_before_fails_closed_real(self) -> None:
        # 12/13. después de BEFORE, repo_root sustituido por symlink ->
        # capture_change_evidence falla cerrado; el target del symlink NO
        # se usa como repositorio de evidencia.
        decoy_root = self.authorized_root / "decoy"
        decoy_root.mkdir()
        _init_fake_repo(decoy_root)
        moved = self.authorized_root / "repo_moved"
        self.repo_root.rename(moved)
        if not _try_make_symlink(self.repo_root, decoy_root, target_is_directory=True):
            moved.rename(self.repo_root)
            self.skipTest("symlink creation not permitted in this environment")
        try:
            with self.assertRaises(EvidenceError):
                capture_change_evidence(self.before, ["allowed.txt"])
        finally:
            if self.repo_root.is_symlink():
                self.repo_root.unlink()
            if moved.exists() and not self.repo_root.exists():
                moved.rename(self.repo_root)

    def test_repo_root_replaced_by_symlink_after_before_fails_closed_mocked(self) -> None:
        # 14. equivalente determinista (sin depender de privilegios de
        # symlink): repo_root sustituido -> EvidenceError, sin ejecutar
        # diff/status sobre el destino.
        with mock.patch("orchestrator.evidence._is_link_like", return_value=True):
            with self.assertRaises(EvidenceError):
                capture_change_evidence(self.before, ["allowed.txt"])

    def test_git_dir_replaced_by_symlink_after_before_fails_closed(self) -> None:
        # 15. después de BEFORE, .git sustituido por symlink -> fail closed.
        real_git = self.repo_root / ".git"
        moved = self.authorized_root / "real_git_dir"
        real_git.rename(moved)
        if not _try_make_symlink(real_git, moved, target_is_directory=True):
            moved.rename(real_git)
            self.skipTest("symlink creation not permitted in this environment")
        try:
            with self.assertRaises(EvidenceError):
                capture_change_evidence(self.before, ["allowed.txt"])
        finally:
            if real_git.is_symlink():
                real_git.unlink()
            if moved.exists() and not real_git.exists():
                moved.rename(real_git)

    def test_git_dir_converted_to_gitdir_file_after_before_fails_closed(self) -> None:
        # 16. después de BEFORE, .git convertido en archivo "gitdir:" ->
        # fail closed.
        real_git = self.repo_root / ".git"
        moved = self.authorized_root / "real_git_dir"
        real_git.rename(moved)
        (self.repo_root / ".git").write_text(f"gitdir: {moved}\n", encoding="utf-8")
        try:
            with self.assertRaises(EvidenceError):
                capture_change_evidence(self.before, ["allowed.txt"])
        finally:
            (self.repo_root / ".git").unlink()
            moved.rename(real_git)

    def test_show_toplevel_mismatch_in_after_fails_closed(self) -> None:
        # 17. show-toplevel mismatch en AFTER -> fail closed.
        real_run_git = _run_git

        def fake_run_git(git_executable, args, *, cwd, timeout=15):
            if args[:2] == ["rev-parse", "--show-toplevel"]:
                return subprocess.CompletedProcess(
                    args=["git"],
                    returncode=0,
                    stdout=str(self.authorized_root) + "\n",
                    stderr="",
                )
            return real_run_git(git_executable, args, cwd=cwd, timeout=timeout)

        with mock.patch("orchestrator.evidence._run_git", side_effect=fake_run_git):
            with self.assertRaises(EvidenceError):
                capture_change_evidence(self.before, ["allowed.txt"])

    def test_revalidation_failure_happens_before_after_diff_or_status(self) -> None:
        # 18. el fallo de revalidación ocurre ANTES de git diff/status del
        # AFTER: ningún subcommand "diff"/"status" llega a subprocess.run
        # una vez que _validate_repo_root() ya rechazó el repo_root.
        with mock.patch("orchestrator.evidence._is_link_like", return_value=True):
            with mock.patch(
                "orchestrator.evidence.subprocess.run", wraps=subprocess.run
            ) as mock_run:
                with self.assertRaises(EvidenceError):
                    capture_change_evidence(self.before, ["allowed.txt"])
            # _is_link_like ya rechaza antes de resolver siquiera el path,
            # por lo que ningún subprocess (ni show-toplevel) se ejecuta.
            mock_run.assert_not_called()


# ================================================================
# D. SCOPE
# ================================================================


class ScopeTests(EvidenceTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_single_authorized_change_passes(self) -> None:
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertTrue(result.success)
        self.assertEqual(result.out_of_scope_paths, ())

    def test_change_outside_allowed_paths_fails(self) -> None:
        (self.repo_root / "untouched.txt").write_text("MODIFIED", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.success)
        self.assertIn("untouched.txt", result.out_of_scope_paths)

    def test_new_file_out_of_scope_fails(self) -> None:
        (self.repo_root / "rogue.txt").write_text("rogue", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.success)
        self.assertIn("rogue.txt", result.out_of_scope_paths)

    def test_delete_out_of_scope_fails(self) -> None:
        (self.repo_root / "untouched.txt").unlink()
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.success)
        self.assertIn("untouched.txt", result.out_of_scope_paths)

    def test_rename_source_out_of_scope_fails(self) -> None:
        _git("mv", "untouched.txt", "renamed.txt", cwd=self.repo_root)
        evidence = capture_change_evidence(self.before, ["renamed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.success)
        self.assertIn("untouched.txt", result.out_of_scope_paths)

    def test_rename_destination_out_of_scope_fails(self) -> None:
        _git("mv", "untouched.txt", "renamed.txt", cwd=self.repo_root)
        evidence = capture_change_evidence(self.before, ["untouched.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.success)
        self.assertIn("renamed.txt", result.out_of_scope_paths)

    def test_out_of_scope_is_exactly_touched_paths_minus_allowed(self) -> None:
        # REPORTING-001: el alcance usa EXACTAMENTE la misma unión que
        # touched_paths (modified + untracked + deleted + ambos extremos de
        # un rename), para cualquier conjunto autorizado.
        before = self.make_mixed_changes()
        everything = ("after.txt", "allowed.txt", "before.txt", "new.txt", "old.txt")
        allowed_sets = [
            ["allowed.txt"],
            ["allowed.txt", "new.txt"],
            ["allowed.txt", "before.txt"],  # solo el origen del rename
            ["allowed.txt", "after.txt"],  # solo el destino del rename
            list(everything),
        ]
        for allowed in allowed_sets:
            with self.subTest(allowed=allowed):
                evidence = capture_change_evidence(before, allowed)
                self.assertEqual(evidence.touched_paths, everything)
                expected = tuple(p for p in evidence.touched_paths if p not in set(allowed))
                self.assertEqual(evidence.out_of_scope_paths, expected)
                self.assertEqual(evidence.has_out_of_scope_changes, bool(expected))

    def test_all_touched_authorized_yields_no_out_of_scope(self) -> None:
        before = self.make_mixed_changes()
        evidence = capture_change_evidence(
            before, ["allowed.txt", "new.txt", "old.txt", "before.txt", "after.txt"]
        )
        self.assertEqual(evidence.out_of_scope_paths, ())
        self.assertFalse(evidence.has_out_of_scope_changes)
        self.assertTrue(evaluate(evidence, expected_head_unchanged=True).success)

    def test_absolute_allowed_path_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            capture_change_evidence(self.before, ["/etc/passwd"])

    def test_allowed_path_with_dotdot_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            capture_change_evidence(self.before, ["../outside.txt"])


# ================================================================
# D2. WINDOWS-STYLE PATH REJECTION (CORRECTION-001, hallazgo 3)
# ================================================================


class WindowsStylePathRejectionTests(unittest.TestCase):
    """Pruebas unitarias directas de _normalize_allowed_paths(), sin
    necesidad de repositorio real. Windows-style paths deben rechazarse
    aunque la prueba se ejecute en otro sistema operativo."""

    def test_windows_backslash_absolute_rejected(self) -> None:
        # 8. Windows absolute C:\... rechazado.
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["C:\\Users\\anapo\\secret.txt"])

    def test_windows_forward_slash_drive_rejected(self) -> None:
        # 9. Windows C:/... rechazado.
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["C:/Users/anapo/secret.txt"])

    def test_unc_backslash_path_rejected(self) -> None:
        # 10 (variante backslash). UNC path rechazado.
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["\\\\server\\share\\x"])

    def test_unc_forward_slash_path_rejected(self) -> None:
        # 10. UNC path rechazado (variante '/').
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["//server/share/x"])

    def test_drive_relative_without_separator_rejected(self) -> None:
        # "cualquier drive Windows", incluida la forma sin separador.
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["C:relative.txt"])

    def test_posix_absolute_path_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["/absolute/path"])

    def test_empty_string_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths([""])

    def test_traversal_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            _normalize_allowed_paths(["sub/../../escape.txt"])

    def test_ordinary_relative_path_accepted(self) -> None:
        result = _normalize_allowed_paths(["sub/dir.txt"])
        self.assertEqual(result, frozenset({"sub/dir.txt"}))

    def test_ordinary_relative_path_with_unicode_and_spaces_accepted(self) -> None:
        result = _normalize_allowed_paths(["café ñ.txt", "file with spaces.txt"])
        self.assertEqual(result, frozenset({"café ñ.txt", "file with spaces.txt"}))


# ================================================================
# E. HEAD
# ================================================================


class HeadPolicyTests(EvidenceTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_head_unchanged_and_expected_unchanged_passes(self) -> None:
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.head_changed)
        self.assertTrue(result.success)

    def test_new_commit_with_expected_unchanged_fails(self) -> None:
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        _git("add", "allowed.txt", cwd=self.repo_root)
        _git("commit", "-m", "unexpected commit", cwd=self.repo_root)
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=True)
        self.assertFalse(result.success)
        self.assertIn("HEAD changed unexpectedly", result.reason)

    def test_new_commit_is_recorded_as_head_changed_regardless_of_policy(self) -> None:
        (self.repo_root / "allowed.txt").write_text("AFTER", encoding="utf-8")
        _git("add", "allowed.txt", cwd=self.repo_root)
        _git("commit", "-m", "unexpected commit", cwd=self.repo_root)
        evidence = capture_change_evidence(self.before, ["allowed.txt"])
        result = evaluate(evidence, expected_head_unchanged=False)
        self.assertTrue(result.head_changed)
        # Sin la política activa, un HEAD distinto no implica fallo por sí
        # solo (no hay cambios fuera de alcance en este escenario).
        self.assertTrue(result.success)
        # Git nunca se resetea/revierte por esta evaluación.
        self.assertEqual(self.real_head(), evidence.current_head_sha)


# ================================================================
# F. COMMAND SECURITY
# ================================================================


class CommandSecurityTests(EvidenceTestCase):
    def test_git_subprocess_uses_shell_false(self) -> None:
        with mock.patch(
            "orchestrator.evidence.subprocess.run", wraps=subprocess.run
        ) as mock_run:
            capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        self.assertTrue(mock_run.called)
        for call in mock_run.call_args_list:
            self.assertIs(call.kwargs["shell"], False)

    def test_git_subprocess_uses_correct_cwd(self) -> None:
        with mock.patch(
            "orchestrator.evidence.subprocess.run", wraps=subprocess.run
        ) as mock_run:
            capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        for call in mock_run.call_args_list:
            self.assertEqual(call.kwargs["cwd"], str(self.repo_root.resolve()))

    def test_git_subprocess_uses_timeout(self) -> None:
        with mock.patch(
            "orchestrator.evidence.subprocess.run", wraps=subprocess.run
        ) as mock_run:
            capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
        for call in mock_run.call_args_list:
            self.assertIsInstance(call.kwargs["timeout"], int)
            self.assertGreater(call.kwargs["timeout"], 0)

    def test_git_error_fails_closed(self) -> None:
        failing = subprocess.CompletedProcess(args=["git"], returncode=128, stdout="", stderr="boom")
        with mock.patch("orchestrator.evidence.subprocess.run", return_value=failing):
            with self.assertRaises(EvidenceError):
                capture_snapshot(self.repo_root, authorized_root=self.authorized_root)

    def test_no_remote_or_destructive_git_subcommand_used(self) -> None:
        forbidden = {
            "push", "pull", "fetch", "merge", "rebase", "reset", "clean",
            "checkout", "switch", "remote", "tag", "add", "commit", "show",
        }
        with mock.patch(
            "orchestrator.evidence.subprocess.run", wraps=subprocess.run
        ) as mock_run:
            capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
            before = capture_snapshot(self.repo_root, authorized_root=self.authorized_root)
            capture_change_evidence(before, ["allowed.txt"])
        for call in mock_run.call_args_list:
            argv = call.args[0]
            subcommand = argv[1] if len(argv) > 1 else None
            self.assertNotIn(subcommand, forbidden)

    def test_disallowed_subcommand_rejected_before_subprocess(self) -> None:
        with mock.patch("orchestrator.evidence.subprocess.run") as mock_run:
            with self.assertRaises(EvidenceError):
                _run_git("git", ["push", "origin", "main"], cwd=self.repo_root)
        mock_run.assert_not_called()

    def test_show_subcommand_no_longer_allowed(self) -> None:
        # CORRECTION-001, hallazgo 2: "show" se elimina de la allowlist al
        # quedar sin uso (la inferencia de renombres por hash se eliminó).
        with mock.patch("orchestrator.evidence.subprocess.run") as mock_run:
            with self.assertRaises(EvidenceError):
                _run_git("git", ["show", "HEAD:allowed.txt"], cwd=self.repo_root)
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
