"""Pruebas de orchestrator.sandbox — CLAUDE-EXECUTION-002 / CORRECTION-001.

Cubren exclusivamente el ciclo de vida seguro del sandbox (creación
confinada, instantánea determinista sin seguir enlaces, eliminación
confinada que verifica identidad ANTES de seguir cualquier enlace), sin
invocar subprocess ni depender de Claude Code.
"""

import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.sandbox import (  # noqa: E402
    SANDBOX_PREFIX,
    SandboxError,
    _is_link_like,
    _make_safe_cleanup_handler,
    cleanup_sandbox,
    create_sandbox,
    snapshot,
)


def _try_make_symlink(link_path: Path, target: Path, *, target_is_directory: bool) -> bool:
    """Intenta crear un symlink real. Devuelve False (sin lanzar) si el
    entorno no lo permite (p. ej. Windows sin privilegio/Developer Mode),
    para que la prueba que lo use pueda hacer skip de la parte que
    depende de un enlace real, sin dejar de tener una prueba lógica
    determinista equivalente en otro lugar."""
    try:
        os.symlink(str(target), str(link_path), target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


class CreateSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_sandbox_is_created_inside_repo_root(self) -> None:
        sandbox = create_sandbox(self.repo_root)
        try:
            self.assertTrue(sandbox.is_dir())
            self.assertEqual(sandbox.parent, self.repo_root)
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root)

    def test_sandbox_name_has_expected_prefix_and_is_unpredictable(self) -> None:
        sandbox_a = create_sandbox(self.repo_root)
        sandbox_b = create_sandbox(self.repo_root)
        try:
            self.assertTrue(sandbox_a.name.startswith(SANDBOX_PREFIX))
            self.assertTrue(sandbox_b.name.startswith(SANDBOX_PREFIX))
            self.assertNotEqual(sandbox_a.name, sandbox_b.name)
        finally:
            cleanup_sandbox(sandbox_a, repo_root=self.repo_root)
            cleanup_sandbox(sandbox_b, repo_root=self.repo_root)

    def test_sandbox_starts_empty(self) -> None:
        sandbox = create_sandbox(self.repo_root)
        try:
            self.assertEqual(list(sandbox.iterdir()), [])
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root)

    def test_create_sandbox_requires_existing_repo_root(self) -> None:
        missing = self.repo_root / "does_not_exist"
        with self.assertRaises(SandboxError):
            create_sandbox(missing)

    def test_create_sandbox_respects_custom_prefix(self) -> None:
        # EVIDENCE-001 reutiliza create_sandbox()/cleanup_sandbox() con un
        # prefijo propio (.git_evidence_probe_); se verifica que el
        # parámetro se respeta y no se degrada al prefijo por defecto.
        custom_prefix = ".custom_probe_"
        sandbox = create_sandbox(self.repo_root, prefix=custom_prefix)
        try:
            self.assertTrue(sandbox.name.startswith(custom_prefix))
            self.assertFalse(sandbox.name.startswith(SANDBOX_PREFIX))
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root, prefix=custom_prefix)


class SnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.sandbox = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_empty_sandbox_snapshot_is_empty(self) -> None:
        self.assertEqual(snapshot(self.sandbox), {})

    def test_snapshot_detects_file_size_and_sha256(self) -> None:
        (self.sandbox / "a.txt").write_text("hello", encoding="utf-8")
        result = snapshot(self.sandbox)
        self.assertEqual(set(result), {"a.txt"})
        entry = result["a.txt"]
        self.assertEqual(entry.kind, "file")
        self.assertEqual(entry.size, len(b"hello"))
        self.assertEqual(entry.sha256, hashlib.sha256(b"hello").hexdigest())

    def test_snapshot_detects_directory(self) -> None:
        (self.sandbox / "subdir").mkdir()
        result = snapshot(self.sandbox)
        self.assertEqual(result["subdir"].kind, "dir")
        self.assertIsNone(result["subdir"].size)
        self.assertIsNone(result["subdir"].sha256)

    def test_snapshot_changes_when_content_changes(self) -> None:
        target = self.sandbox / "a.txt"
        target.write_text("BEFORE", encoding="utf-8")
        before = snapshot(self.sandbox)
        target.write_text("AFTER", encoding="utf-8")
        after = snapshot(self.sandbox)
        self.assertNotEqual(before["a.txt"], after["a.txt"])

    def test_snapshot_stable_when_nothing_changes(self) -> None:
        (self.sandbox / "a.txt").write_text("same", encoding="utf-8")
        first = snapshot(self.sandbox)
        second = snapshot(self.sandbox)
        self.assertEqual(first, second)

    def test_snapshot_detects_created_and_deleted_paths(self) -> None:
        (self.sandbox / "a.txt").write_text("x", encoding="utf-8")
        before = snapshot(self.sandbox)
        (self.sandbox / "a.txt").unlink()
        (self.sandbox / "b.txt").write_text("y", encoding="utf-8")
        after = snapshot(self.sandbox)
        self.assertEqual(set(before) - set(after), {"a.txt"})
        self.assertEqual(set(after) - set(before), {"b.txt"})


class CleanupSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cleanup_removes_sandbox_directory(self) -> None:
        sandbox = create_sandbox(self.repo_root)
        (sandbox / "leftover.txt").write_text("x", encoding="utf-8")
        cleanup_sandbox(sandbox, repo_root=self.repo_root)
        self.assertFalse(sandbox.exists())

    def test_cleanup_refuses_path_outside_repo_root(self) -> None:
        outside = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(SandboxError):
                cleanup_sandbox(outside, repo_root=self.repo_root)
            self.assertTrue(outside.exists())  # no se tocó
        finally:
            outside.rmdir()

    def test_cleanup_refuses_repo_root_itself(self) -> None:
        with self.assertRaises(SandboxError):
            cleanup_sandbox(self.repo_root, repo_root=self.repo_root)
        self.assertTrue(self.repo_root.exists())

    def test_cleanup_refuses_non_direct_child(self) -> None:
        sandbox = create_sandbox(self.repo_root)
        nested = sandbox / "nested_fake_sandbox"
        nested.mkdir()
        try:
            with self.assertRaises(SandboxError):
                cleanup_sandbox(nested, repo_root=self.repo_root)
            self.assertTrue(nested.exists())
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root)

    def test_cleanup_refuses_path_without_sandbox_prefix(self) -> None:
        not_a_sandbox = self.repo_root / "some_other_dir"
        not_a_sandbox.mkdir()
        try:
            with self.assertRaises(SandboxError):
                cleanup_sandbox(not_a_sandbox, repo_root=self.repo_root)
            self.assertTrue(not_a_sandbox.exists())
        finally:
            not_a_sandbox.rmdir()

    def test_cleanup_respects_custom_prefix(self) -> None:
        custom_prefix = ".custom_probe_"
        sandbox = create_sandbox(self.repo_root, prefix=custom_prefix)
        # El prefijo por defecto (SANDBOX_PREFIX) NO debe aceptar este
        # sandbox, ya que su nombre real usa custom_prefix.
        with self.assertRaises(SandboxError):
            cleanup_sandbox(sandbox, repo_root=self.repo_root)
        self.assertTrue(sandbox.exists())
        # Con el prefijo correcto, la limpieza sí procede.
        cleanup_sandbox(sandbox, repo_root=self.repo_root, prefix=custom_prefix)
        self.assertFalse(sandbox.exists())


class IsLinkLikeTests(unittest.TestCase):
    """Prueba unitaria y determinista del helper de detección, sin
    depender de privilegios de symlink/junction del sistema operativo."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_ordinary_directory_is_not_link_like(self) -> None:
        self.assertFalse(_is_link_like(self.tmp_path))

    def test_ordinary_file_is_not_link_like(self) -> None:
        f = self.tmp_path / "a.txt"
        f.write_text("x", encoding="utf-8")
        self.assertFalse(_is_link_like(f))

    def test_mocked_junction_is_link_like(self) -> None:
        # 3 (parte determinista). No depende de privilegios de Windows:
        # simula que Path.is_junction() detecta un junction real.
        with mock.patch.object(Path, "is_junction", return_value=True, create=True):
            self.assertTrue(_is_link_like(self.tmp_path))

    def test_missing_is_junction_degrades_to_symlink_only(self) -> None:
        # Portabilidad: si la versión de Python no tiene is_junction(),
        # _is_link_like() no debe romperse ni asumir nada; solo detecta
        # symlinks.
        with mock.patch.object(Path, "is_junction", None, create=True):
            with mock.patch.object(Path, "is_symlink", return_value=False):
                self.assertFalse(_is_link_like(self.tmp_path))


class SnapshotDoesNotFollowLinksTests(unittest.TestCase):
    """4 y 5: snapshot registra un enlace como 'symlink' y NUNCA recursa ni
    lee a través de él, tanto con un symlink real (cuando el entorno lo
    permite) como con la detección forzada de forma determinista."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.sandbox = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_symlink_to_directory_is_registered_and_not_traversed(self) -> None:
        outside = Path(tempfile.mkdtemp())
        try:
            (outside / "secret.txt").write_text("outside-content", encoding="utf-8")
            link = self.sandbox / "link_to_outside"
            if not _try_make_symlink(link, outside, target_is_directory=True):
                self.skipTest("symlink creation not permitted in this environment")

            result = snapshot(self.sandbox)

            # 4. se registra como symlink.
            self.assertEqual(set(result), {"link_to_outside"})
            self.assertEqual(result["link_to_outside"].kind, "symlink")
            self.assertIsNone(result["link_to_outside"].size)
            self.assertIsNone(result["link_to_outside"].sha256)
            # 5. NO se incluye ningún archivo existente detrás del enlace.
            self.assertNotIn("link_to_outside/secret.txt", result)
            self.assertEqual(
                [k for k in result if k.startswith("link_to_outside/")], []
            )
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_symlink_to_file_is_registered_without_reading_target(self) -> None:
        outside = Path(tempfile.mkdtemp())
        try:
            target_file = outside / "secret.txt"
            target_file.write_text("outside-content", encoding="utf-8")
            link = self.sandbox / "link_to_file"
            if not _try_make_symlink(link, target_file, target_is_directory=False):
                self.skipTest("symlink creation not permitted in this environment")

            result = snapshot(self.sandbox)
            self.assertEqual(result["link_to_file"].kind, "symlink")
            self.assertIsNone(result["link_to_file"].size)
            self.assertIsNone(result["link_to_file"].sha256)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_mocked_link_like_entry_is_not_traversed(self) -> None:
        # Equivalente determinista, sin depender de privilegios de
        # symlink/junction: fuerza _is_link_like() a True para una entrada
        # que en realidad es un directorio ordinario con contenido, y
        # confirma que snapshot() no desciende en ella.
        nested = self.sandbox / "looks_like_a_link"
        nested.mkdir()
        (nested / "inside.txt").write_text("should-not-be-read", encoding="utf-8")

        with mock.patch("orchestrator.sandbox._is_link_like") as mock_is_link_like:
            mock_is_link_like.side_effect = lambda p: p.name == "looks_like_a_link"
            result = snapshot(self.sandbox)

        self.assertEqual(set(result), {"looks_like_a_link"})
        self.assertEqual(result["looks_like_a_link"].kind, "symlink")


class CleanupRejectsLinkTests(unittest.TestCase):
    """1, 2 y 3: cleanup_sandbox rechaza un candidato symlink/junction
    ANTES de eliminar nada, y nunca toca el destino del enlace."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cleanup_rejects_real_symlink_sandbox_path_and_preserves_target(self) -> None:
        sandbox_b = create_sandbox(self.repo_root)
        (sandbox_b / "secret.txt").write_text("do-not-delete-me", encoding="utf-8")

        link_path = self.repo_root / f"{SANDBOX_PREFIX}fake_link"
        if not _try_make_symlink(link_path, sandbox_b, target_is_directory=True):
            cleanup_sandbox(sandbox_b, repo_root=self.repo_root)
            self.skipTest("symlink creation not permitted in this environment")

        try:
            # 1. cleanup rechaza el candidato symlink.
            with self.assertRaises(SandboxError):
                cleanup_sandbox(link_path, repo_root=self.repo_root)

            # 2. NO elimina el target del symlink.
            self.assertTrue(sandbox_b.exists())
            self.assertEqual(
                (sandbox_b / "secret.txt").read_text(encoding="utf-8"),
                "do-not-delete-me",
            )
        finally:
            if link_path.is_symlink():
                link_path.unlink()
            cleanup_sandbox(sandbox_b, repo_root=self.repo_root)

    def test_cleanup_rejects_mocked_junction(self) -> None:
        # 3. cleanup rechaza junction cuando Path.is_junction() esté
        # disponible (determinista, sin depender de privilegios reales).
        sandbox = create_sandbox(self.repo_root)
        try:
            with mock.patch.object(Path, "is_junction", return_value=True, create=True):
                with self.assertRaises(SandboxError):
                    cleanup_sandbox(sandbox, repo_root=self.repo_root)
            self.assertTrue(sandbox.exists())  # rechazado, no eliminado
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root)


class LinkSwapCleanupRegressionTests(unittest.TestCase):
    """Regresión específica del hallazgo del Director: sandbox A + hermano
    B con SANDBOX_PREFIX + A sustituido por un enlace hacia B. cleanup(A)
    debe fallar cerrado y B debe permanecer intacto."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_symlink_swap_regression_real_symlink(self) -> None:
        sandbox_a = create_sandbox(self.repo_root)
        sandbox_b = create_sandbox(self.repo_root)
        (sandbox_b / "secret.txt").write_text("do-not-delete-me", encoding="utf-8")

        shutil.rmtree(sandbox_a)  # 3. eliminar A
        if not _try_make_symlink(sandbox_a, sandbox_b, target_is_directory=True):
            # Entorno sin privilegio para symlinks: limpiar y delegar en
            # la prueba determinista equivalente de abajo.
            cleanup_sandbox(sandbox_b, repo_root=self.repo_root)
            self.skipTest("symlink creation not permitted in this environment")

        try:
            # 5. ejecutar cleanup_sandbox(A) -> debe fallar cerrado.
            with self.assertRaises(SandboxError):
                cleanup_sandbox(sandbox_a, repo_root=self.repo_root)

            # B sigue existiendo y su contenido sigue intacto.
            self.assertTrue(sandbox_b.exists())
            self.assertEqual(
                (sandbox_b / "secret.txt").read_text(encoding="utf-8"),
                "do-not-delete-me",
            )
        finally:
            if sandbox_a.is_symlink():
                sandbox_a.unlink()
            cleanup_sandbox(sandbox_b, repo_root=self.repo_root)

    def test_symlink_swap_regression_logical_equivalent(self) -> None:
        """Prueba determinista del control lógico (no depende de
        privilegios de symlink): fuerza a que el candidato A sea
        'link-like' exactamente como ocurriría tras la sustitución real,
        y confirma que el hermano B (con SANDBOX_PREFIX también) nunca se
        toca."""
        sandbox_a = create_sandbox(self.repo_root)
        sandbox_b = create_sandbox(self.repo_root)
        (sandbox_b / "secret.txt").write_text("do-not-delete-me", encoding="utf-8")

        with mock.patch("orchestrator.sandbox._is_link_like", return_value=True):
            with self.assertRaises(SandboxError):
                cleanup_sandbox(sandbox_a, repo_root=self.repo_root)

        # B (el hermano) nunca se tocó.
        self.assertTrue(sandbox_b.exists())
        self.assertEqual(
            (sandbox_b / "secret.txt").read_text(encoding="utf-8"),
            "do-not-delete-me",
        )
        # A tampoco se eliminó (fue rechazado antes del rmtree).
        self.assertTrue(sandbox_a.exists())

        cleanup_sandbox(sandbox_a, repo_root=self.repo_root)
        cleanup_sandbox(sandbox_b, repo_root=self.repo_root)


# ================================================================
# PREFIX VALIDATION (CORRECTION-001, hallazgo 4)
# ================================================================


class PrefixValidationTests(unittest.TestCase):
    """_validate_prefix() se ejecuta ANTES de tempfile.mkdtemp()
    (create_sandbox) y ANTES de cualquier otra comprobación de
    cleanup_sandbox()."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _assert_create_rejected_before_mkdtemp(self, prefix) -> None:
        with mock.patch("orchestrator.sandbox.tempfile.mkdtemp") as mock_mkdtemp:
            with self.assertRaises(SandboxError):
                create_sandbox(self.repo_root, prefix=prefix)
        mock_mkdtemp.assert_not_called()

    def test_empty_prefix_rejected_before_mkdtemp(self) -> None:
        # 11. prefix="" rechazado antes de mkdtemp.
        self._assert_create_rejected_before_mkdtemp("")

    def test_dot_prefix_rejected(self) -> None:
        # 12. prefix="." rechazado.
        self._assert_create_rejected_before_mkdtemp(".")

    def test_dotdot_prefix_rejected(self) -> None:
        self._assert_create_rejected_before_mkdtemp("..")

    def test_parent_traversal_prefix_rejected_before_mkdtemp(self) -> None:
        # 13. prefix="../" rechazado antes de mkdtemp (nunca llega a
        # intentar crear nada fuera de repo_root).
        self._assert_create_rejected_before_mkdtemp("../")

    def test_prefix_with_forward_slash_rejected(self) -> None:
        # 14. prefix con "/" rechazado.
        self._assert_create_rejected_before_mkdtemp("sub/dir_")

    def test_prefix_with_backslash_rejected(self) -> None:
        # 15. prefix con "\\" rechazado.
        self._assert_create_rejected_before_mkdtemp("sub\\dir_")

    def test_prefix_with_nul_rejected(self) -> None:
        self._assert_create_rejected_before_mkdtemp("bad\x00prefix_")

    def test_non_string_prefix_rejected(self) -> None:
        with self.assertRaises(SandboxError):
            create_sandbox(self.repo_root, prefix=123)  # type: ignore[arg-type]

    def test_legitimate_claude_write_probe_prefix_still_works(self) -> None:
        # Prefijo legítimo de CLAUDE-EXECUTION-002: sigue funcionando.
        sandbox = create_sandbox(self.repo_root, prefix=".claude_write_probe_")
        try:
            self.assertTrue(sandbox.name.startswith(".claude_write_probe_"))
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root, prefix=".claude_write_probe_")

    def test_legitimate_evidence_probe_prefix_still_works(self) -> None:
        # Prefijo legítimo de EVIDENCE-001: sigue funcionando.
        sandbox = create_sandbox(self.repo_root, prefix=".git_evidence_probe_")
        try:
            self.assertTrue(sandbox.name.startswith(".git_evidence_probe_"))
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root, prefix=".git_evidence_probe_")

    def test_cleanup_with_empty_prefix_deletes_nothing(self) -> None:
        # 17. cleanup prefix inválido no elimina nada. Reproduce
        # exactamente el hallazgo del Director: "victim" NO debe
        # eliminarse cuando prefix="" (que de otro modo anularía por
        # completo la comprobación startswith()).
        victim = create_sandbox(self.repo_root, prefix=SANDBOX_PREFIX)
        try:
            with self.assertRaises(SandboxError):
                cleanup_sandbox(victim, repo_root=self.repo_root, prefix="")
            self.assertTrue(victim.exists())
        finally:
            cleanup_sandbox(victim, repo_root=self.repo_root, prefix=SANDBOX_PREFIX)

    def test_cleanup_with_traversal_prefix_rejected_before_any_check(self) -> None:
        victim = create_sandbox(self.repo_root, prefix=SANDBOX_PREFIX)
        try:
            with self.assertRaises(SandboxError):
                cleanup_sandbox(victim, repo_root=self.repo_root, prefix="../")
            self.assertTrue(victim.exists())
        finally:
            cleanup_sandbox(victim, repo_root=self.repo_root, prefix=SANDBOX_PREFIX)


class CreateSandboxDirectChildTests(unittest.TestCase):
    """CORRECTION-001, hallazgo 4: create_sandbox() debe garantizar hijo
    DIRECTO de repo_root, simétrico con cleanup_sandbox()."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_create_sandbox_produces_direct_child(self) -> None:
        # 16. create sandbox produce hijo directo.
        sandbox = create_sandbox(self.repo_root)
        try:
            self.assertEqual(sandbox.parent, self.repo_root)
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root)

    def test_create_sandbox_rejects_non_direct_child_result(self) -> None:
        # Caso adversarial: si mkdtemp() devolviera una ruta que no es
        # hijo directo de repo_root, create_sandbox debe rechazarla.
        nested = self.repo_root / "nested_dir"
        nested.mkdir()
        fake = nested / "fake_sandbox_dir"
        fake.mkdir()
        with mock.patch("orchestrator.sandbox.tempfile.mkdtemp", return_value=str(fake)):
            with self.assertRaises(SandboxError):
                create_sandbox(self.repo_root, prefix=SANDBOX_PREFIX)


# ================================================================
# ONEXC HANDLER HARDENING (CORRECTION-001, hallazgo 5)
# ================================================================


class SafeCleanupHandlerTests(unittest.TestCase):
    """El handler onexc de shutil.rmtree() (_make_safe_cleanup_handler)
    falla cerrado ante cualquier situación que no sea exactamente el caso
    esperado (PermissionError sobre un path ordinario, dentro del árbol,
    no symlink/junction, con una operación de eliminación conocida)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cleanup_root = Path(self._tmp.name).resolve() / "root"
        self.cleanup_root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_non_permission_error_is_not_processed(self) -> None:
        # 18. onexc no procesa error distinto de PermissionError.
        target = self.cleanup_root / "f.txt"
        target.write_text("x", encoding="utf-8")
        handler = _make_safe_cleanup_handler(self.cleanup_root)
        with mock.patch("orchestrator.sandbox.os.chmod") as mock_chmod:
            with self.assertRaises(SandboxError):
                handler(os.unlink, str(target), FileNotFoundError("boom"))
            mock_chmod.assert_not_called()

    def test_chmod_not_called_on_symlink(self) -> None:
        # 19. onexc no hace chmod de symlink.
        target = self.cleanup_root / "link.txt"
        real_target = self.cleanup_root / "real.txt"
        real_target.write_text("x", encoding="utf-8")
        if not _try_make_symlink(target, real_target, target_is_directory=False):
            self.skipTest("symlink creation not permitted in this environment")
        handler = _make_safe_cleanup_handler(self.cleanup_root)
        with mock.patch("orchestrator.sandbox.os.chmod") as mock_chmod:
            with self.assertRaises(SandboxError):
                handler(os.unlink, str(target), PermissionError(13, "denied"))
            mock_chmod.assert_not_called()

    def test_chmod_not_called_on_junction_mocked(self) -> None:
        # 20. onexc no hace chmod de junction (mockeado, determinista: no
        # se usa mklink).
        target = self.cleanup_root / "j"
        target.mkdir()
        handler = _make_safe_cleanup_handler(self.cleanup_root)
        with mock.patch.object(Path, "is_junction", return_value=True, create=True):
            with mock.patch("orchestrator.sandbox.os.chmod") as mock_chmod:
                with self.assertRaises(SandboxError):
                    handler(os.rmdir, str(target), PermissionError(13, "denied"))
                mock_chmod.assert_not_called()

    def test_chmod_not_called_outside_cleanup_root(self) -> None:
        # 21. onexc no hace chmod fuera de cleanup_root.
        outside_tmp = tempfile.TemporaryDirectory()
        try:
            outside_file = Path(outside_tmp.name) / "outside.txt"
            outside_file.write_text("x", encoding="utf-8")
            handler = _make_safe_cleanup_handler(self.cleanup_root)
            with mock.patch("orchestrator.sandbox.os.chmod") as mock_chmod:
                with self.assertRaises(SandboxError):
                    handler(os.unlink, str(outside_file), PermissionError(13, "denied"))
                mock_chmod.assert_not_called()
        finally:
            outside_tmp.cleanup()

    def test_retry_failure_becomes_sandbox_error(self) -> None:
        # 22 (CORRECTION-002: corregido -- falso positivo). La prueba
        # anterior pasaba una función local NO reconocida como `func`, por
        # lo que obtenía SandboxError en la validación de "operación
        # permitida" (paso 2) y NUNCA llegaba al chmod ni al reintento:
        # no demostraba un fallo ocurrido DESPUÉS del chmod.
        #
        # Esta versión hace que `os.unlink` (la MISMA función que el
        # handler reconoce como retryable, capturada en
        # _retryable_functions en el momento de construir el handler) sea,
        # a la vez, la función pasada como `func` y la que falla en el
        # reintento -- de modo que el camino real ejercitado sea:
        # operación reconocida -> PermissionError aceptado -> candidato
        # válido -> chmod ejecutado -> reintento de esa misma operación ->
        # ese reintento falla -> SandboxError.
        target = self.cleanup_root / "f.txt"
        target.write_text("x", encoding="utf-8")

        with mock.patch("orchestrator.sandbox.os.chmod") as mock_chmod, mock.patch(
            "orchestrator.sandbox.os.unlink"
        ) as mock_unlink:
            mock_unlink.side_effect = OSError("still locked after chmod")
            # El handler captura _retryable_functions = (os.unlink, ...) en
            # el momento de esta llamada, es decir, captura mock_unlink.
            handler = _make_safe_cleanup_handler(self.cleanup_root)

            with self.assertRaises(SandboxError):
                handler(mock_unlink, str(target), PermissionError(13, "denied"))

            # chmod SI se ejecutó (paso 5), exactamente una vez, sobre el
            # candidato validado, sin seguir enlaces.
            mock_chmod.assert_called_once_with(target, stat.S_IWRITE, follow_symlinks=False)
            # El reintento SI se invocó (la misma operación reconocida),
            # exactamente una vez, y fue ESE reintento el que falló.
            mock_unlink.assert_called_once_with(str(target))

    def test_unexpected_operation_rejected_without_chmod(self) -> None:
        # Solo se reintentan operaciones de eliminación conocidas
        # (os.unlink/os.remove/os.rmdir); cualquier otra falla cerrado.
        handler = _make_safe_cleanup_handler(self.cleanup_root)
        with mock.patch("orchestrator.sandbox.os.chmod") as mock_chmod:
            with self.assertRaises(SandboxError):
                handler(os.scandir, str(self.cleanup_root), PermissionError(13, "denied"))
            mock_chmod.assert_not_called()

    def test_successful_retry_after_chmod(self) -> None:
        # Caso feliz real: un archivo de solo lectura se limpia y el
        # reintento tiene éxito.
        target = self.cleanup_root / "f.txt"
        target.write_text("x", encoding="utf-8")
        os.chmod(target, stat.S_IREAD)
        handler = _make_safe_cleanup_handler(self.cleanup_root)
        handler(os.unlink, str(target), PermissionError(13, "denied"))
        self.assertFalse(target.exists())


class NestedLinkCleanupRejectionTests(unittest.TestCase):
    """CORRECTION-001, hallazgo 5: antes de shutil.rmtree(), ningún
    descendiente anidado puede ser symlink/junction."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cleanup_rejects_tree_with_nested_symlink_real(self) -> None:
        sandbox = create_sandbox(self.repo_root)
        outside = Path(tempfile.mkdtemp())
        try:
            nested_link = sandbox / "nested_link"
            if not _try_make_symlink(nested_link, outside, target_is_directory=True):
                self.skipTest("symlink creation not permitted in this environment")
            with self.assertRaises(SandboxError):
                cleanup_sandbox(sandbox, repo_root=self.repo_root)
            self.assertTrue(sandbox.exists())
        finally:
            if (sandbox / "nested_link").is_symlink():
                (sandbox / "nested_link").unlink()
            cleanup_sandbox(sandbox, repo_root=self.repo_root)
            shutil.rmtree(outside, ignore_errors=True)

    def test_cleanup_rejects_tree_with_nested_link_mocked(self) -> None:
        sandbox = create_sandbox(self.repo_root)
        try:
            nested_dir = sandbox / "sub"
            nested_dir.mkdir()
            fake_link = nested_dir / "looks_like_a_link"
            fake_link.mkdir()
            with mock.patch(
                "orchestrator.sandbox._is_link_like",
                side_effect=lambda p: p.name == "looks_like_a_link",
            ):
                with self.assertRaises(SandboxError):
                    cleanup_sandbox(sandbox, repo_root=self.repo_root)
            self.assertTrue(sandbox.exists())
        finally:
            cleanup_sandbox(sandbox, repo_root=self.repo_root)


if __name__ == "__main__":
    unittest.main()
