"""Pruebas del adaptador ClaudeCodeAdapter (DeveloperPort) —
CLAUDE-EXECUTION-001 (handshake read-only) y CLAUDE-EXECUTION-002
(write-probe determinista en sandbox efímero).

No dependen de llamadas reales a Claude: subprocess.run y shutil.which se
mockean siempre en esta suite, y cualquier "modificación de filesystem" de
Claude se simula escribiendo directamente en un directorio temporal real
(nunca dentro del repositorio). La única invocación real autorizada es la
prueba LIVE manual descrita en el informe de entrega, fuera de esta suite.
"""

import json
import shutil
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

from orchestrator.adapters.claude_code import (  # noqa: E402
    EXPECTED_HANDSHAKE_RESULT,
    EXPECTED_WRITE_RESULT,
    HANDSHAKE_PROMPT,
    WRITE_PROBE_AFTER_CONTENT,
    WRITE_PROBE_BEFORE_CONTENT,
    WRITE_PROBE_DO_NOT_TOUCH_CONTENT,
    WRITE_PROBE_DO_NOT_TOUCH_FILENAME,
    WRITE_PROBE_PROMPT,
    WRITE_PROBE_TARGET_FILENAME,
    DeveloperExecutionError,
    DeveloperResult,
    DeveloperWriteResult,
    _build_args,
    prepare_sandbox_files,
    run_handshake,
    run_write_probe,
)

# Lista de flags que nunca deben aparecer en argv, sin importar el escenario
# (CORRECTION-001: dangerously-skip-permissions + su alias, y ningún flag de
# herramientas/--add-dir añadido por este incremento).
NEVER_ALLOWED_ARGV_FRAGMENTS = (
    "dangerously-skip-permissions",
    "--add-dir",
    "--allowedTools",
    "--allowed-tools",
    "--tools",
)


def _valid_developer_config(**overrides) -> dict:
    config = {
        "executable": "claude",
        "output_format": "json",
        "max_turns": 1,
        "timeout_seconds": 60,
        "permission_mode": "plan",
        "restricted": True,
    }
    config.update(overrides)
    return config


def _valid_result_payload(**overrides) -> dict:
    """JSON completo de éxito del handshake determinista. Cada prueba de
    fallo cerrado parte de aquí y rompe/elimina un único campo."""
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": EXPECTED_HANDSHAKE_RESULT,
        "session_id": "abc123",
        "num_turns": 1,
        "duration_ms": 1234,
    }
    payload.update(overrides)
    return payload


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["claude"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _valid_write_probe_developer_config(**write_probe_overrides) -> dict:
    """developer_config COMPLETO (executable/output_format compartidos +
    write_probe.* propio), tal como lo recibe run_write_probe()."""
    write_probe = {
        "max_turns": 3,
        "timeout_seconds": 90,
        "permission_mode": "acceptEdits",
        "restricted": True,
    }
    write_probe.update(write_probe_overrides)
    return {
        "executable": "claude",
        "output_format": "json",
        "write_probe": write_probe,
    }


def _valid_write_result_payload(**overrides) -> dict:
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": EXPECTED_WRITE_RESULT,
        "session_id": "sess-write-1",
        "num_turns": 2,
        "duration_ms": 987,
    }
    payload.update(overrides)
    return payload


def _fake_subprocess_run(mutate_fn, *, returncode: int = 0, stdout: str = ""):
    """Sustituto de subprocess.run(): en vez de invocar un proceso real,
    aplica `mutate_fn(cwd)` sobre el directorio recibido en kwargs['cwd']
    (simulando lo que Claude habría escrito en el sandbox) y devuelve un
    CompletedProcess con el (returncode, stdout) indicados. `mutate_fn`
    puede ser None para simular "Claude no tocó nada"."""

    def _run(args, **kwargs):
        if mutate_fn is not None:
            mutate_fn(Path(kwargs["cwd"]))
        return subprocess.CompletedProcess(
            args=args, returncode=returncode, stdout=stdout, stderr=""
        )

    return _run


def _write_target_after(cwd: Path) -> None:
    (cwd / WRITE_PROBE_TARGET_FILENAME).write_text(WRITE_PROBE_AFTER_CONTENT, encoding="utf-8")


def _leave_target_unchanged(cwd: Path) -> None:
    pass


def _write_target_wrong_content(cwd: Path) -> None:
    (cwd / WRITE_PROBE_TARGET_FILENAME).write_text("WRONG_CONTENT", encoding="utf-8")


def _write_target_after_and_touch_do_not_touch(cwd: Path) -> None:
    _write_target_after(cwd)
    (cwd / WRITE_PROBE_DO_NOT_TOUCH_FILENAME).write_text("MODIFIED", encoding="utf-8")


def _write_target_after_and_create_extra_file(cwd: Path) -> None:
    _write_target_after(cwd)
    (cwd / "EXTRA.txt").write_text("unexpected", encoding="utf-8")


def _write_target_after_and_delete_do_not_touch(cwd: Path) -> None:
    _write_target_after(cwd)
    (cwd / WRITE_PROBE_DO_NOT_TOUCH_FILENAME).unlink()


def _rename_target(cwd: Path) -> None:
    (cwd / WRITE_PROBE_TARGET_FILENAME).rename(cwd / "RENAMED.txt")


class BuildArgsTests(unittest.TestCase):
    """1. Construcción correcta de argumentos (nivel función pura)."""

    def test_build_args_shape(self) -> None:
        args = _build_args(
            "/resolved/claude", output_format="json", max_turns=3, permission_mode="plan"
        )
        self.assertEqual(
            args,
            [
                "/resolved/claude",
                "-p",
                "--output-format",
                "json",
                "--max-turns",
                "3",
                "--permission-mode",
                "plan",
                "--restricted",
            ],
        )
        # El prompt NUNCA forma parte de los argumentos.
        self.assertTrue(all(HANDSHAKE_PROMPT not in a for a in args))

    def test_build_args_contains_restricted(self) -> None:
        # 7. argv contiene --restricted (CORRECTION-001, hallazgo 2).
        args = _build_args(
            "/resolved/claude", output_format="json", max_turns=1, permission_mode="plan"
        )
        self.assertIn("--restricted", args)


class SuccessfulHandshakeTests(unittest.TestCase):
    """Cubre en una sola invocación real (mockeada) los ítems 2-7, 11, 12 y 13
    de la corrección, más el ítem 6 ("respuesta exacta esperada -> PASS")."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_successful_handshake_builds_secure_call_and_parses_result(self) -> None:
        developer_config = _valid_developer_config(max_turns=2)
        completed = _completed(returncode=0, stdout=json.dumps(_valid_result_payload()))

        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ) as mock_which, mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ) as mock_run:
            result = run_handshake(
                developer_config=developer_config,
                prompt=HANDSHAKE_PROMPT,
                cwd=self.cwd,
                authorized_root=self.cwd,
            )

        # El ejecutable se resuelve vía shutil.which(configured_executable).
        mock_which.assert_called_once_with("claude")
        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        argv = call_args[0]

        # 1. construcción correcta de argumentos
        self.assertEqual(argv[0], "/resolved/claude")
        self.assertIn("-p", argv)
        # 4. output-format=json
        self.assertEqual(argv[argv.index("--output-format") + 1], "json")
        # 5. max-turns configurado
        self.assertEqual(argv[argv.index("--max-turns") + 1], "2")
        # 6. permission-mode=plan
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "plan")
        # 7. argv contiene --restricted
        self.assertIn("--restricted", argv)
        # 13. ningún flag prohibido aparece en argv
        joined = " ".join(argv)
        for fragment in NEVER_ALLOWED_ARGV_FRAGMENTS:
            self.assertNotIn(fragment, joined)

        # 11. subprocess continúa con shell=False
        self.assertIs(call_kwargs["shell"], False)
        # 12. prompt continúa fuera de argv y enviado por stdin
        self.assertEqual(call_kwargs["input"], HANDSHAKE_PROMPT)
        self.assertTrue(all(HANDSHAKE_PROMPT not in a for a in argv))
        # cwd correcto
        self.assertEqual(call_kwargs["cwd"], str(self.cwd))
        self.assertEqual(call_kwargs["timeout"], 60)

        # 6. respuesta exacta esperada -> PASS (DeveloperResult correcto)
        self.assertIsInstance(result, DeveloperResult)
        self.assertTrue(result.success)
        self.assertFalse(result.is_error)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.result_text, EXPECTED_HANDSHAKE_RESULT)
        self.assertEqual(result.session_id, "abc123")
        self.assertEqual(result.num_turns, 1)
        self.assertEqual(result.duration_ms, 1234)


class FailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_with(self, *, which_return="/resolved/claude", run_return=None, run_side_effect=None):
        developer_config = _valid_developer_config()
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value=which_return
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            return_value=run_return,
            side_effect=run_side_effect,
        ) as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_handshake(
                    developer_config=developer_config,
                    prompt=HANDSHAKE_PROMPT,
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )
        return mock_run

    def test_missing_executable_fails_closed(self) -> None:
        # 8. executable ausente -> fail closed, subprocess.run NUNCA se invoca.
        mock_run = self._run_with(which_return=None)
        mock_run.assert_not_called()

    def test_timeout_fails_closed(self) -> None:
        # 9. timeout -> fail closed.
        self._run_with(
            run_side_effect=subprocess.TimeoutExpired(cmd=["claude"], timeout=60)
        )

    def test_nonzero_exit_code_fails_closed(self) -> None:
        # 10. exit code != 0 -> fail closed.
        self._run_with(run_return=_completed(returncode=1, stdout="", stderr="boom"))

    def test_invalid_json_fails_closed(self) -> None:
        # JSON inválido -> fail closed.
        self._run_with(run_return=_completed(returncode=0, stdout="not json at all"))

    def test_json_not_an_object_fails_closed(self) -> None:
        self._run_with(run_return=_completed(returncode=0, stdout="[1, 2, 3]"))

    def test_missing_type_fails_closed(self) -> None:
        # 1. JSON sin type -> fail closed.
        payload = _valid_result_payload()
        del payload["type"]
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_type_not_result_fails_closed(self) -> None:
        # 2. type != result -> fail closed. Reproduce exactamente el caso
        # del Director: {"type": "assistant", "is_error": false, "result": "TOTALLY_WRONG"}.
        payload = _valid_result_payload(type="assistant", result="TOTALLY_WRONG")
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_missing_subtype_fails_closed(self) -> None:
        # 3. JSON sin subtype -> fail closed.
        payload = _valid_result_payload()
        del payload["subtype"]
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_subtype_not_success_fails_closed(self) -> None:
        # 4. subtype != success -> fail closed. Reproduce exactamente el caso
        # del Director: subtype "failure" con is_error: false, result "TOTALLY_WRONG".
        payload = _valid_result_payload(subtype="failure", result="TOTALLY_WRONG")
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_bare_is_error_false_and_result_totally_wrong_fails_closed(self) -> None:
        # Reproduce exactamente el primer caso del Director:
        # {"is_error": false, "result": "TOTALLY_WRONG"} (sin type/subtype).
        self._run_with(
            run_return=_completed(
                returncode=0,
                stdout='{"is_error": false, "result": "TOTALLY_WRONG"}',
            )
        )

    def test_result_mismatch_fails_closed(self) -> None:
        # 5. result diferente del handshake esperado -> fail closed. Sin
        # coincidencia parcial: type/subtype/is_error correctos, solo el
        # texto de 'result' difiere.
        payload = _valid_result_payload(result="TOTALLY_WRONG")
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_result_partial_match_is_not_accepted(self) -> None:
        # No se acepta startswith/coincidencia parcial: un prefijo válido
        # seguido de texto adicional debe rechazarse igual que un mismatch total.
        payload = _valid_result_payload(result=EXPECTED_HANDSHAKE_RESULT + " extra")
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_is_error_true_fails_closed(self) -> None:
        payload = _valid_result_payload(is_error=True, result="something went wrong")
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_is_error_missing_fails_closed(self) -> None:
        # Defensivo: is_error ausente no se asume False.
        payload = _valid_result_payload()
        del payload["is_error"]
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_result_field_missing_fails_closed(self) -> None:
        payload = _valid_result_payload()
        del payload["result"]
        self._run_with(run_return=_completed(returncode=0, stdout=json.dumps(payload)))

    def test_cwd_outside_authorized_root_is_rejected(self) -> None:
        # 15. ninguna llamada a AIP/FOA (o cualquier otro directorio): un cwd
        # fuera de authorized_root se rechaza ANTES de invocar subprocess.
        outside = Path(tempfile.mkdtemp())
        try:
            developer_config = _valid_developer_config()
            with mock.patch(
                "orchestrator.adapters.claude_code.shutil.which",
                return_value="/resolved/claude",
            ), mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run"
            ) as mock_run:
                with self.assertRaises(DeveloperExecutionError):
                    run_handshake(
                        developer_config=developer_config,
                        prompt=HANDSHAKE_PROMPT,
                        cwd=outside,
                        authorized_root=self.cwd,
                    )
            mock_run.assert_not_called()
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class DeveloperConfigValidationTests(unittest.TestCase):
    """Validación defensiva de developer_config, previa a cualquier
    resolución de ejecutable o invocación de subprocess."""

    def test_missing_executable_in_config_rejected(self) -> None:
        developer_config = _valid_developer_config()
        del developer_config["executable"]
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_handshake(
                    developer_config=developer_config,
                    prompt=HANDSHAKE_PROMPT,
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_permission_mode_other_than_plan_rejected(self) -> None:
        # Ningún modo distinto de "plan" está autorizado en este incremento
        # (sin edición, sin Bash); esto también impide indirectamente
        # cualquier variante de bypassPermissions.
        developer_config = _valid_developer_config(permission_mode="bypassPermissions")
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_handshake(
                    developer_config=developer_config,
                    prompt=HANDSHAKE_PROMPT,
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_output_format_other_than_json_rejected(self) -> None:
        developer_config = _valid_developer_config(output_format="text")
        with self.assertRaises(DeveloperExecutionError):
            run_handshake(
                developer_config=developer_config,
                prompt=HANDSHAKE_PROMPT,
                cwd=REPO_ROOT,
                authorized_root=REPO_ROOT,
            )

    def test_restricted_not_true_rejected(self) -> None:
        # Defensa en profundidad a nivel de adaptador (además de la
        # validación de config_loader): restricted debe ser exactamente True.
        developer_config = _valid_developer_config(restricted=False)
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_handshake(
                    developer_config=developer_config,
                    prompt=HANDSHAKE_PROMPT,
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()


# ============================================================
# CLAUDE-EXECUTION-002: write-probe (sandbox efímero)
# ============================================================


class PrepareSandboxFilesTests(unittest.TestCase):
    def test_creates_exact_before_and_do_not_touch_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            prepare_sandbox_files(sandbox)
            self.assertEqual(
                (sandbox / WRITE_PROBE_TARGET_FILENAME).read_text(encoding="utf-8"),
                WRITE_PROBE_BEFORE_CONTENT,
            )
            self.assertEqual(
                (sandbox / WRITE_PROBE_DO_NOT_TOUCH_FILENAME).read_text(encoding="utf-8"),
                WRITE_PROBE_DO_NOT_TOUCH_CONTENT,
            )


class WriteProbeTestCase(unittest.TestCase):
    """Sandbox real (directorio temporal fuera del repo, para no depender
    de orchestrator.sandbox en estas pruebas de adaptador) con TARGET.txt/
    DO_NOT_TOUCH.txt ya preparados, como los recibiría run_write_probe()."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.sandbox = Path(self._tmp.name).resolve()
        prepare_sandbox_files(self.sandbox)

    def tearDown(self) -> None:
        self._tmp.cleanup()


class WriteProbeSuccessTests(WriteProbeTestCase):
    def test_target_before_to_after_only_passes(self) -> None:
        # 9. TARGET BEFORE->AFTER únicamente -> PASS. Cubre también 1-8,
        # 11 y 13 (argv/subprocess/cwd/authorized_root) en una sola llamada.
        developer_config = _valid_write_probe_developer_config(max_turns=5)
        payload = _valid_write_result_payload()

        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ) as mock_which, mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            side_effect=_fake_subprocess_run(_write_target_after, stdout=json.dumps(payload)),
        ) as mock_run:
            result = run_write_probe(
                developer_config=developer_config,
                cwd=self.sandbox,
                authorized_root=self.sandbox,
            )

        mock_which.assert_called_once_with("claude")
        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        argv = call_args[0]

        # 4. argv contiene acceptEdits
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "acceptEdits")
        self.assertEqual(argv[argv.index("--max-turns") + 1], "5")
        # 5. argv contiene --restricted
        self.assertIn("--restricted", argv)
        # ningún flag prohibido
        joined = " ".join(argv)
        for fragment in NEVER_ALLOWED_ARGV_FRAGMENTS:
            self.assertNotIn(fragment, joined)

        # 6. shell=False
        self.assertIs(call_kwargs["shell"], False)
        # 7. prompt enviado mediante stdin
        self.assertEqual(call_kwargs["input"], WRITE_PROBE_PROMPT)
        # 8. prompt no aparece en argv
        self.assertTrue(all(WRITE_PROBE_PROMPT not in a for a in argv))
        # 2. cwd de subprocess == sandbox; 3. authorized_root == sandbox
        self.assertEqual(call_kwargs["cwd"], str(self.sandbox))
        self.assertEqual(call_kwargs["timeout"], 90)

        self.assertIsInstance(result, DeveloperWriteResult)
        self.assertTrue(result.success)
        self.assertEqual(result.result_text, EXPECTED_WRITE_RESULT)
        self.assertEqual(result.changed_paths, (WRITE_PROBE_TARGET_FILENAME,))
        self.assertEqual(result.created_paths, ())
        self.assertEqual(result.deleted_paths, ())
        self.assertEqual(result.session_id, "sess-write-1")
        self.assertEqual(result.num_turns, 2)
        self.assertEqual(result.duration_ms, 987)

        # Evidencia independiente adicional: releer los archivos reales.
        self.assertEqual(
            (self.sandbox / WRITE_PROBE_TARGET_FILENAME).read_text(encoding="utf-8"),
            WRITE_PROBE_AFTER_CONTENT,
        )
        self.assertEqual(
            (self.sandbox / WRITE_PROBE_DO_NOT_TOUCH_FILENAME).read_text(encoding="utf-8"),
            WRITE_PROBE_DO_NOT_TOUCH_CONTENT,
        )


class WriteProbeFailClosedTests(WriteProbeTestCase):
    def _expect_failure(
        self,
        mutate_fn,
        *,
        returncode: int = 0,
        payload: dict | None = None,
        developer_config: dict | None = None,
    ) -> None:
        if developer_config is None:
            developer_config = _valid_write_probe_developer_config()
        stdout = json.dumps(payload) if payload is not None else ""
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            side_effect=_fake_subprocess_run(mutate_fn, returncode=returncode, stdout=stdout),
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_write_probe(
                    developer_config=developer_config,
                    cwd=self.sandbox,
                    authorized_root=self.sandbox,
                )

    def test_target_unchanged_fails_closed(self) -> None:
        # 10. TARGET no cambia -> FAIL
        self._expect_failure(_leave_target_unchanged, payload=_valid_write_result_payload())

    def test_target_wrong_content_fails_closed(self) -> None:
        # 11. TARGET termina con contenido distinto de AFTER -> FAIL
        self._expect_failure(_write_target_wrong_content, payload=_valid_write_result_payload())

    def test_do_not_touch_modified_fails_closed(self) -> None:
        # 12. DO_NOT_TOUCH cambia -> FAIL
        self._expect_failure(
            _write_target_after_and_touch_do_not_touch, payload=_valid_write_result_payload()
        )

    def test_extra_file_created_fails_closed(self) -> None:
        # 13. archivo adicional creado -> FAIL
        self._expect_failure(
            _write_target_after_and_create_extra_file, payload=_valid_write_result_payload()
        )

    def test_do_not_touch_deleted_fails_closed(self) -> None:
        # 14. archivo eliminado -> FAIL
        self._expect_failure(
            _write_target_after_and_delete_do_not_touch, payload=_valid_write_result_payload()
        )

    def test_target_renamed_fails_closed(self) -> None:
        # 15. archivo renombrado -> FAIL (se ve como delete + create)
        self._expect_failure(_rename_target, payload=_valid_write_result_payload())

    def test_claude_says_ok_but_filesystem_wrong_fails_closed(self) -> None:
        # 16. respuesta CLAUDE_WRITE_OK pero filesystem incorrecto -> FAIL.
        # La evidencia de filesystem tiene prioridad sobre la narrativa.
        self._expect_failure(_leave_target_unchanged, payload=_valid_write_result_payload())

    def test_filesystem_correct_but_response_wrong_fails_closed(self) -> None:
        # 17. filesystem correcto pero respuesta distinta -> FAIL
        self._expect_failure(
            _write_target_after,
            payload=_valid_write_result_payload(result="NOT_THE_RIGHT_TEXT"),
        )

    def test_missing_type_fails_closed(self) -> None:
        # 18a. type ausente -> FAIL
        payload = _valid_write_result_payload()
        del payload["type"]
        self._expect_failure(_write_target_after, payload=payload)

    def test_subtype_not_success_fails_closed(self) -> None:
        # 18b. subtype != success -> FAIL
        self._expect_failure(
            _write_target_after, payload=_valid_write_result_payload(subtype="failure")
        )

    def test_is_error_true_fails_closed(self) -> None:
        # 18c. is_error inválido -> FAIL
        self._expect_failure(
            _write_target_after, payload=_valid_write_result_payload(is_error=True)
        )

    def test_timeout_fails_closed(self) -> None:
        # 19. timeout -> FAIL
        developer_config = _valid_write_probe_developer_config()
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["claude"], timeout=90),
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_write_probe(
                    developer_config=developer_config,
                    cwd=self.sandbox,
                    authorized_root=self.sandbox,
                )

    def test_nonzero_exit_code_fails_closed(self) -> None:
        # 20. exit code != 0 -> FAIL
        self._expect_failure(
            _write_target_after, returncode=1, payload=_valid_write_result_payload()
        )

    def test_cwd_outside_authorized_root_fails_before_subprocess(self) -> None:
        # 21. cwd fuera de authorized_root -> FAIL antes de subprocess.run.
        outside = Path(tempfile.mkdtemp())
        try:
            developer_config = _valid_write_probe_developer_config()
            with mock.patch(
                "orchestrator.adapters.claude_code.shutil.which",
                return_value="/resolved/claude",
            ), mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run"
            ) as mock_run:
                with self.assertRaises(DeveloperExecutionError):
                    run_write_probe(
                        developer_config=developer_config,
                        cwd=outside,
                        authorized_root=self.sandbox,
                    )
            mock_run.assert_not_called()
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class WriteProbeConfigValidationTests(unittest.TestCase):
    """Defensa en profundidad a nivel de adaptador (además de
    config_loader): permission_mode/restricted del write_probe."""

    def test_permission_mode_other_than_accept_edits_rejected(self) -> None:
        developer_config = _valid_write_probe_developer_config(permission_mode="plan")
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_write_probe(
                    developer_config=developer_config,
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_restricted_not_true_rejected(self) -> None:
        developer_config = _valid_write_probe_developer_config(restricted=False)
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_write_probe(
                    developer_config=developer_config,
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
