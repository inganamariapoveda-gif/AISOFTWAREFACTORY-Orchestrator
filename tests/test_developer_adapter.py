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
    ClaudeFailureCategory,
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
    run_developer_task,
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


def _valid_task_execution_developer_config(**task_execution_overrides) -> dict:
    """TASK-EXECUTION-005: developer_config COMPLETO (executable/
    output_format compartidos + task_execution.* propio), tal como lo
    recibe run_developer_task(). Independiente por completo de
    write_probe: este dict NUNCA declara la clave 'write_probe'."""
    task_execution = {
        "enabled": True,
        "max_turns": 8,
        "timeout_seconds": 90,
        "permission_mode": "acceptEdits",
        "restricted": True,
    }
    task_execution.update(task_execution_overrides)
    return {
        "executable": "claude",
        "output_format": "json",
        "task_execution": task_execution,
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


# ============================================================
# TASK-EXECUTION-002: run_developer_task (adaptador genérico de tarea de
# desarrollo). Reutiliza la MISMA validación de developer_config que el
# write-probe (_valid_write_probe_developer_config): permission_mode ==
# acceptEdits, restricted == true. A diferencia del handshake/write-probe,
# NUNCA exige un texto de 'result' exacto -- solo su estructura.
# ============================================================


def _valid_generic_result_payload(**overrides) -> dict:
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": "whatever Claude says, never checked verbatim",
        "session_id": "sess-generic-1",
        "num_turns": 3,
        "duration_ms": 4321,
    }
    payload.update(overrides)
    return payload


class RunDeveloperTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_valid_success_builds_secure_call_and_parses_structurally(self) -> None:
        developer_config = _valid_task_execution_developer_config(max_turns=4)
        completed = _completed(returncode=0, stdout=json.dumps(_valid_generic_result_payload()))

        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ) as mock_which, mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ) as mock_run:
            result = run_developer_task(
                developer_config=developer_config,
                prompt="STRUCTURED TASK INSTRUCTION",
                cwd=self.cwd,
                authorized_root=self.cwd,
            )

        mock_which.assert_called_once_with("claude")
        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        argv = call_args[0]

        # acceptEdits + --restricted (reutiliza las mismas garantías del
        # write-probe, D-EXEC-002).
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "acceptEdits")
        self.assertIn("--restricted", argv)
        joined = " ".join(argv)
        for fragment in NEVER_ALLOWED_ARGV_FRAGMENTS:
            self.assertNotIn(fragment, joined)

        # shell=False; prompt SOLO por stdin, nunca en argv.
        self.assertIs(call_kwargs["shell"], False)
        self.assertEqual(call_kwargs["input"], "STRUCTURED TASK INSTRUCTION")
        self.assertTrue(all("STRUCTURED TASK INSTRUCTION" not in a for a in argv))
        self.assertEqual(call_kwargs["cwd"], str(self.cwd))
        self.assertEqual(call_kwargs["timeout"], 90)

        self.assertIsInstance(result, DeveloperResult)
        self.assertTrue(result.success)
        self.assertFalse(result.is_error)
        # Nunca exige un texto exacto de 'result' (a diferencia del
        # handshake/write-probe): cualquier string estructuralmente válido
        # es aceptado.
        self.assertEqual(result.result_text, "whatever Claude says, never checked verbatim")

    def test_cwd_outside_authorized_root_rejected_before_subprocess(self) -> None:
        outside = Path(tempfile.mkdtemp())
        try:
            developer_config = _valid_task_execution_developer_config()
            with mock.patch(
                "orchestrator.adapters.claude_code.shutil.which",
                return_value="/resolved/claude",
            ), mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run"
            ) as mock_run:
                with self.assertRaises(DeveloperExecutionError):
                    run_developer_task(
                        developer_config=developer_config,
                        prompt="x",
                        cwd=outside,
                        authorized_root=self.cwd,
                    )
            mock_run.assert_not_called()
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_timeout_fails_closed(self) -> None:
        developer_config = _valid_task_execution_developer_config()
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["claude"], timeout=90),
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )

    def test_nonzero_exit_code_fails_closed(self) -> None:
        developer_config = _valid_task_execution_developer_config()
        completed = _completed(returncode=1, stderr="boom")
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )

    def test_malformed_json_fails_closed(self) -> None:
        developer_config = _valid_task_execution_developer_config()
        completed = _completed(returncode=0, stdout="not json at all")
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )

    def test_wrong_subtype_fails_closed(self) -> None:
        developer_config = _valid_task_execution_developer_config()
        payload = _valid_generic_result_payload(subtype="failure")
        completed = _completed(returncode=0, stdout=json.dumps(payload))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )

    def test_is_error_true_fails_closed(self) -> None:
        developer_config = _valid_task_execution_developer_config()
        payload = _valid_generic_result_payload(is_error=True)
        completed = _completed(returncode=0, stdout=json.dumps(payload))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )

    def test_result_not_str_fails_closed(self) -> None:
        developer_config = _valid_task_execution_developer_config()
        payload = _valid_generic_result_payload(result=12345)
        completed = _completed(returncode=0, stdout=json.dumps(payload))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )

    def test_permission_mode_other_than_accept_edits_rejected(self) -> None:
        developer_config = _valid_task_execution_developer_config(permission_mode="plan")
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_restricted_not_true_rejected(self) -> None:
        developer_config = _valid_task_execution_developer_config(restricted=False)
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_task_execution_missing_fails_closed(self) -> None:
        # F. developer.task_execution ausente por completo: fail closed,
        # SIN fallback a write_probe.
        developer_config = {"executable": "claude", "output_format": "json"}
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_task_execution_present_but_write_probe_only_fails_closed(self) -> None:
        # F (variante): solo write_probe declarado, sin task_execution: NO
        # hay fallback implícito al bloque write_probe.
        developer_config = _valid_write_probe_developer_config()
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_task_execution_enabled_false_fails_closed(self) -> None:
        # G. developer.task_execution.enabled == false: fail closed.
        developer_config = _valid_task_execution_developer_config(enabled=False)
        with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
            with self.assertRaises(DeveloperExecutionError):
                run_developer_task(
                    developer_config=developer_config,
                    prompt="x",
                    cwd=REPO_ROOT,
                    authorized_root=REPO_ROOT,
                )
        mock_run.assert_not_called()

    def test_task_execution_max_turns_invalid_fails_closed(self) -> None:
        # J. max_turns inválido (cero, negativo o no entero): fail closed.
        for invalid_max_turns in (0, -1, "8", None):
            developer_config = _valid_task_execution_developer_config(
                max_turns=invalid_max_turns
            )
            with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
                with self.assertRaises(DeveloperExecutionError):
                    run_developer_task(
                        developer_config=developer_config,
                        prompt="x",
                        cwd=REPO_ROOT,
                        authorized_root=REPO_ROOT,
                    )
            mock_run.assert_not_called()

    def test_task_execution_timeout_invalid_fails_closed(self) -> None:
        # K. timeout_seconds inválido (cero, negativo o no entero): fail
        # closed.
        for invalid_timeout in (0, -1, "90", None):
            developer_config = _valid_task_execution_developer_config(
                timeout_seconds=invalid_timeout
            )
            with mock.patch("orchestrator.adapters.claude_code.subprocess.run") as mock_run:
                with self.assertRaises(DeveloperExecutionError):
                    run_developer_task(
                        developer_config=developer_config,
                        prompt="x",
                        cwd=REPO_ROOT,
                        authorized_root=REPO_ROOT,
                    )
            mock_run.assert_not_called()


class GenericTaskConfigIndependenceTests(unittest.TestCase):
    """TASK-EXECUTION-005: run_developer_task usa EXCLUSIVAMENTE
    developer.task_execution -- nunca developer.write_probe -- y ese
    presupuesto es independiente en ambas direcciones del write-probe y del
    handshake."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_generic_task_argv_uses_task_execution_max_turns_eight(self) -> None:
        # A. El argv de run_developer_task contiene --max-turns 8 (el
        # presupuesto propio de task_execution, distinto de write_probe).
        developer_config = _valid_task_execution_developer_config()
        completed = _completed(returncode=0, stdout=json.dumps(_valid_generic_result_payload()))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ) as mock_run:
            run_developer_task(
                developer_config=developer_config,
                prompt="x",
                cwd=self.cwd,
                authorized_root=self.cwd,
            )
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[argv.index("--max-turns") + 1], "8")

    def test_write_probe_argv_still_uses_max_turns_three(self) -> None:
        # B. run_write_probe sigue usando --max-turns 3, sin importar el
        # cambio anterior en run_developer_task.
        developer_config = _valid_write_probe_developer_config()
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp).resolve()
            prepare_sandbox_files(cwd)
            completed = _completed(
                returncode=0, stdout=json.dumps(_valid_write_result_payload())
            )
            with mock.patch(
                "orchestrator.adapters.claude_code.shutil.which",
                return_value="/resolved/claude",
            ), mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run",
                side_effect=_fake_subprocess_run(_write_target_after, stdout=completed.stdout),
            ) as mock_run:
                run_write_probe(
                    developer_config=developer_config,
                    cwd=cwd,
                    authorized_root=cwd,
                )
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[argv.index("--max-turns") + 1], "3")

    def test_handshake_argv_still_uses_max_turns_one(self) -> None:
        # C. el handshake sigue usando --max-turns 1.
        developer_config = _valid_developer_config()
        completed = _completed(
            returncode=0, stdout=json.dumps(_valid_result_payload())
        )
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ) as mock_run:
            run_handshake(
                developer_config=developer_config,
                prompt=HANDSHAKE_PROMPT,
                cwd=self.cwd,
                authorized_root=self.cwd,
            )
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[argv.index("--max-turns") + 1], "1")

    def test_changing_write_probe_max_turns_does_not_affect_generic_task(self) -> None:
        # D. cambiar write_probe.max_turns en la config de prueba NO afecta
        # run_developer_task (que ni siquiera lee esa clave).
        developer_config = _valid_task_execution_developer_config()
        developer_config["write_probe"] = {
            "enabled": True,
            "permission_mode": "acceptEdits",
            "restricted": True,
            "max_turns": 999,
            "timeout_seconds": 90,
        }
        completed = _completed(returncode=0, stdout=json.dumps(_valid_generic_result_payload()))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ) as mock_run:
            run_developer_task(
                developer_config=developer_config,
                prompt="x",
                cwd=self.cwd,
                authorized_root=self.cwd,
            )
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[argv.index("--max-turns") + 1], "8")

    def test_changing_task_execution_max_turns_does_not_affect_write_probe(self) -> None:
        # E. cambiar task_execution.max_turns en la config de prueba NO
        # afecta run_write_probe (que ni siquiera lee esa clave).
        developer_config = _valid_write_probe_developer_config()
        developer_config["task_execution"] = {
            "enabled": True,
            "permission_mode": "acceptEdits",
            "restricted": True,
            "max_turns": 999,
            "timeout_seconds": 90,
        }
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp).resolve()
            prepare_sandbox_files(cwd)
            completed = _completed(
                returncode=0, stdout=json.dumps(_valid_write_result_payload())
            )
            with mock.patch(
                "orchestrator.adapters.claude_code.shutil.which",
                return_value="/resolved/claude",
            ), mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run",
                side_effect=_fake_subprocess_run(_write_target_after, stdout=completed.stdout),
            ) as mock_run:
                run_write_probe(
                    developer_config=developer_config,
                    cwd=cwd,
                    authorized_root=cwd,
                )
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[argv.index("--max-turns") + 1], "3")


# ============================================================
# TASK-EXECUTION-003: safe failure diagnostics de run_developer_task cuando
# el proceso Claude termina con exit_code != 0. Nunca expone el prompt
# (enviado por stdin), nunca expone el campo JSON `result` ni stdout/stderr
# crudos completos; solo campos estructurales allowlisted de un stdout JSON
# y un fragmento acotado/saneado de stderr.
# ============================================================


class RunDeveloperTaskSafeFailureDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_and_capture_error(
        self,
        *,
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        prompt: str = "STRUCTURED PROMPT SECRET_PROMPT_MARKER_XYZ",
    ) -> str:
        developer_config = _valid_task_execution_developer_config()
        completed = _completed(returncode=returncode, stdout=stdout, stderr=stderr)
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            with self.assertRaises(DeveloperExecutionError) as cm:
                run_developer_task(
                    developer_config=developer_config,
                    prompt=prompt,
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )
        return str(cm.exception)

    def test_nonzero_exit_with_normal_stderr_includes_exit_code_and_sanitized_stderr(
        self,
    ) -> None:
        # A. exit code != 0 + stderr normal: el error contiene exit_code y
        # el stderr saneado/acotado.
        message = self._run_and_capture_error(returncode=1, stderr="permission denied")
        self.assertIn("exit_code=1", message)
        self.assertIn("permission denied", message)

    def test_stderr_over_limit_is_bounded_to_500_chars(self) -> None:
        # B. stderr > 500 chars: nunca expone más del límite.
        long_stderr = "X" * 2000
        message = self._run_and_capture_error(returncode=1, stderr=long_stderr)
        self.assertIn("exit_code=1", message)
        self.assertLessEqual(message.count("X"), 500)

    def test_stdout_json_error_extracts_only_allowlisted_fields(self) -> None:
        # C. stdout JSON: extrae ÚNICAMENTE campos allowlisted.
        payload = json.dumps(
            {
                "type": "result",
                "subtype": "error",
                "is_error": True,
                "api_error_status": 429,
                "stop_reason": "max_turns",
                "permission_denials": ["Bash"],
                "result": "SECRET_CONTENT_SHOULD_NOT_APPEAR",
                "session_id": "sess-should-not-appear-either",
                "usage": {"input_tokens": 111},
                "modelUsage": {"claude": {"inputTokens": 5}},
            }
        )
        message = self._run_and_capture_error(returncode=1, stdout=payload)
        self.assertIn("exit_code=1", message)
        self.assertIn("error", message)
        self.assertIn("429", message)
        self.assertIn("max_turns", message)
        # CAPACITY-DETECTION-001: permission_denials se reduce a su CONTEO;
        # su contenido (p. ej. tool_input de la herramienta denegada) nunca
        # aparece en el mensaje (que llega al resultado público).
        self.assertIn("permission_denial_count=1", message)
        self.assertNotIn("Bash", message)
        self.assertNotIn("SECRET_CONTENT_SHOULD_NOT_APPEAR", message)
        self.assertNotIn("sess-should-not-appear-either", message)
        self.assertNotIn("input_tokens", message)
        self.assertNotIn("modelUsage", message)

    def test_stdout_result_secret_never_appears_in_error(self) -> None:
        # D. stdout JSON contiene result: "SECRET_CONTENT_SHOULD_NOT_APPEAR"
        # -- el error final NUNCA debe contener ese valor.
        payload = json.dumps(
            {
                "type": "result",
                "subtype": "error",
                "is_error": True,
                "result": "SECRET_CONTENT_SHOULD_NOT_APPEAR",
            }
        )
        message = self._run_and_capture_error(returncode=1, stdout=payload)
        self.assertNotIn("SECRET_CONTENT_SHOULD_NOT_APPEAR", message)

    def test_non_json_stdout_with_empty_stderr_reports_presence_only(self) -> None:
        # E. stdout no JSON + stderr vacío: solo indica stdout_present=true,
        # sin reproducir el contenido de stdout.
        message = self._run_and_capture_error(
            returncode=1, stdout="raw text SECRET_STDOUT_MARKER not json", stderr=""
        )
        self.assertIn("exit_code=1", message)
        self.assertIn("stdout_present=true", message)
        self.assertNotIn("SECRET_STDOUT_MARKER", message)

    def test_prompt_never_appears_in_any_diagnostic(self) -> None:
        # F. ningún diagnostic incluye el prompt.
        secret_prompt = "STRUCTURED PROMPT SECRET_PROMPT_MARKER_XYZ"
        message = self._run_and_capture_error(
            returncode=1,
            stdout=json.dumps({"type": "result", "subtype": "error", "is_error": True}),
            stderr="some stderr text",
            prompt=secret_prompt,
        )
        self.assertNotIn(secret_prompt, message)
        self.assertNotIn("SECRET_PROMPT_MARKER_XYZ", message)

    def test_success_path_still_works(self) -> None:
        # G. success path sigue funcionando igual: no se toca en absoluto.
        developer_config = _valid_task_execution_developer_config()
        completed = _completed(
            returncode=0, stdout=json.dumps(_valid_generic_result_payload())
        )
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            result = run_developer_task(
                developer_config=developer_config,
                prompt="x",
                cwd=self.cwd,
                authorized_root=self.cwd,
            )
        self.assertTrue(result.success)
        self.assertEqual(
            result.result_text, "whatever Claude says, never checked verbatim"
        )


# ============================================================
# CAPACITY-DETECTION-001: clasificación ESTRUCTURADA y segura de fallos del
# Developer. Solo señales estructurales (tipo de excepción, exit code, campos
# JSON allowlisted); nunca texto de stdout/stderr/result. Ninguna categoría
# autoriza retry: esto solo etiqueta el fallo.
# ============================================================


class ClaudeFailureClassificationTests(unittest.TestCase):
    ALLOWED_DETAIL_KEYS = frozenset(
        {
            "exit_code",
            "type",
            "subtype",
            "is_error",
            "api_error_status",
            "stop_reason",
            "permission_denial_count",
            "json_top_level_keys",
        }
    )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @staticmethod
    def _payload(**fields) -> str:
        base = {"type": "result", "subtype": "error_during_execution", "is_error": True}
        base.update(fields)
        return json.dumps(base)

    def _error(
        self,
        *,
        returncode: int = 1,
        stdout: str = "",
        stderr: str = "",
        which_return: str | None = "/resolved/claude",
        run_side_effect=None,
    ) -> DeveloperExecutionError:
        completed = _completed(returncode=returncode, stdout=stdout, stderr=stderr)
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value=which_return
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            return_value=completed,
            side_effect=run_side_effect,
        ):
            with self.assertRaises(DeveloperExecutionError) as cm:
                run_developer_task(
                    developer_config=_valid_task_execution_developer_config(),
                    prompt="x",
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )
        return cm.exception

    # ---- A. api_error_status == 429 -> CLAUDE_TEMPORARY_LIMIT ----

    def test_429_with_nonzero_exit_is_temporary_limit(self) -> None:
        exc = self._error(returncode=1, stdout=self._payload(api_error_status=429))
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_TEMPORARY_LIMIT)
        self.assertEqual(exc.category, "CLAUDE_TEMPORARY_LIMIT")
        self.assertEqual(exc.details["api_error_status"], 429)
        self.assertEqual(exc.details["exit_code"], 1)
        self.assertEqual(exc.details["type"], "result")
        self.assertIs(exc.details["is_error"], True)

    # ---- B. subtype == error_max_turns -> CLAUDE_MAX_TURNS ----

    def test_error_max_turns_subtype_is_max_turns(self) -> None:
        exc = self._error(returncode=1, stdout=self._payload(subtype="error_max_turns"))
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_MAX_TURNS)
        self.assertEqual(exc.details["subtype"], "error_max_turns")

    def test_max_turns_is_never_inferred_from_text_or_stop_reason(self) -> None:
        # Solo `subtype == "error_max_turns"` clasifica: ni stderr textual ni
        # stop_reason por sí solo.
        exc = self._error(
            returncode=1,
            stdout=self._payload(subtype="error", stop_reason="max_turns"),
            stderr="Reached max turns (8)",
        )
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(exc.details["stop_reason"], "max_turns")

    # ---- C. permission_denials no vacío -> CLAUDE_PERMISSION_DENIED ----

    def test_non_empty_permission_denials_is_permission_denied(self) -> None:
        denials = [{"tool_name": "Bash", "tool_input": {"command": "SECRET_DENIAL_CMD"}}]
        exc = self._error(returncode=1, stdout=self._payload(permission_denials=denials))
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_PERMISSION_DENIED)
        self.assertEqual(exc.details["permission_denial_count"], 1)
        # Solo el conteo: nunca el contenido de las denegaciones.
        self.assertNotIn("SECRET_DENIAL_CMD", json.dumps(exc.details))
        self.assertNotIn("SECRET_DENIAL_CMD", str(exc))
        self.assertNotIn("Bash", json.dumps(exc.details))

    def test_empty_or_non_list_permission_denials_do_not_classify(self) -> None:
        empty = self._error(stdout=self._payload(permission_denials=[]))
        self.assertIs(empty.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(empty.details["permission_denial_count"], 0)

        not_a_list = self._error(stdout=self._payload(permission_denials="Bash"))
        self.assertIs(not_a_list.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertNotIn("permission_denial_count", not_a_list.details)

    # ---- D. timeout -> CLAUDE_TIMEOUT ----

    def test_timeout_is_claude_timeout(self) -> None:
        exc = self._error(
            run_side_effect=subprocess.TimeoutExpired(cmd=["claude"], timeout=90)
        )
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_TIMEOUT)
        self.assertEqual(exc.details, {})
        self.assertIn("timed out", str(exc))

    def test_handshake_and_write_probe_timeouts_are_classified_too(self) -> None:
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["claude"], timeout=60),
        ):
            with self.assertRaises(DeveloperExecutionError) as handshake:
                run_handshake(
                    developer_config=_valid_developer_config(),
                    prompt=HANDSHAKE_PROMPT,
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )
            prepare_sandbox_files(self.cwd)
            with self.assertRaises(DeveloperExecutionError) as write_probe:
                run_write_probe(
                    developer_config=_valid_write_probe_developer_config(),
                    cwd=self.cwd,
                    authorized_root=self.cwd,
                )
        self.assertIs(handshake.exception.category, ClaudeFailureCategory.CLAUDE_TIMEOUT)
        self.assertIs(write_probe.exception.category, ClaudeFailureCategory.CLAUDE_TIMEOUT)

    # ---- E. ejecutable ausente -> CLAUDE_EXECUTABLE_MISSING ----

    def test_executable_not_on_path_is_executable_missing(self) -> None:
        exc = self._error(which_return=None)
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTABLE_MISSING)
        self.assertEqual(exc.details, {})

    def test_file_not_found_at_launch_is_executable_missing(self) -> None:
        exc = self._error(run_side_effect=FileNotFoundError("SECRET_PATH_MARKER"))
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTABLE_MISSING)
        self.assertNotIn("SECRET_PATH_MARKER", str(exc))

    # ---- F. error desconocido -> CLAUDE_EXECUTION_ERROR (fail closed) ----

    def test_unknown_nonzero_error_is_general_execution_error(self) -> None:
        exc = self._error(returncode=2, stdout="", stderr="boom")
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(exc.details, {"exit_code": 2})

    def test_non_json_stdout_only_carries_exit_code(self) -> None:
        exc = self._error(returncode=1, stdout="raw text SECRET_STDOUT_MARKER not json")
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(exc.details, {"exit_code": 1})

    def test_limit_wording_in_text_never_classifies(self) -> None:
        # Sin matching textual: ni stderr ni stdout no JSON ni el campo
        # `result` con lenguaje de "límite"/"cuota" producen categoría alguna.
        by_stderr = self._error(
            returncode=1, stderr="429 rate limit exceeded: usage limit reached, quota"
        )
        by_stdout = self._error(returncode=1, stdout="HTTP 429 Too Many Requests")
        by_result = self._error(
            returncode=1,
            stdout=self._payload(result="You have hit your usage limit (429)"),
        )
        for exc in (by_stderr, by_stdout, by_result):
            self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)

    # ---- G/H. exit 0 con error NO es éxito y se clasifica igual ----

    def test_exit_zero_with_is_error_true_is_classified(self) -> None:
        plain = self._error(
            returncode=0,
            stdout=json.dumps({"type": "result", "subtype": "success", "is_error": True}),
        )
        self.assertIs(plain.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(plain.details["exit_code"], 0)
        self.assertIs(plain.details["is_error"], True)
        # Mensaje existente conservado.
        self.assertIn("developer reported is_error=True", str(plain))

        limited = self._error(
            returncode=0,
            stdout=json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": True,
                    "api_error_status": 429,
                }
            ),
        )
        self.assertIs(limited.category, ClaudeFailureCategory.CLAUDE_TEMPORARY_LIMIT)
        self.assertEqual(limited.details["exit_code"], 0)

    def test_exit_zero_with_non_success_subtype_is_classified(self) -> None:
        max_turns = self._error(
            returncode=0,
            stdout=self._payload(subtype="error_max_turns", is_error=False),
        )
        self.assertIs(max_turns.category, ClaudeFailureCategory.CLAUDE_MAX_TURNS)
        self.assertEqual(max_turns.details["exit_code"], 0)
        self.assertEqual(max_turns.details["subtype"], "error_max_turns")
        self.assertIn("'subtype' is missing or is not 'success'", str(max_turns))

        denied = self._error(
            returncode=0,
            stdout=self._payload(
                subtype="failure", is_error=False, permission_denials=[{"tool_name": "Edit"}]
            ),
        )
        self.assertIs(denied.category, ClaudeFailureCategory.CLAUDE_PERMISSION_DENIED)
        self.assertEqual(denied.details["permission_denial_count"], 1)

        generic = self._error(
            returncode=0,
            stdout=json.dumps(_valid_generic_result_payload(subtype="failure")),
        )
        self.assertIs(generic.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(generic.details["subtype"], "failure")

    def test_exit_zero_invalid_or_non_object_json_keeps_message_and_is_general(self) -> None:
        invalid = self._error(returncode=0, stdout="not json at all")
        self.assertEqual(str(invalid), "developer output is not valid JSON")
        self.assertIs(invalid.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(invalid.details, {"exit_code": 0})

        non_object = self._error(returncode=0, stdout="[1, 2, 3]")
        self.assertEqual(str(non_object), "developer JSON output is not a JSON object")
        self.assertEqual(non_object.details, {"exit_code": 0})

    # ---- CORRECTION-001: un is_error NO booleano nunca se reproduce ----

    _INVALID_IS_ERROR_MESSAGE = "developer returned invalid is_error field"

    def test_non_boolean_is_error_value_is_never_exposed(self) -> None:
        sentinel = "SENSITIVE_ARBITRARY_SENTINEL"
        for bogus in (sentinel, [sentinel], {"k": sentinel}, 1, 0.5, None):
            for returncode in (0, 1):
                with self.subTest(is_error=type(bogus).__name__, returncode=returncode):
                    payload = json.dumps(
                        {"type": "result", "subtype": "success", "is_error": bogus}
                    )
                    exc = self._error(returncode=returncode, stdout=payload)
                    self.assertNotIn(sentinel, str(exc))
                    self.assertNotIn(sentinel, repr(exc))
                    self.assertNotIn(sentinel, json.dumps(exc.details))
                    self.assertNotIn("is_error", exc.details)
                    self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
                    if returncode == 0:
                        # Diagnóstico CONSTANTE, no derivado del valor.
                        self.assertEqual(str(exc), self._INVALID_IS_ERROR_MESSAGE)
                    # is_error solo aparece en details si es booleano.
                    self.assertEqual(
                        exc.details["json_top_level_keys"], ["is_error", "subtype", "type"]
                    )

    def test_missing_is_error_uses_the_same_constant_message(self) -> None:
        exc = self._error(
            returncode=0, stdout=json.dumps({"type": "result", "subtype": "success"})
        )
        self.assertEqual(str(exc), self._INVALID_IS_ERROR_MESSAGE)
        self.assertNotIn("is_error", exc.details)

    def test_boolean_is_error_true_keeps_its_fixed_message_and_detail(self) -> None:
        exc = self._error(
            returncode=0,
            stdout=json.dumps({"type": "result", "subtype": "success", "is_error": True}),
        )
        self.assertEqual(str(exc), "developer reported is_error=True")
        self.assertIs(exc.details["is_error"], True)

    def test_non_boolean_is_error_is_not_exposed_by_handshake_or_write_probe(self) -> None:
        sentinel = "SENSITIVE_ARBITRARY_SENTINEL"
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ):
            handshake_payload = _valid_result_payload(is_error=sentinel)
            with mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run",
                return_value=_completed(returncode=0, stdout=json.dumps(handshake_payload)),
            ):
                with self.assertRaises(DeveloperExecutionError) as handshake:
                    run_handshake(
                        developer_config=_valid_developer_config(),
                        prompt=HANDSHAKE_PROMPT,
                        cwd=self.cwd,
                        authorized_root=self.cwd,
                    )

            prepare_sandbox_files(self.cwd)
            probe_payload = _valid_write_result_payload(is_error=sentinel)
            with mock.patch(
                "orchestrator.adapters.claude_code.subprocess.run",
                return_value=_completed(returncode=0, stdout=json.dumps(probe_payload)),
            ):
                with self.assertRaises(DeveloperExecutionError) as write_probe:
                    run_write_probe(
                        developer_config=_valid_write_probe_developer_config(),
                        cwd=self.cwd,
                        authorized_root=self.cwd,
                    )
        for caught in (handshake, write_probe):
            self.assertEqual(str(caught.exception), self._INVALID_IS_ERROR_MESSAGE)
            self.assertNotIn(sentinel, str(caught.exception))

    # ---- CORRECTION-001: success + permission_denials NO es fallo ----

    def test_success_with_permission_denials_stays_success_and_exposes_nothing(self) -> None:
        # subtype "success" + is_error false + permission_denials no vacío: una
        # acción intermedia denegada no invalida por sí sola un resultado final
        # estructurado como éxito. CLAUDE_PERMISSION_DENIED solo clasifica una
        # ejecución que ya está en camino de fallo.
        payload = _valid_generic_result_payload(
            permission_denials=[
                {"tool_name": "Bash", "tool_input": {"command": "FICTITIOUS_DENIED_CMD"}}
            ]
        )
        completed = _completed(returncode=0, stdout=json.dumps(payload))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            result = run_developer_task(
                developer_config=_valid_task_execution_developer_config(),
                prompt="x",
                cwd=self.cwd,
                authorized_root=self.cwd,
            )
        self.assertTrue(result.success)
        self.assertFalse(result.is_error)
        # Ningún campo del resultado transporta las denegaciones.
        self.assertNotIn("FICTITIOUS_DENIED_CMD", repr(result))
        self.assertFalse(any("denial" in name for name in vars(result)))

    def test_permission_denials_still_classify_a_failing_run(self) -> None:
        # Contraste: la MISMA lista en una ejecución que ya falla sí clasifica.
        payload = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": True,
                "permission_denials": [{"tool_input": "FICTITIOUS_DENIED_CMD"}],
            }
        )
        exc = self._error(returncode=0, stdout=payload)
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_PERMISSION_DENIED)
        self.assertEqual(exc.details["permission_denial_count"], 1)
        self.assertNotIn("FICTITIOUS_DENIED_CMD", str(exc))
        self.assertNotIn("FICTITIOUS_DENIED_CMD", json.dumps(exc.details))

    def test_exit_zero_success_still_returns_success(self) -> None:
        completed = _completed(returncode=0, stdout=json.dumps(_valid_generic_result_payload()))
        with mock.patch(
            "orchestrator.adapters.claude_code.shutil.which", return_value="/resolved/claude"
        ), mock.patch(
            "orchestrator.adapters.claude_code.subprocess.run", return_value=completed
        ):
            result = run_developer_task(
                developer_config=_valid_task_execution_developer_config(),
                prompt="x",
                cwd=self.cwd,
                authorized_root=self.cwd,
            )
        self.assertTrue(result.success)

    # ---- I. precedencia: permission > max_turns > 429 > general ----

    def test_precedence_permission_over_max_turns_over_429_over_general(self) -> None:
        denials = [{"tool_name": "Bash"}]
        cases = [
            (
                {
                    "permission_denials": denials,
                    "subtype": "error_max_turns",
                    "api_error_status": 429,
                },
                ClaudeFailureCategory.CLAUDE_PERMISSION_DENIED,
            ),
            (
                {"permission_denials": denials, "api_error_status": 429},
                ClaudeFailureCategory.CLAUDE_PERMISSION_DENIED,
            ),
            (
                {"subtype": "error_max_turns", "api_error_status": 429},
                ClaudeFailureCategory.CLAUDE_MAX_TURNS,
            ),
            ({"api_error_status": 429}, ClaudeFailureCategory.CLAUDE_TEMPORARY_LIMIT),
            ({}, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR),
        ]
        for fields, expected in cases:
            for returncode in (1, 0):
                with self.subTest(fields=sorted(fields), returncode=returncode):
                    exc = self._error(returncode=returncode, stdout=self._payload(**fields))
                    self.assertIs(exc.category, expected)

    # ---- validación estricta de forma: nada raro se transporta ----

    def test_only_strictly_valid_field_shapes_are_carried(self) -> None:
        # "429" (str), 429.0 (float) y True (bool) NO son api_error_status == 429.
        for bogus in ("429", 429.0, True):
            with self.subTest(api_error_status=bogus):
                exc = self._error(stdout=self._payload(api_error_status=bogus))
                self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
                self.assertNotIn("api_error_status", exc.details)

        # Un subtype con caracteres fuera del patrón seguro (p. ej. salto de
        # línea final) no clasifica ni se transporta.
        exc = self._error(stdout=self._payload(subtype="error_max_turns\n"))
        self.assertIs(exc.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertNotIn("subtype", exc.details)

        exc = self._error(
            stdout=self._payload(stop_reason="free text with spaces", is_error="yes")
        )
        self.assertNotIn("stop_reason", exc.details)
        self.assertNotIn("is_error", exc.details)

    def test_json_top_level_keys_are_sorted_names_only_and_bounded(self) -> None:
        exc = self._error(stdout=self._payload(zeta=1, alpha=2, **{"bad key!": 3}))
        keys = exc.details["json_top_level_keys"]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(
            keys, ["alpha", "is_error", "subtype", "type", "zeta"]
        )  # "bad key!" descartada

        many = {f"k{i:03d}": i for i in range(200)}
        exc = self._error(stdout=json.dumps(many))
        self.assertEqual(len(exc.details["json_top_level_keys"]), 64)

    # ---- fuga de datos: solo nombres de clave, jamás valores ----

    def test_details_never_contain_sensitive_values(self) -> None:
        payload = {
            "type": "result",
            "subtype": "error_during_execution",
            "is_error": True,
            "api_error_status": 429,
            "stop_reason": "end_turn",
            "permission_denials": [{"tool_input": "SENTINEL_DENIAL"}],
            "result": "SENTINEL_RESULT",
            "session_id": "SENTINEL_SESSION",
            "usage": {"input_tokens": "SENTINEL_USAGE"},
            "modelUsage": {"model": "SENTINEL_MODELUSAGE"},
        }
        exc = self._error(
            returncode=1, stdout=json.dumps(payload), stderr="SENTINEL_STDERR"
        )
        serialized = json.dumps(exc.details) + exc.category.value
        for sentinel in (
            "SENTINEL_DENIAL",
            "SENTINEL_RESULT",
            "SENTINEL_SESSION",
            "SENTINEL_USAGE",
            "SENTINEL_MODELUSAGE",
            "SENTINEL_STDERR",
        ):
            self.assertNotIn(sentinel, serialized)
        # El mensaje textual (que llega al resultado público) tampoco filtra
        # stdout, denegaciones, session_id, usage ni modelUsage.
        for sentinel in (
            "SENTINEL_DENIAL",
            "SENTINEL_RESULT",
            "SENTINEL_SESSION",
            "SENTINEL_USAGE",
            "SENTINEL_MODELUSAGE",
        ):
            self.assertNotIn(sentinel, str(exc))
        # Los NOMBRES de clave sí se conservan; sus valores nunca.
        self.assertEqual(
            exc.details["json_top_level_keys"],
            sorted(payload),
        )
        self.assertLessEqual(set(exc.details), self.ALLOWED_DETAIL_KEYS)

    # ---- compatibilidad de la excepción ----

    def test_error_stays_catchable_with_safe_defaults(self) -> None:
        plain = DeveloperExecutionError("some message")
        self.assertEqual(str(plain), "some message")
        self.assertIs(plain.category, ClaudeFailureCategory.CLAUDE_EXECUTION_ERROR)
        self.assertEqual(plain.details, {})
        self.assertIsInstance(plain, Exception)

        by_name = DeveloperExecutionError("m", category="CLAUDE_TIMEOUT")
        self.assertIs(by_name.category, ClaudeFailureCategory.CLAUDE_TIMEOUT)
        with self.assertRaises(ValueError):
            DeveloperExecutionError("m", category="CLAUDE_AUTH_ERROR")  # no existe (aún)

    def test_category_set_is_exactly_the_authorized_one(self) -> None:
        self.assertEqual(
            {c.value for c in ClaudeFailureCategory},
            {
                "CLAUDE_TEMPORARY_LIMIT",
                "CLAUDE_MAX_TURNS",
                "CLAUDE_TIMEOUT",
                "CLAUDE_PERMISSION_DENIED",
                "CLAUDE_EXECUTABLE_MISSING",
                "CLAUDE_EXECUTION_ERROR",
            },
        )


if __name__ == "__main__":
    unittest.main()
