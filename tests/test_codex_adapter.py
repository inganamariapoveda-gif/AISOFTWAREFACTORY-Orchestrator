"""Codex foundation tests: subprocess is always mocked; no provider calls."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
from orchestrator.adapters import codex_cli


def codex_agent(enabled=True):
    agent = yaml.safe_load((REPO_ROOT / "config/AGENTS.yaml").read_text(encoding="utf-8"))["agents"]["codex_builder"]
    agent = copy.deepcopy(agent)
    agent["enabled"] = enabled
    return agent


def jsonl(*events):
    return "\n".join(json.dumps(event) for event in events)


SUCCESS_OUTPUT = jsonl(
    {"type": "thread.started", "thread_id": "PRIVATE_SESSION_MARKER"},
    {"type": "turn.started"},
    {"type": "item.completed", "item": {"id": "1", "type": "agent_message", "text": "PRIVATE_MODEL_MARKER"}},
    {"type": "turn.completed", "usage": {"input_tokens": 10}},
)


class CodexAdapterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.config = codex_agent()

    def call(self, output=SUCCESS_OUTPUT, code=0, error=None, **overrides):
        values = dict(repository_root=self.root, authorized_root=self.root,
                      instruction="BOUNDED_INSTRUCTION_MARKER", execution_config=self.config)
        values.update(overrides)
        with mock.patch.object(codex_cli.shutil, "which", return_value="/resolved/codex"), mock.patch.object(
            codex_cli.subprocess, "run", side_effect=error,
            return_value=subprocess.CompletedProcess([], code, output, "PRIVATE_STDERR_MARKER"),
        ) as process:
            result = codex_cli.run_codex_task(**values)
        return result, process

    def test_secure_invocation_and_sanitized_success(self):
        result, process = self.call()
        self.assertTrue(result.completed)
        self.assertEqual(result.failure_category, codex_cli.CodexFailureCategory.SUCCESS)
        self.assertEqual((result.provider, result.adapter), ("openai_codex", "codex_cli"))
        args = process.call_args.args[0]
        self.assertIsInstance(args, list)
        self.assertEqual(args[:4], ["/resolved/codex", "-a", "never", "exec"])
        self.assertEqual(args[args.index("-C") + 1], str(self.root))
        self.assertEqual(args[args.index("--sandbox") + 1], "workspace-write")
        for flag in ("--json", "--ephemeral", "--ignore-user-config"):
            self.assertIn(flag, args)
        for setting in ("sandbox_workspace_write.network_access=false", "sandbox_workspace_write.writable_roots=[]",
                        "sandbox_workspace_write.exclude_slash_tmp=true", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                        "tools.web_search=false"):
            self.assertIn(setting, args)
        self.assertEqual(args[-1], "-")
        self.assertNotIn("BOUNDED_INSTRUCTION_MARKER", str(args))
        kwargs = process.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["cwd"], self.root)
        self.assertEqual(kwargs["input"], "BOUNDED_INSTRUCTION_MARKER")
        self.assertEqual(kwargs["timeout"], 600)
        self.assertIsInstance(kwargs["env"], dict)
        self.assertIsNot(kwargs["env"], codex_cli.os.environ)
        self.assertNotIn("PRIVATE_", str(asdict(result)))
        self.assertNotIn("resume", args)
        self.assertNotIn("--last", args)
        self.assertNotIn("--add-dir", args)
        process.assert_called_once()

    def test_child_environment_allowlist_and_no_secret_disclosure(self):
        safe = {"Path": "C:/runtime", "PathExt": ".EXE", "SystemRoot": "C:/Windows",
                "USERPROFILE": "C:/Users/test", "HOME": "C:/Users/test",
                "CODEX_HOME": "C:/unread-auth-location", "TEMP": "C:/temp", "TMP": "C:/temp"}
        secrets = {"AISOFTWAREFACTORY_SLACK_WEBHOOK_URL": "PRIVATE_SLACK_WEBHOOK",
                   "OPENAI_API_KEY": "PRIVATE_OPENAI_KEY", "ANTHROPIC_API_KEY": "PRIVATE_ANTHROPIC_KEY",
                   "DATABASE_URL": "PRIVATE_DATABASE_URL", "RANDOM_APPLICATION_SECRET": "PRIVATE_RANDOM_SECRET",
                   "github_token": "PRIVATE_GITHUB_TOKEN"}
        parent = dict(safe, **secrets, COMSPEC="unused", APPDATA="unused")
        for error in (None, OSError("PRIVATE_RANDOM_SECRET"),
                      subprocess.TimeoutExpired("PRIVATE_OPENAI_KEY", 600)):
            with self.subTest(error=type(error).__name__), mock.patch.object(codex_cli.os, "environ", parent), \
                    mock.patch.object(Path, "read_text", side_effect=AssertionError("no auth reads")):
                result, process = self.call(error=error)
            child = process.call_args.kwargs["env"]
            self.assertEqual(child, safe)
            self.assertIsNot(child, parent)
            self.assertEqual(parent, dict(safe, **secrets, COMSPEC="unused", APPDATA="unused"))
            self.assertEqual(process.call_args.kwargs["input"], "BOUNDED_INSTRUCTION_MARKER")
            public = str((process.call_args.args, process.call_args.kwargs["input"],
                          asdict(result), codex_cli.CodexExecutionError(result)))
            for value in secrets.values():
                self.assertNotIn(value, public)
            process.assert_called_once()

    def test_missing_optional_environment_is_not_manufactured(self):
        with mock.patch.object(codex_cli.os, "environ", {"SystemRoot": "C:/Windows"}):
            result, process = self.call()
        self.assertTrue(result.completed)
        self.assertEqual(process.call_args.kwargs["env"], {"SystemRoot": "C:/Windows"})

    def test_missing_windows_context_never_launches_or_inherits(self):
        for parent in ({}, {"SystemRoot": ""}, {"SYSTEMROOT": "C:/Windows", "Path": "a", "PATH": "b"}):
            with mock.patch.object(codex_cli.os, "environ", parent), mock.patch.object(codex_cli.os, "name", "nt"):
                result, process = self.call()
            self.assertEqual(result.failure_category.value, "PROCESS_FAILURE")
            process.assert_not_called()

    def test_invalid_and_incomplete_streams_fail_closed(self):
        streams = ["", "garbage", "[]", jsonl({"type": "turn.started"}),
                   jsonl({"type": "turn.completed"}), SUCCESS_OUTPUT + "\n{",
                   SUCCESS_OUTPUT + '\n{"type":"turn.failed"}',
                   jsonl({"type": "turn.started"}, {"type": "turn.completed"}, {"type": "turn.completed"}),
                   jsonl({"type": "turn.started"}, {"type": "item.started", "item": {"id": "1"}}, {"type": "turn.completed"}),
                   jsonl({"type": "turn.started"}, {"type": "unrecognized"})]
        for stream in streams:
            with self.subTest(stream=stream):
                result, _ = self.call(output=stream)
                self.assertFalse(result.completed)
                self.assertEqual(result.failure_category.value, "MALFORMED_OUTPUT")

    def test_failed_terminal_is_unknown_not_capacity_or_auth(self):
        result, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": "turn.failed", "error": {"message": "rate limit auth"}}))
        self.assertEqual(result.failure_category.value, "UNKNOWN")
        self.assertNotIn("rate limit", str(result))

    def test_ambiguous_json_keys_and_non_json_constants_rejected(self):
        for terminal in ('{"type":"turn.failed","type":"turn.completed"}',
                         '{"type":"turn.completed","usage":NaN}'):
            result, _ = self.call(output='{"type":"turn.started"}\n' + terminal)
            self.assertEqual(result.failure_category.value, "MALFORMED_OUTPUT")

    def test_nonzero_exit_is_process_failure_even_with_success_json(self):
        result, _ = self.call(code=1)
        self.assertEqual(result.failure_category.value, "PROCESS_FAILURE")
        self.assertFalse(result.completed)

    def test_timeout_is_sanitized_and_not_retried(self):
        result, process = self.call(error=subprocess.TimeoutExpired("PRIVATE_COMMAND", 600, output="PRIVATE_OUTPUT", stderr="PRIVATE_ERROR"))
        self.assertEqual(result.failure_category.value, "TIMEOUT")
        self.assertNotIn("PRIVATE", str(result))
        process.assert_called_once()

    def test_executable_launch_failure(self):
        result, _ = self.call(error=FileNotFoundError("PRIVATE_PATH"))
        self.assertEqual(result.failure_category.value, "EXECUTABLE_UNAVAILABLE")

    def test_unresolvable_executable_never_launches(self):
        with mock.patch.object(codex_cli.shutil, "which", return_value=None), mock.patch.object(codex_cli.subprocess, "run") as process:
            result = codex_cli.run_codex_task(repository_root=self.root, authorized_root=self.root,
                                            instruction="bounded", execution_config=self.config)
        self.assertEqual(result.failure_category.value, "EXECUTABLE_UNAVAILABLE")
        process.assert_not_called()

    def test_wrong_root_or_disabled_never_launches(self):
        result, process = self.call(authorized_root=self.root.parent)
        self.assertFalse(result.completed)
        process.assert_not_called()
        self.config["enabled"] = False
        result, process = self.call()
        self.assertFalse(result.completed)
        process.assert_not_called()

    def test_unsafe_configuration_never_launches(self):
        self.config["task_execution"]["network_access"] = True
        result, process = self.call()
        self.assertFalse(result.completed)
        process.assert_not_called()

    def test_completed_item_sequence(self):
        result, _ = self.call(output=jsonl({"type": "turn.started"},
            {"type": "item.started", "item": {"id": "1", "type": "command_execution"}},
            {"type": "item.completed", "item": {"id": "1", "type": "command_execution"}},
            {"type": "turn.completed"}))
        self.assertTrue(result.completed)

    def test_decode_and_os_errors_are_sanitized(self):
        for error, expected in ((UnicodeError("PRIVATE"), "MALFORMED_OUTPUT"), (OSError("PRIVATE"), "PROCESS_FAILURE")):
            result, _ = self.call(error=error)
            self.assertEqual(result.failure_category.value, expected)
            self.assertNotIn("PRIVATE", str(result))
