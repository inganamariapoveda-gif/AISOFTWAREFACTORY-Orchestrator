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
    def test_strict_schema_diagnostics_are_unique_private_and_non_authoritative(self):
        expected = (codex_cli.CommandExpectation(codex_cli.command_fingerprint("PRIVATE_EXACT")),)
        for fields, present, string, matched in (({}, 0, 0, False),
                ({"command": None}, 1, 0, False), ({"command": ["PRIVATE_ARGV"]}, 1, 0, False),
                ({"command": "PRIVATE_OUTER_COMMAND"}, 1, 1, False),
                ({"command": "PRIVATE_EXACT"}, 1, 1, True)):
            with self.subTest(present=present, string=string, matched=matched):
                item = dict(id="PRIVATE_DIAGNOSTIC_ID", type="command_execution", **fields)
                output = jsonl({"type": "turn.started"}, *(
                    {"type": kind, "item": item} for kind in ("item.started", "item.updated", "item.completed")),
                    {"type": "turn.completed"})
                actual, _ = self.call(output=output, expected_commands=expected)
                self.assertEqual(actual.command_execution_count, 1)
                self.assertEqual(actual.command_field_present_count, present)
                self.assertEqual(actual.command_field_string_count, string)
                self.assertEqual(actual.lifecycle_command_consistent_count, string)
                self.assertEqual(actual.command_attestations[0].observed, matched)
                self.assertEqual(actual.unexpected_command_execution_count, int(bool(string and not matched)))
                public = repr(asdict(actual))
                for private in ("PRIVATE_EXACT", "PRIVATE_OUTER_COMMAND", "PRIVATE_ARGV", "PRIVATE_DIAGNOSTIC_ID"):
                    self.assertNotIn(private, public)
                neutral, _ = self.call(output=output)
                self.assertEqual(neutral.command_field_present_count, 0)
                self.assertEqual(neutral.command_field_string_count, 0)
                self.assertEqual(neutral.lifecycle_command_consistent_count, 0)

    def test_schema_diagnostics_conflict_and_missing_event_still_fail_closed(self):
        expected = (codex_cli.CommandExpectation(codex_cli.command_fingerprint("EXACT")),)
        first = dict(id="PRIVATE_ID", type="command_execution", command="EXACT")
        for last in (dict(first, command="CHANGED"), dict(id="PRIVATE_ID", type="command_execution")):
            actual, _ = self.call(output=jsonl({"type": "turn.started"},
                {"type": "item.started", "item": first}, {"type": "item.completed", "item": last},
                {"type": "turn.completed"}), expected_commands=expected)
            self.assertEqual(actual.command_field_present_count, 1)
            self.assertEqual(actual.command_field_string_count, 1)
            self.assertEqual(actual.lifecycle_command_consistent_count, 0)
            self.assertFalse(actual.command_attestations[0].consistent)
            self.assertEqual(actual.command_payload_conflict_count, int("command" in last))
            self.assertEqual(actual.malformed_command_attestation_count, int("command" not in last))

    def test_strict_command_attestation_matrix(self):
        commands = ("OUTSIDE_EXACT", "NETWORK_EXACT", "DESCENDANT_EXACT")
        expectations = tuple(codex_cli.CommandExpectation(codex_cli.command_fingerprint(value)) for value in commands)
        def item(identity, command, kind="command_execution"):
            return {"id": identity, "type": kind, "command": command}
        def stream(items):
            return jsonl({"type": "turn.started"}, *items, {"type": "turn.completed"})
        events = []
        for index, command in enumerate(commands):
            payload = item(f"PRIVATE_ITEM_ID_{index}", command)
            events.extend({"type": kind, "item": payload} for kind in ("item.started", "item.updated", "item.completed"))
        result, _ = self.call(output=stream(events), expected_commands=expectations)
        self.assertEqual(result.command_execution_count, 3)
        self.assertTrue(all(value.observed and value.started and value.completed and value.consistent and not value.duplicate
                            for value in result.command_attestations))
        self.assertEqual(result.unexpected_command_execution_count, 0)
        public = repr(asdict(result))
        self.assertNotIn("PRIVATE_ITEM_ID_", public)
        for value in commands:
            self.assertNotIn(value, public)
            self.assertNotIn(codex_cli.command_fingerprint(value).hex(), public)
            self.assertNotIn(repr(codex_cli.command_fingerprint(value)), public)
        for extra, field in ((item("extra", "UNEXPECTED"), "unexpected_command_execution_count"),
                             (item("file", "unused", "file_change"), "file_change_item_count"),
                             (item("tool", "unused", "mcp_tool_call"), "unexpected_action_item_count")):
            actual, _ = self.call(output=stream(events + [{"type": "item.completed", "item": extra}]), expected_commands=expectations)
            self.assertEqual(getattr(actual, field), 1)
        duplicate = item("different-id", commands[0])
        actual, _ = self.call(output=stream(events + [{"type": "item.started", "item": duplicate},
            {"type": "item.completed", "item": duplicate}]), expected_commands=expectations)
        self.assertTrue(actual.command_attestations[0].duplicate)
        self.assertFalse(actual.command_attestations[0].consistent)

    def test_strict_missing_nonstring_and_lifecycle(self):
        expected = (codex_cli.CommandExpectation(codex_cli.command_fingerprint("EXACT")),)
        for value in (None, [], 5):
            payload = {"id": "PRIVATE_ID", "type": "command_execution", "command": value}
            actual, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": "item.completed", "item": payload},
                {"type": "turn.completed"}), expected_commands=expected)
            self.assertEqual(actual.malformed_command_attestation_count, 1)
            self.assertFalse(actual.command_attestations[0].consistent)
        payload = {"id": "PRIVATE_ID", "type": "command_execution", "command": "EXACT"}
        for kind in ("item.started", "item.completed"):
            actual, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": kind, "item": payload},
                {"type": "turn.completed"}), expected_commands=expected)
            self.assertFalse(actual.command_attestations and all(v.started and v.completed for v in actual.command_attestations))
        missing = {"id": "PRIVATE_ID", "type": "command_execution"}
        actual, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": "item.completed", "item": missing},
            {"type": "turn.completed"}), expected_commands=expected)
        self.assertEqual(actual.malformed_command_attestation_count, 1)

    def test_strict_payload_conflict_and_exact_representation(self):
        expected = (codex_cli.CommandExpectation(codex_cli.command_fingerprint("EXACT")),)
        first = {"id": "PRIVATE_ID", "type": "command_execution", "command": "EXACT"}
        for changed in ("EXACT ", "exact", "prefix EXACT suffix"):
            last = dict(first, command=changed)
            actual, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": "item.started", "item": first},
                {"type": "item.completed", "item": last}, {"type": "turn.completed"}), expected_commands=expected)
            self.assertEqual(actual.command_payload_conflict_count, 1)
            self.assertFalse(actual.command_attestations[0].consistent)
        failed_command = dict(first, status="failed", exit_code=1)
        actual, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": "item.started", "item": first},
            {"type": "item.completed", "item": failed_command}, {"type": "turn.completed"}), expected_commands=expected)
        self.assertTrue(actual.command_attestations[0].completed)
        self.assertFalse(hasattr(actual.command_attestations[0], "succeeded"))

    def test_strict_default_neutral_invalid_expectations_and_malformed_stream(self):
        actual, _ = self.call()
        self.assertEqual(actual.command_attestations, ())
        expected = codex_cli.CommandExpectation(codex_cli.command_fingerprint("PRIVATE_COMMAND"))
        for expectations in ((expected, expected), (codex_cli.CommandExpectation(b"bad"),)):
            actual, process = self.call(expected_commands=expectations)
            process.assert_not_called()
        actual, _ = self.call(output="not-json", expected_commands=(expected,))
        self.assertEqual(actual.failure_category.value, "MALFORMED_OUTPUT")
        self.assertEqual(actual.command_attestations, ())

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

    def test_turn_only_and_message_have_no_action_evidence(self):
        for events in ([], [{"type": "item.completed", "item": {"id": "m", "type": "agent_message", "text": "PRIVATE_SECRET"}}]):
            result, _ = self.call(output=jsonl({"type": "turn.started"}, *events, {"type": "turn.completed"}))
            self.assertTrue(result.completed)
            self.assertFalse(result.action_evidence_observed)
            self.assertEqual(result.event_count, 2 + len(events))

    def test_action_counts_are_unique_and_sanitized(self):
        command = {"id": "PRIVATE_ID", "type": "command_execution", "command": "PRIVATE_COMMAND", "aggregated_output": "PRIVATE_SECRET"}
        file_item = {"id": "PRIVATE_FILE_ID", "type": "file_change", "changes": [{"path": "PRIVATE_PATH"}]}
        stream = jsonl({"type": "turn.started"}, {"type": "item.started", "item": command},
            {"type": "item.updated", "item": command}, {"type": "item.completed", "item": command},
            {"type": "item.completed", "item": file_item}, {"type": "turn.completed"})
        result, _ = self.call(output=stream)
        self.assertTrue(result.completed)
        self.assertTrue(result.action_evidence_observed)
        self.assertEqual((result.event_count, result.item_started_count, result.item_completed_count,
                          result.command_execution_count, result.file_change_item_count), (6, 1, 2, 1, 1))
        self.assertNotIn("PRIVATE", str(asdict(result)))

    def test_malformed_action_and_failure_after_action(self):
        for item in ({"type": "command_execution"}, {"id": "", "type": "command_execution"}, {"id": "a", "type": []}):
            result, _ = self.call(output=jsonl({"type": "turn.started"}, {"type": "item.completed", "item": item}, {"type": "turn.completed"}))
            self.assertEqual(result.failure_category.value, "MALFORMED_OUTPUT")
        stream = jsonl({"type": "turn.started"}, {"type": "item.completed", "item": {"id": "a", "type": "command_execution"}}, {"type": "turn.failed"})
        result, _ = self.call(output=stream)
        self.assertFalse(result.completed)
        self.assertTrue(result.action_evidence_observed)
        result, _ = self.call(output=stream, code=1)
        self.assertEqual(result.failure_category.value, "PROCESS_FAILURE")

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
