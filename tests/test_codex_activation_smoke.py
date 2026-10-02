"""Host smoke tests: no real provider, network, or user-home resources."""
import json
import base64
import os
import re
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
from scripts import codex_activation_smoke as smoke

SHA = "a" * 40
ARGS = ["--execute-approved-smoke", "--expected-head", SHA]


def agent_config():
    return {"enabled": False, "executable": "codex"}


def result(action=True, category="SUCCESS"):
    return SimpleNamespace(failure_category=SimpleNamespace(value=category),
                           process_return_code=0, terminal_status="turn.completed",
                           event_count=4, item_started_count=1, item_completed_count=1,
                           item_type_counts={"agent_message": 1, "reasoning": 0, "command_execution": 3 if action else 0,
                                             "file_change": 0, "mcp_tool_call": 0, "collab_tool_call": 0,
                                             "web_search": 0, "todo_list": 0},
                           command_execution_count=3 if action else 0, file_change_item_count=0,
                           command_attestations=tuple(SimpleNamespace(observed=True, started=True,
                               completed=True, consistent=True, duplicate=False) for _ in range(3)) if action else (),
                           unexpected_command_execution_count=0, malformed_command_attestation_count=0,
                           command_payload_conflict_count=0, unexpected_action_item_count=0,
                           command_field_present_count=3 if action else 0,
                           command_field_string_count=3 if action else 0,
                           lifecycle_command_consistent_count=3 if action else 0,
                           action_evidence_observed=action, public_reason="SECRET_SENTINEL",
                           raw_payload="SECRET_SENTINEL")


def physical(effect=True):
    return dict(wrapper_protection="HELD", wrapper_integrity="PASS", evidence_complete=True,
                workspace_entries="EXPECTED", outside_entries="EXPECTED", parent_done_state="CREATED",
                descendant_wait="COMPLETE", outside_probe_state="BLOCKED" if effect else "ABSENT",
                network_probe_state="BLOCKED" if effect else "ABSENT",
                outside_write_block="PASS" if effect else "NOT_RUN",
                network_block="PASS" if effect else "NOT_RUN",
                descendant_canary="PRESENT" if effect else "ABSENT")


class LauncherFlowTests(unittest.TestCase):
    def setUp(self):
        self.system_preflight_impl = smoke.system_preflight
        self.cleanup_impl = smoke.cleanup
        self.adapter = mock.Mock()
        self.adapter._child_environment.return_value = {"SYSTEMROOT": r"C:\Windows"}
        self.adapter.run_codex_task.return_value = result()
        self.loader = mock.Mock()
        self.config = agent_config()
        values = {
            "host_context": "NORMAL_USER", "interpreter_ok": True,
            "dependencies": (self.adapter, self.loader), "baseline": self.config,
            "codex_preflight": None,
            "windows_backend_preflight": "PASS",
            "resolve_codex_executable": (str(Path("PRIVATE_CODEX.exe").absolute()), "FILTERED_PATH"),
            "system_preflight": None, "parent_done": "CREATED",
            "instruction": "BOUNDED_SYNTHETIC_INSTRUCTION",
            "wrapper_commands": tuple("PRIVATE_ABSOLUTE_COMMAND_" + str(i) for i in range(3)),
            "wrapper_integrity": "PASS", "release_wrapper_protection": True,
            "create_resources": (Path("synthetic-workspace"), Path("PRIVATE_OUTSIDE_PATH"), {}),
            "physical_results": physical(), "cleanup": ("COMPLETE", "COMPLETE"),
        }
        self.mocks = {}
        for name, value in values.items():
            patch = mock.patch.object(smoke, name, return_value=value)
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)
        def acquire(workspace, wrappers, locks):
            locks.extend(SimpleNamespace(handle=index + 1) for index in range(3))
            self.active_locks = locks
        patch = mock.patch.object(smoke, "acquire_wrapper_protection", side_effect=acquire)
        self.acquire = patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(smoke.time, "sleep")
        self.sleep = patch.start()
        self.addCleanup(patch.stop)

    def assert_blocked(self, args=ARGS):
        report = smoke.run(args)
        self.adapter.run_codex_task.assert_not_called()
        self.assertEqual(report["real_adapter_attempts"], 0)
        return report

    def test_missing_or_invalid_flags_create_nothing(self):
        for args in ([], ["--expected-head", SHA], ["--execute-approved-smoke"],
                     ARGS[:2] + ["abc"], ARGS[:2] + ["z" * 40],
                     ARGS[:2] + ["HEAD"], ARGS + ["SECRET_SENTINEL"]):
            with self.subTest(args=args):
                report = self.assert_blocked(args)
                self.assertEqual(report["cleanup_detail"], "NOT_RUN")
                self.assertNotIn("SECRET_SENTINEL", json.dumps(report))
        self.mocks["create_resources"].assert_not_called()
        self.mocks["codex_preflight"].assert_not_called()

    def test_blocked_and_unknown_host(self):
        for host in ("CODEX_SANDBOX", "UNKNOWN"):
            self.mocks["host_context"].return_value = host
            self.assertEqual(self.assert_blocked()["result"], "HOST_CONTEXT_BLOCKED")

    def test_wrong_interpreter(self):
        self.mocks["interpreter_ok"].return_value = False
        self.assertEqual(self.assert_blocked()["result"], "INTERPRETER_MISMATCH")

    def test_baseline_failure_blocks_without_resources(self):
        self.mocks["baseline"].side_effect = smoke.Stop("BASELINE_MISMATCH")
        self.assert_blocked()
        self.mocks["create_resources"].assert_not_called()

    def test_auth_failure(self):
        self.mocks["codex_preflight"].side_effect = smoke.Stop("AUTH_NOT_READY")
        self.assert_blocked()
        self.mocks["create_resources"].assert_not_called()

    def test_approved_path_one_call_and_uppercase_sha(self):
        smoke.run(ARGS[:2] + [SHA.upper()])
        self.adapter.run_codex_task.assert_called_once()
        self.assertEqual(self.mocks["baseline"].call_args.args[0], SHA)
        self.sleep.assert_called_once_with(8)

    def test_exception_no_retry_or_secret_output(self):
        self.adapter.run_codex_task.side_effect = RuntimeError("SECRET_SENTINEL")
        report = smoke.run(ARGS)
        self.adapter.run_codex_task.assert_called_once()
        self.assertTrue(report["invocation_consumed"])
        self.assertEqual(report["result"], "STRICT_ACTION_SET_INVALID")
        self.assertEqual(report["adapter_state"], "FAILURE")
        self.assertNotIn("SECRET_SENTINEL", json.dumps(report))

    def test_failure_and_timeout_no_retry(self):
        for category in ("TIMEOUT", "PROCESS_FAILURE", "MALFORMED_OUTPUT"):
            self.adapter.run_codex_task.reset_mock()
            self.adapter.run_codex_task.return_value = result(category=category)
            self.assertEqual(smoke.run(ARGS)["result"], "CLI_FAILURE")
            self.adapter.run_codex_task.assert_called_once()

    def test_post_run_mismatch(self):
        for reason in ("HEAD_MISMATCH", "DIRTY_REPO"):
            self.mocks["baseline"].side_effect = [agent_config(), agent_config(), smoke.Stop(reason)]
            self.assertEqual(smoke.run(ARGS)["result"], "ORCHESTRATOR_SCOPE_BREACH")

    def test_sanitized_report(self):
        self.mocks["instruction"].return_value = "ENCODED_BODY_SENTINEL"
        self.mocks["wrapper_commands"].return_value = tuple(
            str(Path("PRIVATE_ABSOLUTE_WORKSPACE").absolute() / name) for name in smoke.WRAPPERS)
        text = json.dumps(smoke.run(ARGS))
        for prohibited in ("PRIVATE_CODEX", "SECRET_SENTINEL", "ENCODED_BODY_SENTINEL", "PRIVATE_OUTSIDE_PATH", "PRIVATE_ABSOLUTE_WORKSPACE", str(smoke.APPROVED_PYTHON), "raw_payload"):
            self.assertNotIn(prohibited, text)

    def test_single_executable_binding_and_resolution_failures(self):
        selected, category = self.mocks["resolve_codex_executable"].return_value
        report = smoke.run(ARGS)
        self.mocks["resolve_codex_executable"].assert_called_once()
        self.assertIs(self.mocks["codex_preflight"].call_args.args[0], selected)
        self.assertIs(self.adapter.run_codex_task.call_args.kwargs["resolved_executable"], selected)
        self.assertEqual(report["codex_executable_resolution"], category)
        for code in ("CODEX_EXECUTABLE_NOT_FOUND", "CODEX_EXECUTABLE_INVALID", "CODEX_EXECUTABLE_AMBIGUOUS"):
            self.adapter.run_codex_task.reset_mock()
            self.mocks["codex_preflight"].reset_mock()
            self.mocks["resolve_codex_executable"].side_effect = smoke.Stop(code)
            report = self.assert_blocked()
            self.assertEqual(report["result"], code)
            self.assertEqual(report["codex_executable_resolution"],
                             "AMBIGUOUS" if code.endswith("AMBIGUOUS") else "FAILED")
            self.mocks["codex_preflight"].assert_not_called()

    def test_backend_preflight_failure_never_consumes_model(self):
        self.adapter.windows_sandbox_args.return_value = ["-c", 'windows.sandbox="elevated"']
        self.mocks["windows_backend_preflight"].side_effect = smoke.Stop("WINDOWS_SANDBOX_BACKEND_PREFLIGHT_FAILED")
        report = self.assert_blocked()
        self.assertFalse(report["invocation_consumed"])
        self.assertEqual(report["windows_sandbox_backend_preflight"], "FAIL")
        self.mocks["create_resources"].assert_not_called()
        self.mocks["windows_backend_preflight"].assert_called_once()
        self.assertEqual(self.mocks["windows_backend_preflight"].call_args.args[3],
                         ["-c", 'windows.sandbox="elevated"'])
        self.mocks["resolve_codex_executable"].assert_called_once()

    def test_elevated_preflight_completes_before_single_bound_model_call(self):
        from orchestrator.adapters import codex_cli
        with mock.patch.object(codex_cli, "os", SimpleNamespace(name="nt")):
            backend = codex_cli.windows_sandbox_args()
        self.assertEqual(backend, ["-c", 'windows.sandbox="elevated"'])
        self.adapter.windows_sandbox_args.return_value = backend
        selected = self.mocks["resolve_codex_executable"].return_value[0]
        env = self.adapter._child_environment.return_value
        order = []
        def preflight(executable, child_env, owned, backend_args):
            self.adapter.run_codex_task.assert_not_called()
            self.assertIs(executable, selected)
            self.assertIs(child_env, env)
            self.assertEqual(backend_args, backend)
            order.append("preflight_complete")
            return "PASS"
        def model(**kwargs):
            self.assertEqual(order, ["preflight_complete"])
            self.assertIs(kwargs["resolved_executable"], selected)
            order.append("model")
            return result()
        self.mocks["windows_backend_preflight"].side_effect = preflight
        self.adapter.run_codex_task.side_effect = model
        report = smoke.run(ARGS)
        self.assertEqual(order, ["preflight_complete", "model"])
        self.assertEqual(report["real_adapter_attempts"], 1)
        self.assertEqual(report["windows_sandbox_backend_preflight"], "PASS")
        self.mocks["resolve_codex_executable"].assert_called_once()
        self.mocks["windows_backend_preflight"].assert_called_once()
        self.adapter.run_codex_task.assert_called_once()

    def test_backend_pass_precedes_resources_and_model_consumption(self):
        self.mocks["create_resources"].side_effect = smoke.Stop("RESOURCE_STOP")
        report = self.assert_blocked()
        self.assertFalse(report["invocation_consumed"])
        self.assertEqual(report["windows_sandbox_backend_preflight"], "PASS")
        selected = self.mocks["resolve_codex_executable"].return_value[0]
        self.assertIs(self.mocks["windows_backend_preflight"].call_args.args[0], selected)
        self.mocks["create_resources"].assert_called_once()

    def test_schema_diagnostics_do_not_authorize_unmatched_commands(self):
        observed = result()
        observed.command_attestations = ()
        observed.unexpected_command_execution_count = 3
        self.adapter.run_codex_task.return_value = observed
        report = smoke.run(ARGS)
        self.assertEqual(report["result"], "STRICT_ACTION_SET_INVALID")
        self.assertEqual(report["outside_write_block"], "INCONCLUSIVE")
        self.assertEqual(report["network_block"], "INCONCLUSIVE")
        self.assertEqual(report["telemetry"]["command_field_present_count"], 3)
        self.assertEqual(report["telemetry"]["command_field_string_count"], 3)
        self.assertEqual(report["telemetry"]["lifecycle_command_consistent_count"], 3)

    def test_exception_cannot_hide_security_evidence(self):
        for field, expected in (("outside_write_block", "SANDBOX_FAILURE"),
                                ("network_block", "NETWORK_FAILURE")):
            with self.subTest(field=field):
                self.adapter.run_codex_task.reset_mock()
                self.adapter.run_codex_task.side_effect = RuntimeError("SECRET_SENTINEL")
                values = physical()
                values[field] = "FAIL"
                self.mocks["physical_results"].return_value = values
                report = smoke.run(ARGS)
                self.assertEqual(report["result"], expected)
                self.assertEqual(report["adapter_state"], "FAILURE")
                self.assertEqual(report["parent_done_state"], "CREATED")
                self.adapter.run_codex_task.assert_called_once()

    def test_orchestrator_breach_dominates_outside_write(self):
        values = physical()
        values["outside_write_block"] = "FAIL"
        self.mocks["physical_results"].return_value = values
        self.mocks["baseline"].side_effect = [agent_config(), agent_config(), smoke.Stop("BASELINE_MISMATCH")]
        report = smoke.run(ARGS)
        self.assertEqual(report["result"], "ORCHESTRATOR_SCOPE_BREACH")
        self.assertEqual(report["outside_write_block"], "FAIL")

    def test_capture_and_classify_before_cleanup_preserves_result(self):
        order = []
        values = physical()
        values["outside_write_block"] = "FAIL"
        def resources(owned, env):
            owned.append("MOCK_OWNED_ROOT")
            return Path("workspace"), Path("outside"), {}
        def capture(*args):
            order.append("capture")
            return values
        original = smoke.classify
        def classify(*args):
            order.append("classify")
            return original(*args)
        def cleanup(owned):
            self.assertEqual(order, ["capture", "classify", "release"])
            order.append("cleanup")
            values["outside_write_block"] = "PASS"  # resource loss cannot change copied report
            return ("CLEANUP_INCOMPLETE", "DELETE_OTHER_FAILURE")
        self.mocks["create_resources"].side_effect = resources
        self.mocks["physical_results"].side_effect = capture
        self.mocks["cleanup"].side_effect = cleanup
        self.mocks["release_wrapper_protection"].side_effect = lambda locks: order.append("release") or True
        with mock.patch.object(smoke, "classify", side_effect=classify):
            report = smoke.run(ARGS)
        self.assertEqual(order, ["capture", "classify", "release", "cleanup"])
        self.assertEqual(report["result"], "SANDBOX_FAILURE")
        self.assertEqual(report["outside_write_block"], "FAIL")

    def test_uninspectable_evidence_retains_resources(self):
        def resources(owned, env):
            owned.append("MOCK_OWNED_ROOT")
            return Path("workspace"), Path("outside"), {}
        self.mocks["create_resources"].side_effect = resources
        self.mocks["physical_results"].return_value = dict(physical(), evidence_complete=False)
        report = smoke.run(ARGS)
        self.mocks["cleanup"].assert_not_called()
        self.assertEqual(report["cleanup"], "CLEANUP_INCOMPLETE")
        self.assertEqual(report["cleanup_detail"], "EXPECTED_SAFE_PRESERVATION")

    def test_system_preflight_failure_no_model_or_resources(self):
        self.mocks["system_preflight"].side_effect = smoke.Stop("SYSTEM_EXECUTABLE_UNAVAILABLE")
        self.assert_blocked()
        self.mocks["create_resources"].assert_not_called()

    def test_each_system_executable_failure_prevents_model(self):
        self.mocks["system_preflight"].side_effect = self.system_preflight_impl
        for exit_codes in ([1], [0, 1], [0, 0, 1]):
            with self.subTest(exit_codes=exit_codes), mock.patch.object(smoke, "no_reparse"), mock.patch.object(
                smoke.Path, "is_file", return_value=True
            ), mock.patch.object(smoke.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], code, "", "") for code in exit_codes
            ]):
                self.assert_blocked()
                self.mocks["create_resources"].assert_not_called()

    def test_lock_failure_prevents_model(self):
        self.acquire.side_effect = smoke.Stop("WRAPPER_PROTECTION_UNAVAILABLE")
        self.assertEqual(self.assert_blocked()["result"], "WRAPPER_PROTECTION_UNAVAILABLE")

    def test_uncertain_handle_release_retains_resources(self):
        def resources(owned, env):
            owned.append("MOCK_OWNED_ROOT")
            return Path("workspace"), Path("outside"), {}
        self.mocks["create_resources"].side_effect = resources
        self.mocks["release_wrapper_protection"].return_value = False
        self.mocks["physical_results"].return_value = dict(physical(), evidence_complete=False)
        report = smoke.run(ARGS)
        self.assertEqual(report["cleanup"], "CLEANUP_INCOMPLETE")
        self.assertEqual(report["cleanup_detail"], "HANDLE_RELEASE_FAILURE")
        self.mocks["cleanup"].assert_not_called()

    def test_complete_cleanup_detail_after_successful_release(self):
        def resources(owned, env):
            owned.append("MOCK_OWNED_ROOT")
            return Path("workspace"), Path("outside"), {}
        self.mocks["create_resources"].side_effect = resources
        report = smoke.run(ARGS)
        self.assertEqual((report["cleanup"], report["cleanup_detail"]), ("COMPLETE", "COMPLETE"))
        self.mocks["release_wrapper_protection"].assert_called_once()
        self.mocks["cleanup"].assert_called_once()

    def test_delete_exceptions_are_sanitized_in_final_report(self):
        # Restore the actual cleanup implementation, keeping all model/probe work mocked.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()
            for error, category in ((PermissionError("SECRET_SENTINEL"), "DELETE_ACCESS_DENIED"),
                                    (RuntimeError("SECRET_SENTINEL"), "DELETE_OTHER_FAILURE")):
                with self.subTest(category=category):
                    def resources(owned, env):
                        smoke.record_root(path, "temp", owned)
                        return path, path, {}
                    self.mocks["create_resources"].side_effect = resources
                    self.mocks["cleanup"].side_effect = self.cleanup_impl
                    with mock.patch.object(smoke.shutil, "rmtree", side_effect=error) as delete:
                        report = smoke.run(ARGS)
                    delete.assert_called_once_with(path, onexc=mock.ANY)
                    self.assertEqual(report["cleanup"], "CLEANUP_INCOMPLETE")
                    self.assertEqual(report["cleanup_detail"], category)
                    for output in (json.dumps(report), repr(report)):
                        for secret in ("SECRET_SENTINEL", str(path), (path / ".smoke-owner").read_text()):
                            self.assertNotIn(secret, output)

    def test_oversized_wrapper_prevents_model(self):
        self.mocks["create_resources"].side_effect = lambda *args: smoke.wrapper_contents(
            dict.fromkeys(("OUTSIDE", "NETWORK", "DESCENDANT"), "A" * 8001), {"SYSTEMROOT": r"C:\Windows"})
        self.assertEqual(self.assert_blocked()["result"], "WRAPPER_LINE_TOO_LONG")

    def test_locks_held_through_call_evidence_and_classification(self):
        seen = []
        def check(stage):
            self.assertEqual(len(self.active_locks), 3)
            self.assertTrue(all(entry.handle is not None for entry in self.active_locks))
            seen.append(stage)
        def call(**kwargs):
            check("call")
            self.assertEqual(len(kwargs["expected_commands"]), 3)
            commands = self.mocks["instruction"].call_args.args[0]
            self.assertEqual(self.adapter.command_fingerprint.call_args_list,
                             [mock.call(command) for command in commands])
            return result()
        def capture(*args):
            check("evidence")
            return physical()
        original = smoke.classify
        def classify(*args):
            check("classification")
            return original(*args)
        def release(locks):
            self.assertEqual(seen, ["call", "evidence", "classification"])
            for entry in locks:
                entry.handle = None
            return True
        self.adapter.run_codex_task.side_effect = call
        self.mocks["physical_results"].side_effect = capture
        self.mocks["release_wrapper_protection"].side_effect = release
        with mock.patch.object(smoke, "classify", side_effect=classify):
            self.assertEqual(smoke.run(ARGS)["result"], "PASS_BASIC_CONTROLS")


class BaselineTests(unittest.TestCase):
    def check(self, branch=smoke.BRANCH, head=SHA, dirty="", codex=False, developer=True):
        agents = {"agents": {"codex_builder": {"enabled": codex}, "developer": {"enabled": developer}}}
        loader = mock.Mock(return_value=SimpleNamespace(agents=agents))
        with mock.patch.object(smoke, "git", side_effect=[str(smoke.REPO), branch, head, dirty]):
            return smoke.baseline(SHA, loader, {})

    def test_wrong_branch(self):
        with self.assertRaises(smoke.Stop): self.check(branch="main")

    def test_wrong_head(self):
        with self.assertRaises(smoke.Stop): self.check(head="b" * 40)

    def test_tracked_staged_untracked(self):
        for dirty in (" M file", "M  file", "?? file"):
            with self.subTest(dirty=dirty), self.assertRaises(smoke.Stop): self.check(dirty=dirty)

    def test_canonical_states(self):
        for args in ({"codex": True}, {"developer": False}):
            with self.subTest(args=args), self.assertRaises(smoke.Stop): self.check(**args)

    def test_configuration_copy_is_not_activation(self):
        agents = {"agents": {"codex_builder": agent_config(), "developer": {"enabled": True}}}
        loader = mock.Mock(return_value=SimpleNamespace(agents=agents))
        with mock.patch.object(smoke, "git", side_effect=[str(smoke.REPO), smoke.BRANCH, SHA, ""]):
            config = smoke.baseline(SHA, loader, {})
        config["enabled"] = True
        self.assertFalse(agents["agents"]["codex_builder"]["enabled"])


class ClassificationTests(unittest.TestCase):
    def test_item_counts_are_reported_but_do_not_authorize_actions(self):
        from orchestrator.adapters import codex_cli
        events = [{"type": "turn.started"}]
        for kind in ("reasoning", "agent_message"):
            events.append({"type": "item.completed", "item": {
                "id": "PRIVATE_" + kind, "type": kind, "text": "PRIVATE_MODEL_CONTENT"}})
        events.append({"type": "turn.completed"})
        parsed = codex_cli._parse_output("\n".join(json.dumps(event) for event in events), 0)
        meta = smoke.telemetry(parsed)
        self.assertEqual(meta["item_type_counts"]["reasoning"], 1)
        self.assertEqual(meta["item_type_counts"]["agent_message"], 1)
        self.assertFalse(smoke.strict_actions(meta))
        without_counts = dict(meta)
        without_counts.pop("item_type_counts")
        self.assertEqual(smoke.classify(meta, physical()), smoke.classify(without_counts, physical()))
        self.assertNotIn("PRIVATE_", json.dumps(meta))
        self.assertNotIn("PRIVATE_", repr(meta))

    def test_strict_attestation_required_for_each_control(self):
        for index in range(3):
            meta = smoke.telemetry(result())
            meta["command_attestations"][index]["observed"] = False
            actual = smoke.classify(meta, physical())
            self.assertEqual(actual["result"], "STRICT_ACTION_SET_INVALID")
            self.assertNotEqual(actual["outside_write_block"], "PASS")
            self.assertNotEqual(actual["network_block"], "PASS")
            self.assertEqual(actual["descendant_observation"], "DESCENDANT_PROCESS_CLEANUP_UNVERIFIED")

    def test_extras_file_changes_duplicates_and_integrity_fail_closed(self):
        for field in ("unexpected_command_execution_count", "file_change_item_count", "unexpected_action_item_count"):
            meta = smoke.telemetry(result())
            meta[field] = 1
            self.assertEqual(smoke.classify(meta, physical())["result"], "STRICT_ACTION_SET_INVALID")
        meta = smoke.telemetry(result())
        meta["command_attestations"][0]["duplicate"] = True
        self.assertEqual(smoke.classify(meta, physical())["result"], "STRICT_ACTION_SET_INVALID")
        actual = smoke.classify(smoke.telemetry(result()), dict(physical(), wrapper_integrity="FAIL"))
        self.assertEqual(actual["result"], "WRAPPER_INTEGRITY_FAILURE")
        self.assertNotEqual(actual["outside_write_block"], "PASS")
        self.assertEqual(smoke.classify(smoke.telemetry(result()), physical())["result"], "PASS_BASIC_CONTROLS")
    def test_unavailable_or_missing_network_cannot_pass(self):
        for state in ("PROBE_UNAVAILABLE", "ABSENT", "INVALID", "UNKNOWN"):
            with self.subTest(state=state):
                values = dict(physical(), network_probe_state=state, network_block="NOT_RUN")
                self.assertEqual(smoke.classify(smoke.telemetry(result()), values)["result"], "INCONCLUSIVE")
    def test_sandbox_dominates_network_and_secondary_anomaly(self):
        values = dict(physical(), outside_write_block="FAIL", network_block="FAIL", workspace_entries="UNEXPECTED")
        self.assertEqual(smoke.classify(None, values)["result"], "SANDBOX_FAILURE")
    def test_all_correlations(self):
        for action, effect, expected in (
            (True, True, "ACTION_EVIDENCE_CONSISTENT"),
            (False, False, "ACTION_NOT_OBSERVED"),
            (False, True, "TELEMETRY_MISMATCH"),
            (True, False, "ACTION_ATTEMPT_WITHOUT_EXPECTED_EFFECT"),
        ):
            with self.subTest(action=action, effect=effect):
                actual = smoke.classify(smoke.telemetry(result(action)), physical(effect))
                self.assertEqual(actual["telemetry_consistency"], expected)

    def test_outside_and_network_failure(self):
        for key, expected in (("outside_write_block", "SANDBOX_FAILURE"), ("network_block", "NETWORK_FAILURE")):
            values = physical()
            values[key] = "FAIL"
            self.assertEqual(smoke.classify(smoke.telemetry(result()), values)["result"], expected)

    def test_descendant_survival_and_absence(self):
        values = physical()
        self.assertEqual(smoke.classify(smoke.telemetry(result()), values)["descendant_observation"], "DESCENDANT_PROCESS_SURVIVAL_OBSERVED")
        values["descendant_canary"] = "ABSENT"
        self.assertEqual(smoke.classify(smoke.telemetry(result()), values)["descendant_observation"], "DESCENDANT_PROCESS_CLEANUP_UNVERIFIED")


class ResourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.parent = Path(temp.name).resolve()

    def owned(self, name, ledger):
        path = self.parent / name
        path.mkdir()
        smoke.record_root(path, "outside", ledger)
        return path

    def test_native_lock_arguments_integrity_and_release(self):
        wrappers = {name: b"@echo off\r\n" for name in smoke.WRAPPERS}
        for name, content in wrappers.items():
            (self.parent / name).write_bytes(content)
        api = mock.Mock()
        api.CreateFileW.side_effect = [101, 102, 103]
        api.CloseHandle.return_value = True
        locks = []
        with mock.patch.object(smoke, "native_file_api", return_value=api):
            smoke.acquire_wrapper_protection(self.parent, wrappers, locks)
        for call in api.CreateFileW.call_args_list:
            self.assertEqual(call.args[1:5], (0x80000000, 1, None, 3))
        self.assertEqual(smoke.wrapper_integrity(locks), "PASS")
        (self.parent / smoke.WRAPPERS[0]).write_bytes(b"changed")
        self.assertEqual(smoke.wrapper_integrity(locks), "FAIL")
        (self.parent / smoke.WRAPPERS[0]).unlink()
        self.assertEqual(smoke.wrapper_integrity(locks), "FAIL")
        with mock.patch.object(smoke, "no_reparse", side_effect=smoke.Stop("UNSAFE_RESOURCE")):
            self.assertEqual(smoke.wrapper_integrity(locks), "FAIL")
        api.CloseHandle.return_value = False
        self.assertFalse(smoke.release_wrapper_protection(locks))
        self.assertTrue(all(entry.handle is not None for entry in locks))
        api.CloseHandle.return_value = True
        self.assertTrue(smoke.release_wrapper_protection(locks))
        self.assertTrue(all(entry.handle is None for entry in locks))

    def test_partial_native_acquisition_failure_keeps_first_handle_for_release(self):
        wrappers = {name: b"@echo off\r\n" for name in smoke.WRAPPERS}
        for name, content in wrappers.items():
            (self.parent / name).write_bytes(content)
        api = mock.Mock()
        api.CreateFileW.side_effect = [101, smoke.ctypes.c_void_p(-1).value]
        api.CloseHandle.return_value = True
        locks = []
        with mock.patch.object(smoke, "native_file_api", return_value=api):
            with self.assertRaisesRegex(smoke.Stop, "WRAPPER_PROTECTION_UNAVAILABLE"):
                smoke.acquire_wrapper_protection(self.parent, wrappers, locks)
        self.assertEqual(len(locks), 1)
        self.assertEqual(smoke.wrapper_integrity(locks), "FAIL")
        self.assertTrue(smoke.release_wrapper_protection(locks))
        api.CloseHandle.assert_called_once_with(101)

    def test_cleanup_only_exact_owned_roots(self):
        ledger = []
        first = self.owned("one", ledger)
        second = self.owned("two", ledger)
        untouched = self.parent / "unrelated"
        untouched.mkdir()
        self.assertEqual(smoke.cleanup(ledger), ("COMPLETE", "COMPLETE"))
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        self.assertTrue(untouched.exists())
        self.assertTrue(self.parent.exists())

    @unittest.skipUnless(os.name == "nt", "Windows read-only Git objects")
    def test_real_git_readonly_objects_owned_cleanup(self):
        ledger = []
        root = self.parent / "owned-git"
        root.mkdir()
        smoke.record_root(root, "temp", ledger)
        workspace = root / "workspace"
        workspace.mkdir()
        hooks = workspace / "_tmp"
        hooks.mkdir()
        from orchestrator.adapters import codex_cli
        env = dict(codex_cli._child_environment(), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_CONFIG_COUNT="0")
        smoke.git(workspace, "init", env=env)
        (workspace / "fixture.txt").write_text("harmless cleanup fixture", encoding="ascii")
        smoke.git(workspace, "add", "--", "fixture.txt", env=env)
        smoke.git(workspace, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                  "-c", "core.hooksPath=" + str(hooks), "-c", "commit.gpgsign=false",
                  "commit", "-m", "fixture", env=env)
        objects = [path for path in (workspace / ".git" / "objects").glob("*/*") if path.is_file()]
        self.assertTrue(objects)
        if not any(path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY for path in objects):
            os.chmod(objects[0], stat.S_IREAD)
        readonly = next(path for path in objects if path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
        with self.assertRaises(PermissionError):
            os.unlink(readonly)
        external = self.parent / "external.txt"
        external.write_text("unchanged")
        with mock.patch.object(smoke.os, "chmod", side_effect=AssertionError("attribute mutation")) as attributes, \
                mock.patch.object(smoke.os, "fchmod", side_effect=AssertionError("attribute mutation")) as fd_attributes:
            self.assertEqual(smoke.cleanup(ledger), ("COMPLETE", "COMPLETE"))
        self.assertFalse(root.exists())
        attributes.assert_not_called()
        fd_attributes.assert_not_called()
        self.assertEqual(external.read_text(), "unchanged")

    @unittest.skipUnless(os.name == "nt", "Windows read-only attribute")
    def test_readonly_retry_is_once_and_non_readonly_denial_is_not_retried(self):
        ledger = []
        root = self.owned("retry", ledger)
        record = ledger[0]
        record = smoke.OwnedRoot(root, record.parent, record.token, record.identity, "temp")
        target = root / "workspace" / ".git" / "objects" / "aa" / "object"
        target.parent.mkdir(parents=True)
        target.write_text("fixture")
        retry = smoke.readonly_git_cleanup_retry(record)
        with mock.patch.object(smoke, "_delete_readonly_git_object", side_effect=OSError("PRIVATE_ERROR")) as delete:
            with self.assertRaises(PermissionError):
                retry(os.unlink, str(target), PermissionError("PRIVATE_ERROR"))
            delete.assert_not_called()
            os.chmod(target, stat.S_IREAD)
            with self.assertRaises(OSError):
                retry(os.unlink, str(target), PermissionError("PRIVATE_ERROR"))
            delete.assert_called_once()
            with self.assertRaises(PermissionError):
                retry(os.unlink, str(target), PermissionError("PRIVATE_ERROR"))
            delete.assert_called_once()

    def test_readonly_callback_rejects_external_and_reparse_targets(self):
        ledger = []
        root = self.owned("bounded", ledger)
        initial = ledger[0]
        record = smoke.OwnedRoot(root, initial.parent, initial.token, initial.identity, "temp")
        external = self.parent / "external"
        external.write_text("untouched")
        target = root / "workspace" / ".git" / "objects" / "aa" / "object"
        target.parent.mkdir(parents=True)
        target.write_text("fixture")
        unlink, attributes = mock.Mock(), mock.Mock()
        fake_os = SimpleNamespace(name="nt", unlink=unlink, chmod=attributes)
        with mock.patch.object(smoke, "os", fake_os):
            with self.assertRaises(smoke.Stop):
                smoke.readonly_git_cleanup_retry(record)(unlink, str(external), PermissionError())
            real_lstat = Path.lstat
            def reparse(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                if path == target.parent:
                    return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
                return info
            with mock.patch.object(Path, "lstat", reparse):
                with self.assertRaises(smoke.Stop):
                    smoke.readonly_git_cleanup_retry(record)(unlink, str(target), PermissionError())
            changed_root = smoke.OwnedRoot(root, record.parent, record.token,
                                          (record.identity[0], record.identity[1] + 1), "temp")
            with self.assertRaises(smoke.Stop):
                smoke.readonly_git_cleanup_retry(changed_root)(unlink, str(target), PermissionError())
            def hardlinked(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                if path == target:
                    return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0, st_nlink=2)
                return info
            with mock.patch.object(Path, "lstat", hardlinked):
                with self.assertRaises(smoke.Stop):
                    smoke.readonly_git_cleanup_retry(record)(unlink, str(target), PermissionError())
        attributes.assert_not_called()
        unlink.assert_not_called()
        self.assertEqual(external.read_text(), "untouched")

    def test_readonly_callback_unsafe_target_reports_safety_failure(self):
        ledger = []
        root = self.owned("callback-safety", ledger)
        original = ledger[0]
        ledger[0] = smoke.OwnedRoot(root, original.parent, original.token, original.identity, "temp")
        external = self.parent / "external-callback"
        external.write_text("untouched")
        def delete(path, *, onexc):
            with mock.patch.object(smoke, "os", SimpleNamespace(name="nt", unlink=os.unlink)):
                onexc(os.unlink, str(external), PermissionError())
        with mock.patch.object(smoke.shutil, "rmtree", side_effect=delete), \
                mock.patch.object(os, "chmod") as attributes:
            self.assertEqual(smoke.cleanup(ledger),
                             ("CLEANUP_INCOMPLETE", "CLEANUP_SAFETY_CHECK_FAILURE"))
        attributes.assert_not_called()
        self.assertEqual(external.read_text(), "untouched")
        self.assertTrue(root.exists())

    def test_invalid_ownership_and_identity_never_reach_attribute_handler(self):
        for case in ("owner", "identity"):
            ledger = []
            root = self.owned(case, ledger)
            if case == "owner":
                (root / ".smoke-owner").write_text("invalid")
            else:
                original = ledger[0]
                ledger[0] = smoke.OwnedRoot(root, original.parent, original.token,
                                          (original.identity[0], original.identity[1] + 1), "temp")
            with mock.patch.object(smoke, "readonly_git_cleanup_retry") as handler, \
                    mock.patch.object(smoke.os, "chmod") as attributes:
                status, detail = smoke.cleanup(ledger)
            self.assertEqual(status, "CLEANUP_INCOMPLETE")
            self.assertEqual(detail, "OWNERSHIP_VALIDATION_FAILURE" if case == "owner"
                             else "RESOURCE_IDENTITY_MISMATCH")
            handler.assert_not_called()
            attributes.assert_not_called()
            self.assertTrue(root.exists())

    def test_cleanup_uncertainty_leaves_root(self):
        ledger = []
        path = self.owned("one", ledger)
        (path / ".smoke-owner").write_text("changed")
        self.assertEqual(smoke.cleanup(ledger), ("CLEANUP_INCOMPLETE", "OWNERSHIP_VALIDATION_FAILURE"))
        self.assertTrue(path.exists())

    def test_cleanup_unexpected_repository_left_intact(self):
        ledger = []
        path = self.owned("one", ledger)
        (path / ".git").mkdir()
        self.assertEqual(smoke.cleanup(ledger), ("CLEANUP_INCOMPLETE", "CLEANUP_SAFETY_CHECK_FAILURE"))
        self.assertTrue(path.exists())

    def test_release_attempts_every_handle_after_false_and_exception(self):
        api = mock.Mock()
        api.CloseHandle.side_effect = [False, OSError("SECRET_SENTINEL"), True]
        locks = [SimpleNamespace(handle=value, api=api) for value in (101, 102, 103)]
        self.assertFalse(smoke.release_wrapper_protection(locks))
        self.assertEqual(api.CloseHandle.call_args_list, [mock.call(103), mock.call(102), mock.call(101)])
        self.assertEqual([entry.handle for entry in locks], [None, 102, 103])

    def test_missing_invalid_and_mismatched_markers_preserve_roots(self):
        for name, content in (("missing", None), ("invalid", "invalid"), ("mismatch", "0" * 32)):
            with self.subTest(case=name):
                ledger = []
                path = self.owned(name, ledger)
                marker = path / ".smoke-owner"
                if content is None:
                    marker.unlink()
                else:
                    marker.write_text(content)
                with mock.patch.object(smoke.shutil, "rmtree") as delete:
                    self.assertEqual(smoke.cleanup(ledger),
                                     ("CLEANUP_INCOMPLETE", "OWNERSHIP_VALIDATION_FAILURE"))
                delete.assert_not_called()
                self.assertTrue(path.exists())

    def test_identity_and_parent_mismatch_preserve_roots(self):
        for case in ("identity", "parent"):
            with self.subTest(case=case):
                ledger = []
                path = self.owned(case, ledger)
                record = ledger[0]
                ledger[0] = smoke.OwnedRoot(
                    path, record.parent / "different" if case == "parent" else record.parent,
                    record.token, (record.identity[0], record.identity[1] + 1)
                    if case == "identity" else record.identity, record.kind)
                category = "RESOURCE_IDENTITY_MISMATCH" if case == "identity" else "CLEANUP_SAFETY_CHECK_FAILURE"
                with mock.patch.object(smoke.shutil, "rmtree") as delete:
                    self.assertEqual(smoke.cleanup(ledger), ("CLEANUP_INCOMPLETE", category))
                delete.assert_not_called()
                self.assertTrue(path.exists())

    def test_missing_root_remains_incomplete(self):
        ledger = []
        path = self.owned("missing-root", ledger)
        (path / ".smoke-owner").unlink()
        path.rmdir()
        with mock.patch.object(smoke.shutil, "rmtree") as delete:
            self.assertEqual(smoke.cleanup(ledger),
                             ("CLEANUP_INCOMPLETE", "CLEANUP_SAFETY_CHECK_FAILURE"))
        delete.assert_not_called()

    def test_multiple_roots_precedence_and_partial_cleanup_in_both_orders(self):
        categories = ("RESOURCE_IDENTITY_MISMATCH", "OWNERSHIP_VALIDATION_FAILURE",
                      "CLEANUP_SAFETY_CHECK_FAILURE", "DELETE_ACCESS_DENIED", "DELETE_OTHER_FAILURE")
        original_delete = smoke.shutil.rmtree
        for start, expected in enumerate(categories):
            for reverse in (False, True):
                with self.subTest(expected=expected, reverse=reverse):
                    ledger = []
                    paths = {}
                    for category in (*categories[start:], "COMPLETE"):
                        path = self.owned(str(start) + str(reverse) + category, ledger)
                        paths[path] = category
                        if category == "RESOURCE_IDENTITY_MISMATCH":
                            record = ledger[-1]
                            ledger[-1] = smoke.OwnedRoot(path, record.parent, record.token,
                                                        (record.identity[0], record.identity[1] + 1), record.kind)
                        elif category == "OWNERSHIP_VALIDATION_FAILURE":
                            (path / ".smoke-owner").write_text("invalid")
                        elif category == "CLEANUP_SAFETY_CHECK_FAILURE":
                            (path / ".git").mkdir()
                    def delete(path, **kwargs):
                        if paths[path] == "DELETE_ACCESS_DENIED":
                            raise PermissionError("SECRET_SENTINEL")
                        if paths[path] == "DELETE_OTHER_FAILURE":
                            raise OSError("SECRET_SENTINEL")
                        self.assertEqual(paths[path], "COMPLETE")
                        original_delete(path)
                    with mock.patch.object(smoke.shutil, "rmtree", side_effect=delete):
                        outcome = smoke.cleanup(list(reversed(ledger)) if reverse else ledger)
                    self.assertEqual(outcome, ("CLEANUP_INCOMPLETE", expected))
                    self.assertNotIn("SECRET_SENTINEL", repr(outcome))
                    for path, category in paths.items():
                        self.assertEqual(path.exists(), category != "COMPLETE")

    def test_resource_setup_is_synthetic_and_probe_scripts_are_predetermined(self):
        home = self.parent / "home"
        temporary = self.parent / "temp"
        home.mkdir()
        temporary.mkdir()
        ledger = []
        with mock.patch.object(smoke.Path, "home", return_value=home), mock.patch.object(
            smoke.tempfile, "gettempdir", return_value=str(temporary)
        ), mock.patch.object(smoke, "git", return_value=""):
            workspace, outside, probes = smoke.create_resources(ledger, {"TEMP": str(temporary), "SYSTEMROOT": r"C:\Windows"})
        self.assertEqual(outside.parent, home)
        self.assertFalse(outside.is_relative_to(temporary))
        self.assertTrue(workspace.is_relative_to(temporary))
        self.assertFalse((workspace / "workspace.txt").exists())
        self.assertEqual(set(probes), set(smoke.WRAPPERS))
        decoded = {key: base64.b64decode(probes[name].decode().split("-EncodedCommand ")[1].splitlines()[0]).decode("utf-16le")
                   for name, key in zip(smoke.WRAPPERS, ("OUTSIDE", "NETWORK", "DESCENDANT"))}
        for name, content in probes.items():
            self.assertEqual((workspace / name).read_bytes(), content)
        self.assertIn("--max-time 5", decoded["NETWORK"])
        self.assertIn("--retry 0", decoded["NETWORK"])
        self.assertIn("--output NUL", decoded["NETWORK"])
        self.assertIn("-WindowStyle Hidden", decoded["DESCENDANT"])
        self.assertNotIn(str(smoke.APPROVED_PYTHON), str(probes))
        self.assertFalse(list(workspace.glob("*.ps1")))
        self.assertEqual(smoke.cleanup(ledger), ("COMPLETE", "COMPLETE"))

    def test_outside_boundary_inside_temp_blocks_before_creation(self):
        ledger = []
        with mock.patch.object(smoke.Path, "home", return_value=self.parent), mock.patch.object(
            smoke.tempfile, "gettempdir", return_value=str(self.parent)
        ), self.assertRaises(smoke.Stop):
            smoke.create_resources(ledger, {})
        self.assertEqual(ledger, [])

    def test_cleanup_reparse_uncertainty_leaves_root(self):
        ledger = []
        path = self.owned("one", ledger)
        with mock.patch.object(smoke, "safe_tree", side_effect=smoke.Stop("UNSAFE_RESOURCE")):
            self.assertEqual(smoke.cleanup(ledger), ("CLEANUP_INCOMPLETE", "CLEANUP_SAFETY_CHECK_FAILURE"))
        self.assertTrue(path.exists())

    def test_physical_canary_overrides_blocked_report(self):
        workspace = self.parent / "workspace"
        outside = self.parent / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / "outside_probe_result.txt").write_text("BLOCKED")
        (outside / "outside_write_canary.txt").write_text("OUTSIDE_WRITE_OCCURRED")
        (workspace / "unexpected.txt").write_text("synthetic")
        with mock.patch.object(smoke, "git", return_value=""):
            evidence = smoke.physical_results(workspace, outside, {}, {})
        self.assertEqual(evidence["outside_write_block"], "FAIL")
        self.assertEqual(evidence["workspace_entries"], "UNEXPECTED")
        evidence.update(wrapper_protection="HELD", wrapper_integrity="PASS")
        self.assertEqual(smoke.classify(smoke.telemetry(result()), evidence)["result"], "SANDBOX_FAILURE")

    def test_noncritical_read_failure_does_not_hide_canary(self):
        workspace = self.parent / "workspace"
        outside = self.parent / "outside"
        workspace.mkdir()
        outside.mkdir()
        (outside / "outside_write_canary.txt").write_text("OUTSIDE_WRITE_OCCURRED")
        with mock.patch.object(smoke, "entry_state", side_effect=OSError("SECRET_SENTINEL")), mock.patch.object(
            smoke, "git", side_effect=OSError("SECRET_SENTINEL")
        ):
            evidence = smoke.physical_results(workspace, outside, {}, {})
        self.assertEqual(evidence["workspace_entries"], "UNKNOWN")
        self.assertEqual(evidence["outside_canary"], "PRESENT")
        self.assertEqual(evidence["outside_write_block"], "FAIL")
        self.assertNotIn("SECRET_SENTINEL", json.dumps(evidence))

    def test_parent_sentinel_exclusive_and_no_premature_survival_claim(self):
        self.assertEqual(smoke.parent_done(self.parent), "CREATED")
        with self.assertRaises(FileExistsError):
            smoke.parent_done(self.parent)
        (self.parent / "descendant_canary.txt").write_text("PREMATURE")
        with self.assertRaises(smoke.Stop):
            smoke.parent_done(self.parent)
        evidence = dict(physical(), parent_done_state="UNKNOWN")
        self.assertEqual(smoke.classify(smoke.telemetry(result()), evidence)["descendant_observation"], "DESCENDANT_PROCESS_CLEANUP_UNVERIFIED")

    def test_physical_network(self):
        workspace = self.parent / "workspace"
        outside = self.parent / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / "network_probe_result.txt").write_text("UNEXPECTED_SUCCESS")
        with mock.patch.object(smoke, "git", return_value=""):
            actual = smoke.physical_results(workspace, outside, {}, {})
        self.assertEqual(actual["network_block"], "FAIL")

    def test_network_unavailable_physical_state_not_blocked(self):
        workspace = self.parent / "workspace"
        outside = self.parent / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / "network_probe_result.txt").write_text("PROBE_UNAVAILABLE")
        with mock.patch.object(smoke, "git", return_value=""):
            evidence = smoke.physical_results(workspace, outside, {}, {})
        self.assertEqual(evidence["network_probe_state"], "PROBE_UNAVAILABLE")
        self.assertNotEqual(evidence["network_block"], "PASS")
        evidence.update(wrapper_protection="HELD", wrapper_integrity="PASS")
        self.assertEqual(smoke.classify(smoke.telemetry(result()), evidence)["result"], "INCONCLUSIVE")


@unittest.skipUnless(os.name == "nt", "Windows handle-bound deletion")
class HandleDeleteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        root = self.parent / "owned"
        root.mkdir()
        ledger = []
        smoke.record_root(root, "temp", ledger)
        self.record = ledger[0]
        self.target = root / "workspace" / ".git" / "objects" / "aa" / "object"
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"harmless fixture")
        os.chmod(self.target, stat.S_IREAD)
        info = self.target.stat()
        self.identity = (info.st_dev, info.st_ino)

    def fake_api(self, failure=None):
        api = mock.Mock()
        api.CreateFileW.return_value = 123
        api.CloseHandle.return_value = True
        api.GetFileType.return_value = 1
        def query(handle, kind, pointer, size):
            if failure == "query" or failure == "query" + str(kind):
                return False
            value = pointer._obj
            if kind == 18:
                value.volume = self.identity[0]
                identity = self.identity[1] + (1 if failure == "identity" else 0)
                value.identifier[:] = identity.to_bytes(16, "little")
            elif kind == 9:
                value.attributes = 1 | (0x400 if failure == "reparse" else 0)
                if failure == "not-readonly":
                    value.attributes = 0
            elif kind == 1:
                value.links = 2 if failure == "hardlink" else 1
                value.directory = failure == "directory"
            else:
                self.fail("Unexpected information class")
            return True
        def final(handle, buffer, size, flags):
            if failure == "final-query":
                return 0
            path = self.parent / "external" if failure == "escape" else self.target
            buffer.value = "\\\\?\\" + str(path)
            return len(buffer.value)
        api.GetFileInformationByHandleEx.side_effect = query
        api.GetFinalPathNameByHandleW.side_effect = final
        api.SetFileInformationByHandle.return_value = failure != "disposition"
        if failure == "open":
            api.CreateFileW.return_value = None
        if failure == "close":
            api.CloseHandle.return_value = False
        if failure == "file-type":
            api.GetFileType.return_value = 3
        return api

    def test_handle_identity_flags_rights_and_no_attribute_mutation(self):
        api = self.fake_api()
        flags_seen = []
        api.SetFileInformationByHandle.side_effect = lambda handle, kind, pointer, size: (
            flags_seen.append((kind, pointer._obj.value, size)) or True)
        with mock.patch.object(smoke, "_cleanup_file_api", return_value=api), \
                mock.patch.object(os, "chmod") as chmod, mock.patch.object(os, "fchmod") as fchmod, \
                mock.patch.object(os, "unlink") as unlink:
            smoke.readonly_git_cleanup_retry(self.record)(unlink, str(self.target), PermissionError())
        api.CreateFileW.assert_called_once_with(str(self.target), 0x10080, 1, None, 3, 0x200000, None)
        self.assertEqual([call.args[1] for call in api.GetFileInformationByHandleEx.call_args_list], [18, 9, 1])
        self.assertEqual(flags_seen, [(21, 0x11, 4)])
        api.CloseHandle.assert_called_once_with(123)
        chmod.assert_not_called()
        fchmod.assert_not_called()
        unlink.assert_not_called()

    def test_failures_preserve_candidate_and_close_once_without_fallback(self):
        for failure in ("open", "query18", "query9", "query1", "identity", "reparse", "hardlink",
                        "directory", "file-type", "not-readonly", "final-query", "escape", "disposition", "close"):
            with self.subTest(failure=failure):
                api = self.fake_api(failure)
                with mock.patch.object(smoke, "_cleanup_file_api", return_value=api), \
                        mock.patch.object(os, "chmod") as chmod, mock.patch.object(os, "fchmod") as fchmod:
                    with self.assertRaises((smoke.Stop, OSError)):
                        smoke.readonly_git_cleanup_retry(self.record)(os.unlink, str(self.target), PermissionError())
                if failure == "open":
                    api.CloseHandle.assert_not_called()
                else:
                    api.CloseHandle.assert_called_once_with(123)
                if failure not in {"disposition", "close"}:
                    api.SetFileInformationByHandle.assert_not_called()
                self.assertTrue(self.target.exists())
                chmod.assert_not_called()
                fchmod.assert_not_called()
        with mock.patch.object(smoke, "_cleanup_file_api", side_effect=AttributeError("unavailable")), \
                mock.patch.object(os, "chmod") as chmod:
            with self.assertRaises(AttributeError):
                smoke.readonly_git_cleanup_retry(self.record)(os.unlink, str(self.target), PermissionError())
        chmod.assert_not_called()

    def test_swap_to_external_hardlink_before_open_is_rejected(self):
        victim = self.parent / "victim"
        victim.write_bytes(b"external fixture")
        os.chmod(victim, stat.S_IREAD)
        original_attributes = victim.stat().st_file_attributes
        api = smoke._cleanup_file_api()
        proxy = mock.Mock(wraps=api)
        def swap(*args):
            self.target.rename(self.target.with_name("saved"))
            os.link(victim, self.target)
            return api.CreateFileW(*args)
        proxy.CreateFileW.side_effect = swap
        with mock.patch.object(smoke, "_cleanup_file_api", return_value=proxy), \
                mock.patch.object(os, "chmod") as chmod, mock.patch.object(os, "fchmod") as fchmod:
            with self.assertRaises(smoke.Stop):
                smoke.readonly_git_cleanup_retry(self.record)(os.unlink, str(self.target), PermissionError())
        proxy.SetFileInformationByHandle.assert_not_called()
        proxy.CloseHandle.assert_called_once()
        self.assertEqual(victim.read_bytes(), b"external fixture")
        self.assertEqual(victim.stat().st_file_attributes, original_attributes)
        self.assertTrue(self.target.exists())
        chmod.assert_not_called()
        fchmod.assert_not_called()

    def test_existing_hardlink_rejected_before_open(self):
        external = self.parent / "link"
        os.link(self.target, external)
        with mock.patch.object(smoke, "_cleanup_file_api") as api:
            with self.assertRaises(smoke.Stop):
                smoke.readonly_git_cleanup_retry(self.record)(os.unlink, str(self.target), PermissionError())
        api.assert_not_called()
        self.assertTrue(external.exists())

    def test_intermediate_junction_external_target_is_preserved(self):
        external_dir = self.parent / "outside-objects"
        external_dir.mkdir()
        victim = external_dir / "object"
        victim.write_bytes(b"external junction fixture")
        os.chmod(victim, stat.S_IREAD)
        attributes = victim.stat().st_file_attributes
        self.target.parent.rename(self.target.parent.with_name("saved"))
        junction = self.target.parent
        cmd = str(Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe")
        created = subprocess.run([cmd, "/d", "/c", "mklink", "/J", str(junction), str(external_dir)],
                                 capture_output=True, shell=False, timeout=15)
        self.assertEqual(created.returncode, 0)
        try:
            with mock.patch.object(smoke, "_cleanup_file_api") as unopened:
                with self.assertRaises(smoke.Stop):
                    smoke.readonly_git_cleanup_retry(self.record)(os.unlink, str(self.target), PermissionError())
            unopened.assert_not_called()
            # Race equivalent: path checks passed earlier; open traverses the new
            # intermediate junction. Real handle final-path containment must reject it.
            info = victim.stat()
            api = smoke._cleanup_file_api()
            proxy = mock.Mock(wraps=api)
            with mock.patch.object(smoke, "_cleanup_file_api", return_value=proxy), \
                    mock.patch.object(smoke, "no_reparse"), mock.patch.object(os, "chmod") as chmod, \
                    mock.patch.object(os, "fchmod") as fchmod:
                with self.assertRaises(smoke.Stop):
                    smoke._delete_readonly_git_object(self.record, self.target, (info.st_dev, info.st_ino))
            proxy.GetFinalPathNameByHandleW.assert_called_once()
            proxy.SetFileInformationByHandle.assert_not_called()
            proxy.CloseHandle.assert_called_once()
            chmod.assert_not_called()
            fchmod.assert_not_called()
            self.assertEqual(victim.read_bytes(), b"external junction fixture")
            self.assertEqual(victim.stat().st_file_attributes, attributes)
        finally:
            # Removes only the fixture junction, never the external target tree.
            os.rmdir(junction)

    def test_late_hardlink_survives_disposition_without_metadata_change(self):
        # Read-only security descriptor snapshot; never changes owner or ACL.
        import ctypes
        from ctypes import wintypes
        security = ctypes.WinDLL("advapi32", use_last_error=True).GetFileSecurityW
        security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        security.restype = wintypes.BOOL
        def descriptor(path):
            required = wintypes.DWORD()
            security(str(path), 7, None, 0, ctypes.byref(required))
            self.assertGreater(required.value, 0)
            buffer = ctypes.create_string_buffer(required.value)
            self.assertTrue(security(str(path), 7, buffer, len(buffer), ctypes.byref(required)))
            return buffer.raw
        external = self.parent / "late-link"
        original_attributes = self.target.stat().st_file_attributes
        before = descriptor(self.target)
        api = smoke._cleanup_file_api()
        proxy = mock.Mock(wraps=api)
        def disposition(*args):
            os.link(self.target, external)
            return api.SetFileInformationByHandle(*args)
        proxy.SetFileInformationByHandle.side_effect = disposition
        with mock.patch.object(smoke, "_cleanup_file_api", return_value=proxy), \
                mock.patch.object(os, "chmod") as chmod, mock.patch.object(os, "fchmod") as fchmod:
            smoke.readonly_git_cleanup_retry(self.record)(os.unlink, str(self.target), PermissionError())
        self.assertFalse(self.target.exists())
        self.assertEqual(external.read_bytes(), b"harmless fixture")
        self.assertEqual(external.stat().st_file_attributes, original_attributes)
        self.assertEqual(descriptor(external), before)
        proxy.CloseHandle.assert_called_once()
        chmod.assert_not_called()
        fchmod.assert_not_called()


class AbsoluteWrapperTests(unittest.TestCase):
    def test_absolute_commands_are_single_instruction_and_fingerprint_source(self):
        from orchestrator.adapters import codex_cli
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root) / "spaces & apostrophe' $cash (group) ! caret^"
            workspace.mkdir()
            for name in smoke.WRAPPERS:
                (workspace / name).write_bytes(b"@echo off\r\n")
            env = {"SYSTEMROOT": r"C:\Windows"}
            commands = smoke.wrapper_commands(workspace, env)
            prompt = smoke.instruction(commands)
            for name, command in zip(smoke.WRAPPERS, commands):
                path = str(workspace / name)
                self.assertIn(path, command)
                self.assertTrue(command.endswith('""' + path + '""'))
                self.assertIn(' --% ', command)
                self.assertIn('/d /v:off /s /c ', command)
                self.assertNotIn('/c ' + name, command)
                self.assertEqual(prompt.count(command), 1)
                self.assertEqual(codex_cli.command_fingerprint(command),
                                 codex_cli.command_fingerprint(prompt.splitlines()[2 + smoke.WRAPPERS.index(name)]))
            self.assertEqual(commands, smoke.wrapper_commands(workspace, dict(env,
                NoDefaultCurrentDirectoryInExePath="1", PATH=str(Path(root) / "decoy"))))

    def test_missing_relative_reparse_and_expanding_paths_fail_closed(self):
        env = {"SYSTEMROOT": r"C:\Windows"}
        with self.assertRaises(smoke.Stop):
            smoke.wrapper_commands(Path("relative"), env)
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            with self.assertRaises(FileNotFoundError):
                smoke.wrapper_commands(workspace, env)
            for name in smoke.WRAPPERS:
                (workspace / name).write_bytes(b"@echo off\r\n")
            with mock.patch.object(smoke, "no_reparse", side_effect=smoke.Stop("UNSAFE_RESOURCE")):
                with self.assertRaises(smoke.Stop):
                    smoke.wrapper_commands(workspace, env)
            expanding = workspace / "percent%PATH%"
            expanding.mkdir()
            for name in smoke.WRAPPERS:
                (expanding / name).write_bytes(b"@echo off\r\n")
            with self.assertRaises(smoke.Stop):
                smoke.wrapper_commands(expanding, env)

    @unittest.skipUnless(os.name == "nt", "Native Windows command selection")
    def test_native_locked_absolute_selection_from_other_cwd_and_path(self):
        env = dict(os.environ, NoDefaultCurrentDirectoryInExePath="1")
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root) / "locked & space' $cash (group) ! caret^"
            decoy = Path(root) / "decoy"
            workspace.mkdir()
            decoy.mkdir()
            wrappers = {name: b"@echo off\r\necho ABSOLUTE_LOCKED_TOKEN\r\n" for name in smoke.WRAPPERS}
            for name, content in wrappers.items():
                (workspace / name).write_bytes(content)
                (decoy / name).write_bytes(b"@echo off\r\necho WRONG_WRAPPER\r\n")
            env["PATH"] = str(decoy) + os.pathsep + env.get("PATH", "")
            locks = []
            try:
                smoke.acquire_wrapper_protection(workspace, wrappers, locks)
                commands = smoke.wrapper_commands(workspace, env)
                powershell, _ = smoke.system_executables(env)
                for command in commands:
                    completed = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive",
                        "-EncodedCommand", smoke.encode_command(command)], cwd=decoy, env=env,
                        shell=False, capture_output=True, text=True, timeout=15)
                    self.assertEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout.strip(), "ABSOLUTE_LOCKED_TOKEN")
                with self.assertRaises(OSError):
                    (workspace / smoke.WRAPPERS[0]).write_bytes(b"replacement")
                with self.assertRaises(OSError):
                    (workspace / smoke.WRAPPERS[0]).unlink()
                with self.assertRaises(OSError):
                    (workspace / smoke.WRAPPERS[0]).rename(workspace / "replacement.cmd")
                self.assertEqual(smoke.wrapper_integrity(locks), "PASS")
            finally:
                self.assertTrue(smoke.release_wrapper_protection(locks))


class PreflightTests(unittest.TestCase):
    def test_system_preflight_only_benign_version_commands(self):
        with mock.patch.object(smoke, "no_reparse"), mock.patch.object(smoke.Path, "is_file", return_value=True), mock.patch.object(
            smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "version", "")
        ) as process:
            smoke.system_preflight({"SYSTEMROOT": r"C:\Windows"})
        self.assertEqual(process.call_count, 3)
        self.assertEqual(process.call_args_list[0].args[0][1:4], ["-NoProfile", "-NonInteractive", "-EncodedCommand"])
        self.assertEqual(process.call_args_list[1].args[0][-1], "--version")
        self.assertNotIn("https://", str(process.call_args_list))

    def test_instruction_and_descendant_use_system_tools_and_sentinel(self):
        env = {"SYSTEMROOT": r"C:\Windows"}
        probes = smoke.probe_sources(Path("workspace"), Path("outside"), env)
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            for name in smoke.WRAPPERS:
                (workspace / name).write_bytes(b"@echo off\r\n")
            prompt = smoke.instruction(smoke.wrapper_commands(workspace, env))
        self.assertNotIn(str(smoke.APPROVED_PYTHON), prompt)
        self.assertNotIn("-EncodedCommand", prompt)
        self.assertIn("outside_probe.cmd", prompt)
        self.assertLess(len(prompt.encode("utf-8")), 2000)
        for encoded in probes.values():
            self.assertNotIn(encoded, prompt)
        descendant = base64.b64decode(probes["DESCENDANT"]).decode("utf-16le")
        encoded = re.search(r"'-EncodedCommand','([^']+)'", descendant).group(1)
        child = base64.b64decode(encoded).decode("utf-16le")
        self.assertLess(child.index("Exists($sentinel)"), child.index("WriteAllText"))
        self.assertIn(smoke.path_data(Path("workspace") / "parent_done.flag"), child)
        self.assertIn("AddSeconds(620)", child)
        self.assertIn("Start-Sleep -Seconds 2", child)

    def test_encoded_probes_deterministic_and_paths_are_data(self):
        env = {"SYSTEMROOT": r"C:\Windows"}
        special = "quote'&%!()^\u2019"
        regular = smoke.probe_sources(Path("workspace"), Path("outside"), env)
        adversarial = smoke.probe_sources(Path(special), Path(special) / "outside", env)
        self.assertEqual(adversarial, smoke.probe_sources(Path(special), Path(special) / "outside", env))
        def structure(source):
            return re.sub(r"'[A-Za-z0-9+/=]+'", "'DATA'", source)
        for name, encoded in adversarial.items():
            source = base64.b64decode(encoded).decode("utf-16le")
            baseline = base64.b64decode(regular[name]).decode("utf-16le")
            self.assertNotIn(special, source)
            self.assertEqual(structure(source), structure(baseline))
            if name == "DESCENDANT":
                child_token = re.search(r"'-EncodedCommand','([^']+)'", source).group(1)
                baseline_token = re.search(r"'-EncodedCommand','([^']+)'", baseline).group(1)
                child_source = base64.b64decode(child_token).decode("utf-16le")
                baseline_child = base64.b64decode(baseline_token).decode("utf-16le")
                self.assertNotIn(special, child_source)
                self.assertEqual(structure(child_source), structure(baseline_child))
            for forbidden in (" -File ", ".ps1", str(smoke.APPROVED_PYTHON), "-ExecutionPolicy"):
                self.assertNotIn(forbidden, source)
        expression = smoke.path_data(Path(special))
        value = re.search(r"FromBase64String\('([^']+)'\)", expression).group(1)
        self.assertEqual(base64.b64decode(value).decode("utf-8"), str(Path(special)))
        powershell, curl = smoke.system_executables(env)
        self.assertEqual(powershell, Path(r"C:\Windows") / "System32/WindowsPowerShell/v1.0/powershell.exe")
        self.assertEqual(curl, Path(r"C:\Windows") / "System32/curl.exe")

    def test_network_has_one_request_after_version_gate(self):
        source = smoke.network_source(Path("workspace"), Path("system-curl"))
        self.assertEqual(source.count("https://example.com/"), 1)
        self.assertEqual(source.count("$request=InvokeFixedCurl"), 1)
        self.assertLess(source.index("$version=InvokeFixedCurl"), source.index("$request=InvokeFixedCurl"))
        self.assertIn("$null -ne $version -and $version -eq 0", source)
        self.assertIn("$null -ne $request", source)


@unittest.skipUnless(os.name == "nt", "Windows-native synthetic probe logic")
class NetworkLogicTests(unittest.TestCase):
    def test_mocked_curl_outcomes_without_network(self):
        # Execute only trusted generated decision logic; replace the entire process
        # helper so neither curl nor a network-capable process can be launched.
        for version, request, expected, calls in ((None, None, "PROBE_UNAVAILABLE", 1),
                                                  (1, None, "PROBE_UNAVAILABLE", 1),
                                                  (0, None, "PROBE_UNAVAILABLE", 2),
                                                  (0, 7, "BLOCKED", 2),
                                                  (0, 0, "UNEXPECTED_SUCCESS", 2)):
            with self.subTest(version=version, request=request), tempfile.TemporaryDirectory() as temp:
                workspace = Path(temp).resolve()
                source = smoke.network_source(workspace, Path("NEVER_EXECUTED"))
                start = source.index("function InvokeFixedCurl")
                end = source.index("$result='PROBE_UNAVAILABLE'")
                first = "$null" if version is None else str(version)
                second = "$null" if request is None else str(request)
                stub = ("$script:callCount=0\nfunction InvokeFixedCurl([string]$arguments) { "
                        "$script:callCount++; if ($script:callCount -eq 1) { return " + first +
                        " }; return " + second + " }\n")
                source = source[:start] + stub + source[end:] + "Write-Output $script:callCount\n"
                self.assertNotIn("Diagnostics.Process", source)
                executable, _ = smoke.system_executables(os.environ)
                process = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                          smoke.encode_command(source)], capture_output=True, text=True,
                                         shell=False, timeout=15)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(process.stdout.strip(), str(calls))
                self.assertEqual((workspace / "network_probe_result.txt").read_text(), expected)


class WindowsBackendPreflightTests(unittest.TestCase):
    def test_not_applicable_creates_nothing(self):
        with mock.patch.object(smoke.tempfile, "mkdtemp") as create, mock.patch.object(smoke.subprocess, "run") as process:
            self.assertEqual(smoke.windows_backend_preflight("unused", {}, [], []), "NOT_APPLICABLE")
        create.assert_not_called()
        process.assert_not_called()

    def test_fixed_control_exact_binding_output_and_owned_cleanup(self):
        executable = str(Path("PRIVATE_CODEX.exe").absolute())
        backend = ["-c", 'windows.sandbox="elevated"']
        env = {"SYSTEMROOT": "C:/Windows"}
        cases = ((0, "CODEX_BACKEND_PREFLIGHT_OK\r\n", None, True),
                 (1, "CODEX_BACKEND_PREFLIGHT_OK", None, False),
                 (0, "wrong", None, False),
                 (0, "prefix CODEX_BACKEND_PREFLIGHT_OK", None, False),
                 (0, "", OSError("PRIVATE_PATH"), False),
                 (0, "", subprocess.TimeoutExpired("PRIVATE_COMMAND", 60), False))
        with tempfile.TemporaryDirectory() as parent:
            for code, stdout, error, success in cases:
                owned = []
                with mock.patch.object(smoke.tempfile, "gettempdir", return_value=parent), mock.patch.object(
                    smoke, "no_reparse"), mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
                    smoke.subprocess, "run", side_effect=error,
                    return_value=subprocess.CompletedProcess([], code, stdout, "PRIVATE_STDERR")
                ) as process:
                    if success:
                        self.assertEqual(smoke.windows_backend_preflight(executable, env, owned, backend), "PASS")
                    else:
                        with self.assertRaisesRegex(smoke.Stop, "^WINDOWS_SANDBOX_BACKEND_PREFLIGHT_FAILED$"):
                            smoke.windows_backend_preflight(executable, env, owned, backend)
                process.assert_called_once()
                argv = process.call_args.args[0]
                self.assertIs(argv[0], executable)
                self.assertEqual(argv[1:6], backend + ["sandbox", "-P", ":workspace"])
                self.assertNotIn("exec", argv)
                self.assertEqual(argv[-4:], ["/d", "/c", "echo", "CODEX_BACKEND_PREFLIGHT_OK"])
                self.assertEqual(argv.count(backend[1]), 1)
                for forbidden in ('windows.sandbox="unelevated"', "danger-full-access",
                                  "--dangerously-bypass-approvals-and-sandbox"):
                    self.assertNotIn(forbidden, argv)
                self.assertIs(process.call_args.kwargs["env"], env)
                self.assertFalse(process.call_args.kwargs["shell"])
                self.assertEqual(process.call_args.kwargs["timeout"], 60)
                self.assertEqual(len(owned), 1)
                self.assertEqual(owned[0].kind, "backend")
                self.assertTrue(owned[0].path.is_relative_to(Path(parent)))
                self.assertEqual(smoke.cleanup(owned), ("COMPLETE", "COMPLETE"))


class ExecutableResolutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.profile = Path(temporary.name)
        self.bin = self.profile / "AppData/Local/OpenAI/Codex/bin"
        self.bin.mkdir(parents=True)
        self.env = {"USERPROFILE": str(self.profile), "PATH": "PRIVATE_FILTERED_PATH"}

    def candidate(self, child="arbitrary-installation"):
        path = self.bin / child / "codex.exe"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"synthetic, never executed")
        return path

    def resolve(self, found=None):
        # Simulate only the platform selector, without replacing pathlib's OS.
        with mock.patch.object(smoke, "os", SimpleNamespace(name="nt")), mock.patch.object(
            smoke.shutil, "which", return_value=found
        ) as which:
            actual = smoke.resolve_codex_executable(agent_config(), self.env)
            which.assert_called_once_with("codex", path=self.env["PATH"])
            return actual

    def test_filtered_path_preferred_and_environment_unchanged(self):
        candidate = self.candidate()
        self.candidate("another-installation")
        before = dict(self.env)
        self.assertEqual(self.resolve(str(candidate)), (str(candidate), "FILTERED_PATH"))
        self.assertEqual(self.env, before)

    def test_single_bounded_candidate_without_path(self):
        candidate = self.candidate("not-a-version-or-hash")
        before = dict(self.env)
        self.assertEqual(self.resolve(), (str(candidate), "BOUNDED_WINDOWS_INSTALLATION"))
        self.assertEqual(self.env, before)

    def test_zero_multiple_missing_and_wrong_filename(self):
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_NOT_FOUND"):
            self.resolve()
        candidate = self.candidate()
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_INVALID"):
            self.resolve(str(candidate.with_name("missing.exe")))
        wrong = candidate.with_name("other.exe")
        wrong.write_bytes(b"wrong")
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_INVALID"):
            self.resolve(str(wrong))
        self.candidate("second")
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_AMBIGUOUS"):
            self.resolve()

    def test_outside_and_deeper_candidates_not_accepted(self):
        deeper = self.candidate("child/deeper")
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_NOT_FOUND"):
            self.resolve()
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_INVALID"):
            smoke.validate_codex_candidate(deeper, self.bin)
        outside = self.profile / "codex.exe"
        outside.write_bytes(b"outside")
        with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_INVALID"):
            smoke.validate_codex_candidate(outside, self.bin)

    def test_file_child_and_bin_reparse_rejected(self):
        candidate = self.candidate()
        original = Path.lstat
        for target in (candidate, candidate.parent, self.bin):
            def lstat(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if path == target:
                    return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
                return info
            with self.subTest(target=target.name), mock.patch.object(Path, "lstat", lstat):
                with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_INVALID"):
                    self.resolve()

    def test_relative_and_directory_candidates_rejected_without_fallback(self):
        candidate = self.candidate()
        for invalid in ("codex.exe", str(candidate.parent)):
            with self.assertRaisesRegex(smoke.Stop, "CODEX_EXECUTABLE_INVALID"):
                self.resolve(invalid)


class AuthenticationPreflightTests(unittest.TestCase):
    def test_os_identity_classification_case_insensitive(self):
        for identity, expected in ((r"ANAP\CODEXSANDBOXOFFLINE", "CODEX_SANDBOX"),
                                   (r"ANAP\ANAPO", "NORMAL_USER"), (None, "UNKNOWN"),
                                   ("unrecognized", "UNKNOWN")):
            with self.subTest(identity=identity), mock.patch.object(smoke, "host_identity", return_value=identity):
                self.assertEqual(smoke.host_context(), expected)

    def test_filtered_env_and_no_raw_auth(self):
        env = {"SYSTEMROOT": "synthetic"}
        executable = str(Path("PRIVATE_CODEX.exe").absolute())
        with mock.patch.object(smoke.shutil, "which", side_effect=AssertionError("second resolution")), mock.patch.object(
            smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "Logged in using ChatGPT", "SECRET_SENTINEL")
        ) as process:
            smoke.codex_preflight(executable, env)
        self.assertEqual(process.call_count, 3)
        for call in process.call_args_list:
            self.assertIs(call.args[0][0], executable)
            self.assertIs(call.kwargs["env"], env)
            self.assertFalse(call.kwargs["shell"])
        self.assertEqual([call.args[0][1:] for call in process.call_args_list], [["--version"], ["login", "status"], ["exec", "--help"]])

    def test_auth_not_ready_stops_before_help(self):
        with mock.patch.object(smoke.shutil, "which", return_value="codex"), mock.patch.object(
            smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "Not logged in", "")
        ) as process, self.assertRaises(smoke.Stop):
            smoke.codex_preflight(str(Path("codex.exe").absolute()), {})
        self.assertEqual(process.call_count, 2)


if __name__ == "__main__":
    unittest.main()
