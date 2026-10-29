"""Offline durable coordination, interruption windows and concurrent callers."""

from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from orchestrator import github_actions_backend as backend
from orchestrator.github_actions_operation import (
    GitHubOperationError, GitHubOperationResult, coordinate_github_operation,
)
from orchestrator.store import Store, StoreError
from tests.test_github_actions_backend import FakeClock, FakeOpener, FakeResponse


class SimulatedCrash(BaseException):
    pass


class GitHubOperationTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection"):
            patcher = mock.patch(target, side_effect=AssertionError("Real network forbidden"))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "operations.db"
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.close())
        self.store.register_project("SAMPLE", "Sample", ".", "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need")
        self.config = backend.GitHubBackendConfig.from_policies(yaml.safe_load(
            (ROOT / "config/POLICIES.yaml").read_text(encoding="utf-8")))
        self.request = backend.DispatchRequest("a" * 40, "unit", "b" * 64)
        self.clock = FakeClock()
        self.limits = dict(request_timeout_seconds=5, overall_timeout_seconds=20, poll_interval_seconds=1)

    def preflight(self):
        return [FakeResponse({"id": 17, "path": backend.WORKFLOW_PATH, "state": "active"}),
                FakeResponse({"ref": "refs/tags/safe-test-runner-v1",
                              "object": {"type": "commit", "sha": self.config.workflow_source_sha}})]

    def dispatch_response(self, **changes):
        return FakeResponse(dict({"workflow_run_id": 431, "run_url": backend._run_url(431),
                                  "html_url": f"https://github.com/{backend.REPOSITORY}/actions/runs/431"},
                                 **changes))

    def run_response(self, **changes):
        return FakeResponse(dict({"id": 431, "event": "workflow_dispatch", "status": "completed",
                                  "conclusion": "success", "head_sha": self.config.workflow_source_sha,
                                  "run_attempt": 1, "workflow_id": 17,
                                  "repository": {"full_name": backend.REPOSITORY}}, **changes))

    def transport(self, responses):
        opener = FakeOpener(responses, self.clock)
        transport = backend.GitHubActionsTransport(self.config, lambda: "OFFLINE_SENTINEL",
            opener=opener, monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        return transport, opener

    def coordinate(self, transport, **changes):
        return coordinate_github_operation(self.store, transport, "T-1", self.request,
                                           **dict(self.limits, **changes))

    def row(self):
        rows = self.store._conn.execute("SELECT id FROM external_operation").fetchall()
        self.assertEqual(len(rows), 1)
        return self.store.get_external_operation(rows[0][0])

    def prepare(self):
        transport, _ = self.transport([FakeResponse({}, status=503)])
        self.assertEqual(self.coordinate(transport).disposition, "PRE_SEND_BLOCKED")
        return self.row()

    def identify(self):
        row = self.prepare()
        self.store.claim_external_dispatch(row["id"])
        return self.store.bind_external_operation(row["id"], remote_operation_id="431")

    def restart(self):
        self.store.close()
        self.store = Store(self.path)

    def unrelated_rows(self):
        tables = [r[0] for r in self.store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT IN ('external_operation', 'sqlite_sequence')")]
        return {name: self.store._conn.execute('SELECT * FROM "' + name + '"').fetchall() for name in tables}

    def test_fresh_success_orders_prepare_preflight_claim_post_bind_observe_terminal(self):
        transport, opener = self.transport(self.preflight() + [self.dispatch_response()]
                                           + self.preflight() + [self.run_response()])
        phases = []
        original = opener.open
        def inspect_open(request, *, timeout):
            with Store(self.path) as durable:
                op_id = self.row()["id"]
                phases.append((request.method, durable.get_external_operation(op_id)["phase"]))
            return original(request, timeout=timeout)
        before = self.unrelated_rows()
        with mock.patch.object(opener, "open", side_effect=inspect_open):
            result = self.coordinate(transport)
        self.assertEqual(phases, [("GET", "PREPARED"), ("GET", "PREPARED"),
                                  ("POST", "DISPATCH_ATTEMPTED"), ("GET", "RUN_IDENTIFIED"),
                                  ("GET", "RUN_IDENTIFIED"), ("GET", "RUN_IDENTIFIED")])
        self.assertEqual(result.disposition, "TERMINAL_OBSERVED")
        self.assertEqual((result.remote_operation_id, result.terminal_status, result.terminal_result),
                         ("431", "completed", "success"))
        self.assertEqual(self.unrelated_rows(), before)
        self.restart()
        self.assertEqual(self.row()["phase"], "TERMINAL_OBSERVED")

    def test_preflight_failure_stays_prepared_and_independent_invocation_can_try(self):
        transport, opener = self.transport([FakeResponse({}, status=503)])
        with mock.patch.object(self.store, "claim_external_dispatch", wraps=self.store.claim_external_dispatch) as claim:
            result = self.coordinate(transport)
        claim.assert_not_called()
        self.assertEqual((result.phase, result.disposition), ("PREPARED", "PRE_SEND_BLOCKED"))
        self.assertEqual([c[0].method for c in opener.calls], ["GET"])
        transport, opener = self.transport(self.preflight() + [self.dispatch_response()]
                                           + self.preflight() + [self.run_response()])
        self.assertEqual(self.coordinate(transport).disposition, "TERMINAL_OBSERVED")
        self.assertEqual(sum(c[0].method == "POST" for c in opener.calls), 1)

    def test_unknown_receipt_survives_restart_without_any_remote_call(self):
        transport, opener = self.transport(self.preflight() + [RuntimeError("SECRET body https://evil.invalid")])
        result = self.coordinate(transport)
        self.assertEqual((result.phase, result.disposition, result.remote_operation_id),
                         ("DISPATCH_ATTEMPTED", "BLOCKED_UNKNOWN", None))
        self.assertEqual([c[0].method for c in opener.calls], ["GET", "GET", "POST"])
        self.restart()
        transport, opener = self.transport([])
        self.assertEqual(self.coordinate(transport), result)
        self.assertEqual(opener.calls, [])

    def test_known_id_from_controlled_dispatch_error_is_bound_before_observe(self):
        transport, opener = self.transport(self.preflight() + [self.dispatch_response(run_url="https://evil.invalid")]
                                           + self.preflight() + [self.run_response()])
        original = transport.observe
        def observe(run_id, **limits):
            self.assertEqual((self.row()["phase"], self.row()["remote_operation_id"]), ("RUN_IDENTIFIED", "431"))
            return original(run_id, **limits)
        with mock.patch.object(transport, "observe", side_effect=observe) as observer:
            result = self.coordinate(transport)
        observer.assert_called_once_with(431, **self.limits)
        self.assertEqual(result.disposition, "TERMINAL_OBSERVED")
        self.assertEqual(sum(c[0].method == "POST" for c in opener.calls), 1)
        self.assertNotIn("evil", repr(result))

    def test_restart_from_known_id_observes_exact_id_only(self):
        self.identify()
        self.restart()
        transport, opener = self.transport(self.preflight() + [self.run_response()])
        with mock.patch.object(transport, "dispatch", side_effect=AssertionError("redispatch")) as dispatch:
            self.assertEqual(self.coordinate(transport).disposition, "TERMINAL_OBSERVED")
        dispatch.assert_not_called()
        self.assertEqual([c[0].method for c in opener.calls], ["GET"] * 3)
        self.assertEqual(opener.calls[-1][0].full_url, backend._run_url(431))

    def test_observation_error_and_timeout_preserve_id_for_next_invocation(self):
        self.identify()
        for failure in (RuntimeError("SECRET"), TimeoutError("SECRET")):
            transport, opener = self.transport(self.preflight() + [failure])
            result = self.coordinate(transport)
            self.assertEqual((result.phase, result.disposition, result.remote_operation_id),
                             ("RUN_IDENTIFIED", "OBSERVATION_PENDING", "431"))
            self.assertTrue(all(c[0].method == "GET" for c in opener.calls))
        transport, opener = self.transport(self.preflight() + [self.run_response()])
        self.assertEqual(self.coordinate(transport).disposition, "TERMINAL_OBSERVED")
        self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_terminal_replay_returns_only_persisted_evidence_without_provider(self):
        row = self.identify()
        self.store.complete_external_operation(row["id"], remote_operation_id="431",
            terminal_status="completed", terminal_result="failure")
        self.restart()
        transport, opener = self.transport([])
        before = self.unrelated_rows()
        with mock.patch.object(transport, "dispatch") as dispatch, mock.patch.object(transport, "observe") as observe:
            result = self.coordinate(transport)
        dispatch.assert_not_called()
        observe.assert_not_called()
        self.assertEqual(opener.calls, [])
        self.assertEqual(result.terminal_result, "failure")
        self.assertEqual(self.unrelated_rows(), before)

    def test_canonical_identity_hashes_and_logical_field_separation(self):
        row = self.prepare()
        identity = dict(task_id="T-1", provider="github_actions", operation_type="workflow_dispatch",
                        candidate_sha="a" * 40, logical_test_id="unit", argv_sha256="b" * 64)
        encode = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                                        separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(row["operation_key"], encode(identity))
        trusted = {name: getattr(self.config, name) for name in (
            "repository", "workflow_id", "workflow_ref", "workflow_source_sha", "api_version", "return_run_details")}
        self.assertEqual(row["request_fingerprint"], encode(dict(identity, trusted=trusted)))
        transport, _ = self.transport([FakeResponse({}, status=503)])
        self.assertEqual(self.coordinate(transport).operation_id, row["id"])
        self.store.create_task("T-2", "SAMPLE", "Other", "Need")
        ids = {row["id"]}
        for task, request in [("T-2", self.request), ("T-1", replace(self.request, candidate_sha="c" * 40)),
                              ("T-1", replace(self.request, logical_test_id="lint")),
                              ("T-1", replace(self.request, argv_sha256="d" * 64))]:
            transport, _ = self.transport([FakeResponse({}, status=503)])
            ids.add(coordinate_github_operation(self.store, transport, task, request, **self.limits).operation_id)
        self.assertEqual(len(ids), 5)

    def test_config_drift_conflicts_before_network_for_every_fingerprint_field(self):
        original = self.prepare()
        for name, value in (("repository", "other/repo"), ("workflow_id", "other.yml"),
                            ("workflow_ref", "other"), ("workflow_source_sha", "c" * 40),
                            ("api_version", "other"), ("return_run_details", False)):
            transport, opener = self.transport([])
            # Simulate a future trusted configuration version, without widening
            # today's fixed config validator or deriving values from a packet.
            changed = replace(self.config)
            object.__setattr__(changed, name, value)
            with mock.patch.object(transport, "_config", changed), self.assertRaises(GitHubOperationError) as error:
                self.coordinate(transport)
            self.assertIsNone(error.exception.__context__)
            self.assertEqual(opener.calls, [])
            self.assertEqual(self.row(), original)

    def test_claim_failure_is_pre_send_blocked_with_zero_post(self):
        transport, opener = self.transport(self.preflight())
        with mock.patch.object(self.store, "claim_external_dispatch", side_effect=StoreError("SECRET")):
            result = self.coordinate(transport)
        self.assertEqual(result.disposition, "PRE_SEND_BLOCKED")
        self.assertEqual([c[0].method for c in opener.calls], ["GET", "GET"])

    def test_losing_claim_reloads_once_and_can_observe_winners_id(self):
        row = self.prepare()
        transport, opener = self.transport(self.preflight() + self.preflight() + [self.run_response()])
        def lose(operation_id):
            with Store(self.path) as other:
                self.assertTrue(other.claim_external_dispatch(operation_id))
                other.bind_external_operation(operation_id, remote_operation_id="431")
            return False
        with mock.patch.object(self.store, "claim_external_dispatch", side_effect=lose):
            result = self.coordinate(transport)
        self.assertEqual(result.operation_id, row["id"])
        self.assertEqual(result.disposition, "TERMINAL_OBSERVED")
        self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_remote_id_substitution_and_invalid_terminal_metadata_never_overwrite(self):
        original = self.identify()
        for changes in ({"id": 432}, {"head_sha": "c" * 40}, {"conclusion": "SECRET"},
                        {"workflow_id": 18}, {"repository": {"full_name": "other/repo"}}):
            transport, opener = self.transport(self.preflight() + [self.run_response(**changes)])
            result = self.coordinate(transport)
            self.assertEqual(result.disposition, "OBSERVATION_PENDING")
            self.assertEqual(self.row(), original)
            self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_binding_conflict_stops_before_observation_without_exception_details(self):
        transport, opener = self.transport(self.preflight() + [self.dispatch_response()])
        with mock.patch.object(self.store, "bind_external_operation", side_effect=StoreError("SECRET")), \
                mock.patch.object(transport, "observe") as observe, self.assertRaises(GitHubOperationError) as error:
            self.coordinate(transport)
        observe.assert_not_called()
        self.assertEqual(str(error.exception), "External operation coordination blocked")
        self.assertIsNone(error.exception.__context__)
        self.assertEqual(self.row()["phase"], "DISPATCH_ATTEMPTED")

    def test_result_is_frozen_closed_and_contains_no_provider_payload(self):
        result = self.coordinate(self.transport([FakeResponse({}, status=503)])[0])
        self.assertEqual({f.name for f in fields(result)}, {"operation_id", "phase", "disposition",
                         "remote_operation_id", "terminal_status", "terminal_result"})
        with self.assertRaises(FrozenInstanceError):
            result.phase = "OTHER"
        for changes in ({"disposition": "APPROVED"}, {"phase": "OTHER"},
                        {"remote_operation_id": "https://evil.invalid"}, {"terminal_result": "SECRET"}):
            with self.assertRaises(GitHubOperationError):
                replace(result, **changes)

    def test_crash_windows_before_preflight_and_before_claim_remain_prepared(self):
        for before in ("preflight", "claim"):
            transport, opener = self.transport(self.preflight())
            owner, method = ((transport, "_workflow_identity") if before == "preflight"
                             else (self.store, "claim_external_dispatch"))
            with mock.patch.object(owner, method, side_effect=SimulatedCrash), self.assertRaises(SimulatedCrash):
                self.coordinate(transport)
            self.assertEqual(self.row()["phase"], "PREPARED")
            self.assertEqual(len(opener.calls), 0 if before == "preflight" else 2)
        self.restart()
        self.assertEqual(self.row()["phase"], "PREPARED")

    def test_crash_after_claim_before_post_is_unknown_even_without_post(self):
        transport, opener = self.transport(self.preflight())
        with mock.patch.object(transport, "_dispatch_once", side_effect=SimulatedCrash), self.assertRaises(SimulatedCrash):
            self.coordinate(transport)
        self.assertEqual([c[0].method for c in opener.calls], ["GET", "GET"])
        self.restart()
        transport, opener = self.transport([])
        self.assertEqual(self.coordinate(transport).disposition, "BLOCKED_UNKNOWN")
        self.assertEqual(opener.calls, [])

    def test_crash_after_remote_acceptance_before_id_persistence_remains_unknown(self):
        transport, opener = self.transport(self.preflight() + [self.dispatch_response()])
        with mock.patch.object(self.store, "bind_external_operation", side_effect=SimulatedCrash), \
                self.assertRaises(SimulatedCrash):
            self.coordinate(transport)
        self.assertEqual([c[0].method for c in opener.calls], ["GET", "GET", "POST"])
        self.restart()
        transport, opener = self.transport([])
        self.assertEqual(self.coordinate(transport).disposition, "BLOCKED_UNKNOWN")
        self.assertEqual(opener.calls, [])

    def test_crash_during_polling_keeps_durable_id_for_observe_only(self):
        transport, opener = self.transport(self.preflight() + [self.dispatch_response()]
                                           + self.preflight() + [self.run_response(status="in_progress", conclusion=None)])
        with mock.patch.object(transport, "_sleep", side_effect=SimulatedCrash), self.assertRaises(SimulatedCrash):
            self.coordinate(transport)
        self.restart()
        self.assertEqual((self.row()["phase"], self.row()["remote_operation_id"]), ("RUN_IDENTIFIED", "431"))
        transport, opener = self.transport(self.preflight() + [self.run_response()])
        self.assertEqual(self.coordinate(transport).disposition, "TERMINAL_OBSERVED")
        self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_two_independent_coordinators_have_at_most_one_post(self):
        barrier = threading.Barrier(2)
        loser_done = threading.Event()
        outcomes, errors, calls, claims = [], [], [], []
        before = self.unrelated_rows()
        def worker():
            try:
                with Store(self.path) as store:
                    clock = FakeClock()
                    opener = FakeOpener(self.preflight() + [self.dispatch_response()]
                                        + self.preflight() + [self.run_response()], clock)
                    original_open = opener.open
                    def open_request(request, *, timeout):
                        if len(opener.calls) == 1:
                            barrier.wait(timeout=10)
                        if request.method == "POST":
                            if not loser_done.wait(timeout=10):
                                raise AssertionError("loser did not finish")
                        return original_open(request, timeout=timeout)
                    transport = backend.GitHubActionsTransport(self.config, lambda: "OFFLINE",
                        opener=opener, monotonic=clock.monotonic, sleep=clock.sleep)
                    original_claim = store.claim_external_dispatch
                    def claim(operation_id):
                        claimed = original_claim(operation_id)
                        claims.append(claimed)
                        return claimed
                    with mock.patch.object(opener, "open", side_effect=open_request), \
                            mock.patch.object(store, "claim_external_dispatch", side_effect=claim):
                        result = coordinate_github_operation(store, transport, "T-1", self.request, **self.limits)
                    outcomes.append(result)
                    calls.extend(c[0].method for c in opener.calls)
                    if result.disposition == "BLOCKED_UNKNOWN":
                        loser_done.set()
            except BaseException as error:
                errors.append(error)
                loser_done.set()
        workers = [threading.Thread(target=worker) for _ in range(2)]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join(timeout=20)
        self.assertFalse(any(thread.is_alive() for thread in workers))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(claims), [False, True])
        self.assertEqual(calls.count("POST"), 1)
        self.assertEqual(sorted(r.disposition for r in outcomes), ["BLOCKED_UNKNOWN", "TERMINAL_OBSERVED"])
        self.assertEqual(len({r.operation_id for r in outcomes}), 1)
        self.assertEqual(self.row()["phase"], "TERMINAL_OBSERVED")
        self.assertEqual(self.unrelated_rows(), before)


if __name__ == "__main__":
    unittest.main()
