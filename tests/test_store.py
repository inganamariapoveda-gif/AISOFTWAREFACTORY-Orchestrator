import inspect
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.state_machine import InvalidTransitionError  # noqa: E402
from orchestrator.store import (  # noqa: E402
    TASK_SUSPENSION_COLUMNS,
    InvalidIdError,
    Store,
    StoreError,
)


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = Path(self._tmp.name) / "test.db"
        self.store = Store(db_path)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()


class CandidateMaterializationStoreTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        from orchestrator import candidate_materialization as cm
        from dataclasses import asdict
        self.store.register_project("SAMPLE", "Sample", ".", "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need")
        root = str(Path(self._tmp.name).resolve())
        metadata = cm.CommitMetadata("candidate\n", "Test", "test@example.invalid", 1700000000,
                                     "+0000", "Test", "test@example.invalid", 1700000000, "+0000")
        self.intent = dict(materialization_key=cm.materialization_key("T-1", root, "task/test", "a" * 40),
            task_packet_sha256="b" * 64, repo_root=root, branch="task/test", base_head_sha="a" * 40,
            base_tree_sha="c" * 40, manifest_sha256=cm.digest(b"[]"), manifest_json="[]",
            commit_metadata_json=cm.canonical(asdict(metadata)))

    def prepare(self, **changes):
        return self.store.prepare_candidate_materialization("T-1", **dict(self.intent, **changes))

    def seal(self, operation_id, **changes):
        return self.store.seal_candidate_materialization(operation_id,
            **dict(dict(candidate_tree_sha="d" * 40, candidate_commit_sha="e" * 40), **changes))

    def test_candidate_prepare_replay_and_persisted_identity(self):
        row = self.prepare()
        self.assertEqual(row["phase"], "PREPARED")
        self.assertIsNone(row["candidate_tree_sha"])
        self.assertEqual(self.prepare(), row)
        with Store(Path(self._tmp.name) / "test.db") as other:
            self.assertEqual(other.get_candidate_materialization(row["id"]), row)
            self.assertEqual(other.get_candidate_materialization_by_key(self.intent["materialization_key"]), row)

    def test_candidate_same_key_different_intent_conflicts(self):
        row = self.prepare()
        for field, value in (("task_packet_sha256", "f" * 64), ("base_tree_sha", "f" * 40),
                             ("commit_metadata_json", self.intent["commit_metadata_json"].replace("candidate", "changed"))):
            with self.subTest(field=field), self.assertRaises(StoreError):
                self.prepare(**{field: value})
        self.assertEqual(self.store.get_candidate_materialization(row["id"]), row)

    def test_candidate_seal_idempotent_and_divergent_conflict(self):
        row = self.prepare()
        sealed = self.seal(row["id"])
        self.assertEqual(sealed["phase"], "SEALED")
        self.assertEqual(self.seal(row["id"]), sealed)
        self.assertEqual(self.prepare(), sealed)
        for field in ("candidate_tree_sha", "candidate_commit_sha"):
            with self.assertRaises(StoreError):
                self.seal(row["id"], **{field: "f" * 40})
        self.assertEqual(self.store.get_candidate_materialization(row["id"]), sealed)

    def test_candidate_invalid_data_and_schema_phases_fail_closed(self):
        for changes in ({"materialization_key": "x" * 64}, {"manifest_sha256": "d" * 64},
                        {"manifest_json": "[ ]"}, {"commit_metadata_json": "{}"}, {"unexpected": True}):
            with self.assertRaises(StoreError):
                self.prepare(**changes)
        row = self.prepare()
        for value in (True, 0, -1, "1"):
            with self.assertRaises(StoreError):
                self.store.get_candidate_materialization(value)
        for value in (None, "0" * 40, "A" * 40, "a" * 64):
            with self.assertRaises(StoreError):
                self.seal(row["id"], candidate_tree_sha=value)
        with self.assertRaises(StoreError):
            self.seal(999)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute("UPDATE candidate_materialization SET phase='INSTALLED'")
        self.store._conn.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute("UPDATE candidate_materialization SET phase='SEALED'")
        self.store._conn.rollback()

    def test_candidate_missing_task_and_no_state_budget_effects(self):
        from orchestrator.candidate_materialization import materialization_key
        missing = dict(self.intent, materialization_key=materialization_key(
            "MISSING", self.intent["repo_root"], self.intent["branch"], self.intent["base_head_sha"]))
        with self.assertRaises(StoreError):
            self.store.prepare_candidate_materialization("MISSING", **missing)
        before = self.store.get_task("T-1"), self.store.get_history("T-1"), self.store.list_agent_runs("T-1")
        self.seal(self.prepare()["id"])
        self.assertEqual(before, (self.store.get_task("T-1"), self.store.get_history("T-1"), self.store.list_agent_runs("T-1")))

    def race(self, action):
        barrier = threading.Barrier(2)
        results, errors = [], []
        def worker():
            try:
                with Store(Path(self._tmp.name) / "test.db") as other:
                    barrier.wait(timeout=10)
                    results.append(action(other))
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])

    def test_candidate_concurrent_prepare_converges(self):
        self.race(lambda store: store.prepare_candidate_materialization("T-1", **self.intent))
        self.assertEqual(self.store._conn.execute("SELECT count(*) FROM candidate_materialization").fetchone()[0], 1)

    def test_candidate_concurrent_seal_converges(self):
        row = self.prepare()
        self.race(lambda store: store.seal_candidate_materialization(row["id"],
            candidate_tree_sha="d" * 40, candidate_commit_sha="e" * 40))


class ExternalOperationStoreTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.store.register_project("SAMPLE", "Sample", ".", "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need")
        self.intent = dict(provider="github_actions", operation_type="workflow_dispatch",
                           operation_key="a" * 64, request_fingerprint="b" * 64)

    def prepare(self, **changes):
        return self.store.prepare_external_operation("T-1", **dict(self.intent, **changes))

    def identified(self):
        row = self.prepare()
        self.store.mark_external_dispatch_attempted(row["id"])
        return self.store.bind_external_operation(row["id"], remote_operation_id="431")

    def terminal(self, operation_id, **changes):
        return self.store.complete_external_operation(operation_id, **dict(
            dict(remote_operation_id="431", terminal_status="completed", terminal_result="success"), **changes))

    def test_prepared_durable_and_queries(self):
        row = self.prepare()
        self.assertEqual(row["phase"], "PREPARED")
        self.assertIsNone(row["remote_operation_id"])
        self.assertIsNone(row["terminal_status"])
        self.assertIsNone(row["terminal_result"])
        self.store.close()
        self.store = Store(Path(self._tmp.name) / "test.db")
        self.assertEqual(self.store.get_external_operation(row["id"]), row)
        self.assertEqual(self.store.get_external_operation_by_key("a" * 64), row)
        self.assertIsNone(self.store.get_external_operation_by_key("c" * 64))

    def test_intent_idempotent_and_conflicts(self):
        row = self.prepare()
        self.assertEqual(self.prepare(), row)
        for field, value in (("provider", "other"), ("operation_type", "other"),
                             ("request_fingerprint", "c" * 64)):
            with self.subTest(field=field), self.assertRaises(StoreError):
                self.prepare(**{field: value})
        self.store.create_task("T-2", "SAMPLE", "Other", "Need")
        with self.assertRaises(StoreError):
            self.store.prepare_external_operation("T-2", **self.intent)
        self.assertEqual(self.store.get_external_operation(row["id"]), row)

    def test_strict_hash_and_metadata_structure(self):
        for field in ("operation_key", "request_fingerprint"):
            for value in (None, True, 1, "A" * 64, "g" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n"):
                with self.subTest(field=field, value=value), self.assertRaises(StoreError):
                    self.prepare(**{field: value})
        for field in ("provider", "operation_type"):
            with self.subTest(field=field), self.assertRaises(StoreError) as error:
                self.prepare(**{field: "SECRET_SENTINEL\n"})
            self.assertNotIn("SECRET_SENTINEL", str(error.exception))
        for value in (True, 0, -1, "1", None):
            with self.subTest(value=value), self.assertRaises(StoreError):
                self.store.get_external_operation(value)
        with self.assertRaises(StoreError):
            self.store.prepare_external_operation("MISSING", **self.intent)

    def test_attempted_without_id_survives_restart_and_replay(self):
        row = self.prepare()
        attempted = self.store.mark_external_dispatch_attempted(row["id"])
        self.assertEqual(attempted["phase"], "DISPATCH_ATTEMPTED")
        self.assertIsNone(attempted["remote_operation_id"])
        self.store.close()
        self.store = Store(Path(self._tmp.name) / "test.db")
        self.assertEqual(self.prepare(), attempted)
        self.assertEqual(self.store.mark_external_dispatch_attempted(row["id"]), attempted)
        # No automatic operation replacement, phase reset or provider invocation.
        self.assertEqual(self.store._conn.execute("SELECT count(*) FROM external_operation").fetchone()[0], 1)

    def test_forward_only_no_skipped_phases(self):
        row = self.prepare()
        with self.assertRaises(StoreError):
            self.store.bind_external_operation(row["id"], remote_operation_id="431")
        with self.assertRaises(StoreError):
            self.terminal(row["id"])
        self.store.mark_external_dispatch_attempted(row["id"])
        with self.assertRaises(StoreError):
            self.terminal(row["id"])
        self.store.bind_external_operation(row["id"], remote_operation_id="431")
        with self.assertRaises(StoreError):
            self.store.mark_external_dispatch_attempted(row["id"])
        self.terminal(row["id"])
        with self.assertRaises(StoreError):
            self.store.bind_external_operation(row["id"], remote_operation_id="431")
        with self.assertRaises(StoreError):
            self.store.mark_external_dispatch_attempted(999)

    def test_binding_idempotent_conflicting_identity_rejected(self):
        row = self.identified()
        self.assertEqual(self.store.bind_external_operation(row["id"], remote_operation_id="431"), row)
        with self.assertRaises(StoreError):
            self.store.bind_external_operation(row["id"], remote_operation_id="432")
        self.assertEqual(self.store.get_external_operation(row["id"]), row)
        self.store.close()
        self.store = Store(Path(self._tmp.name) / "test.db")
        self.assertEqual(self.store.get_external_operation(row["id"]), row)

    def test_remote_identity_unique_within_provider_and_type(self):
        self.identified()
        other = self.prepare(operation_key="c" * 64)
        attempted = self.store.mark_external_dispatch_attempted(other["id"])
        with self.assertRaises(StoreError) as error:
            self.store.bind_external_operation(other["id"], remote_operation_id="431")
        self.assertIsNone(error.exception.__context__)
        self.assertEqual(self.store.get_external_operation(other["id"]), attempted)
        for changes in ({"provider": "other"}, {"operation_type": "other"}):
            key = "d" * 64 if "provider" in changes else "e" * 64
            row = self.prepare(operation_key=key, **changes)
            self.store.mark_external_dispatch_attempted(row["id"])
            self.store.bind_external_operation(row["id"], remote_operation_id="431")

    def test_terminal_idempotence_conflicts_and_restart(self):
        row = self.identified()
        with self.assertRaises(StoreError):
            self.terminal(row["id"], remote_operation_id="432")
        terminal = self.terminal(row["id"])
        self.assertEqual(terminal["phase"], "TERMINAL_OBSERVED")
        self.assertEqual(self.terminal(row["id"]), terminal)
        for changes in ({"terminal_result": "failure"}, {"terminal_status": "other"},
                        {"remote_operation_id": "432"}):
            with self.subTest(changes=changes), self.assertRaises(StoreError):
                self.terminal(row["id"], **changes)
        self.store.close()
        self.store = Store(Path(self._tmp.name) / "test.db")
        self.assertEqual(self.terminal(row["id"]), terminal)
        self.assertEqual(self.prepare(), terminal)

    def test_no_task_budget_history_or_approval_side_effects(self):
        task = self.store.get_task("T-1")
        history = self.store.get_history("T-1")
        result = self.terminal(self.identified()["id"])
        self.assertEqual(self.store.get_task("T-1"), task)
        self.assertEqual(self.store.get_history("T-1"), history)
        self.assertEqual(self.store.list_agent_runs("T-1"), [])
        self.assertIsNone(self.store.get_suspension("T-1"))
        self.assertFalse(set(result) & {"approval", "technical_approval", "human_approval", "token", "body"})

    def _race_external_writes(self, actions):
        # Independent connections, synchronized start, no sleeps or fixed winner.
        barrier = threading.Barrier(2)
        outcomes = [None, None]
        updates = [[], []]
        def worker(index):
            try:
                with Store(Path(self._tmp.name) / "test.db") as other:
                    other._conn.set_trace_callback(lambda sql: updates[index].append(sql)
                        if sql.startswith("UPDATE external_operation ") else None)
                    barrier.wait(timeout=10)
                    outcomes[index] = ("ok", actions[index](other))
            except Exception as error:
                outcomes[index] = ("error", error)
        workers = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=15)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertTrue(all(outcome is not None for outcome in outcomes))
        return outcomes, updates

    def test_concurrent_binding_same_operation_same_remote_id_is_idempotent(self):
        operation = self.prepare()
        self.store.mark_external_dispatch_attempted(operation["id"])
        action = lambda store: store.bind_external_operation(operation["id"], remote_operation_id="431")
        outcomes, updates = self._race_external_writes([action, action])
        self.assertEqual([kind for kind, _ in outcomes], ["ok", "ok"])
        final = self.store.get_external_operation(operation["id"])
        self.assertEqual(final["phase"], "RUN_IDENTIFIED")
        self.assertEqual(final["remote_operation_id"], "431")
        self.assertEqual([row for _, row in outcomes], [final, final])
        self.assertEqual(sum(map(len, updates)), 1)
        self.assertEqual(self.store._conn.execute("SELECT count(*) FROM external_operation").fetchone()[0], 1)

    def test_concurrent_binding_different_operations_same_remote_id_has_one_winner(self):
        operations = [self.prepare(), self.prepare(operation_key="c" * 64)]
        before = [self.store.mark_external_dispatch_attempted(row["id"]) for row in operations]
        actions = [lambda store, op_id=row["id"]: store.bind_external_operation(op_id, remote_operation_id="431")
                   for row in operations]
        outcomes, _ = self._race_external_writes(actions)
        self.assertEqual(sorted(kind for kind, _ in outcomes), ["error", "ok"])
        for index, (kind, value) in enumerate(outcomes):
            final = self.store.get_external_operation(operations[index]["id"])
            if kind == "ok":
                self.assertEqual(final, value)
                self.assertEqual(final["phase"], "RUN_IDENTIFIED")
                self.assertEqual(final["remote_operation_id"], "431")
            else:
                self.assertIs(type(value), StoreError)
                self.assertEqual(str(value), "external operation uniqueness or structure conflict")
                self.assertIsNone(value.__context__)
                self.assertEqual(final, before[index])
        self.assertEqual(self.store._conn.execute(
            "SELECT count(*) FROM external_operation WHERE remote_operation_id = '431'"
        ).fetchone()[0], 1)

    def test_concurrent_terminalization_identical_evidence_is_idempotent(self):
        operation = self.identified()
        action = lambda store: store.complete_external_operation(operation["id"],
            remote_operation_id="431", terminal_status="completed", terminal_result="success")
        outcomes, updates = self._race_external_writes([action, action])
        self.assertEqual([kind for kind, _ in outcomes], ["ok", "ok"])
        final = self.store.get_external_operation(operation["id"])
        self.assertEqual(final["phase"], "TERMINAL_OBSERVED")
        self.assertEqual((final["remote_operation_id"], final["terminal_status"], final["terminal_result"]),
                         ("431", "completed", "success"))
        self.assertEqual([row for _, row in outcomes], [final, final])
        self.assertEqual(sum(map(len, updates)), 1)

    def test_concurrent_terminalization_conflicting_evidence_has_one_winner(self):
        operation = self.identified()
        results = ["success", "failure"]
        actions = [lambda store, result=result: store.complete_external_operation(operation["id"],
            remote_operation_id="431", terminal_status="completed", terminal_result=result) for result in results]
        outcomes, updates = self._race_external_writes(actions)
        self.assertEqual(sorted(kind for kind, _ in outcomes), ["error", "ok"])
        final = self.store.get_external_operation(operation["id"])
        self.assertEqual(final["phase"], "TERMINAL_OBSERVED")
        self.assertEqual(final["remote_operation_id"], "431")
        self.assertEqual(final["terminal_status"], "completed")
        for index, (kind, value) in enumerate(outcomes):
            if kind == "ok":
                self.assertEqual(final, value)
                self.assertEqual(final["terminal_result"], results[index])
            else:
                self.assertIs(type(value), StoreError)
                self.assertEqual(str(value), "external operation phase conflict")
                self.assertNotEqual(final["terminal_result"], results[index])
        self.assertEqual(sum(map(len, updates)), 1)

    def test_concurrent_same_key_has_one_identity(self):
        barrier = threading.Barrier(2)
        results, errors = [], []
        def worker():
            try:
                with Store(Path(self._tmp.name) / "test.db") as other:
                    barrier.wait(timeout=10)
                    results.append(other.prepare_external_operation("T-1", **self.intent)["id"])
            except Exception as error:
                errors.append(type(error).__name__)
        workers = [threading.Thread(target=worker) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=15)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(len(set(results)), 1)

    def test_claim_dispatch_only_first_prepared_transition_authorizes(self):
        row = self.prepare()
        trace = []
        self.store._conn.set_trace_callback(trace.append)
        self.assertIs(self.store.claim_external_dispatch(row["id"]), True)
        attempted = self.store.get_external_operation(row["id"])
        self.assertEqual(attempted["phase"], "DISPATCH_ATTEMPTED")
        self.assertIs(self.store.claim_external_dispatch(row["id"]), False)
        self.assertEqual(self.store.get_external_operation(row["id"]), attempted)
        self.assertIn("BEGIN IMMEDIATE", trace)
        self.assertEqual(sum(sql.startswith("UPDATE external_operation ") for sql in trace), 1)
        self.store.bind_external_operation(row["id"], remote_operation_id="431")
        self.assertIs(self.store.claim_external_dispatch(row["id"]), False)
        self.terminal(row["id"])
        self.assertIs(self.store.claim_external_dispatch(row["id"]), False)

    def test_claim_missing_or_invalid_operation_fails_closed(self):
        for value in (999, True, 0, -1, "1", None):
            with self.subTest(value=value), self.assertRaises(StoreError):
                self.store.claim_external_dispatch(value)
        self.assertFalse(self.store._conn.in_transaction)

    def test_concurrent_dispatch_claim_has_one_winner_and_one_write(self):
        row = self.prepare()
        action = lambda store: store.claim_external_dispatch(row["id"])
        outcomes, updates = self._race_external_writes([action, action])
        self.assertEqual([kind for kind, _ in outcomes], ["ok", "ok"])
        self.assertEqual(sorted(value for _, value in outcomes), [False, True])
        self.assertEqual(sum(map(len, updates)), 1)
        self.assertEqual(self.store.get_external_operation(row["id"])["phase"], "DISPATCH_ATTEMPTED")


class ResourceBudgetStoreTests(StoreTestCase):
    def test_profile_correction_ceiling_isolated_from_invocation_limits(self):
        limits = self.policies["resource_budget"]["profiles"]["standard"]
        limits.update(max_builder_invocations=10, max_total_model_invocations=12, max_correction_attempts=2)
        self.assertGreater(self.policies["attempts"]["max_correction_attempts"], limits["max_correction_attempts"])
        self.reserve()
        self.assertEqual(self.store.get_task("T-1")["attempt_count"], 0)
        for count in (1, 2):
            self.store.transition_task("T-1", "AUTOMATED_TEST", "test", "test")
            self.store.transition_task("T-1", "CHANGES_REQUESTED", "test", "test")
            self.assertIsNotNone(self.reserve(phase="correction"))
            self.assertEqual(self.store.get_task("T-1")["attempt_count"], count)
        self.store.transition_task("T-1", "AUTOMATED_TEST", "test", "test")
        self.store.transition_task("T-1", "CHANGES_REQUESTED", "test", "test")
        before = self.store.list_agent_runs("T-1")
        self.assertLess(len(before), limits["max_builder_invocations"])
        self.assertLess(len(before), limits["max_total_model_invocations"])
        self.assertIsNone(self.reserve(phase="correction"))
        self.assertEqual(self.store.list_agent_runs("T-1"), before)
        self.assertEqual(self.store.get_task("T-1")["status"], "BLOCKED")
        event = self.store.get_history("T-1")[-1]
        self.assertEqual((event["from_status"], event["to_status"]), ("CHANGES_REQUESTED", "BLOCKED"))
        self.assertEqual(event["reason"], "resource budget exhausted")

    def setUp(self):
        super().setUp()
        import yaml
        self.policies = yaml.safe_load((REPO_ROOT / "config/POLICIES.yaml").read_text(encoding="utf-8"))
        self.store.register_project("SAMPLE", "Sample", ".", "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need")
        self.store.transition_task("T-1", "SPECIFICATION", "test", "test")
        self.store.transition_task("T-1", "DEVELOPING", "test", "test")

    def reserve(self, store=None, role="builder", phase=None):
        return (store or self.store).reserve_agent_run(
            "T-1", role=role, agent="developer" if role == "builder" else "verifier",
            provider="test_provider", phase=phase or ("implementation" if role == "builder" else "review"),
            resource_profile="standard", policies=self.policies,
        )

    def review_state(self):
        self.store.transition_task("T-1", "AUTOMATED_TEST", "test", "test")
        self.store.transition_task("T-1", "TECHNICAL_REVIEW", "test", "test")

    def test_builder_reserved_success_failure_and_restart_count(self):
        first = self.reserve()
        second = self.reserve()
        self.store.complete_agent_run(second, state="SUCCEEDED")
        third = self.reserve()
        self.store.complete_agent_run(third, state="FAILED")
        with Store(Path(self._tmp.name) / "test.db") as reopened:
            self.assertIsNone(self.reserve(reopened))
            runs = reopened.list_agent_runs("T-1")
        self.assertEqual([r["state"] for r in runs], ["RESERVED", "SUCCEEDED", "FAILED"])
        self.assertEqual([r["ordinal"] for r in runs], [1, 2, 3])
        self.assertTrue(all(r["task_id"] == "T-1" and r["role"] == "builder" for r in runs))
        self.assertFalse(set(runs[0]) & {"prompt", "stdout", "stderr", "result", "conversation"})
        self.assertIsNotNone(first)

    def test_verifier_limit(self):
        self.review_state()
        self.assertIsNotNone(self.reserve(role="verifier"))
        self.assertIsNotNone(self.reserve(role="verifier"))
        self.assertIsNone(self.reserve(role="verifier"))

    def test_total_limit_independent(self):
        self.policies["resource_budget"]["profiles"]["standard"]["max_total_model_invocations"] = 3
        self.reserve()
        self.reserve()
        self.review_state()
        self.assertIsNotNone(self.reserve(role="verifier"))
        self.assertIsNone(self.reserve(role="verifier"))

    def test_concurrent_reservations_are_bounded(self):
        barrier = threading.Barrier(5)
        outcomes, errors = [], []
        def worker():
            try:
                with Store(Path(self._tmp.name) / "test.db") as other:
                    barrier.wait(timeout=10)
                    outcomes.append(self.reserve(other))
            except Exception as exc:
                errors.append(type(exc).__name__)
        workers = [threading.Thread(target=worker) for _ in range(5)]
        for worker_thread in workers:
            worker_thread.start()
        for worker_thread in workers:
            worker_thread.join(timeout=15)
        self.assertEqual(errors, [])
        self.assertEqual(sum(value is not None for value in outcomes), 3)
        self.assertEqual(len(self.store.list_agent_runs("T-1")), 3)

    def test_policy_increase_cannot_refill_and_profile_cannot_change(self):
        for _ in range(3):
            self.reserve()
        self.policies["resource_budget"]["profiles"]["standard"]["max_builder_invocations"] = 4
        self.assertIsNone(self.reserve())
        with self.assertRaises(StoreError):
            self.store.reserve_agent_run("T-1", role="builder", agent="developer", provider="test",
                phase="implementation", resource_profile="high_assurance", policies=self.policies)

    def test_corrections_and_capacity_are_separate(self):
        self.reserve()
        self.assertEqual(self.store.get_task("T-1")["attempt_count"], 0)
        for _ in range(2):
            self.store.transition_task("T-1", "AUTOMATED_TEST", "test", "test")
            self.store.transition_task("T-1", "CHANGES_REQUESTED", "test", "test")
            self.assertIsNotNone(self.reserve(phase="correction"))
        self.assertEqual(self.store.get_task("T-1")["attempt_count"], 2)
        self.store.transition_task("T-1", "AUTOMATED_TEST", "test", "test")
        self.store.transition_task("T-1", "CHANGES_REQUESTED", "test", "test")
        self.assertIsNone(self.reserve(phase="correction"))


class ProjectAndTaskCreationTests(StoreTestCase):
    def test_create_project_and_task(self) -> None:
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need text")
        task = self.store.get_task("T-1")
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task["status"], "BACKLOG")
        self.assertEqual(task["project_id"], "SAMPLE")
        self.assertEqual(task["attempt_count"], 0)

    def test_create_task_without_project_fails(self) -> None:
        with self.assertRaises(StoreError):
            self.store.create_task("T-1", "MISSING", "Title", "Need")

    def test_duplicate_project_fails(self) -> None:
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")
        with self.assertRaises(StoreError):
            self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")


class TransitionPersistenceTests(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need text")

    def test_valid_transition_persists(self) -> None:
        task = self.store.transition_task("T-1", "SPECIFICATION", "director takes task", "director")
        self.assertEqual(task["status"], "SPECIFICATION")

    def test_status_event_is_recorded(self) -> None:
        self.store.transition_task("T-1", "SPECIFICATION", "director takes task", "director")
        history = self.store.get_history("T-1")
        self.assertEqual(len(history), 2)  # creación + transición
        self.assertEqual(history[0]["from_status"], None)
        self.assertEqual(history[0]["to_status"], "BACKLOG")
        self.assertEqual(history[1]["from_status"], "BACKLOG")
        self.assertEqual(history[1]["to_status"], "SPECIFICATION")
        self.assertEqual(history[1]["reason"], "director takes task")
        self.assertEqual(history[1]["actor"], "director")

    def test_invalid_transition_does_not_alter_state(self) -> None:
        before = self.store.get_task("T-1")
        assert before is not None
        with self.assertRaises(InvalidTransitionError):
            self.store.transition_task("T-1", "COMPLETED", "skip ahead", "operator")
        after = self.store.get_task("T-1")
        assert after is not None
        self.assertEqual(before["status"], after["status"])
        self.assertEqual(before["updated_at"], after["updated_at"])

    def test_invalid_transition_does_not_add_status_event(self) -> None:
        history_before = self.store.get_history("T-1")
        with self.assertRaises(InvalidTransitionError):
            self.store.transition_task("T-1", "COMPLETED", "skip ahead", "operator")
        history_after = self.store.get_history("T-1")
        self.assertEqual(len(history_before), len(history_after))

    def test_history_reconstructs_full_sequence(self) -> None:
        self.store.transition_task("T-1", "SPECIFICATION", "r1", "director")
        self.store.transition_task("T-1", "DEVELOPING", "r2", "director")
        self.store.transition_task("T-1", "AUTOMATED_TEST", "r3", "motor")
        history = self.store.get_history("T-1")
        sequence = [(event["from_status"], event["to_status"]) for event in history]
        self.assertEqual(
            sequence,
            [
                (None, "BACKLOG"),
                ("BACKLOG", "SPECIFICATION"),
                ("SPECIFICATION", "DEVELOPING"),
                ("DEVELOPING", "AUTOMATED_TEST"),
            ],
        )


class InvalidIdTests(StoreTestCase):
    def test_invalid_project_id_rejected(self) -> None:
        for bad_id in ["../etc", "id with spaces", "id;drop table", "", "a" * 100]:
            with self.assertRaises(InvalidIdError):
                self.store.register_project(bad_id, "Name", "./x", "ref")

    def test_invalid_task_id_rejected(self) -> None:
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")
        for bad_id in ["../etc", "id with spaces", "id;drop table", ""]:
            with self.assertRaises(InvalidIdError):
                self.store.create_task(bad_id, "SAMPLE", "Title", "Need")

    def test_invalid_id_rejected_on_get_and_transition(self) -> None:
        with self.assertRaises(InvalidIdError):
            self.store.get_task("bad id")
        with self.assertRaises(InvalidIdError):
            self.store.transition_task("bad id", "SPECIFICATION", "r", "a")


# ============================================================
# CAPACITY-RESUME-FOUNDATION-001: get_project, task_suspension, suspensión y
# reclamo ATÓMICOS. Todos los tests usan bases SQLite TEMPORALES: nunca se
# crea orchestrator.db real ni se conecta nada al executor.
# ============================================================

WAITING = "WAITING_FOR_CLAUDE_CAPACITY"
T0 = "2026-01-01T10:00:00+00:00"
T1 = "2026-01-01T10:30:00+00:00"
T2 = "2026-01-01T11:00:00+00:00"

# Nada de esto puede existir como columna: Store no persiste datos de Claude.
FORBIDDEN_COLUMN_WORDS = (
    "stdout",
    "stderr",
    "prompt",
    "result",
    "session",
    "usage",
    "modelusage",
    "credential",
    "reason",
    "transcript",
    "project_id",
    "failure_category",
    "created_at",
)


def _suspension_fields(**overrides) -> dict:
    fields = {
        "task_packet_path": "tasks/T_1.yaml",
        "task_packet_sha256": "1" * 64,
        "project_rules_sha256": "2" * 64,
        "permissions_sha256": "3" * 64,
        "baseline_head_sha": "b" * 40,
        "baseline_branch": "main",
        "working_tree_fingerprint": "a" * 64,
        "touched_paths": ["src/a.ts", "src/b.ts"],
        "capacity_wait_count": 1,
        "capacity_wait_started_at": T0,
        "next_retry_at": T1,
    }
    fields.update(overrides)
    return fields


def _suspend_fields(**overrides) -> dict:
    return {"reason": "temporary limit", "actor": "orchestrator", **_suspension_fields(**overrides)}


class SuspensionTestCase(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.db_path = Path(self._tmp.name) / "test.db"

    def make_task(self, task_id: str = "T-1", *, status: str = "DEVELOPING") -> None:
        if self.store.get_project("SAMPLE") is None:
            self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")
        self.store.create_task(task_id, "SAMPLE", "Title", "Need text")
        if status == "BACKLOG":
            return
        self.store.transition_task(task_id, "SPECIFICATION", "setup", "director")
        if status == "SPECIFICATION":
            return
        self.store.transition_task(task_id, "DEVELOPING", "setup", "director")

    def task_status(self, task_id: str = "T-1") -> str:
        task = self.store.get_task(task_id)
        assert task is not None
        return task["status"]


class GetProjectTests(StoreTestCase):
    def test_returns_none_for_unknown_project_and_creates_nothing(self) -> None:
        self.assertIsNone(self.store.get_project("SAMPLE"))
        self.assertIsNone(self.store.get_project("SAMPLE"))
        rows = self.store._conn.execute("SELECT COUNT(*) FROM project").fetchone()
        self.assertEqual(rows[0], 0)

    def test_returns_the_registered_project_unchanged(self) -> None:
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref-1")
        before = self.store._conn.execute("SELECT * FROM project").fetchall()
        project = self.store.get_project("SAMPLE")
        assert project is not None
        self.assertEqual(project["id"], "SAMPLE")
        self.assertEqual(project["name"], "Sample")
        self.assertEqual(project["repo_path"], "./projects/SAMPLE")
        self.assertEqual(project["rules_ref"], "ref-1")
        self.assertIn("created_at", project)
        self.assertEqual(self.store._conn.execute("SELECT * FROM project").fetchall(), before)

    def test_invalid_ids_are_rejected_before_any_query(self) -> None:
        for bad in ("../etc", "id with spaces", "x'; DROP TABLE project;--", "", "a" * 100):
            with self.subTest(project_id=bad):
                with self.assertRaises(InvalidIdError):
                    self.store.get_project(bad)


class TaskSuspensionSchemaTests(SuspensionTestCase):
    def columns(self, table: str) -> list[tuple[str, str, int]]:
        rows = self.store._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [(row[1], row[2], row[3]) for row in rows]  # name, type, notnull

    def test_new_table_is_created_automatically(self) -> None:
        tables = {
            row[0]
            for row in self.store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertLessEqual({"project", "task", "status_event", "task_suspension"}, tables)

    def test_task_suspension_columns_are_exactly_the_approved_thirteen(self) -> None:
        names = [name for name, _type, _nn in self.columns("task_suspension")]
        self.assertEqual(
            names,
            [
                "task_id",
                "task_packet_path",
                "task_packet_sha256",
                "project_rules_sha256",
                "permissions_sha256",
                "baseline_head_sha",
                "baseline_branch",
                "working_tree_fingerprint",
                "touched_paths_json",
                "capacity_wait_count",
                "capacity_wait_started_at",
                "next_retry_at",
                "updated_at",
            ],
        )
        self.assertEqual(list(TASK_SUSPENSION_COLUMNS), names)
        for name, sql_type, not_null in self.columns("task_suspension"):
            # Las 13 columnas son NOT NULL, incluida task_id (CORRECTION-001:
            # SQLite no lo impone implícitamente a una PK de tipo TEXT).
            self.assertEqual(not_null, 1, name)
            self.assertEqual(sql_type, "INTEGER" if name == "capacity_wait_count" else "TEXT", name)

    def test_task_id_is_explicitly_not_null_primary_key_and_foreign_key(self) -> None:
        # Comprobación DIRECTA en SQLite (PRAGMA), sin depender de la
        # validación de las APIs de Python.
        info = {
            row[1]: row
            for row in self.store._conn.execute("PRAGMA table_info(task_suspension)")
        }
        task_id = info["task_id"]  # (cid, name, type, notnull, dflt_value, pk)
        self.assertEqual(task_id[3], 1, "task_id must be NOT NULL")
        self.assertEqual(task_id[5], 1, "task_id must be the PRIMARY KEY")
        self.assertEqual([n for n, row in info.items() if row[5]], ["task_id"])
        foreign_keys = [
            (row[2], row[3], row[4])  # (tabla referenciada, columna local, columna referenciada)
            for row in self.store._conn.execute("PRAGMA foreign_key_list(task_suspension)")
        ]
        self.assertEqual(foreign_keys, [("task", "task_id", "id")])
        self.assertEqual(self.store._conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_direct_insert_with_null_task_id_is_rejected_by_sqlite(self) -> None:
        # SQL directo, saltándose por completo cualquier validación de Store.
        self.make_task()
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.store._conn.execute(
                "INSERT INTO task_suspension VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (None, "p", "1" * 64, "2" * 64, "3" * 64, "b" * 40, "m", "a" * 64, "[]", 1, T0, T1, T0),
            )
        self.assertIn("NOT NULL", str(ctx.exception))
        self.store._conn.rollback()
        rows = self.store._conn.execute("SELECT COUNT(*) FROM task_suspension").fetchone()
        self.assertEqual(rows[0], 0)

    def test_existing_tables_keep_their_exact_columns(self) -> None:
        self.assertEqual(
            [c[0] for c in self.columns("project")],
            ["id", "name", "repo_path", "rules_ref", "created_at"],
        )
        self.assertEqual(
            [c[0] for c in self.columns("task")],
            [
                "id",
                "project_id",
                "title",
                "need_text",
                "status",
                "attempt_count",
                "created_at",
                "updated_at",
            ],
        )
        self.assertEqual(
            [c[0] for c in self.columns("status_event")],
            ["id", "task_id", "from_status", "to_status", "reason", "actor", "created_at"],
        )

    def test_no_sensitive_claude_data_columns_exist(self) -> None:
        names = [name.lower() for name, _t, _n in self.columns("task_suspension")]
        for word in FORBIDDEN_COLUMN_WORDS:
            for name in names:
                self.assertNotIn(word, name, f"forbidden column {name!r}")

    def test_foreign_keys_are_enforced(self) -> None:
        self.assertEqual(self.store._conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute(
                "INSERT INTO task_suspension VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("NOPE", "p", "1" * 64, "2" * 64, "3" * 64, "b" * 40, "m", "a" * 64, "[]", 1, T0, T1, T0),
            )
        self.store._conn.rollback()

    def test_capacity_wait_count_check_constraint(self) -> None:
        self.make_task()
        for bad in (0, -1):
            with self.subTest(count=bad):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.store._conn.execute(
                        "INSERT INTO task_suspension VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        ("T-1", "p", "1" * 64, "2" * 64, "3" * 64, "b" * 40, "m", "a" * 64, "[]", bad, T0, T1, T0),
                    )
                self.store._conn.rollback()

    def test_opening_a_legacy_database_adds_the_table_without_altering_old_data(self) -> None:
        legacy = Path(self._tmp.name) / "legacy.db"
        conn = sqlite3.connect(str(legacy))
        conn.executescript(
            """
            CREATE TABLE project (id TEXT PRIMARY KEY, name TEXT NOT NULL, repo_path TEXT NOT NULL,
                rules_ref TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE task (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id),
                title TEXT NOT NULL, need_text TEXT NOT NULL, status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE status_event (id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL REFERENCES task(id), from_status TEXT, to_status TEXT NOT NULL,
                reason TEXT, actor TEXT NOT NULL, created_at TEXT NOT NULL);
            INSERT INTO project VALUES ('OLD', 'Old', './old', 'ref', '2025-01-01T00:00:00+00:00');
            INSERT INTO task VALUES ('OLD-1', 'OLD', 't', 'n', 'BLOCKED', 2, 'c', 'u');
            """
        )
        conn.commit()
        conn.close()
        with Store(legacy) as store:
            task = store.get_task("OLD-1")
            assert task is not None
            self.assertEqual((task["status"], task["attempt_count"]), ("BLOCKED", 2))
            self.assertIsNone(store.get_suspension("OLD-1"))
            self.assertIn(
                "task_suspension",
                {r[0] for r in store._conn.execute("SELECT name FROM sqlite_master")},
            )
            # La tabla nueva nace con task_id NOT NULL + PRIMARY KEY explícitos.
            task_id = {
                row[1]: row for row in store._conn.execute("PRAGMA table_info(task_suspension)")
            }["task_id"]
            self.assertEqual((task_id[3], task_id[5]), (1, 1))
            # Las tablas anteriores no se recrearon ni se alteraron.
            project = store.get_project("OLD")
            assert project is not None
            self.assertEqual(project["repo_path"], "./old")
            self.assertEqual(
                [row[1] for row in store._conn.execute("PRAGMA table_info(task)")],
                [
                    "id",
                    "project_id",
                    "title",
                    "need_text",
                    "status",
                    "attempt_count",
                    "created_at",
                    "updated_at",
                ],
            )

    def test_tests_never_create_the_real_database(self) -> None:
        self.assertFalse((REPO_ROOT / "orchestrator.db").exists())


class SuspensionCrudTests(SuspensionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.make_task()

    def test_create_and_read(self) -> None:
        created = self.store.create_suspension("T-1", **_suspension_fields())
        read = self.store.get_suspension("T-1")
        self.assertEqual(created, read)
        assert read is not None
        self.assertEqual(read["task_id"], "T-1")
        self.assertEqual(read["baseline_head_sha"], "b" * 40)
        self.assertEqual(json.loads(read["touched_paths_json"]), ["src/a.ts", "src/b.ts"])
        self.assertEqual(read["capacity_wait_count"], 1)
        self.assertEqual(read["capacity_wait_started_at"], T0)
        self.assertEqual(read["next_retry_at"], T1)
        self.assertEqual(set(read), set(TASK_SUSPENSION_COLUMNS))
        # create no cambia el estado de la tarea.
        self.assertEqual(self.task_status(), "DEVELOPING")

    def test_get_returns_none_when_absent(self) -> None:
        self.assertIsNone(self.store.get_suspension("T-1"))

    def test_duplicate_fails_closed_and_keeps_the_original(self) -> None:
        self.store.create_suspension("T-1", **_suspension_fields())
        with self.assertRaises(StoreError):
            self.store.create_suspension("T-1", **_suspension_fields(capacity_wait_count=5))
        stored = self.store.get_suspension("T-1")
        assert stored is not None
        self.assertEqual(stored["capacity_wait_count"], 1)

    def test_create_for_missing_task_fails(self) -> None:
        with self.assertRaises(StoreError):
            self.store.create_suspension("NOPE-1", **_suspension_fields())
        self.assertIsNone(self.store.get_suspension("NOPE-1"))

    def test_update_changes_only_the_mutable_fields(self) -> None:
        created = self.store.create_suspension("T-1", **_suspension_fields())
        updated = self.store.update_suspension(
            "T-1",
            working_tree_fingerprint="c" * 64,
            touched_paths=["src/a.ts", "src/c.ts"],
            capacity_wait_count=2,
            next_retry_at=T2,
        )
        self.assertEqual(updated["working_tree_fingerprint"], "c" * 64)
        self.assertEqual(json.loads(updated["touched_paths_json"]), ["src/a.ts", "src/c.ts"])
        self.assertEqual(updated["capacity_wait_count"], 2)
        self.assertEqual(updated["next_retry_at"], T2)
        for immutable in (
            "task_packet_path",
            "task_packet_sha256",
            "project_rules_sha256",
            "permissions_sha256",
            "baseline_head_sha",
            "baseline_branch",
            "capacity_wait_started_at",
        ):
            self.assertEqual(updated[immutable], created[immutable], immutable)

    def test_update_cannot_touch_identity_fields(self) -> None:
        self.store.create_suspension("T-1", **_suspension_fields())
        with self.assertRaises(TypeError):
            self.store.update_suspension(  # type: ignore[call-arg]
                "T-1",
                working_tree_fingerprint="c" * 64,
                touched_paths=[],
                capacity_wait_count=2,
                next_retry_at=T2,
                baseline_head_sha="d" * 40,
            )

    def test_update_may_keep_the_same_counter(self) -> None:
        # update_suspension actualiza metadata de la suspensión EXISTENTE sin
        # representar un nuevo evento de capacidad: el contador puede quedar
        # igual (a diferencia de suspend_for_capacity, que exige incremento).
        self.store.create_suspension("T-1", **_suspension_fields(capacity_wait_count=3))
        updated = self.store.update_suspension(
            "T-1",
            working_tree_fingerprint="c" * 64,
            touched_paths=["src/a.ts"],
            capacity_wait_count=3,
            next_retry_at=T2,
        )
        self.assertEqual(updated["capacity_wait_count"], 3)
        self.assertEqual(updated["working_tree_fingerprint"], "c" * 64)
        self.assertEqual(updated["next_retry_at"], T2)

    def test_update_never_decreases_the_counter(self) -> None:
        self.store.create_suspension("T-1", **_suspension_fields(capacity_wait_count=3))
        with self.assertRaises(StoreError):
            self.store.update_suspension(
                "T-1",
                working_tree_fingerprint="c" * 64,
                touched_paths=[],
                capacity_wait_count=2,
                next_retry_at=T2,
            )
        stored = self.store.get_suspension("T-1")
        assert stored is not None
        self.assertEqual(stored["capacity_wait_count"], 3)

    def test_update_and_delete_of_missing_suspension_fail(self) -> None:
        with self.assertRaises(StoreError):
            self.store.update_suspension(
                "T-1",
                working_tree_fingerprint="c" * 64,
                touched_paths=[],
                capacity_wait_count=2,
                next_retry_at=T2,
            )
        with self.assertRaises(StoreError):
            self.store.delete_suspension("T-1")

    def test_delete_removes_only_the_suspension(self) -> None:
        self.store.create_suspension("T-1", **_suspension_fields())
        history_before = self.store.get_history("T-1")
        self.store.delete_suspension("T-1")
        self.assertIsNone(self.store.get_suspension("T-1"))
        self.assertEqual(self.task_status(), "DEVELOPING")
        self.assertEqual(self.store.get_history("T-1"), history_before)
        with self.assertRaises(StoreError):
            self.store.delete_suspension("T-1")

    def test_invalid_values_are_rejected(self) -> None:
        bad_cases = {
            "task_packet_sha256": "not-a-hash",
            "project_rules_sha256": "A" * 64,  # mayúsculas: no es hex canónico
            "permissions_sha256": "3" * 63,
            "baseline_head_sha": "b" * 39,
            "working_tree_fingerprint": "z" * 64,
            "task_packet_path": "",
            "capacity_wait_started_at": "yesterday",
            "next_retry_at": "2026-01-01T10:30:00",  # sin zona horaria
            "capacity_wait_count": 0,
            "touched_paths": "src/a.ts",  # un str no es una lista de paths
        }
        for field, value in bad_cases.items():
            with self.subTest(field=field):
                with self.assertRaises(StoreError):
                    self.store.create_suspension("T-1", **_suspension_fields(**{field: value}))
        for count in (True, False, 1.0, "1"):
            with self.subTest(count=count):
                with self.assertRaises(StoreError):
                    self.store.create_suspension(
                        "T-1", **_suspension_fields(capacity_wait_count=count)
                    )
        self.assertIsNone(self.store.get_suspension("T-1"))

    def test_detached_head_baseline_branch_may_be_empty(self) -> None:
        created = self.store.create_suspension("T-1", **_suspension_fields(baseline_branch=""))
        self.assertEqual(created["baseline_branch"], "")

    def test_invalid_task_ids_are_rejected(self) -> None:
        for bad in ("../x", "a b", "x'; DROP TABLE task_suspension;--"):
            with self.subTest(task_id=bad):
                with self.assertRaises(InvalidIdError):
                    self.store.get_suspension(bad)
                with self.assertRaises(InvalidIdError):
                    self.store.create_suspension(bad, **_suspension_fields())
                with self.assertRaises(InvalidIdError):
                    self.store.delete_suspension(bad)


class AtomicSuspendTests(SuspensionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.make_task()

    def test_first_suspension_is_atomic_and_complete(self) -> None:
        task = self.store.suspend_for_capacity("T-1", **_suspend_fields())
        self.assertEqual(task["status"], WAITING)
        suspension = self.store.get_suspension("T-1")
        assert suspension is not None
        self.assertEqual(suspension["capacity_wait_count"], 1)
        self.assertEqual(suspension["baseline_head_sha"], "b" * 40)
        events = self.store.get_history("T-1")
        self.assertEqual(
            (events[-1]["from_status"], events[-1]["to_status"]), ("DEVELOPING", WAITING)
        )
        self.assertEqual(events[-1]["reason"], "temporary limit")
        self.assertEqual(events[-1]["actor"], "orchestrator")

    def test_only_developing_can_be_suspended_and_nothing_is_written_otherwise(self) -> None:
        self.make_task("T-2", status="BACKLOG")
        history_before = self.store.get_history("T-2")
        with self.assertRaises(InvalidTransitionError):
            self.store.suspend_for_capacity("T-2", **_suspend_fields())
        self.assertEqual(self.task_status("T-2"), "BACKLOG")
        self.assertIsNone(self.store.get_suspension("T-2"))
        self.assertEqual(self.store.get_history("T-2"), history_before)

    def test_missing_task_fails(self) -> None:
        with self.assertRaises(StoreError):
            self.store.suspend_for_capacity("NOPE-1", **_suspend_fields())

    def test_failure_midway_rolls_back_everything(self) -> None:
        # Si la transición falla DESPUÉS de escribir la suspensión, no debe
        # quedar NADA: ni fila, ni evento, ni cambio de estado.
        history_before = self.store.get_history("T-1")

        def boom(*args, **kwargs):
            raise StoreError("simulated failure after the suspension was written")

        self.store._transition_locked = boom  # type: ignore[method-assign]
        with self.assertRaises(StoreError):
            self.store.suspend_for_capacity("T-1", **_suspend_fields())
        del self.store._transition_locked
        self.assertIsNone(self.store.get_suspension("T-1"))
        self.assertEqual(self.task_status(), "DEVELOPING")
        self.assertEqual(self.store.get_history("T-1"), history_before)
        # Y el Store sigue siendo utilizable tras el rollback.
        self.store.suspend_for_capacity("T-1", **_suspend_fields())
        self.assertEqual(self.task_status(), WAITING)

    def test_subsequent_suspension_after_a_resume_updates_the_same_row(self) -> None:
        self.store.suspend_for_capacity("T-1", **_suspend_fields())
        self.store.claim_capacity_resume("T-1", reason="resume", actor="orchestrator")
        task = self.store.suspend_for_capacity(
            "T-1",
            **_suspend_fields(
                working_tree_fingerprint="c" * 64,
                touched_paths=["src/a.ts", "src/b.ts", "src/c.ts"],
                capacity_wait_count=2,
                next_retry_at=T2,
            ),
        )
        self.assertEqual(task["status"], WAITING)
        suspension = self.store.get_suspension("T-1")
        assert suspension is not None
        self.assertEqual(suspension["capacity_wait_count"], 2)
        self.assertEqual(suspension["working_tree_fingerprint"], "c" * 64)
        self.assertEqual(suspension["next_retry_at"], T2)
        # Baseline original e inicio de la espera: intactos.
        self.assertEqual(suspension["baseline_head_sha"], "b" * 40)
        self.assertEqual(suspension["capacity_wait_started_at"], T0)
        rows = self.store._conn.execute("SELECT COUNT(*) FROM task_suspension").fetchone()
        self.assertEqual(rows[0], 1)
        sequence = [(e["from_status"], e["to_status"]) for e in self.store.get_history("T-1")]
        self.assertEqual(
            sequence[-3:],
            [("DEVELOPING", WAITING), (WAITING, "DEVELOPING"), ("DEVELOPING", WAITING)],
        )

    def test_a_later_suspension_can_never_overwrite_the_original_baseline(self) -> None:
        self.store.suspend_for_capacity("T-1", **_suspend_fields())
        self.store.claim_capacity_resume("T-1", reason="resume", actor="orchestrator")
        for field, value in (
            ("baseline_head_sha", "d" * 40),
            ("baseline_branch", "other"),
            ("task_packet_sha256", "9" * 64),
            ("project_rules_sha256", "9" * 64),
            ("permissions_sha256", "9" * 64),
            ("task_packet_path", "tasks/OTHER.yaml"),
            ("capacity_wait_started_at", T2),
        ):
            with self.subTest(field=field):
                with self.assertRaises(StoreError):
                    self.store.suspend_for_capacity(
                        "T-1", **_suspend_fields(capacity_wait_count=2, **{field: value})
                    )
                self.assertEqual(self.task_status(), "DEVELOPING")  # nada cambió
        stored = self.store.get_suspension("T-1")
        assert stored is not None
        self.assertEqual(stored["baseline_head_sha"], "b" * 40)
        self.assertEqual(stored["capacity_wait_count"], 1)

    def test_a_later_suspension_must_increase_the_counter(self) -> None:
        self.store.suspend_for_capacity("T-1", **_suspend_fields(capacity_wait_count=2))
        self.store.claim_capacity_resume("T-1", reason="resume", actor="orchestrator")
        with self.assertRaises(StoreError):
            self.store.suspend_for_capacity("T-1", **_suspend_fields(capacity_wait_count=2))
        self.assertEqual(self.task_status(), "DEVELOPING")

    def test_signature_has_no_place_for_claude_data(self) -> None:
        names = set(inspect.signature(Store.suspend_for_capacity).parameters)
        for word in FORBIDDEN_COLUMN_WORDS:
            if word in ("reason", "created_at", "project_id"):
                continue  # `reason` es el motivo FIJO de status_event, no un dato de Claude
            for name in names:
                self.assertNotIn(word, name.lower())
        with self.assertRaises(TypeError):
            self.store.suspend_for_capacity("T-1", **_suspend_fields(), stdout="x")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            self.store.suspend_for_capacity("T-1", **_suspend_fields(), session_id="x")  # type: ignore[call-arg]

    def test_reason_and_actor_are_validated_and_bounded(self) -> None:
        for override in ({"reason": ""}, {"actor": ""}, {"reason": "x" * 501}):
            with self.subTest(override=override):
                with self.assertRaises(StoreError):
                    self.store.suspend_for_capacity("T-1", **{**_suspend_fields(), **override})
        self.assertEqual(self.task_status(), "DEVELOPING")


class AtomicClaimTests(SuspensionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.make_task()
        self.store.suspend_for_capacity("T-1", **_suspend_fields())

    def test_claim_moves_waiting_to_developing_and_keeps_the_suspension(self) -> None:
        before = self.store.get_suspension("T-1")
        events_before = len(self.store.get_history("T-1"))
        task = self.store.claim_capacity_resume("T-1", reason="resume", actor="orchestrator")
        self.assertEqual(task["status"], "DEVELOPING")
        # La fila task_suspension se CONSERVA, intacta (ni siquiera updated_at).
        self.assertEqual(self.store.get_suspension("T-1"), before)
        events = self.store.get_history("T-1")
        self.assertEqual(len(events), events_before + 1)
        self.assertEqual(
            (events[-1]["from_status"], events[-1]["to_status"]), (WAITING, "DEVELOPING")
        )
        self.assertEqual(events[-1]["reason"], "resume")
        self.assertEqual(events[-1]["actor"], "orchestrator")

    def test_second_claim_fails_closed(self) -> None:
        self.store.claim_capacity_resume("T-1", reason="resume", actor="a")
        events_before = len(self.store.get_history("T-1"))
        with self.assertRaises(StoreError):
            self.store.claim_capacity_resume("T-1", reason="resume again", actor="b")
        self.assertEqual(len(self.store.get_history("T-1")), events_before)
        self.assertEqual(self.task_status(), "DEVELOPING")

    def test_claim_requires_existing_task_waiting_state_and_active_suspension(self) -> None:
        with self.assertRaises(StoreError):
            self.store.claim_capacity_resume("NOPE-1", reason="r", actor="a")

        self.make_task("T-2")  # DEVELOPING, nunca suspendida
        with self.assertRaises(StoreError):
            self.store.claim_capacity_resume("T-2", reason="r", actor="a")
        self.assertEqual(self.task_status("T-2"), "DEVELOPING")

        # WAITING pero SIN suspensión activa: fail closed, estado intacto.
        self.store.delete_suspension("T-1")
        with self.assertRaises(StoreError):
            self.store.claim_capacity_resume("T-1", reason="r", actor="a")
        self.assertEqual(self.task_status("T-1"), WAITING)

    def test_claim_uses_a_conditional_update_on_the_current_status(self) -> None:
        source = inspect.getsource(sys.modules[Store.__module__])
        self.assertIn("WHERE id = ? AND status = ?", source)

    def test_two_connections_only_one_wins(self) -> None:
        other = Store(self.db_path)
        try:
            self.store.claim_capacity_resume("T-1", reason="resume", actor="first")
            with self.assertRaises(StoreError):
                other.claim_capacity_resume("T-1", reason="resume", actor="second")
        finally:
            other.close()
        claims = [
            e
            for e in self.store.get_history("T-1")
            if (e["from_status"], e["to_status"]) == (WAITING, "DEVELOPING")
        ]
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["actor"], "first")

    def test_concurrent_claims_from_many_threads_have_exactly_one_winner(self) -> None:
        contenders = 8
        barrier = threading.Barrier(contenders)
        outcomes: list[str] = []
        lock = threading.Lock()

        def claim(index: int) -> None:
            store = Store(self.db_path)  # una conexión por hilo
            try:
                barrier.wait(timeout=10)
                try:
                    store.claim_capacity_resume("T-1", reason="resume", actor=f"worker-{index}")
                    result = "won"
                except StoreError:
                    result = "lost"
            finally:
                store.close()
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=claim, args=(i,)) for i in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(outcomes), ["lost"] * (contenders - 1) + ["won"])
        claims = [
            e
            for e in self.store.get_history("T-1")
            if (e["from_status"], e["to_status"]) == (WAITING, "DEVELOPING")
        ]
        self.assertEqual(len(claims), 1)
        self.assertEqual(self.task_status(), "DEVELOPING")
        self.assertIsNotNone(self.store.get_suspension("T-1"))


HUMAN_GATE_CHAIN = [
    ("DEVELOPING", "AUTOMATED_TEST"),
    ("AUTOMATED_TEST", "TECHNICAL_REVIEW"),
    ("TECHNICAL_REVIEW", "SECURITY_REVIEW"),
    ("SECURITY_REVIEW", "HUMAN_GATE"),
]


class AtomicFinalizationTests(SuspensionTestCase):
    """CAPACITY-RESUME-EXECUTION-002: finalización y bloqueo ATÓMICOS.
    Cada primitiva es una sola transacción: transiciones + status_event +
    limpieza de suspensión, o NADA (sin estado sin evento, sin evento sin
    estado, sin suspensión huérfana)."""

    def setUp(self) -> None:
        super().setUp()
        self.make_task()

    def snapshot(self) -> tuple:
        return (
            self.store.get_task("T-1"),
            self.store.get_suspension("T-1"),
            self.store.get_history("T-1"),
        )

    def waiting_task(self) -> None:
        self.store.suspend_for_capacity("T-1", **_suspend_fields())

    def resumed_task(self) -> None:
        self.waiting_task()
        self.store.claim_capacity_resume("T-1", reason="resume", actor="orchestrator")

    def fail_on_nth_transition(self, n: int):
        calls = {"count": 0}
        real = self.store._transition_locked

        def flaky(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == n:
                raise StoreError("simulated failure midway")
            return real(*args, **kwargs)

        self.store._transition_locked = flaky  # type: ignore[method-assign]

    def restore_transition(self) -> None:
        del self.store._transition_locked

    # ---- tarea FRESCA ----

    def test_complete_fresh_task_writes_the_whole_chain(self) -> None:
        before_events = len(self.store.get_history("T-1"))
        task = self.store.complete_fresh_task("T-1", reason="pipeline completed", actor="orchestrator")
        self.assertEqual(task["status"], "HUMAN_GATE")
        events = self.store.get_history("T-1")[before_events:]
        self.assertEqual([(e["from_status"], e["to_status"]) for e in events], HUMAN_GATE_CHAIN)
        for event in events:
            self.assertEqual((event["reason"], event["actor"]), ("pipeline completed", "orchestrator"))
        self.assertIsNone(self.store.get_suspension("T-1"))

    def test_complete_fresh_task_rolls_back_completely_on_a_midway_failure(self) -> None:
        before = self.snapshot()
        self.fail_on_nth_transition(3)
        with self.assertRaises(StoreError):
            self.store.complete_fresh_task("T-1", reason="r", actor="a")
        self.restore_transition()
        self.assertEqual(self.snapshot(), before)  # ni estado ni eventos parciales
        # y sigue siendo utilizable
        self.assertEqual(
            self.store.complete_fresh_task("T-1", reason="r", actor="a")["status"], "HUMAN_GATE"
        )

    def test_complete_fresh_task_requires_developing_and_no_suspension(self) -> None:
        self.make_task("T-2", status="BACKLOG")
        before = self.store.get_history("T-2")
        with self.assertRaises(StoreError):
            self.store.complete_fresh_task("T-2", reason="r", actor="a")
        self.assertEqual(self.store.get_history("T-2"), before)
        self.store.create_suspension("T-1", **_suspension_fields())  # suspensión inesperada
        snapshot = self.snapshot()
        with self.assertRaises(StoreError):
            self.store.complete_fresh_task("T-1", reason="r", actor="a")
        self.assertEqual(self.snapshot(), snapshot)

    # ---- tarea REANUDADA ----

    def test_complete_resumed_task_writes_the_chain_and_deletes_the_suspension(self) -> None:
        self.resumed_task()
        before_events = len(self.store.get_history("T-1"))
        task = self.store.complete_resumed_task("T-1", reason="resumed pipeline completed", actor="orchestrator")
        self.assertEqual(task["status"], "HUMAN_GATE")
        events = self.store.get_history("T-1")[before_events:]
        self.assertEqual([(e["from_status"], e["to_status"]) for e in events], HUMAN_GATE_CHAIN)
        self.assertIsNone(self.store.get_suspension("T-1"))

    def test_complete_resumed_task_rolls_back_completely_on_a_midway_failure(self) -> None:
        self.resumed_task()
        before = self.snapshot()
        self.fail_on_nth_transition(4)  # falla en la última transición
        with self.assertRaises(StoreError):
            self.store.complete_resumed_task("T-1", reason="r", actor="a")
        self.restore_transition()
        self.assertEqual(self.snapshot(), before)  # suspensión intacta, sin eventos
        self.assertIsNotNone(self.store.get_suspension("T-1"))

    def test_complete_resumed_task_rolls_back_if_the_suspension_cannot_be_deleted(self) -> None:
        self.resumed_task()
        before = self.snapshot()

        def boom(task_id):
            raise StoreError("simulated delete failure")

        self.store._delete_suspension_locked = boom  # type: ignore[method-assign]
        with self.assertRaises(StoreError):
            self.store.complete_resumed_task("T-1", reason="r", actor="a")
        del self.store._delete_suspension_locked
        self.assertEqual(self.snapshot(), before)  # las 4 transiciones se deshicieron

    def test_complete_resumed_task_requires_developing_and_a_suspension(self) -> None:
        before = self.snapshot()
        with self.assertRaises(StoreError):  # DEVELOPING pero sin suspensión
            self.store.complete_resumed_task("T-1", reason="r", actor="a")
        self.assertEqual(self.snapshot(), before)
        self.waiting_task()  # WAITING, no DEVELOPING
        snapshot = self.snapshot()
        with self.assertRaises(StoreError):
            self.store.complete_resumed_task("T-1", reason="r", actor="a")
        self.assertEqual(self.snapshot(), snapshot)

    # ---- bloqueo de un resume YA reclamado ----

    def test_block_claimed_resume(self) -> None:
        self.resumed_task()
        task = self.store.block_claimed_resume("T-1", reason="blocked: fixed text", actor="orchestrator")
        self.assertEqual(task["status"], "BLOCKED")
        self.assertIsNone(self.store.get_suspension("T-1"))
        last = self.store.get_history("T-1")[-1]
        self.assertEqual(
            (last["from_status"], last["to_status"], last["reason"]),
            ("DEVELOPING", "BLOCKED", "blocked: fixed text"),
        )

    def test_block_claimed_resume_rolls_back_completely_on_a_midway_failure(self) -> None:
        self.resumed_task()
        before = self.snapshot()

        def boom(task_id):
            raise StoreError("simulated delete failure")

        self.store._delete_suspension_locked = boom  # type: ignore[method-assign]
        with self.assertRaises(StoreError):
            self.store.block_claimed_resume("T-1", reason="r", actor="a")
        del self.store._delete_suspension_locked
        # Ni estado BLOCKED sin evento ni evento sin estado ni suspensión huérfana.
        self.assertEqual(self.snapshot(), before)

    def test_block_claimed_resume_requires_developing_and_a_suspension(self) -> None:
        before = self.snapshot()
        with self.assertRaises(StoreError):  # DEVELOPING sin suspensión
            self.store.block_claimed_resume("T-1", reason="r", actor="a")
        self.waiting_task()
        snapshot = self.snapshot()
        with self.assertRaises(StoreError):  # WAITING, no reclamada
            self.store.block_claimed_resume("T-1", reason="r", actor="a")
        self.assertEqual(self.snapshot(), snapshot)
        self.assertNotEqual(before, snapshot)

    # ---- bloqueo mientras se ESPERA ----

    def test_block_waiting_capacity(self) -> None:
        self.waiting_task()
        task = self.store.block_waiting_capacity("T-1", reason="blocked: limit", actor="orchestrator")
        self.assertEqual(task["status"], "BLOCKED")
        self.assertIsNone(self.store.get_suspension("T-1"))
        last = self.store.get_history("T-1")[-1]
        self.assertEqual(
            (last["from_status"], last["to_status"], last["reason"]),
            (WAITING, "BLOCKED", "blocked: limit"),
        )

    def test_block_waiting_capacity_rolls_back_completely_on_a_midway_failure(self) -> None:
        self.waiting_task()
        before = self.snapshot()

        def boom(task_id):
            raise StoreError("simulated delete failure")

        self.store._delete_suspension_locked = boom  # type: ignore[method-assign]
        with self.assertRaises(StoreError):
            self.store.block_waiting_capacity("T-1", reason="r", actor="a")
        del self.store._delete_suspension_locked
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.store.get_task("T-1")["status"], WAITING)

    def test_block_waiting_capacity_requires_waiting_and_a_suspension(self) -> None:
        before = self.snapshot()
        with self.assertRaises(StoreError):  # DEVELOPING, no WAITING
            self.store.block_waiting_capacity("T-1", reason="r", actor="a")
        self.assertEqual(self.snapshot(), before)
        self.waiting_task()
        conn = self.store._conn
        conn.execute("DELETE FROM task_suspension")  # WAITING sin suspensión (inconsistente)
        conn.commit()
        snapshot = self.snapshot()
        with self.assertRaises(StoreError):
            self.store.block_waiting_capacity("T-1", reason="r", actor="a")
        self.assertEqual(self.snapshot(), snapshot)

    # ---- comunes ----

    def test_reasons_and_actors_are_validated_and_bounded(self) -> None:
        self.resumed_task()
        before = self.snapshot()
        for method in (
            self.store.complete_resumed_task,
            self.store.block_claimed_resume,
        ):
            for kwargs in ({"reason": "", "actor": "a"}, {"reason": "x" * 501, "actor": "a"}, {"reason": "r", "actor": ""}):
                with self.subTest(method=method.__name__, kwargs=kwargs):
                    with self.assertRaises(StoreError):
                        method("T-1", **kwargs)
        self.assertEqual(self.snapshot(), before)

    def test_new_primitives_reject_invalid_ids(self) -> None:
        for method in (
            self.store.complete_fresh_task,
            self.store.complete_resumed_task,
            self.store.block_claimed_resume,
            self.store.block_waiting_capacity,
        ):
            with self.subTest(method=method.__name__):
                with self.assertRaises(InvalidIdError):
                    method("../x", reason="r", actor="a")

    def test_no_terminal_state_ever_keeps_an_orphan_suspension(self) -> None:
        self.resumed_task()
        self.store.complete_resumed_task("T-1", reason="r", actor="a")
        self.make_task("T-2")
        self.store.suspend_for_capacity("T-2", **_suspend_fields())
        self.store.block_waiting_capacity("T-2", reason="r", actor="a")
        self.make_task("T-3")
        self.store.suspend_for_capacity("T-3", **_suspend_fields())
        self.store.claim_capacity_resume("T-3", reason="r", actor="a")
        self.store.block_claimed_resume("T-3", reason="r", actor="a")
        rows = self.store._conn.execute(
            "SELECT t.id, t.status FROM task t JOIN task_suspension s ON s.task_id = t.id "
            "WHERE t.status IN ('HUMAN_GATE', 'BLOCKED')"
        ).fetchall()
        self.assertEqual(rows, [])


class AtomicTaskStartTests(SuspensionTestCase):
    """CAPACITY-RESUME-EXECUTION-002 CORRECTION-002: crear una tarea y
    avanzarla hasta DEVELOPING es UNA transacción. Si algo falla no queda ni
    task ni status_event, y el mismo task_id puede reutilizarse."""

    KW = {
        "specification_reason": "specification accepted",
        "developing_reason": "development started",
        "actor": "orchestrator",
    }

    def setUp(self) -> None:
        super().setUp()
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")

    def start(self, task_id: str = "T-1", store=None, **overrides) -> dict:
        kwargs = {**self.KW, **overrides}
        return (store or self.store).create_and_start_task(
            task_id, "SAMPLE", "Title", "fixed need text", **kwargs
        )

    def row_counts(self, task_id: str = "T-1") -> tuple[int, int]:
        conn = self.store._conn
        tasks = conn.execute("SELECT COUNT(*) FROM task WHERE id = ?", (task_id,)).fetchone()[0]
        events = conn.execute(
            "SELECT COUNT(*) FROM status_event WHERE task_id = ?", (task_id,)
        ).fetchone()[0]
        return tasks, events

    def assert_nothing_persisted(self, task_id: str = "T-1") -> None:
        self.assertIsNone(self.store.get_task(task_id))
        self.assertEqual(self.store.get_history(task_id), [])
        self.assertEqual(self.row_counts(task_id), (0, 0))

    def fail_transition_call(self, n: int):
        calls = {"count": 0}
        real = self.store._transition_locked

        def flaky(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == n:
                raise StoreError("simulated failure midway")
            return real(*args, **kwargs)

        self.store._transition_locked = flaky  # type: ignore[method-assign]

    def restore(self, name: str) -> None:
        delattr(self.store, name)

    # ---- éxito ----

    def test_start_creates_the_task_in_developing_with_the_exact_history(self) -> None:
        task = self.start()
        self.assertEqual(task["status"], "DEVELOPING")
        self.assertEqual(task["attempt_count"], 0)
        events = self.store.get_history("T-1")
        self.assertEqual(
            [(e["from_status"], e["to_status"]) for e in events],
            [(None, "BACKLOG"), ("BACKLOG", "SPECIFICATION"), ("SPECIFICATION", "DEVELOPING")],
        )
        self.assertEqual(
            [(e["reason"], e["actor"]) for e in events],
            [
                ("task created", "system"),
                ("specification accepted", "orchestrator"),
                ("development started", "orchestrator"),
            ],
        )
        self.assertEqual([e["id"] for e in events], sorted(e["id"] for e in events))

    def test_history_is_equivalent_to_the_previous_three_step_sequence(self) -> None:
        self.start("NEW-1")
        self.store.create_task("OLD-1", "SAMPLE", "Title", "fixed need text")
        self.store.transition_task("OLD-1", "SPECIFICATION", "specification accepted", "orchestrator")
        self.store.transition_task("OLD-1", "DEVELOPING", "development started", "orchestrator")

        def shape(task_id: str):
            return [
                (e["from_status"], e["to_status"], e["reason"], e["actor"])
                for e in self.store.get_history(task_id)
            ]

        self.assertEqual(shape("NEW-1"), shape("OLD-1"))
        new, old = self.store.get_task("NEW-1"), self.store.get_task("OLD-1")
        for key in ("project_id", "title", "need_text", "status", "attempt_count"):
            self.assertEqual(new[key], old[key], key)

    def test_create_task_keeps_its_public_semantics(self) -> None:
        self.store.create_task("T-1", "SAMPLE", "Title", "need")
        self.assertEqual(self.store.get_task("T-1")["status"], "BACKLOG")
        events = self.store.get_history("T-1")
        self.assertEqual(
            [(e["from_status"], e["to_status"], e["reason"], e["actor"]) for e in events],
            [(None, "BACKLOG", "task created", "system")],
        )

    def test_two_different_tasks_start_independently(self) -> None:
        self.start("T-1")
        self.start("T-2")
        self.assertEqual(self.row_counts("T-1"), (1, 3))
        self.assertEqual(self.row_counts("T-2"), (1, 3))

    # ---- fallos: rollback COMPLETO ----

    def test_failure_after_the_task_insert_leaves_nothing(self) -> None:
        def boom(task_id, now):
            raise StoreError("simulated failure after the task insert")

        self.store._insert_initial_event_locked = boom  # type: ignore[method-assign]
        project_before = self.store.get_project("SAMPLE")
        with self.assertRaises(StoreError):
            self.start()
        self.restore("_insert_initial_event_locked")
        self.assert_nothing_persisted()
        self.assertEqual(self.store.get_project("SAMPLE"), project_before)  # proyecto intacto

    def test_failure_after_the_backlog_event_leaves_nothing(self) -> None:
        self.fail_transition_call(1)  # falla al pasar a SPECIFICATION
        with self.assertRaises(StoreError):
            self.start()
        self.restore("_transition_locked")
        self.assert_nothing_persisted()

    def test_failure_after_specification_leaves_nothing(self) -> None:
        self.fail_transition_call(2)  # SPECIFICATION ya escrita; falla antes de DEVELOPING
        with self.assertRaises(StoreError):
            self.start()
        self.restore("_transition_locked")
        self.assert_nothing_persisted()

    def test_any_exception_type_rolls_everything_back(self) -> None:
        def boom(*args, **kwargs):
            raise RuntimeError("not a StoreError")

        self.store._transition_locked = boom  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError):
            self.start()
        self.restore("_transition_locked")
        self.assert_nothing_persisted()

    def test_state_machine_rejection_rolls_everything_back(self) -> None:
        from orchestrator import store as store_module

        calls = {"n": 0}
        real = store_module.validate_transition

        def picky(from_status, to_status):
            calls["n"] += 1
            if calls["n"] == 2:
                raise InvalidTransitionError("simulated rejection of SPECIFICATION -> DEVELOPING")
            return real(from_status, to_status)

        with mock.patch("orchestrator.store.validate_transition", picky):
            with self.assertRaises(InvalidTransitionError):
                self.start()
        self.assert_nothing_persisted()

    def test_the_same_task_id_is_reusable_after_a_rolled_back_start(self) -> None:
        for n in (1, 2):
            self.fail_transition_call(n)
            with self.assertRaises(StoreError):
                self.start()
            self.restore("_transition_locked")
            self.assert_nothing_persisted()
        task = self.start()  # el fallo previo NO quemó el task_id
        self.assertEqual(task["status"], "DEVELOPING")
        self.assertEqual(self.row_counts(), (1, 3))

    def test_the_project_survives_a_failed_start(self) -> None:
        self.fail_transition_call(2)
        with self.assertRaises(StoreError):
            self.start()
        self.restore("_transition_locked")
        self.assertIsNotNone(self.store.get_project("SAMPLE"))

    # ---- precondiciones ----

    def test_missing_project_creates_nothing(self) -> None:
        with self.assertRaises(StoreError):
            self.store.create_and_start_task("T-1", "NOPE", "Title", "need", **self.KW)
        self.assert_nothing_persisted()

    def test_duplicate_task_id_fails_closed_and_preserves_everything(self) -> None:
        self.start()
        self.store.suspend_for_capacity("T-1", **_suspend_fields())
        before = (
            self.store.get_task("T-1"),
            self.store.get_suspension("T-1"),
            self.store.get_history("T-1"),
        )
        with self.assertRaises(StoreError):
            self.start(specification_reason="another reason")
        after = (
            self.store.get_task("T-1"),
            self.store.get_suspension("T-1"),
            self.store.get_history("T-1"),
        )
        self.assertEqual(after, before)  # tarea, suspensión e historial idénticos

    def test_duplicate_of_a_task_created_with_create_task_fails_closed(self) -> None:
        self.store.create_task("T-1", "SAMPLE", "Title", "need")
        before = (self.store.get_task("T-1"), self.store.get_history("T-1"))
        with self.assertRaises(StoreError):
            self.start()
        self.assertEqual((self.store.get_task("T-1"), self.store.get_history("T-1")), before)

    def test_invalid_input_creates_nothing(self) -> None:
        for bad in ({"task_id": "../x"}, {"task_id": "a b"}):
            with self.assertRaises(InvalidIdError):
                self.store.create_and_start_task(
                    bad["task_id"], "SAMPLE", "Title", "need", **self.KW
                )
        for overrides in (
            {"specification_reason": ""},
            {"developing_reason": ""},
            {"actor": ""},
            {"specification_reason": "x" * 501},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(StoreError):
                    self.start(**overrides)
        for title, need in (("", "need"), ("Title", "")):
            with self.assertRaises(StoreError):
                self.store.create_and_start_task("T-1", "SAMPLE", title, need, **self.KW)
        self.assert_nothing_persisted()

    def test_the_primitive_has_no_place_for_claude_or_task_packet_data(self) -> None:
        names = set(inspect.signature(Store.create_and_start_task).parameters)
        self.assertEqual(
            names,
            {
                "self",
                "task_id",
                "project_id",
                "title",
                "need_text",
                "specification_reason",
                "developing_reason",
                "actor",
            },
        )
        for word in ("stdout", "stderr", "prompt", "result", "session", "usage", "objective", "packet"):
            for name in names:
                self.assertNotIn(word, name.lower())

    # ---- concurrencia ----

    def test_concurrent_starts_of_the_same_task_id_have_exactly_one_winner(self) -> None:
        contenders = 8
        barrier = threading.Barrier(contenders)
        outcomes: list[str] = []
        lock = threading.Lock()

        def contend(index: int) -> None:
            store = Store(self.db_path)  # una conexión por hilo
            try:
                barrier.wait(timeout=10)
                try:
                    store.create_and_start_task(
                        "T-1",
                        "SAMPLE",
                        "Title",
                        "need",
                        specification_reason="spec",
                        developing_reason="dev",
                        actor=f"worker-{index}",
                    )
                    result = "won"
                except StoreError:
                    result = "lost"
            finally:
                store.close()
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=contend, args=(i,)) for i in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(outcomes), ["lost"] * (contenders - 1) + ["won"])
        # Ni doble tarea ni doble cadena de eventos ni estado corrupto.
        self.assertEqual(self.row_counts(), (1, 3))
        self.assertEqual(self.store.get_task("T-1")["status"], "DEVELOPING")
        self.assertEqual(
            [(e["from_status"], e["to_status"]) for e in self.store.get_history("T-1")],
            [(None, "BACKLOG"), ("BACKLOG", "SPECIFICATION"), ("SPECIFICATION", "DEVELOPING")],
        )
        actors = {e["actor"] for e in self.store.get_history("T-1")} - {"system"}
        self.assertEqual(len(actors), 1)  # todos los eventos son del MISMO ganador

    def test_two_connections_only_one_wins_deterministically(self) -> None:
        other = Store(self.db_path)
        try:
            self.start()
            with self.assertRaises(StoreError):
                self.start(store=other, actor="second")
        finally:
            other.close()
        self.assertEqual(self.row_counts(), (1, 3))


class TransitionTaskStateGuardTests(SuspensionTestCase):
    """CORRECTION-001: transition_task no fuerza una transición si otro
    proceso ya cambió el estado entre la lectura y el UPDATE."""

    def test_normal_transition_is_unchanged(self) -> None:
        self.make_task("T-1", status="SPECIFICATION")
        task = self.store.transition_task("T-1", "DEVELOPING", "go", "director")
        self.assertEqual(task["status"], "DEVELOPING")
        last = self.store.get_history("T-1")[-1]
        self.assertEqual(
            (last["from_status"], last["to_status"], last["reason"], last["actor"]),
            ("SPECIFICATION", "DEVELOPING", "go", "director"),
        )

    def test_a_stale_read_never_forces_the_transition(self) -> None:
        self.make_task("T-1")  # DEVELOPING
        self.store.suspend_for_capacity("T-1", **_suspend_fields())  # WAITING
        real_get = Store.get_task
        db_path = self.db_path
        state = {"raced": False}

        def racing_get(store_self, task_id):
            task = real_get(store_self, task_id)  # lectura (WAITING)
            if not state["raced"]:
                state["raced"] = True
                with Store(db_path) as other:
                    other.block_waiting_capacity("T-1", reason="other wins", actor="other")
            return task

        from unittest import mock

        with mock.patch.object(Store, "get_task", racing_get):
            with self.assertRaises(StoreError):
                self.store.transition_task("T-1", "BLOCKED", "stale", "me")
        history = self.store.get_history("T-1")
        blocked = [e for e in history if e["to_status"] == "BLOCKED"]
        self.assertEqual(len(blocked), 1)  # solo la del otro proceso
        self.assertEqual(blocked[0]["reason"], "other wins")
        self.assertEqual(self.task_status(), "BLOCKED")
        # El Store sigue siendo utilizable tras el fallo.
        self.assertEqual(self.store.get_task("T-1")["status"], "BLOCKED")


class WaitingCapacityCandidatesTests(SuspensionTestCase):
    """CAPACITY-WAKEUP-001: API de descubrimiento de solo lectura para resume-due."""

    def wait(self, task_id: str, **overrides) -> None:
        self.make_task(task_id)
        self.store.suspend_for_capacity(task_id, **_suspend_fields(**overrides))

    def test_zero_waiting_tasks_returns_an_empty_list(self) -> None:
        self.make_task("T-1")  # DEVELOPING, no WAITING
        self.assertEqual(self.store.list_waiting_capacity_candidates(), [])

    def test_one_valid_waiting_task(self) -> None:
        self.wait("T-1")
        self.assertEqual(
            self.store.list_waiting_capacity_candidates(),
            [{"task_id": "T-1", "next_retry_at": T1}],
        )

    def test_several_waiting_tasks_are_ordered_by_task_id(self) -> None:
        for task_id in ("T-3", "T-1", "T-2"):
            self.wait(task_id)
        ids = [c["task_id"] for c in self.store.list_waiting_capacity_candidates()]
        self.assertEqual(ids, ["T-1", "T-2", "T-3"])

    def test_only_waiting_tasks_are_returned(self) -> None:
        self.wait("T-1")
        self.make_task("T-2")  # DEVELOPING
        self.make_task("T-3", status="BACKLOG")
        self.make_task("T-4")
        self.store.transition_task("T-4", "BLOCKED", "setup", "director")
        ids = [c["task_id"] for c in self.store.list_waiting_capacity_candidates()]
        self.assertEqual(ids, ["T-1"])

    def test_orphan_waiting_task_appears_with_no_retry_time(self) -> None:
        self.wait("T-1")
        self.store._conn.execute("DELETE FROM task_suspension WHERE task_id = 'T-1'")
        self.store._conn.commit()
        self.assertEqual(
            self.store.list_waiting_capacity_candidates(),
            [{"task_id": "T-1", "next_retry_at": None}],
        )

    def test_invalid_timestamp_is_returned_verbatim_for_the_caller_to_judge(self) -> None:
        self.wait("T-1")
        self.store._conn.execute("UPDATE task_suspension SET next_retry_at = 'tomorrow'")
        self.store._conn.commit()
        self.assertEqual(
            self.store.list_waiting_capacity_candidates(),
            [{"task_id": "T-1", "next_retry_at": "tomorrow"}],
        )

    def test_only_minimal_metadata_is_exposed(self) -> None:
        self.wait("T-1")
        (candidate,) = self.store.list_waiting_capacity_candidates()
        self.assertEqual(set(candidate), {"task_id", "next_retry_at"})

    def test_discovery_is_read_only(self) -> None:
        self.wait("T-1")
        self.wait("T-2")
        self.store._conn.execute("DELETE FROM task_suspension WHERE task_id = 'T-2'")
        self.store._conn.commit()
        before = "\n".join(self.store._conn.iterdump())
        self.store.list_waiting_capacity_candidates()
        self.assertEqual("\n".join(self.store._conn.iterdump()), before)
        self.assertFalse(self.store._conn.in_transaction)

    def test_a_task_that_stops_waiting_disappears_from_the_next_discovery(self) -> None:
        self.wait("T-1")
        self.store.block_waiting_capacity("T-1", reason="closed", actor="orchestrator")
        self.assertEqual(self.store.list_waiting_capacity_candidates(), [])

    def test_opening_a_corrupt_database_fails_without_leaking_the_connection(self) -> None:
        corrupt = Path(self._tmp.name) / "corrupt.db"
        corrupt.write_bytes(b"not a sqlite database" * 50)
        with self.assertRaises(sqlite3.DatabaseError):
            Store(corrupt)
        corrupt.unlink()  # en Windows falla si quedó un handle abierto
        self.assertFalse(corrupt.exists())

    def test_the_query_is_parameterized(self) -> None:
        source = inspect.getsource(self.store.list_waiting_capacity_candidates)
        self.assertNotIn("f\"", source)
        self.assertNotIn("%s", source)
        from orchestrator import store as store_mod

        self.assertIn("?", store_mod._SELECT_WAITING_CANDIDATES_SQL)
        self.assertNotIn(WAITING, store_mod._SELECT_WAITING_CANDIDATES_SQL)


class NotificationEventStoreTests(SuspensionTestCase):
    """HUMAN-GATE-NOTIFY-001: notification_event (at-most-once por entrada a
    HUMAN_GATE) sin ningún dato sensible."""

    def gate_task(self, task_id: str = "T-1") -> int:
        self.make_task(task_id)
        completed = self.store.complete_fresh_task(task_id, reason="pipeline completed", actor="orchestrator")
        return completed["human_gate_status_event_id"]

    def claim(self, task_id: str, event_id, **overrides):
        kwargs = {"event_type": "human_gate", "provider": "slack", "gate_type": "HUMAN_FUNCTIONAL_TEST"}
        kwargs.update(overrides)
        return self.store.claim_human_gate_notification(task_id, event_id, **kwargs)

    def dump(self) -> str:
        return "\n".join(self.store._conn.iterdump())

    # ---- schema ----

    def test_table_is_created_automatically_with_the_minimal_columns(self) -> None:
        rows = self.store._conn.execute("PRAGMA table_info(notification_event)").fetchall()
        self.assertEqual(
            [r[1] for r in rows],
            [
                "id", "task_id", "status_event_id", "event_type", "provider",
                "gate_type", "status", "error_category", "attempted_at", "completed_at",
            ],
        )
        fks = {(r[2], r[3]) for r in self.store._conn.execute("PRAGMA foreign_key_list(notification_event)")}
        self.assertEqual(fks, {("task", "task_id"), ("status_event", "status_event_id")})

    def test_existing_databases_gain_the_table(self) -> None:
        path = Path(self._tmp.name) / "legacy.db"
        conn = sqlite3.connect(str(path))
        conn.executescript(
            "CREATE TABLE project (id TEXT PRIMARY KEY, name TEXT NOT NULL, repo_path TEXT NOT NULL,"
            " rules_ref TEXT NOT NULL, created_at TEXT NOT NULL);"
        )
        conn.commit()
        conn.close()
        with Store(path) as legacy:
            tables = {r[0] for r in legacy._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("notification_event", tables)

    def test_the_table_holds_no_message_secret_or_claude_columns(self) -> None:
        columns = {r[1] for r in self.store._conn.execute("PRAGMA table_info(notification_event)")}
        for forbidden in ("message", "text", "payload", "webhook", "url", "response", "body",
                          "stdout", "stderr", "prompt", "result", "session_id", "path", "token"):
            self.assertFalse(any(forbidden in c for c in columns), forbidden)

    # ---- identidad del gate ----

    def test_complete_fresh_task_returns_the_id_of_the_human_gate_status_event(self) -> None:
        event_id = self.gate_task()
        history = self.store.get_history("T-1")
        self.assertEqual(history[-1]["id"], event_id)
        self.assertEqual(history[-1]["to_status"], "HUMAN_GATE")

    def test_complete_resumed_task_returns_the_id_of_the_human_gate_status_event(self) -> None:
        self.make_task("T-1")
        self.store.suspend_for_capacity("T-1", **_suspend_fields())
        self.store.claim_capacity_resume("T-1", reason="resume", actor="orchestrator")
        completed = self.store.complete_resumed_task("T-1", reason="r", actor="orchestrator")
        history = self.store.get_history("T-1")
        self.assertEqual(completed["human_gate_status_event_id"], history[-1]["id"])
        self.assertEqual(history[-1]["to_status"], "HUMAN_GATE")

    # ---- claim ----

    def test_claim_creates_one_attempting_row_with_minimal_metadata(self) -> None:
        event_id = self.gate_task()
        notification_id = self.claim("T-1", event_id)
        self.assertIsInstance(notification_id, int)
        (row,) = self.store.get_notifications("T-1")
        self.assertEqual(row["id"], notification_id)
        self.assertEqual(
            (row["task_id"], row["status_event_id"], row["event_type"], row["provider"],
             row["gate_type"], row["status"], row["error_category"], row["completed_at"]),
            ("T-1", event_id, "human_gate", "slack", "HUMAN_FUNCTIONAL_TEST", "ATTEMPTING", None, None),
        )
        self.assertIsNotNone(row["attempted_at"])

    def test_unique_prevents_a_second_attempt_for_the_same_gate_entry(self) -> None:
        event_id = self.gate_task()
        self.assertIsNotNone(self.claim("T-1", event_id))
        dump = self.dump()
        self.assertIsNone(self.claim("T-1", event_id))  # already_exists
        self.assertEqual(self.dump(), dump)
        self.assertEqual(len(self.store.get_notifications("T-1")), 1)

    def test_a_different_provider_or_event_type_is_a_different_claim(self) -> None:
        event_id = self.gate_task()
        self.assertIsNotNone(self.claim("T-1", event_id))
        self.assertIsNotNone(self.claim("T-1", event_id, provider="email"))
        self.assertIsNotNone(self.claim("T-1", event_id, event_type="other_event"))

    def test_a_new_entry_to_human_gate_allows_a_new_notification(self) -> None:
        first = self.gate_task()
        self.assertIsNotNone(self.claim("T-1", first))
        self.store.transition_task("T-1", "CHANGES_REQUESTED", "needs work", "human")
        self.store.transition_task("T-1", "DEVELOPING", "fix", "orchestrator")
        second = self.store.complete_fresh_task("T-1", reason="again", actor="orchestrator")[
            "human_gate_status_event_id"
        ]
        self.assertNotEqual(first, second)
        self.assertIsNone(self.claim("T-1", first))  # el gate viejo sigue deduplicado
        self.assertIsNotNone(self.claim("T-1", second))  # el nuevo ingreso sí notifica
        self.assertEqual(len(self.store.get_notifications("T-1")), 2)

    def test_claim_fails_closed_unless_the_event_is_the_human_gate_entry_of_the_task(self) -> None:
        event_id = self.gate_task()
        other_event = self.store.get_history("T-1")[-2]["id"]  # SECURITY_REVIEW
        self.make_task("T-2")
        for label, task_id, status_event_id in (
            ("missing event", "T-1", 99999),
            ("not HUMAN_GATE", "T-1", other_event),
            ("other task's event", "T-2", event_id),
        ):
            with self.subTest(label):
                dump = self.dump()
                with self.assertRaises(StoreError):
                    self.claim(task_id, status_event_id)
                self.assertEqual(self.dump(), dump)

    def test_claim_validates_its_inputs(self) -> None:
        event_id = self.gate_task()
        for kwargs in (
            {"event_type": "Human Gate"}, {"event_type": ""}, {"provider": "Slack"},
            {"provider": "../x"}, {"gate_type": "human_gate"}, {"gate_type": "X" * 80},
        ):
            with self.subTest(kwargs):
                with self.assertRaises(StoreError):
                    self.claim("T-1", event_id, **kwargs)
        for bad_id in ("1", True, None):
            with self.assertRaises(StoreError):
                self.claim("T-1", bad_id)
        with self.assertRaises(InvalidIdError):
            self.claim("../x", event_id)
        self.assertEqual(self.store.get_notifications("T-1"), [])

    # ---- complete ----

    def test_complete_sent_and_failed(self) -> None:
        event_id = self.gate_task()
        sent_id = self.claim("T-1", event_id)
        row = self.store.complete_notification(sent_id, status="SENT")
        self.assertEqual((row["status"], row["error_category"]), ("SENT", None))
        self.assertIsNotNone(row["completed_at"])
        failed_event = self.gate_task("T-2")
        failed_id = self.claim("T-2", failed_event)
        row = self.store.complete_notification(failed_id, status="FAILED", error_category="HTTP_4XX")
        self.assertEqual((row["status"], row["error_category"]), ("FAILED", "HTTP_4XX"))

    def test_error_categories_are_a_fixed_vocabulary(self) -> None:
        from orchestrator.store import NOTIFICATION_ERROR_CATEGORIES

        self.assertEqual(
            NOTIFICATION_ERROR_CATEGORIES,
            {"HTTP_4XX", "HTTP_5XX", "TIMEOUT", "NETWORK", "MISSING_SECRET", "INVALID_WEBHOOK", "CONFIG_INVALID"},
        )
        event_id = self.gate_task()
        notification_id = self.claim("T-1", event_id)
        for bad in ("BOOM", "http 400", "", None, "Traceback (most recent call last)"):
            with self.subTest(bad):
                with self.assertRaises(StoreError):
                    self.store.complete_notification(notification_id, status="FAILED", error_category=bad)
        with self.assertRaises(StoreError):
            self.store.complete_notification(notification_id, status="SENT", error_category="NETWORK")
        with self.assertRaises(StoreError):
            self.store.complete_notification(notification_id, status="ATTEMPTING")
        with self.assertRaises(StoreError):
            self.store.complete_notification(notification_id, status="DONE")
        self.assertEqual(self.store.get_notifications("T-1")[0]["status"], "ATTEMPTING")
        # La CHECK de SQLite también protege la tabla frente a una escritura directa.
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute(
                "UPDATE notification_event SET status = 'FAILED', error_category = 'anything'"
            )
        self.store._conn.rollback()

    def test_complete_only_updates_a_row_that_is_still_attempting(self) -> None:
        event_id = self.gate_task()
        notification_id = self.claim("T-1", event_id)
        self.store.complete_notification(notification_id, status="SENT")
        dump = self.dump()
        with self.assertRaises(StoreError):
            self.store.complete_notification(notification_id, status="FAILED", error_category="NETWORK")
        self.assertEqual(self.dump(), dump)  # la fila terminada no se toca
        with self.assertRaises(StoreError):
            self.store.complete_notification(424242, status="SENT")

    def test_race_between_two_connections_fails_closed(self) -> None:
        event_id = self.gate_task()
        notification_id = self.claim("T-1", event_id)
        with Store(self.db_path) as other:
            self.assertIsNone(
                other.claim_human_gate_notification(
                    "T-1", event_id, event_type="human_gate", provider="slack",
                    gate_type="HUMAN_FUNCTIONAL_TEST",
                )
            )
            other.complete_notification(notification_id, status="SENT")  # gana el otro
        with self.assertRaises(StoreError):
            self.store.complete_notification(notification_id, status="FAILED", error_category="TIMEOUT")
        (row,) = self.store.get_notifications("T-1")
        self.assertEqual(row["status"], "SENT")

    def test_claim_is_atomic_and_leaves_no_partial_row_on_failure(self) -> None:
        event_id = self.gate_task()
        dump = self.dump()
        with mock.patch.object(Store, "_write_transaction", side_effect=StoreError("busy")):
            with self.assertRaises(StoreError):
                self.claim("T-1", event_id)
        self.assertEqual(self.dump(), dump)
        self.assertFalse(self.store._conn.in_transaction)

    # ---- no data ----

    def test_only_fixed_metadata_reaches_the_table(self) -> None:
        event_id = self.gate_task()
        notification_id = self.claim("T-1", event_id)
        self.store.complete_notification(notification_id, status="FAILED", error_category="HTTP_5XX")
        (row,) = self.store.get_notifications("T-1")
        allowed_text = {
            "T-1", "human_gate", "slack", "HUMAN_FUNCTIONAL_TEST", "FAILED", "HTTP_5XX",
            row["attempted_at"], row["completed_at"],
        }
        for key, value in row.items():
            if isinstance(value, str):
                self.assertIn(value, allowed_text, key)

    def test_get_notifications_is_read_only_and_validates_the_id(self) -> None:
        event_id = self.gate_task()
        self.claim("T-1", event_id)
        dump = self.dump()
        self.store.get_notifications("T-1")
        self.assertEqual(self.dump(), dump)
        with self.assertRaises(InvalidIdError):
            self.store.get_notifications("../x")


class ParameterizedSqlTests(unittest.TestCase):
    def test_store_never_builds_sql_with_string_interpolation(self) -> None:
        source = (SRC_DIR / "orchestrator" / "store.py").read_text(encoding="utf-8")
        for needle in ('execute(f"', "execute(f'", "executescript(f", "%s"):
            self.assertNotIn(needle, source, needle)


if __name__ == "__main__":
    unittest.main()
