"""HUMAN-GATE-NOTIFY-001: dominio de notificaciones (puerto + despacho
at-most-once). Notifier falso; ninguna prueba llama a Slack."""

import dataclasses
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator import notifications as notifications_mod  # noqa: E402
from orchestrator.notifications import (  # noqa: E402
    NotificationEvent,
    NotificationOutcome,
    NotificationResult,
    NotifierPort,
    dispatch_human_gate_notification,
    human_gate_dedupe_key,
)
from orchestrator.store import Store, StoreError  # noqa: E402


class FakeNotifier:
    provider = "fake"

    def __init__(self, result=None, error=None) -> None:
        self.result = result if result is not None else NotificationResult("SENT")
        self.error = error
        self.events: list[NotificationEvent] = []

    def notify(self, event: NotificationEvent) -> NotificationResult:
        self.events.append(event)
        if self.error is not None:
            raise self.error
        return self.result


class NotificationsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Store(Path(self._tmp.name) / "test.db")
        self.addCleanup(self.store.close)
        self.store.register_project("SAMPLE", "Sample", "./projects/SAMPLE", "ref")

    def gate_entry(self, task_id: str = "T-1") -> int:
        self.store.create_task(task_id, "SAMPLE", "Title", "Need")
        self.store.transition_task(task_id, "SPECIFICATION", "s", "director")
        self.store.transition_task(task_id, "DEVELOPING", "d", "director")
        return self.store.complete_fresh_task(task_id, reason="r", actor="orchestrator")[
            "human_gate_status_event_id"
        ]

    def dispatch(self, notifier, task_id: str = "T-1", event_id: int | None = None):
        return dispatch_human_gate_notification(
            self.store,
            notifier,
            project_id="SAMPLE",
            task_id=task_id,
            gate_type="HUMAN_FUNCTIONAL_TEST",
            status_event_id=event_id if event_id is not None else self._event_id,
        )

    def notifications(self, task_id: str = "T-1") -> list[dict]:
        return self.store.get_notifications(task_id)


class DomainTests(unittest.TestCase):
    def test_event_is_a_frozen_dataclass_with_exactly_the_five_safe_fields(self) -> None:
        self.assertTrue(dataclasses.is_dataclass(NotificationEvent))
        self.assertEqual(
            [f.name for f in dataclasses.fields(NotificationEvent)],
            ["event_type", "project_id", "task_id", "gate_type", "dedupe_key"],
        )
        event = NotificationEvent("human_gate", "P", "T", "HUMAN_FUNCTIONAL_TEST", "k")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            event.task_id = "other"  # type: ignore[misc]

    def test_result_uses_a_fixed_vocabulary(self) -> None:
        self.assertEqual(NotificationResult("SENT").error_category, None)
        for category in (
            "HTTP_4XX", "HTTP_5XX", "TIMEOUT", "NETWORK",
            "MISSING_SECRET", "INVALID_WEBHOOK", "CONFIG_INVALID",
        ):
            self.assertEqual(NotificationResult("FAILED", category).error_category, category)
        for status, category in (
            ("SENT", "NETWORK"), ("FAILED", None), ("FAILED", "boom"),
            ("FAILED", "Traceback (most recent call last)"), ("DONE", None), ("ATTEMPTING", None),
        ):
            with self.subTest((status, category)):
                with self.assertRaises(ValueError):
                    NotificationResult(status, category)
        self.assertTrue(dataclasses.is_dataclass(NotificationResult))

    def test_the_dedupe_key_identifies_the_gate_entry(self) -> None:
        self.assertEqual(human_gate_dedupe_key("T-1", 7), "human_gate:T-1:7")
        self.assertNotEqual(human_gate_dedupe_key("T-1", 7), human_gate_dedupe_key("T-1", 12))

    def test_the_port_is_a_protocol_any_channel_can_implement(self) -> None:
        self.assertIsInstance(FakeNotifier(), NotifierPort)

    def test_the_engine_does_not_import_slack_or_the_network(self) -> None:
        for name in ("notifications.py", "store.py"):
            source = (SRC_DIR / "orchestrator" / name).read_text(encoding="utf-8")
            for needle in ("slack_notifier", "SlackWebhookNotifier", "urllib", "import socket", "import requests"):
                self.assertNotIn(needle, source, f"{needle!r} in {name}")
        for needle in ("time.sleep", "threading", "asyncio"):
            self.assertNotIn(needle, Path(notifications_mod.__file__).read_text(encoding="utf-8"))


class DispatchTests(NotificationsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._event_id = self.gate_entry()

    def test_sent_claims_sends_once_and_records_sent(self) -> None:
        notifier = FakeNotifier()
        outcome = self.dispatch(notifier)
        self.assertEqual(outcome, NotificationOutcome("sent", None))
        self.assertEqual(len(notifier.events), 1)
        self.assertEqual(
            notifier.events[0],
            NotificationEvent(
                "human_gate", "SAMPLE", "T-1", "HUMAN_FUNCTIONAL_TEST",
                f"human_gate:T-1:{self._event_id}",
            ),
        )
        (row,) = self.notifications()
        self.assertEqual((row["status"], row["error_category"], row["provider"]), ("SENT", None, "fake"))
        self.assertEqual(row["status_event_id"], self._event_id)
        self.assertEqual(self.store.get_task("T-1")["status"], "HUMAN_GATE")

    def test_failed_is_recorded_with_its_fixed_category_and_the_task_is_untouched(self) -> None:
        history_before = self.store.get_history("T-1")
        notifier = FakeNotifier(NotificationResult("FAILED", "HTTP_5XX"))
        outcome = self.dispatch(notifier)
        self.assertEqual(outcome, NotificationOutcome("failed", "HTTP_5XX"))
        (row,) = self.notifications()
        self.assertEqual((row["status"], row["error_category"]), ("FAILED", "HTTP_5XX"))
        self.assertEqual(self.store.get_task("T-1")["status"], "HUMAN_GATE")
        self.assertEqual(self.store.get_history("T-1"), history_before)  # sin BLOCKED ni eventos

    def test_the_same_gate_entry_is_never_notified_twice(self) -> None:
        first = FakeNotifier()
        self.dispatch(first)
        second = FakeNotifier()
        outcome = self.dispatch(second)
        self.assertEqual(outcome, NotificationOutcome("already_attempted", None))
        self.assertEqual(second.events, [])  # sin envío
        self.assertEqual(len(self.notifications()), 1)

    def test_a_failed_attempt_is_not_retried_automatically(self) -> None:
        self.dispatch(FakeNotifier(NotificationResult("FAILED", "TIMEOUT")))
        again = FakeNotifier()
        self.assertEqual(self.dispatch(again).status, "already_attempted")
        self.assertEqual(again.events, [])
        self.assertEqual(self.notifications()[0]["status"], "FAILED")

    def test_an_existing_attempting_row_models_a_dead_process_and_is_not_resent(self) -> None:
        # Proceso muerto entre "reclamar" y "registrar": la fila queda ATTEMPTING.
        self.store.claim_human_gate_notification(
            "T-1", self._event_id, event_type="human_gate", provider="fake",
            gate_type="HUMAN_FUNCTIONAL_TEST",
        )
        notifier = FakeNotifier()
        outcome = self.dispatch(notifier)
        self.assertEqual(outcome.status, "already_attempted")
        self.assertEqual(notifier.events, [])
        (row,) = self.notifications()
        self.assertEqual(row["status"], "ATTEMPTING")  # no se modifica automáticamente
        self.assertIsNone(row["completed_at"])

    def test_a_new_entry_to_human_gate_is_a_new_notification(self) -> None:
        self.dispatch(FakeNotifier())
        self.store.transition_task("T-1", "CHANGES_REQUESTED", "needs work", "human")
        self.store.transition_task("T-1", "DEVELOPING", "fix", "orchestrator")
        second_entry = self.store.complete_fresh_task("T-1", reason="again", actor="o")[
            "human_gate_status_event_id"
        ]
        notifier = FakeNotifier()
        self.assertEqual(self.dispatch(notifier, event_id=second_entry).status, "sent")
        self.assertEqual(len(notifier.events), 1)
        self.assertEqual(len(self.notifications()), 2)

    def test_a_notifier_that_raises_is_recorded_as_a_fixed_network_failure(self) -> None:
        secret_text = "https://hooks.slack.com/services/T/B/SENTINEL-in-exception"
        outcome = self.dispatch(FakeNotifier(error=RuntimeError(secret_text)))
        self.assertEqual(outcome, NotificationOutcome("failed", "NETWORK"))
        (row,) = self.notifications()
        self.assertEqual((row["status"], row["error_category"]), ("FAILED", "NETWORK"))
        self.assertNotIn("SENTINEL", "".join(str(v) for v in row.values()))
        self.assertEqual(self.store.get_task("T-1")["status"], "HUMAN_GATE")

    def test_an_invalid_notifier_result_is_a_failure_not_a_success(self) -> None:
        outcome = self.dispatch(FakeNotifier(result="ok"))  # type: ignore[arg-type]
        self.assertEqual(outcome.status, "failed")
        self.assertEqual(self.notifications()[0]["status"], "FAILED")

    def test_if_recording_fails_the_row_stays_attempting_and_nothing_is_resent(self) -> None:
        notifier = FakeNotifier()
        with mock.patch.object(Store, "complete_notification", side_effect=StoreError("busy")):
            outcome = self.dispatch(notifier)
        self.assertEqual(outcome.status, "sent")  # el envío sí ocurrió
        self.assertEqual(self.notifications()[0]["status"], "ATTEMPTING")
        self.assertEqual(self.dispatch(FakeNotifier()).status, "already_attempted")
        self.assertEqual(len(notifier.events), 1)

    def test_claim_errors_propagate_to_the_caller_and_nothing_is_sent(self) -> None:
        notifier = FakeNotifier()
        with self.assertRaises(StoreError):
            self.dispatch(notifier, event_id=987654)  # no es la entrada al gate de la tarea
        self.assertEqual(notifier.events, [])
        self.assertEqual(self.notifications(), [])

    def test_the_gate_committed_before_any_send(self) -> None:
        observed: dict = {}

        class Probe(FakeNotifier):
            def notify(inner, event):  # noqa: N805
                with Store(Path(self._tmp.name) / "test.db") as other:
                    observed["status"] = other.get_task("T-1")["status"]
                    observed["rows"] = other.get_notifications("T-1")
                return super().notify(event)

        self.dispatch(Probe())
        self.assertEqual(observed["status"], "HUMAN_GATE")  # ya committed y visible
        self.assertEqual(observed["rows"][0]["status"], "ATTEMPTING")  # reclamo previo al envío

    def test_only_one_send_per_call(self) -> None:
        notifier = FakeNotifier(NotificationResult("FAILED", "NETWORK"))
        self.dispatch(notifier)
        self.assertEqual(len(notifier.events), 1)  # sin reintento


if __name__ == "__main__":
    unittest.main()
