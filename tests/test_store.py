import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.state_machine import InvalidTransitionError  # noqa: E402
from orchestrator.store import InvalidIdError, Store, StoreError  # noqa: E402


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = Path(self._tmp.name) / "test.db"
        self.store = Store(db_path)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()


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


if __name__ == "__main__":
    unittest.main()
