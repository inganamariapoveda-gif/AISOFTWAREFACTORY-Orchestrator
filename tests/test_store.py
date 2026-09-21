import inspect
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

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


class ParameterizedSqlTests(unittest.TestCase):
    def test_store_never_builds_sql_with_string_interpolation(self) -> None:
        source = (SRC_DIR / "orchestrator" / "store.py").read_text(encoding="utf-8")
        for needle in ('execute(f"', "execute(f'", "executescript(f", "%s"):
            self.assertNotIn(needle, source, needle)


if __name__ == "__main__":
    unittest.main()
