"""Persistencia SQLite — subconjunto mínimo para BOOTSTRAP (§12).

Tablas: project, task, status_event. Toda transición de estado se persiste
como evento con from/to/reason/actor/timestamp (§5.2, invariante).

Seguridad: todas las queries son parametrizadas; los identificadores de
proyecto/tarea se validan contra un patrón estricto antes de tocar la base
de datos.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .state_machine import INITIAL_STATE, validate_transition

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS project (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    rules_ref TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES project(id),
    title TEXT NOT NULL,
    need_text TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS status_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES task(id),
    from_status TEXT,
    to_status TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class StoreError(Exception):
    """Error controlado de persistencia."""


class InvalidIdError(StoreError):
    """Un project_id/task_id no cumple el patrón permitido."""


def validate_id(value: str, label: str = "id") -> str:
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        raise InvalidIdError(
            f"invalid {label}: {value!r}; must match {ID_PATTERN.pattern}"
        )
    return value


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Wrapper sqlite3 con el subconjunto de persistencia de BOOTSTRAP."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def register_project(
        self, project_id: str, name: str, repo_path: str, rules_ref: str
    ) -> None:
        validate_id(project_id, "project_id")
        now = _utcnow()
        try:
            with closing(self._conn.cursor()) as cur:
                cur.execute(
                    "INSERT INTO project (id, name, repo_path, rules_ref, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (project_id, name, repo_path, rules_ref, now),
                )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"project {project_id!r} already exists") from exc

    def create_task(
        self, task_id: str, project_id: str, title: str, need_text: str
    ) -> None:
        validate_id(task_id, "task_id")
        validate_id(project_id, "project_id")
        now = _utcnow()
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT 1 FROM project WHERE id = ?", (project_id,))
            if cur.fetchone() is None:
                raise StoreError(
                    f"cannot create task: project {project_id!r} does not exist"
                )
            try:
                cur.execute(
                    "INSERT INTO task "
                    "(id, project_id, title, need_text, status, attempt_count, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                    (task_id, project_id, title, need_text, INITIAL_STATE, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"task {task_id!r} already exists") from exc
            cur.execute(
                "INSERT INTO status_event "
                "(task_id, from_status, to_status, reason, actor, created_at) "
                "VALUES (?, NULL, ?, ?, ?, ?)",
                (task_id, INITIAL_STATE, "task created", "system", now),
            )
        self._conn.commit()

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        validate_id(task_id, "task_id")
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT id, project_id, title, need_text, status, attempt_count, "
                "created_at, updated_at FROM task WHERE id = ?",
                (task_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        keys = (
            "id",
            "project_id",
            "title",
            "need_text",
            "status",
            "attempt_count",
            "created_at",
            "updated_at",
        )
        return dict(zip(keys, row))

    def transition_task(
        self, task_id: str, to_status: str, reason: str, actor: str
    ) -> dict[str, Any]:
        validate_id(task_id, "task_id")
        task = self.get_task(task_id)
        if task is None:
            raise StoreError(f"task {task_id!r} does not exist")
        from_status = task["status"]

        # Verificación ANTES de persistir; si falla, no se toca la fila
        # ni se inserta status_event (invariante de la máquina de estados).
        validate_transition(from_status, to_status)

        now = _utcnow()
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "UPDATE task SET status = ?, updated_at = ? WHERE id = ?",
                (to_status, now, task_id),
            )
            cur.execute(
                "INSERT INTO status_event "
                "(task_id, from_status, to_status, reason, actor, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (task_id, from_status, to_status, reason, actor, now),
            )
        self._conn.commit()
        result = self.get_task(task_id)
        assert result is not None
        return result

    def get_history(self, task_id: str) -> list[dict[str, Any]]:
        validate_id(task_id, "task_id")
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT id, task_id, from_status, to_status, reason, actor, created_at "
                "FROM status_event WHERE task_id = ? ORDER BY id ASC",
                (task_id,),
            )
            rows = cur.fetchall()
        keys = ("id", "task_id", "from_status", "to_status", "reason", "actor", "created_at")
        return [dict(zip(keys, row)) for row in rows]
