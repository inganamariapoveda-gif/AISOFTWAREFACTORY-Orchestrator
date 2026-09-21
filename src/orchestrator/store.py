"""Persistencia SQLite — subconjunto mínimo para BOOTSTRAP (§12).

Tablas: project, task, status_event. Toda transición de estado se persiste
como evento con from/to/reason/actor/timestamp (§5.2, invariante).

Seguridad: todas las queries son parametrizadas; los identificadores de
proyecto/tarea se validan contra un patrón estricto antes de tocar la base
de datos.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

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

CREATE TABLE IF NOT EXISTS task_suspension (
    task_id TEXT NOT NULL PRIMARY KEY REFERENCES task(id),
    task_packet_path TEXT NOT NULL,
    task_packet_sha256 TEXT NOT NULL,
    project_rules_sha256 TEXT NOT NULL,
    permissions_sha256 TEXT NOT NULL,
    baseline_head_sha TEXT NOT NULL,
    baseline_branch TEXT NOT NULL,
    working_tree_fingerprint TEXT NOT NULL,
    touched_paths_json TEXT NOT NULL,
    capacity_wait_count INTEGER NOT NULL
        CHECK (capacity_wait_count >= 1),
    capacity_wait_started_at TEXT NOT NULL,
    next_retry_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# CAPACITY-RESUME-FOUNDATION-001: estado a partir del cual se suspende y al
# que se vuelve al reanudar. task_suspension NO almacena nada de Claude
# (stdout, stderr, result, session_id, usage, prompt, credenciales, reason
# heredado): solo identidad de la tarea, hashes, baseline Git, huella del
# working tree, nombres de paths, contadores y timestamps.
STATE_DEVELOPING = "DEVELOPING"
STATE_WAITING_FOR_CLAUDE_CAPACITY = "WAITING_FOR_CLAUDE_CAPACITY"

TASK_SUSPENSION_COLUMNS: tuple[str, ...] = (
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
)

_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_GIT_SHA_HEX_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


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


_MAX_REASON_CHARS = 500

# Consultas de task_suspension: literales completos y parametrizados (nunca
# SQL construido por concatenación).
_SELECT_SUSPENSION_SQL = (
    "SELECT task_id, task_packet_path, task_packet_sha256, project_rules_sha256, "
    "permissions_sha256, baseline_head_sha, baseline_branch, working_tree_fingerprint, "
    "touched_paths_json, capacity_wait_count, capacity_wait_started_at, next_retry_at, "
    "updated_at FROM task_suspension WHERE task_id = ?"
)
_INSERT_SUSPENSION_SQL = (
    "INSERT INTO task_suspension (task_id, task_packet_path, task_packet_sha256, "
    "project_rules_sha256, permissions_sha256, baseline_head_sha, baseline_branch, "
    "working_tree_fingerprint, touched_paths_json, capacity_wait_count, "
    "capacity_wait_started_at, next_retry_at, updated_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_UPDATE_SUSPENSION_SQL = (
    "UPDATE task_suspension SET working_tree_fingerprint = ?, touched_paths_json = ?, "
    "capacity_wait_count = ?, next_retry_at = ?, updated_at = ? WHERE task_id = ?"
)
_INSERT_STATUS_EVENT_SQL = (
    "INSERT INTO status_event (task_id, from_status, to_status, reason, actor, created_at) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)
# El UPDATE es condicional al estado origen leído (WHERE ... AND status = ?):
# solo un proceso puede ganar una carrera.
_UPDATE_TASK_STATUS_SQL = (
    "UPDATE task SET status = ?, updated_at = ? WHERE id = ? AND status = ?"
)


def _require_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value or (not value and not allow_empty):
        raise StoreError(f"{label} must be a{'' if allow_empty else ' non-empty'} string")
    return value


def _require_hex(value: Any, label: str, pattern: "re.Pattern[str]") -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise StoreError(f"{label} must be a lowercase hexadecimal digest")
    return value


def _require_timestamp(value: Any, label: str) -> str:
    text = _require_text(value, label)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise StoreError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise StoreError(f"{label} must include a timezone offset")
    return text


def _require_wait_count(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise StoreError("capacity_wait_count must be an integer >= 1")
    return value


def _encode_touched_paths(touched_paths: Any) -> str:
    """JSON de NOMBRES de path (nunca contenido de archivos). Se conserva el
    orden recibido: el llamador entrega la lista ya ordenada."""
    if not isinstance(touched_paths, (list, tuple)):
        raise StoreError("touched_paths must be a list of path strings")
    for item in touched_paths:
        _require_text(item, "touched path")
    return json.dumps(list(touched_paths), ensure_ascii=False, separators=(",", ":"))


def _validate_reason_actor(reason: Any, actor: Any) -> tuple[str, str]:
    reason_text = _require_text(reason, "reason")
    if len(reason_text) > _MAX_REASON_CHARS:
        raise StoreError(f"reason must not exceed {_MAX_REASON_CHARS} characters")
    return reason_text, _require_text(actor, "actor")


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

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        """Solo lectura: nunca crea ni modifica un proyecto."""
        validate_id(project_id, "project_id")
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT id, name, repo_path, rules_ref, created_at "
                "FROM project WHERE id = ?",
                (project_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        keys = ("id", "name", "repo_path", "rules_ref", "created_at")
        return dict(zip(keys, row))

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

    # ------------------------------------------------------------------
    # CAPACITY-RESUME-FOUNDATION-001: suspensión por capacidad de Claude.
    #
    # Store solo PERSISTE; no decide política (límites, tiempos, reintentos).
    # Nada de esto está conectado todavía al executor.
    # ------------------------------------------------------------------

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        """Transacción de escritura EXPLÍCITA (BEGIN IMMEDIATE): toma el lock
        de escritura de SQLite desde el principio, de modo que leer-validar-
        escribir sea atómico entre conexiones/procesos, sin locks externos.
        Todo o nada: ante cualquier error se hace rollback."""
        if self._conn.in_transaction:
            # Ninguna API pública deja trabajo pendiente: solo puede ser el
            # resto vacío de una operación anterior que falló.
            self._conn.rollback()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise StoreError("database is busy: could not start a write transaction") from exc
        try:
            yield
        except BaseException:
            self._conn.rollback()
            raise
        try:
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StoreError("could not commit the write transaction") from exc

    def _fetch_suspension(self, task_id: str) -> dict[str, Any] | None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(_SELECT_SUSPENSION_SQL, (task_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return dict(zip(TASK_SUSPENSION_COLUMNS, row))

    def get_suspension(self, task_id: str) -> dict[str, Any] | None:
        """Devuelve la fila de task_suspension (columnas tal cual; los paths
        siguen en `touched_paths_json`) o None. Solo lectura."""
        validate_id(task_id, "task_id")
        return self._fetch_suspension(task_id)

    @staticmethod
    def _validated_identity(
        *,
        task_packet_path: Any,
        task_packet_sha256: Any,
        project_rules_sha256: Any,
        permissions_sha256: Any,
        baseline_head_sha: Any,
        baseline_branch: Any,
        capacity_wait_started_at: Any,
    ) -> dict[str, Any]:
        """Campos de identidad de la suspensión: se fijan en la PRIMERA
        suspensión y no cambian después (baseline original preservado)."""
        return {
            "task_packet_path": _require_text(task_packet_path, "task_packet_path"),
            "task_packet_sha256": _require_hex(
                task_packet_sha256, "task_packet_sha256", _SHA256_HEX_RE
            ),
            "project_rules_sha256": _require_hex(
                project_rules_sha256, "project_rules_sha256", _SHA256_HEX_RE
            ),
            "permissions_sha256": _require_hex(
                permissions_sha256, "permissions_sha256", _SHA256_HEX_RE
            ),
            "baseline_head_sha": _require_hex(
                baseline_head_sha, "baseline_head_sha", _GIT_SHA_HEX_RE
            ),
            # Vacío permitido: HEAD desacoplado (`git branch --show-current` == "").
            "baseline_branch": _require_text(
                baseline_branch, "baseline_branch", allow_empty=True
            ),
            "capacity_wait_started_at": _require_timestamp(
                capacity_wait_started_at, "capacity_wait_started_at"
            ),
        }

    def _insert_suspension_locked(
        self,
        task_id: str,
        identity: dict[str, Any],
        *,
        working_tree_fingerprint: str,
        touched_paths_json: str,
        capacity_wait_count: int,
        next_retry_at: str,
    ) -> None:
        """Debe llamarse DENTRO de _write_transaction()."""
        if self.get_task(task_id) is None:
            raise StoreError(f"cannot create suspension: task {task_id!r} does not exist")
        if self._fetch_suspension(task_id) is not None:
            raise StoreError(f"suspension for task {task_id!r} already exists")
        try:
            with closing(self._conn.cursor()) as cur:
                cur.execute(
                    _INSERT_SUSPENSION_SQL,
                    (
                        task_id,
                        identity["task_packet_path"],
                        identity["task_packet_sha256"],
                        identity["project_rules_sha256"],
                        identity["permissions_sha256"],
                        identity["baseline_head_sha"],
                        identity["baseline_branch"],
                        working_tree_fingerprint,
                        touched_paths_json,
                        capacity_wait_count,
                        identity["capacity_wait_started_at"],
                        next_retry_at,
                        _utcnow(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"could not create suspension for task {task_id!r}") from exc

    def create_suspension(
        self,
        task_id: str,
        *,
        task_packet_path: str,
        task_packet_sha256: str,
        project_rules_sha256: str,
        permissions_sha256: str,
        baseline_head_sha: str,
        baseline_branch: str,
        working_tree_fingerprint: str,
        touched_paths: Sequence[str],
        capacity_wait_count: int,
        capacity_wait_started_at: str,
        next_retry_at: str,
    ) -> dict[str, Any]:
        """Crea la suspensión de una tarea existente. Duplicado -> StoreError.
        No cambia el estado de la tarea (eso lo hace suspend_for_capacity)."""
        validate_id(task_id, "task_id")
        identity = self._validated_identity(
            task_packet_path=task_packet_path,
            task_packet_sha256=task_packet_sha256,
            project_rules_sha256=project_rules_sha256,
            permissions_sha256=permissions_sha256,
            baseline_head_sha=baseline_head_sha,
            baseline_branch=baseline_branch,
            capacity_wait_started_at=capacity_wait_started_at,
        )
        fingerprint = _require_hex(
            working_tree_fingerprint, "working_tree_fingerprint", _SHA256_HEX_RE
        )
        paths_json = _encode_touched_paths(touched_paths)
        count = _require_wait_count(capacity_wait_count)
        retry_at = _require_timestamp(next_retry_at, "next_retry_at")
        with self._write_transaction():
            self._insert_suspension_locked(
                task_id,
                identity,
                working_tree_fingerprint=fingerprint,
                touched_paths_json=paths_json,
                capacity_wait_count=count,
                next_retry_at=retry_at,
            )
        stored = self._fetch_suspension(task_id)
        assert stored is not None
        return stored

    def update_suspension(
        self,
        task_id: str,
        *,
        working_tree_fingerprint: str,
        touched_paths: Sequence[str],
        capacity_wait_count: int,
        next_retry_at: str,
    ) -> dict[str, Any]:
        """Actualiza SOLO los campos mutables (huella, paths, contador y
        próximo reintento; el contador nunca puede disminuir). La identidad
        (paquete, hashes, baseline, inicio de la espera) es inmutable.
        Suspensión inexistente -> StoreError."""
        validate_id(task_id, "task_id")
        fingerprint = _require_hex(
            working_tree_fingerprint, "working_tree_fingerprint", _SHA256_HEX_RE
        )
        paths_json = _encode_touched_paths(touched_paths)
        count = _require_wait_count(capacity_wait_count)
        retry_at = _require_timestamp(next_retry_at, "next_retry_at")
        with self._write_transaction():
            existing = self._fetch_suspension(task_id)
            if existing is None:
                raise StoreError(f"suspension for task {task_id!r} does not exist")
            if count < existing["capacity_wait_count"]:
                raise StoreError("capacity_wait_count must not decrease")
            with closing(self._conn.cursor()) as cur:
                cur.execute(
                    _UPDATE_SUSPENSION_SQL,
                    (fingerprint, paths_json, count, retry_at, _utcnow(), task_id),
                )
                if cur.rowcount != 1:
                    raise StoreError(f"suspension for task {task_id!r} was not updated")
        stored = self._fetch_suspension(task_id)
        assert stored is not None
        return stored

    def delete_suspension(self, task_id: str) -> None:
        """Elimina la suspensión (no toca la tarea ni el repositorio).
        Inexistente -> StoreError."""
        validate_id(task_id, "task_id")
        with self._write_transaction():
            if self._fetch_suspension(task_id) is None:
                raise StoreError(f"suspension for task {task_id!r} does not exist")
            with closing(self._conn.cursor()) as cur:
                cur.execute("DELETE FROM task_suspension WHERE task_id = ?", (task_id,))
                if cur.rowcount != 1:
                    raise StoreError(f"suspension for task {task_id!r} was not deleted")

    def _transition_locked(
        self, task_id: str, from_status: str, to_status: str, reason: str, actor: str
    ) -> None:
        """UPDATE condicional del estado + status_event. Debe llamarse DENTRO
        de _write_transaction(). rowcount != 1 -> StoreError (fail closed)."""
        now = _utcnow()
        with closing(self._conn.cursor()) as cur:
            cur.execute(_UPDATE_TASK_STATUS_SQL, (to_status, now, task_id, from_status))
            if cur.rowcount != 1:
                raise StoreError(
                    f"task {task_id!r} is no longer in status {from_status!r}; "
                    "transition not applied"
                )
            cur.execute(
                _INSERT_STATUS_EVENT_SQL,
                (task_id, from_status, to_status, reason, actor, now),
            )

    def suspend_for_capacity(
        self,
        task_id: str,
        *,
        reason: str,
        actor: str,
        task_packet_path: str,
        task_packet_sha256: str,
        project_rules_sha256: str,
        permissions_sha256: str,
        baseline_head_sha: str,
        baseline_branch: str,
        working_tree_fingerprint: str,
        touched_paths: Sequence[str],
        capacity_wait_count: int,
        capacity_wait_started_at: str,
        next_retry_at: str,
    ) -> dict[str, Any]:
        """ATÓMICO (una transacción): DEVELOPING -> WAITING_FOR_CLAUDE_CAPACITY
        + status_event + escritura de task_suspension.

        Soporta (A) la primera suspensión (crea la fila) y (B) una suspensión
        posterior tras una reanudación (la fila se conservó al reclamar: se
        actualizan solo huella, paths, contador y próximo reintento). En (B)
        la identidad (paquete, hashes, baseline, inicio de la espera) debe
        coincidir con la almacenada y el contador debe AUMENTAR: el baseline
        original nunca se sobrescribe. Store no aplica límites ni tiempos:
        esa política es del llamador."""
        validate_id(task_id, "task_id")
        reason_text, actor_text = _validate_reason_actor(reason, actor)
        identity = self._validated_identity(
            task_packet_path=task_packet_path,
            task_packet_sha256=task_packet_sha256,
            project_rules_sha256=project_rules_sha256,
            permissions_sha256=permissions_sha256,
            baseline_head_sha=baseline_head_sha,
            baseline_branch=baseline_branch,
            capacity_wait_started_at=capacity_wait_started_at,
        )
        fingerprint = _require_hex(
            working_tree_fingerprint, "working_tree_fingerprint", _SHA256_HEX_RE
        )
        paths_json = _encode_touched_paths(touched_paths)
        count = _require_wait_count(capacity_wait_count)
        retry_at = _require_timestamp(next_retry_at, "next_retry_at")

        with self._write_transaction():
            task = self.get_task(task_id)
            if task is None:
                raise StoreError(f"task {task_id!r} does not exist")
            from_status = task["status"]
            # La máquina de estados es la autoridad: solo DEVELOPING puede
            # pasar a WAITING_FOR_CLAUDE_CAPACITY.
            validate_transition(from_status, STATE_WAITING_FOR_CLAUDE_CAPACITY)

            existing = self._fetch_suspension(task_id)
            if existing is None:
                self._insert_suspension_locked(
                    task_id,
                    identity,
                    working_tree_fingerprint=fingerprint,
                    touched_paths_json=paths_json,
                    capacity_wait_count=count,
                    next_retry_at=retry_at,
                )
            else:
                for field, value in identity.items():
                    if existing[field] != value:
                        raise StoreError(
                            f"suspension identity field {field!r} does not match the "
                            "stored suspension; the original baseline is never overwritten"
                        )
                if count <= existing["capacity_wait_count"]:
                    raise StoreError("capacity_wait_count must increase on a new suspension")
                with closing(self._conn.cursor()) as cur:
                    cur.execute(
                        _UPDATE_SUSPENSION_SQL,
                        (fingerprint, paths_json, count, retry_at, _utcnow(), task_id),
                    )
                    if cur.rowcount != 1:
                        raise StoreError(f"suspension for task {task_id!r} was not updated")

            self._transition_locked(
                task_id, from_status, STATE_WAITING_FOR_CLAUDE_CAPACITY, reason_text, actor_text
            )
        result = self.get_task(task_id)
        assert result is not None
        return result

    def claim_capacity_resume(
        self, task_id: str, *, reason: str, actor: str
    ) -> dict[str, Any]:
        """ATÓMICO (una transacción): WAITING_FOR_CLAUDE_CAPACITY -> DEVELOPING
        + status_event, CONSERVANDO la fila task_suspension.

        Exige tarea existente, estado WAITING_FOR_CLAUDE_CAPACITY y
        suspensión activa. El UPDATE es condicional (WHERE id = ? AND status
        = 'WAITING_FOR_CLAUDE_CAPACITY') y exige rowcount == 1, dentro de una
        transacción BEGIN IMMEDIATE: si dos procesos compiten, solo uno gana
        y el otro recibe StoreError (fail closed), sin locks externos."""
        validate_id(task_id, "task_id")
        reason_text, actor_text = _validate_reason_actor(reason, actor)

        with self._write_transaction():
            task = self.get_task(task_id)
            if task is None:
                raise StoreError(f"task {task_id!r} does not exist")
            if task["status"] != STATE_WAITING_FOR_CLAUDE_CAPACITY:
                raise StoreError(
                    f"task {task_id!r} is not waiting for Claude capacity "
                    f"(status {task['status']!r})"
                )
            if self._fetch_suspension(task_id) is None:
                raise StoreError(f"task {task_id!r} has no active suspension")
            validate_transition(STATE_WAITING_FOR_CLAUDE_CAPACITY, STATE_DEVELOPING)
            self._transition_locked(
                task_id,
                STATE_WAITING_FOR_CLAUDE_CAPACITY,
                STATE_DEVELOPING,
                reason_text,
                actor_text,
            )
        result = self.get_task(task_id)
        assert result is not None
        return result
