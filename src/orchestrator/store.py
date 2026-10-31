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

CREATE TABLE IF NOT EXISTS agent_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES task(id),
    role TEXT NOT NULL CHECK (role IN ('builder', 'verifier')),
    agent TEXT NOT NULL,
    provider TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('implementation', 'correction', 'capacity_resume', 'review')),
    resource_profile TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RESERVED', 'SUCCEEDED', 'FAILED')),
    reserved_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(task_id, ordinal)
);

CREATE TABLE IF NOT EXISTS external_operation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES task(id),
    provider TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    operation_key TEXT NOT NULL UNIQUE
        CHECK (length(operation_key) = 64 AND operation_key NOT GLOB '*[^0-9a-f]*'),
    request_fingerprint TEXT NOT NULL
        CHECK (length(request_fingerprint) = 64 AND request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    phase TEXT NOT NULL CHECK (phase IN (
        'PREPARED', 'DISPATCH_ATTEMPTED', 'RUN_IDENTIFIED', 'TERMINAL_OBSERVED')),
    remote_operation_id TEXT,
    terminal_status TEXT,
    terminal_result TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, operation_type, remote_operation_id),
    CHECK (
        (phase IN ('PREPARED', 'DISPATCH_ATTEMPTED') AND remote_operation_id IS NULL
            AND terminal_status IS NULL AND terminal_result IS NULL)
        OR (phase = 'RUN_IDENTIFIED' AND remote_operation_id IS NOT NULL
            AND terminal_status IS NULL AND terminal_result IS NULL)
        OR (phase = 'TERMINAL_OBSERVED' AND remote_operation_id IS NOT NULL
            AND terminal_status IS NOT NULL AND terminal_result IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS candidate_materialization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES task(id),
    materialization_key TEXT NOT NULL UNIQUE CHECK (length(materialization_key) = 64 AND materialization_key NOT GLOB '*[^0-9a-f]*'),
    task_packet_sha256 TEXT NOT NULL CHECK (length(task_packet_sha256) = 64 AND task_packet_sha256 NOT GLOB '*[^0-9a-f]*'),
    repo_root TEXT NOT NULL,
    branch TEXT NOT NULL,
    base_head_sha TEXT NOT NULL CHECK (length(base_head_sha) = 40 AND base_head_sha NOT GLOB '*[^0-9a-f]*'),
    base_tree_sha TEXT NOT NULL CHECK (length(base_tree_sha) = 40 AND base_tree_sha NOT GLOB '*[^0-9a-f]*'),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    manifest_json TEXT NOT NULL,
    commit_metadata_json TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('PREPARED', 'SEALED')),
    candidate_tree_sha TEXT,
    candidate_commit_sha TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((phase = 'PREPARED' AND candidate_tree_sha IS NULL AND candidate_commit_sha IS NULL)
        OR (phase = 'SEALED' AND candidate_tree_sha IS NOT NULL AND candidate_commit_sha IS NOT NULL
            AND length(candidate_tree_sha) = 40 AND candidate_tree_sha NOT GLOB '*[^0-9a-f]*'
            AND length(candidate_commit_sha) = 40 AND candidate_commit_sha NOT GLOB '*[^0-9a-f]*'))
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

CREATE TABLE IF NOT EXISTS notification_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES task(id),
    status_event_id INTEGER NOT NULL REFERENCES status_event(id),
    event_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    gate_type TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('ATTEMPTING', 'SENT', 'FAILED')),
    error_category TEXT
        CHECK (error_category IS NULL OR error_category IN (
            'HTTP_4XX', 'HTTP_5XX', 'TIMEOUT', 'NETWORK',
            'MISSING_SECRET', 'INVALID_WEBHOOK', 'CONFIG_INVALID'
        )),
    attempted_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (status_event_id, event_type, provider)
);
"""

# CAPACITY-RESUME-FOUNDATION-001: estado a partir del cual se suspende y al
# que se vuelve al reanudar. task_suspension NO almacena nada de Claude
# (stdout, stderr, result, session_id, usage, prompt, credenciales, reason
# heredado): solo identidad de la tarea, hashes, baseline Git, huella del
# working tree, nombres de paths, contadores y timestamps.
STATE_SPECIFICATION = "SPECIFICATION"
STATE_DEVELOPING = "DEVELOPING"
STATE_WAITING_FOR_CLAUDE_CAPACITY = "WAITING_FOR_CLAUDE_CAPACITY"
STATE_BLOCKED = "BLOCKED"

# CAPACITY-RESUME-EXECUTION-002: cadena válida (Master Spec §5.2) que se
# persiste de forma atómica cuando el pipeline completo termina en HUMAN_GATE.
_HUMAN_GATE_CHAIN: tuple[str, ...] = (
    "AUTOMATED_TEST",
    "TECHNICAL_REVIEW",
    "SECURITY_REVIEW",
    "HUMAN_GATE",
)

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

# HUMAN-GATE-NOTIFY-001: notification_event registra SOLO metadata de un
# intento de aviso (nunca mensaje, webhook, respuesta ni datos de Claude).
# Vocabularios fijos; el Store no conoce a ningún proveedor concreto.
NOTIFICATION_STATUS_ATTEMPTING = "ATTEMPTING"
NOTIFICATION_STATUS_SENT = "SENT"
NOTIFICATION_STATUS_FAILED = "FAILED"
NOTIFICATION_ERROR_CATEGORIES: frozenset[str] = frozenset(
    {
        "HTTP_4XX",
        "HTTP_5XX",
        "TIMEOUT",
        "NETWORK",
        "MISSING_SECRET",
        "INVALID_WEBHOOK",
        "CONFIG_INVALID",
    }
)
_NOTIFICATION_EVENT_TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_NOTIFICATION_PROVIDER_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_NOTIFICATION_GATE_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_NOTIFICATION_COLUMNS: tuple[str, ...] = (
    "id",
    "task_id",
    "status_event_id",
    "event_type",
    "provider",
    "gate_type",
    "status",
    "error_category",
    "attempted_at",
    "completed_at",
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
# CAPACITY-WAKEUP-001: candidatos WAITING. `task` es la fuente del estado;
# LEFT JOIN para NO ocultar tareas WAITING sin task_suspension (huérfanas).
# Solo metadata mínima (id y next_retry_at, NULL si no hay suspensión).
_SELECT_WAITING_CANDIDATES_SQL = (
    "SELECT t.id, s.next_retry_at FROM task t "
    "LEFT JOIN task_suspension s ON s.task_id = t.id "
    "WHERE t.status = ? ORDER BY t.id ASC"
)

# CAPACITY-RESUME-EXECUTION-002 CORRECTION-002: mismas sentencias y convención
# que create_task (evento inicial NULL -> BACKLOG, "task created", "system").
_INSERT_TASK_SQL = (
    "INSERT INTO task "
    "(id, project_id, title, need_text, status, attempt_count, created_at, updated_at) "
    "VALUES (?, ?, ?, ?, ?, 0, ?, ?)"
)
_INSERT_INITIAL_EVENT_SQL = (
    "INSERT INTO status_event "
    "(task_id, from_status, to_status, reason, actor, created_at) "
    "VALUES (?, NULL, ?, ?, ?, ?)"
)
_TASK_CREATED_REASON = "task created"
_TASK_CREATED_ACTOR = "system"

_INSERT_STATUS_EVENT_SQL = (
    "INSERT INTO status_event (task_id, from_status, to_status, reason, actor, created_at) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)
# El UPDATE es condicional al estado origen leído (WHERE ... AND status = ?):
# solo un proceso puede ganar una carrera.
_UPDATE_TASK_STATUS_SQL = (
    "UPDATE task SET status = ?, updated_at = ? WHERE id = ? AND status = ?"
)

# HUMAN-GATE-NOTIFY-001: literales completos y parametrizados.
_SELECT_GATE_EVENT_SQL = (
    "SELECT task_id, to_status FROM status_event WHERE id = ?"
)
_SELECT_EXISTING_NOTIFICATION_SQL = (
    "SELECT id FROM notification_event "
    "WHERE status_event_id = ? AND event_type = ? AND provider = ?"
)
_CLAIM_NOTIFICATION_SQL = (
    "INSERT INTO notification_event "
    "(task_id, status_event_id, event_type, provider, gate_type, status, attempted_at) "
    "VALUES (?, ?, ?, ?, ?, 'ATTEMPTING', ?)"
)
_COMPLETE_NOTIFICATION_SQL = (
    "UPDATE notification_event SET status = ?, error_category = ?, completed_at = ? "
    "WHERE id = ? AND status = 'ATTEMPTING'"
)
_SELECT_NOTIFICATIONS_SQL = (
    "SELECT id, task_id, status_event_id, event_type, provider, gate_type, status, "
    "error_category, attempted_at, completed_at FROM notification_event "
    "WHERE task_id = ? ORDER BY id ASC"
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
    """SQLite persistence and transactional operational resource accounting."""

    def get_candidate_materialization(self, materialization_id: int) -> dict[str, Any] | None:
        if type(materialization_id) is not int or materialization_id <= 0:
            raise StoreError("invalid materialization id")
        return self._candidate_row("id", materialization_id)

    def get_candidate_materialization_by_key(self, key: str) -> dict[str, Any] | None:
        _require_hex(key, "materialization_key", re.compile(r"[0-9a-f]{64}"))
        return self._candidate_row("materialization_key", key)

    def _candidate_row(self, column, value):
        cursor = self._conn.execute(
            "SELECT * FROM candidate_materialization WHERE " + column + " = ?", (value,))
        row = cursor.fetchone()
        return dict(zip((item[0] for item in cursor.description), row)) if row else None

    def prepare_candidate_materialization(self, task_id: str, **intent) -> dict[str, Any]:
        # Shared pure validation; importing here avoids module initialization cycles.
        from .candidate_materialization import validate_intent
        valid = False
        try:
            validate_intent(task_id, intent)
            valid = True
        except Exception:
            pass
        if not valid:
            raise StoreError("invalid materialization intent")
        with self._write_transaction():
            if self.get_task(task_id) is None:
                raise StoreError("materialization task not found")
            row = self.get_candidate_materialization_by_key(intent["materialization_key"])
            if row is not None:
                if row["task_id"] != task_id or any(row[key] != value for key, value in intent.items()):
                    raise StoreError("materialization intent conflict")
                return row
            now = _utcnow()
            cursor = self._conn.execute(
                "INSERT INTO candidate_materialization (task_id, materialization_key, task_packet_sha256, "
                "repo_root, branch, base_head_sha, base_tree_sha, manifest_sha256, manifest_json, "
                "commit_metadata_json, phase, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, ?)",
                (task_id, intent["materialization_key"], intent["task_packet_sha256"], intent["repo_root"],
                 intent["branch"], intent["base_head_sha"], intent["base_tree_sha"], intent["manifest_sha256"],
                 intent["manifest_json"], intent["commit_metadata_json"], now, now))
            return self.get_candidate_materialization(cursor.lastrowid)

    def seal_candidate_materialization(self, materialization_id: int, *, candidate_tree_sha: str,
                                       candidate_commit_sha: str) -> dict[str, Any]:
        for value in (candidate_tree_sha, candidate_commit_sha):
            _require_hex(value, "candidate object", re.compile(r"[0-9a-f]{40}"))
            if value == "0" * 40:
                raise StoreError("invalid candidate object")
        with self._write_transaction():
            row = self.get_candidate_materialization(materialization_id)
            if row is None:
                raise StoreError("materialization not found")
            if row["phase"] == "SEALED":
                if (row["candidate_tree_sha"], row["candidate_commit_sha"]) != (candidate_tree_sha, candidate_commit_sha):
                    raise StoreError("materialization seal conflict")
                return row
            self._conn.execute(
                "UPDATE candidate_materialization SET phase = 'SEALED', candidate_tree_sha = ?, "
                "candidate_commit_sha = ?, updated_at = ? WHERE id = ?",
                (candidate_tree_sha, candidate_commit_sha, _utcnow(), materialization_id))
            return self.get_candidate_materialization(materialization_id)

    @staticmethod
    def _external_code(value: str, label: str) -> str:
        # Logical evidence identifiers/codes only, never raw provider responses.
        if type(value) is not str or ID_PATTERN.fullmatch(value) is None:
            raise StoreError("invalid external operation " + label)
        return value

    def get_external_operation(self, operation_id: int) -> dict[str, Any] | None:
        if type(operation_id) is not int or operation_id <= 0:
            raise StoreError("invalid external operation id")
        return self._external_operation_row("id", operation_id)

    def get_external_operation_by_key(self, operation_key: str) -> dict[str, Any] | None:
        _require_hex(operation_key, "operation_key", re.compile(r"[0-9a-f]{64}"))
        return self._external_operation_row("operation_key", operation_key)

    def _external_operation_row(self, column: str, value: Any) -> dict[str, Any] | None:
        # Column comes only from the two fixed callers above.
        cursor = self._conn.execute(
            f"SELECT * FROM external_operation WHERE {column} = ?", (value,)
        )
        row = cursor.fetchone()
        return dict(zip((item[0] for item in cursor.description), row)) if row else None

    def prepare_external_operation(
        self, task_id: str, *, provider: str, operation_type: str,
        operation_key: str, request_fingerprint: str,
    ) -> dict[str, Any]:
        """Durable intent only, never permission to dispatch or task approval.

        The coordinator supplies both hashes. No alternate key is generated.
        Replaying identical intent returns its current phase without resetting it.
        """
        for label, value in (("task_id", task_id), ("provider", provider),
                             ("operation_type", operation_type)):
            self._external_code(value, label)
        for label, value in (("operation_key", operation_key),
                             ("request_fingerprint", request_fingerprint)):
            _require_hex(value, label, re.compile(r"[0-9a-f]{64}"))
        identity = dict(task_id=task_id, provider=provider, operation_type=operation_type,
                        operation_key=operation_key, request_fingerprint=request_fingerprint)
        with self._write_transaction():
            existing = self.get_external_operation_by_key(operation_key)
            if existing is not None:
                if any(existing[key] != value for key, value in identity.items()):
                    raise StoreError("external operation intent conflict")
                return existing
            if self.get_task(task_id) is None:
                raise StoreError("external operation task not found")
            now = _utcnow()
            cursor = self._conn.execute(
                "INSERT INTO external_operation (task_id, provider, operation_type, operation_key, "
                "request_fingerprint, phase, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'PREPARED', ?, ?)",
                (task_id, provider, operation_type, operation_key, request_fingerprint, now, now),
            )
            return self.get_external_operation(cursor.lastrowid)

    def mark_external_dispatch_attempted(self, operation_id: int) -> dict[str, Any]:
        """Persist BEFORE POST. Missing remote identity remains uncertain.

        Idempotence of this write never grants permission for another POST.
        No provider call, retry, claim, task transition or budget change occurs.
        """
        return self._advance_external_operation(operation_id, "PREPARED", "DISPATCH_ATTEMPTED", {})

    def claim_external_dispatch(self, operation_id: int) -> bool:
        """Only the transaction advancing PREPARED acquires dispatch authority."""
        with self._write_transaction():
            row = self.get_external_operation(operation_id)
            if row is None:
                raise StoreError("external operation not found")
            if row["phase"] != "PREPARED":
                return False
            self._conn.execute(
                "UPDATE external_operation SET phase = 'DISPATCH_ATTEMPTED', updated_at = ? WHERE id = ?",
                (_utcnow(), operation_id),
            )
            return True

    def bind_external_operation(
        self, operation_id: int, *, remote_operation_id: str,
    ) -> dict[str, Any]:
        # Store accepts an opaque identifier, not remote URLs or response bodies.
        self._external_code(remote_operation_id, "remote_operation_id")
        return self._advance_external_operation(
            operation_id, "DISPATCH_ATTEMPTED", "RUN_IDENTIFIED",
            {"remote_operation_id": remote_operation_id},
        )

    def complete_external_operation(
        self, operation_id: int, *, remote_operation_id: str,
        terminal_status: str, terminal_result: str,
    ) -> dict[str, Any]:
        """Record terminal evidence codes, never raw provider output or approval."""
        for label, value in (("remote_operation_id", remote_operation_id),
                             ("terminal_status", terminal_status), ("terminal_result", terminal_result)):
            self._external_code(value, label)
        return self._advance_external_operation(
            operation_id, "RUN_IDENTIFIED", "TERMINAL_OBSERVED",
            dict(remote_operation_id=remote_operation_id,
                 terminal_status=terminal_status, terminal_result=terminal_result),
        )

    def _advance_external_operation(
        self, operation_id: int, previous: str, phase: str, values: dict[str, str],
    ) -> dict[str, Any]:
        conflict = False
        try:
            with self._write_transaction():
                row = self.get_external_operation(operation_id)
                if row is None:
                    raise StoreError("external operation not found")
                if row["phase"] == phase and all(row[key] == value for key, value in values.items()):
                    return row
                if row["phase"] != previous:
                    raise StoreError("external operation phase conflict")
                if row["remote_operation_id"] is not None and values.get("remote_operation_id") != row["remote_operation_id"]:
                    raise StoreError("external operation remote identity conflict")
                # Field names are fixed by the public methods, never caller data.
                fields = {"phase": phase, "updated_at": _utcnow(), **values}
                assignments = ", ".join(key + " = ?" for key in fields)
                self._conn.execute(
                    f"UPDATE external_operation SET {assignments} WHERE id = ?",
                    (*fields.values(), operation_id),
                )
                return self.get_external_operation(operation_id)
        except sqlite3.IntegrityError:
            conflict = True
        if conflict:
            raise StoreError("external operation uniqueness or structure conflict")

    def list_agent_runs(self, task_id: str) -> list[dict[str, Any]]:
        validate_id(task_id, "task_id")
        cursor = self._conn.execute(
            "SELECT * FROM agent_run WHERE task_id = ? ORDER BY ordinal", (task_id,)
        )
        names = [column[0] for column in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]

    def reserve_agent_run(
        self, task_id: str, *, role: str, agent: str, provider: str,
        phase: str, resource_profile: str, policies: dict[str, Any],
    ) -> int | None:
        """Atomic durable consumption. None means exhausted; never refund runs.

        A task retains its initial profile and cannot gain budget from a later
        policy increase. More restrictive current limits still apply.
        """
        from .config_loader import validate_resource_budget

        block = validate_resource_budget(policies)
        validate_id(task_id, "task_id")
        validate_id(agent, "agent")
        validate_id(provider, "provider")
        if role not in {"builder", "verifier"}:
            raise StoreError("invalid resource role")
        if phase not in ({"implementation", "correction", "capacity_resume"} if role == "builder" else {"review"}):
            raise StoreError("invalid resource phase")
        if resource_profile not in block["profiles"]:
            raise StoreError("invalid resource profile")
        limits = dict(block["profiles"][resource_profile])
        limits["max_correction_attempts"] = min(
            limits["max_correction_attempts"], policies["attempts"]["max_correction_attempts"]
        )
        with self._write_transaction():
            task = self.get_task(task_id)
            if task is None:
                raise StoreError("resource task not found")
            expected = {"CHANGES_REQUESTED"} if phase == "correction" else (
                {"DEVELOPING"} if role == "builder" else {"TECHNICAL_REVIEW", "SECURITY_REVIEW"}
            )
            if task["status"] not in expected:
                raise StoreError("invalid task state for resource reservation")
            runs = self.list_agent_runs(task_id)
            for run in runs:
                if run["resource_profile"] != resource_profile:
                    raise StoreError("resource profile cannot change within a task")
                previous = json.loads(run["limits_json"])
                limits = {key: min(value, previous[key]) for key, value in limits.items()}
            role_count = sum(run["role"] == role for run in runs)
            if (role_count >= limits[f"max_{role}_invocations"]
                or len(runs) >= limits["max_total_model_invocations"]
                or (phase == "correction" and task["attempt_count"] >= limits["max_correction_attempts"])):
                if phase == "correction":
                    self._transition_locked(task_id, "CHANGES_REQUESTED", "BLOCKED", "resource budget exhausted", "orchestrator")
                return None
            now = _utcnow()
            cursor = self._conn.execute(
                "INSERT INTO agent_run (task_id, role, agent, provider, phase, resource_profile, "
                "limits_json, ordinal, state, reserved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?)",
                (task_id, role, agent, provider, phase, resource_profile,
                 json.dumps(limits, sort_keys=True), len(runs) + 1, now),
            )
            if phase == "correction":
                self._conn.execute("UPDATE task SET attempt_count = attempt_count + 1 WHERE id = ?", (task_id,))
                self._transition_locked(task_id, "CHANGES_REQUESTED", "DEVELOPING", "authorized correction reserved", "orchestrator")
            return cursor.lastrowid

    def complete_agent_run(self, run_id: int, *, state: str) -> None:
        if state not in {"SUCCEEDED", "FAILED"}:
            raise StoreError("invalid agent run result")
        with self._write_transaction():
            cursor = self._conn.execute(
                "UPDATE agent_run SET state = ?, completed_at = ? WHERE id = ? AND state = 'RESERVED'",
                (state, _utcnow(), run_id),
            )
            if cursor.rowcount != 1:
                raise StoreError("agent run is absent or already completed")

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        try:
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._init_schema()
        except BaseException:
            # DB inaccesible o corrupta: no se deja la conexión (y el archivo)
            # abierta; el heartbeat la reporta como error de infraestructura.
            self._conn.close()
            raise

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
            # CAPACITY-RESUME-EXECUTION-002 CORRECTION-001: el UPDATE es
            # CONDICIONAL al estado origen que se validó. Si otro proceso ya
            # cambió el estado entre la lectura y este UPDATE, NO se fuerza la
            # transición (0 filas afectadas -> StoreError, sin status_event).
            cur.execute(_UPDATE_TASK_STATUS_SQL, (to_status, now, task_id, from_status))
            if cur.rowcount != 1:
                self._conn.rollback()
                raise StoreError(
                    f"task {task_id!r} is no longer in status {from_status!r}; "
                    "transition not applied"
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

    # ------------------------------------------------------------------
    # HUMAN-GATE-NOTIFY-001: registro de avisos salientes (at-most-once).
    #
    # El Store solo PERSISTE metadata mínima de cada intento. Nunca guarda el
    # mensaje, el webhook, la respuesta remota, ni datos de Claude/Task Packet.
    # ------------------------------------------------------------------

    def claim_human_gate_notification(
        self,
        task_id: str,
        status_event_id: int,
        *,
        event_type: str,
        provider: str,
        gate_type: str,
    ) -> int | None:
        """ATÓMICO (BEGIN IMMEDIATE): reclama el aviso de UNA entrada a
        HUMAN_GATE insertando una fila ATTEMPTING.

        Devuelve el id de la fila reclamada (el llamador puede enviar), o None
        si ya existía un intento para (status_event_id, event_type, provider):
        NO se crea otro y el llamador NO debe enviar (at-most-once).
        Fail closed: el status_event debe existir, pertenecer a la tarea y ser
        la entrada a HUMAN_GATE."""
        validate_id(task_id, "task_id")
        if not isinstance(status_event_id, int) or isinstance(status_event_id, bool):
            raise StoreError("status_event_id must be an integer")
        if not isinstance(event_type, str) or not _NOTIFICATION_EVENT_TYPE_RE.fullmatch(event_type):
            raise StoreError("invalid notification event_type")
        if not isinstance(provider, str) or not _NOTIFICATION_PROVIDER_RE.fullmatch(provider):
            raise StoreError("invalid notification provider")
        if not isinstance(gate_type, str) or not _NOTIFICATION_GATE_TYPE_RE.fullmatch(gate_type):
            raise StoreError("invalid notification gate_type")
        with self._write_transaction():
            with closing(self._conn.cursor()) as cur:
                cur.execute(_SELECT_GATE_EVENT_SQL, (status_event_id,))
                row = cur.fetchone()
            if row is None or row[0] != task_id or row[1] != "HUMAN_GATE":
                raise StoreError(
                    "status_event is not the HUMAN_GATE entry of the task; "
                    "notification not claimed"
                )
            with closing(self._conn.cursor()) as cur:
                cur.execute(
                    _SELECT_EXISTING_NOTIFICATION_SQL, (status_event_id, event_type, provider)
                )
                if cur.fetchone() is not None:
                    return None  # already_exists: no se reclama, no se envía
                # Bajo BEGIN IMMEDIATE nadie más inserta entre el SELECT y el
                # INSERT; UNIQUE(status_event_id, event_type, provider) es la
                # segunda defensa (un duplicado haría rollback y StoreError).
                cur.execute(
                    _CLAIM_NOTIFICATION_SQL,
                    (task_id, status_event_id, event_type, provider, gate_type, _utcnow()),
                )
                if cur.rowcount != 1 or not isinstance(cur.lastrowid, int):
                    raise StoreError("notification claim was not recorded")
                return cur.lastrowid

    def complete_notification(
        self, notification_id: int, *, status: str, error_category: str | None = None
    ) -> dict[str, Any]:
        """ATÓMICO: ATTEMPTING -> SENT | FAILED (+ error_category de
        vocabulario fijo, solo con FAILED). UPDATE con guard (AND status =
        'ATTEMPTING') y rowcount == 1: una fila que ya no está ATTEMPTING NO
        se toca (StoreError, fail closed)."""
        if not isinstance(notification_id, int) or isinstance(notification_id, bool):
            raise StoreError("notification_id must be an integer")
        if status == NOTIFICATION_STATUS_SENT:
            if error_category is not None:
                raise StoreError("a SENT notification cannot have an error_category")
        elif status == NOTIFICATION_STATUS_FAILED:
            if error_category not in NOTIFICATION_ERROR_CATEGORIES:
                raise StoreError("a FAILED notification needs a fixed error_category")
        else:
            raise StoreError("notification status must be SENT or FAILED")
        with self._write_transaction():
            with closing(self._conn.cursor()) as cur:
                cur.execute(
                    _COMPLETE_NOTIFICATION_SQL,
                    (status, error_category, _utcnow(), notification_id),
                )
                if cur.rowcount != 1:
                    raise StoreError(
                        "notification is not in ATTEMPTING (or does not exist); not updated"
                    )
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT id, task_id, status_event_id, event_type, provider, gate_type, "
                "status, error_category, attempted_at, completed_at "
                "FROM notification_event WHERE id = ?",
                (notification_id,),
            )
            row = cur.fetchone()
        assert row is not None
        return dict(zip(_NOTIFICATION_COLUMNS, row))

    def get_notifications(self, task_id: str) -> list[dict[str, Any]]:
        """Solo lectura: intentos de aviso de una tarea (solo metadata)."""
        validate_id(task_id, "task_id")
        with closing(self._conn.cursor()) as cur:
            cur.execute(_SELECT_NOTIFICATIONS_SQL, (task_id,))
            rows = cur.fetchall()
        return [dict(zip(_NOTIFICATION_COLUMNS, row)) for row in rows]

    def list_waiting_capacity_candidates(self) -> list[dict[str, Any]]:
        """CAPACITY-WAKEUP-001: descubrimiento de tareas en
        WAITING_FOR_CLAUDE_CAPACITY. SOLO LECTURA (un SELECT parametrizado):
        no reclama, no transiciona y no modifica nada.

        Devuelve [{"task_id": str, "next_retry_at": str | None}] ordenado por
        task_id ASC (determinista). Incluye TAMBIÉN las inconsistentes: una
        tarea WAITING sin suspensión (next_retry_at None) y una suspensión con
        next_retry_at corrupto (se devuelve tal cual; el llamador lo parsea).
        Nunca devuelve hashes, paths, huella, datos de Claude ni contenido."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(_SELECT_WAITING_CANDIDATES_SQL, (STATE_WAITING_FOR_CLAUDE_CAPACITY,))
            rows = cur.fetchall()
        return [{"task_id": row[0], "next_retry_at": row[1]} for row in rows]

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
    ) -> int:
        """UPDATE condicional del estado + status_event. Debe llamarse DENTRO
        de _write_transaction(). rowcount != 1 -> StoreError (fail closed).
        Devuelve el id del status_event creado en ESTA transacción."""
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
            event_id = cur.lastrowid
        if not isinstance(event_id, int) or isinstance(event_id, bool):
            raise StoreError("status_event id was not returned")
        return event_id

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

    # ------------------------------------------------------------------
    # CAPACITY-RESUME-EXECUTION-002: finalización y bloqueo ATÓMICOS.
    #
    # Cada primitiva es UNA transacción (BEGIN IMMEDIATE): transiciones +
    # status_event + limpieza de task_suspension, o nada. Los `reason` los
    # decide el motor (textos fijos); Store nunca recibe datos de Claude.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # CAPACITY-RESUME-EXECUTION-002 CORRECTION-002: inicio ATÓMICO de tarea.
    # ------------------------------------------------------------------

    def _insert_task_locked(
        self, task_id: str, project_id: str, title: str, need_text: str, now: str
    ) -> None:
        """Proyecto existente y task_id nuevo (o StoreError) + INSERT en
        BACKLOG. DENTRO de _write_transaction()."""
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT 1 FROM project WHERE id = ?", (project_id,))
            if cur.fetchone() is None:
                raise StoreError(f"cannot create task: project {project_id!r} does not exist")
            try:
                cur.execute(
                    _INSERT_TASK_SQL,
                    (task_id, project_id, title, need_text, INITIAL_STATE, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"task {task_id!r} already exists") from exc

    def _insert_initial_event_locked(self, task_id: str, now: str) -> None:
        """Evento inicial NULL -> BACKLOG (misma convención que create_task).
        DENTRO de _write_transaction()."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                _INSERT_INITIAL_EVENT_SQL,
                (task_id, INITIAL_STATE, _TASK_CREATED_REASON, _TASK_CREATED_ACTOR, now),
            )

    def create_and_start_task(
        self,
        task_id: str,
        project_id: str,
        title: str,
        need_text: str,
        *,
        specification_reason: str,
        developing_reason: str,
        actor: str,
    ) -> dict[str, Any]:
        """ATÓMICO (una transacción BEGIN IMMEDIATE): crea una tarea NUEVA y la
        avanza hasta DEVELOPING:

            (nada) -> BACKLOG -> SPECIFICATION -> DEVELOPING

        con los tres status_event (NULL->BACKLOG "task created"/"system", y las
        dos transiciones con los motivos y el actor recibidos, validadas por la
        máquina de estados). Exige proyecto existente y task_id inexistente
        (dos intentos concurrentes: solo uno gana). Ante CUALQUIER fallo en
        cualquier punto se hace rollback de TODA la tarea: no queda ni task ni
        status_event, así que el mismo task_id puede reutilizarse. El proyecto
        es una entidad independiente y nunca se toca. `create_task` conserva su
        semántica pública (solo BACKLOG). No recibe ni persiste nada de Claude
        ni del Task Packet más allá de title/need_text que decide el llamador."""
        validate_id(task_id, "task_id")
        validate_id(project_id, "project_id")
        title_text = _require_text(title, "title")
        need = _require_text(need_text, "need_text")
        specification_text, actor_text = _validate_reason_actor(specification_reason, actor)
        developing_text, _actor = _validate_reason_actor(developing_reason, actor)
        now = _utcnow()
        with self._write_transaction():
            self._insert_task_locked(task_id, project_id, title_text, need, now)
            self._insert_initial_event_locked(task_id, now)
            validate_transition(INITIAL_STATE, STATE_SPECIFICATION)
            self._transition_locked(
                task_id, INITIAL_STATE, STATE_SPECIFICATION, specification_text, actor_text
            )
            validate_transition(STATE_SPECIFICATION, STATE_DEVELOPING)
            self._transition_locked(
                task_id, STATE_SPECIFICATION, STATE_DEVELOPING, developing_text, actor_text
            )
        result = self.get_task(task_id)
        assert result is not None
        return result

    def _require_task_status_locked(self, task_id: str, expected_status: str) -> None:
        task = self.get_task(task_id)
        if task is None:
            raise StoreError(f"task {task_id!r} does not exist")
        if task["status"] != expected_status:
            raise StoreError(
                f"task {task_id!r} must be in status {expected_status!r} "
                f"(found {task['status']!r})"
            )

    def _advance_to_human_gate_locked(self, task_id: str, reason: str, actor: str) -> int:
        """DEVELOPING -> AUTOMATED_TEST -> TECHNICAL_REVIEW -> SECURITY_REVIEW
        -> HUMAN_GATE, validando cada paso con la máquina de estados y
        escribiendo un status_event por transición. DENTRO de una transacción.
        Devuelve el id del status_event de la ENTRADA a HUMAN_GATE (última
        transición), creado en la misma transacción."""
        current = STATE_DEVELOPING
        gate_event_id = 0
        for target in _HUMAN_GATE_CHAIN:
            validate_transition(current, target)
            gate_event_id = self._transition_locked(task_id, current, target, reason, actor)
            current = target
        return gate_event_id

    def _human_gate_result(self, task_id: str, gate_event_id: int) -> dict[str, Any]:
        result = self.get_task(task_id)
        assert result is not None
        # HUMAN-GATE-NOTIFY-001: id del status_event que produjo la entrada a
        # HUMAN_GATE (identidad del gate para deduplicar notificaciones).
        return {**result, "human_gate_status_event_id": gate_event_id}

    def _delete_suspension_locked(self, task_id: str) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute("DELETE FROM task_suspension WHERE task_id = ?", (task_id,))
            if cur.rowcount != 1:
                raise StoreError(f"suspension for task {task_id!r} was not deleted")

    def complete_fresh_task(self, task_id: str, *, reason: str, actor: str) -> dict[str, Any]:
        """ATÓMICO: DEVELOPING -> ... -> HUMAN_GATE de una tarea FRESCA (sin
        suspensión: si existiera alguna, StoreError; no hay nada que
        borrar). Cualquier fallo a mitad -> rollback completo."""
        validate_id(task_id, "task_id")
        reason_text, actor_text = _validate_reason_actor(reason, actor)
        with self._write_transaction():
            self._require_task_status_locked(task_id, STATE_DEVELOPING)
            if self._fetch_suspension(task_id) is not None:
                raise StoreError(
                    f"task {task_id!r} has a suspension: use complete_resumed_task"
                )
            gate_event_id = self._advance_to_human_gate_locked(task_id, reason_text, actor_text)
        return self._human_gate_result(task_id, gate_event_id)

    def complete_resumed_task(self, task_id: str, *, reason: str, actor: str) -> dict[str, Any]:
        """ATÓMICO: DEVELOPING -> ... -> HUMAN_GATE de una tarea REANUDADA
        (exige suspensión existente) + eliminación de task_suspension."""
        validate_id(task_id, "task_id")
        reason_text, actor_text = _validate_reason_actor(reason, actor)
        with self._write_transaction():
            self._require_task_status_locked(task_id, STATE_DEVELOPING)
            if self._fetch_suspension(task_id) is None:
                raise StoreError(f"task {task_id!r} has no active suspension")
            gate_event_id = self._advance_to_human_gate_locked(task_id, reason_text, actor_text)
            self._delete_suspension_locked(task_id)
        return self._human_gate_result(task_id, gate_event_id)

    def block_claimed_resume(self, task_id: str, *, reason: str, actor: str) -> dict[str, Any]:
        """ATÓMICO: una reanudación YA reclamada (DEVELOPING, con suspensión)
        termina en BLOCKED + status_event con reason FIJO + eliminación de
        task_suspension. No toca el repositorio ni las ediciones parciales."""
        validate_id(task_id, "task_id")
        reason_text, actor_text = _validate_reason_actor(reason, actor)
        with self._write_transaction():
            self._require_task_status_locked(task_id, STATE_DEVELOPING)
            if self._fetch_suspension(task_id) is None:
                raise StoreError(f"task {task_id!r} has no active suspension")
            validate_transition(STATE_DEVELOPING, STATE_BLOCKED)
            self._transition_locked(
                task_id, STATE_DEVELOPING, STATE_BLOCKED, reason_text, actor_text
            )
            self._delete_suspension_locked(task_id)
        result = self.get_task(task_id)
        assert result is not None
        return result

    def block_waiting_capacity(
        self, task_id: str, *, reason: str, actor: str
    ) -> dict[str, Any]:
        """ATÓMICO: una tarea que TODAVÍA espera capacidad
        (WAITING_FOR_CLAUDE_CAPACITY, con suspensión) pasa a BLOCKED +
        status_event + eliminación de task_suspension (p. ej. max_wait
        agotado antes de reclamar)."""
        validate_id(task_id, "task_id")
        reason_text, actor_text = _validate_reason_actor(reason, actor)
        with self._write_transaction():
            self._require_task_status_locked(task_id, STATE_WAITING_FOR_CLAUDE_CAPACITY)
            if self._fetch_suspension(task_id) is None:
                raise StoreError(f"task {task_id!r} has no active suspension")
            validate_transition(STATE_WAITING_FOR_CLAUDE_CAPACITY, STATE_BLOCKED)
            self._transition_locked(
                task_id,
                STATE_WAITING_FOR_CLAUDE_CAPACITY,
                STATE_BLOCKED,
                reason_text,
                actor_text,
            )
            self._delete_suspension_locked(task_id)
        result = self.get_task(task_id)
        assert result is not None
        return result
