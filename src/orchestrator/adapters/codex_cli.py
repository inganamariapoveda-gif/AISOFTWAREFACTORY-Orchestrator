"""Disabled-by-default Codex CLI foundation; no policy, persistence or retries.

JSONL assumptions are deliberately isolated here pending activation validation.
subprocess.run kills/waits for its direct child on timeout. Descendant cleanup
and effective Windows sandbox boundaries remain activation-review limitations.
"""
from __future__ import annotations

import enum
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

from ..config_loader import ConfigError, validate_codex_execution_config


def windows_sandbox_args() -> list[str]:
    """Director-approved native Windows compatibility binding; no fallback."""
    return ["-c", 'windows.sandbox="elevated"'] if os.name == "nt" else []


def _child_environment() -> dict[str, str]:
    # PATH/PATHEXT: local executable lookup; SYSTEMROOT: Windows runtime.
    # USERPROFILE/HOME/CODEX_HOME: existing home/auth-store location only.
    # TEMP/TMP: runtime temporary files. No application settings or credentials.
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "USERPROFILE", "HOME",
               "CODEX_HOME", "TEMP", "TMP"}
    child: dict[str, str] = {}
    seen: set[str] = set()
    for key in sorted(os.environ):
        normalized = key.upper()
        if normalized in allowed:
            if normalized in seen:
                raise ValueError("ambiguous child environment")
            seen.add(normalized)
            child[key] = os.environ[key]
    if os.name == "nt":
        root = next((value for key, value in child.items() if key.upper() == "SYSTEMROOT"), "")
        path = PureWindowsPath(root)
        if (not re.fullmatch(r"[A-Za-z]:", path.drive) or not path.is_absolute()
                or not re.match(r"^[A-Za-z]:[\\/]", root) or ".." in path.parts
                or any(character in root[2:] for character in ':*?"<>|\x00\r\n')):
            raise ValueError("invalid Windows execution context")
        child["SYSTEMDRIVE"] = path.drive.upper()
    return child


class CodexFailureCategory(str, enum.Enum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    EXECUTABLE_UNAVAILABLE = "EXECUTABLE_UNAVAILABLE"
    PROCESS_FAILURE = "PROCESS_FAILURE"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    AUTH_UNAVAILABLE = "AUTH_UNAVAILABLE"
    TEMPORARY_CAPACITY = "TEMPORARY_CAPACITY"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CommandExpectation:
    fingerprint: bytes


@dataclass(frozen=True)
class CommandAttestation:
    observed: bool = False
    started: bool = False
    completed: bool = False
    consistent: bool = False
    duplicate: bool = False


def command_fingerprint(command: str) -> bytes:
    if type(command) is not str:
        raise ValueError("invalid diagnostic command")
    return hashlib.sha256(b"codex-command-v1\0str\0" + command.encode("utf-8")).digest()


def _validate_expectations(expectations):
    if not isinstance(expectations, tuple) or any(
        not isinstance(value, CommandExpectation) or type(value.fingerprint) is not bytes
        or len(value.fingerprint) != 32 for value in expectations
    ) or len({value.fingerprint for value in expectations}) != len(expectations):
        raise ValueError("invalid command expectations")


class _CommandTracker:
    """Private transient state: IDs/digests never leave this parser helper."""
    def __init__(self, expectations):
        self.expected = tuple(value.fingerprint for value in expectations)
        self.items = {}
        self.other_ids = set()
        self.types = {}
        self.malformed = 0
        self.conflicts = 0

    def observe(self, kind, item):
        identity, item_type = item["id"], item["type"]
        if identity in self.types and self.types[identity] != item_type:
            self.conflicts += 1
        self.types[identity] = item_type
        if item_type != "command_execution":
            if item_type not in {"agent_message", "reasoning", "file_change"}:
                self.other_ids.add(identity)
            return
        state = self.items.setdefault(identity, dict(digests=set(), started=False, completed=False, valid=True,
                                                     field_present=False, field_string=False))
        # Diagnostic counts are unique command items with at least one suitable
        # observation, not event counts. Acceptance still validates every event.
        state["field_present"] |= "command" in item
        state["field_string"] |= type(item.get("command")) is str
        if type(item.get("command")) is not str:
            self.malformed += 1
            state["valid"] = False
        else:
            digest = command_fingerprint(item["command"])
            if state["digests"] and digest not in state["digests"]:
                self.conflicts += 1
                state["valid"] = False
            state["digests"].add(digest)
        if kind == "item.started":
            if state["started"] or state["completed"]:
                state["valid"] = False
            state["started"] = True
        elif kind == "item.completed":
            state["completed"] = True
        elif state["completed"]:
            state["valid"] = False

    def summary(self):
        attestations = []
        for digest in self.expected:
            matches = [state for state in self.items.values() if digest in state["digests"]]
            unique = len(matches) == 1
            state = matches[0] if unique else {}
            attestations.append(CommandAttestation(bool(matches), state.get("started", False),
                state.get("completed", False), unique and state["valid"] and self.conflicts == 0,
                len(matches) > 1))
        return dict(command_attestations=tuple(attestations),
            command_field_present_count=sum(state["field_present"] for state in self.items.values()),
            command_field_string_count=sum(state["field_string"] for state in self.items.values()),
            lifecycle_command_consistent_count=sum(state["valid"] and state["started"]
                and state["completed"] and len(state["digests"]) == 1 for state in self.items.values()),
            unexpected_command_execution_count=sum(
                bool(state["digests"] - set(self.expected)) for state in self.items.values()),
            malformed_command_attestation_count=self.malformed,
            command_payload_conflict_count=self.conflicts,
            unexpected_action_item_count=len(self.other_ids))


ITEM_TYPES = ("agent_message", "reasoning", "command_execution", "file_change",
              "mcp_tool_call", "collab_tool_call", "web_search", "todo_list")


@dataclass(frozen=True)
class CodexResult:
    """SUCCESS means turn completion at the adapter boundary, not task approval."""
    completed: bool
    failure_category: CodexFailureCategory
    public_reason: str
    process_return_code: int | None = None
    terminal_status: str | None = None
    provider: str = "openai_codex"
    adapter: str = "codex_cli"
    event_count: int = 0
    item_started_count: int = 0
    item_completed_count: int = 0
    command_execution_count: int = 0
    file_change_item_count: int = 0
    action_evidence_observed: bool = False
    command_attestations: tuple[CommandAttestation, ...] = ()
    unexpected_command_execution_count: int = 0
    malformed_command_attestation_count: int = 0
    command_payload_conflict_count: int = 0
    unexpected_action_item_count: int = 0
    command_field_present_count: int = 0
    command_field_string_count: int = 0
    lifecycle_command_consistent_count: int = 0
    item_type_counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(ITEM_TYPES, 0))


def _result(category: CodexFailureCategory, code: int | None = None,
            terminal: str | None = None, **telemetry: Any) -> CodexResult:
    # Never derive a reason from model text, stderr, paths or exception messages.
    return CodexResult(category is CodexFailureCategory.SUCCESS, category,
                       "Codex execution: " + category.value, code, terminal, **telemetry)


class CodexExecutionError(Exception):
    """Application bridge to its existing post-failure evidence path."""
    def __init__(self, result: CodexResult):
        super().__init__(result.public_reason)
        self.category = result.failure_category
        self.details = {
            "provider": result.provider, "adapter": result.adapter,
            "process_return_code": result.process_return_code,
            "terminal_status": result.terminal_status,
        }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-JSON constant")


def _parse_output(stdout: str, returncode: int,
                  expected_commands: tuple[CommandExpectation, ...] = ()) -> CodexResult:
    # No reliable structured auth/capacity/resource marker has been verified.
    # Those enum values are reserved; free-form stderr is never classified.
    if returncode != 0:
        return _result(CodexFailureCategory.PROCESS_FAILURE, returncode)
    started = False
    terminal = None
    pending_items: set[str] = set()
    seen = False
    counts = dict(event_count=0, item_started_count=0, item_completed_count=0,
                  command_execution_count=0, file_change_item_count=0)
    action_ids: dict[str, str] = {}
    # Transient IDs only; report unique items per known type, not lifecycle events.
    typed_ids = {kind: set() for kind in ITEM_TYPES}
    tracker = _CommandTracker(expected_commands) if expected_commands else None
    try:
        for line in stdout.splitlines():
            if not line.strip():
                continue
            event = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            if not isinstance(event, dict) or not isinstance(event.get("type"), str):
                raise ValueError
            kind = event["type"]
            counts["event_count"] += 1
            seen = True
            if terminal is not None:
                raise ValueError
            if kind == "thread.started":
                if started:
                    raise ValueError
            elif kind == "turn.started":
                if started:
                    raise ValueError
                started = True
            elif kind in {"turn.completed", "turn.failed"}:
                if not started or pending_items:
                    raise ValueError
                terminal = kind
            elif kind == "error":
                return _result(CodexFailureCategory.UNKNOWN, returncode, "error")
            elif kind in {"item.started", "item.updated", "item.completed"}:
                item = event.get("item")
                if not started or not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    raise ValueError
                item_type = item.get("type")
                if not isinstance(item_type, str) or not item["id"]:
                    raise ValueError
                if item_type in typed_ids:
                    typed_ids[item_type].add(item["id"])
                if tracker is not None:
                    tracker.observe(kind, item)
                if item_type in {"command_execution", "file_change"}:
                    previous = action_ids.get(item["id"])
                    if previous is not None and previous != item_type:
                        raise ValueError
                    if previous is None:
                        action_ids[item["id"]] = item_type
                        key = "command_execution_count" if item_type == "command_execution" else "file_change_item_count"
                        counts[key] += 1
                if kind == "item.started":
                    counts["item_started_count"] += 1
                elif kind == "item.completed":
                    counts["item_completed_count"] += 1
                if kind == "item.started":
                    if item["id"] in pending_items:
                        raise ValueError
                    pending_items.add(item["id"])
                elif kind == "item.completed":
                    pending_items.discard(item["id"])
            else:
                raise ValueError
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return _result(CodexFailureCategory.MALFORMED_OUTPUT, returncode)
    if not seen or terminal is None:
        return _result(CodexFailureCategory.MALFORMED_OUTPUT, returncode)
    diagnostic = tracker.summary() if tracker is not None else {}
    diagnostic["item_type_counts"] = {kind: len(ids) for kind, ids in typed_ids.items()}
    if terminal == "turn.failed":
        return _result(CodexFailureCategory.UNKNOWN, returncode, terminal,
                       **counts, action_evidence_observed=bool(action_ids), **diagnostic)
    return _result(CodexFailureCategory.SUCCESS, returncode, terminal,
                   **counts, action_evidence_observed=bool(action_ids), **diagnostic)


def run_codex_task(*, repository_root: Path, authorized_root: Path,
                   instruction: str, execution_config: dict[str, Any],
                   expected_commands: tuple[CommandExpectation, ...] = (),
                   resolved_executable: str | Path | None = None) -> CodexResult:
    try:
        _validate_expectations(expected_commands)
        settings = validate_codex_execution_config(execution_config)
        root = Path(repository_root).resolve(strict=True)
        allowed = Path(authorized_root).resolve(strict=True)
        if root != allowed or not root.is_dir() or execution_config["enabled"] is not True:
            return _result(CodexFailureCategory.UNKNOWN)
        if not isinstance(instruction, str) or not instruction.strip():
            return _result(CodexFailureCategory.UNKNOWN)
    except (ConfigError, OSError, ValueError, TypeError):
        return _result(CodexFailureCategory.UNKNOWN)
    if resolved_executable is None:
        executable = shutil.which(execution_config["executable"])
    else:
        try:
            candidate = Path(resolved_executable)
            if not candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError
            # Inspect lexical ancestors; do not resolve/follow links. Full
            # installation provenance belongs to the trusted activation caller.
            for part in (candidate, *candidate.parents):
                info = part.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise ValueError
            if not stat.S_ISREG(candidate.stat().st_mode):
                raise ValueError
            executable = str(resolved_executable)
        except (OSError, ValueError, TypeError):
            return _result(CodexFailureCategory.EXECUTABLE_UNAVAILABLE)
    if executable is None:
        return _result(CodexFailureCategory.EXECUTABLE_UNAVAILABLE)
    argv = [
        executable, *windows_sandbox_args(), "-a", settings["approval_policy"], "exec",
        "-C", str(root), "--sandbox", settings["sandbox"], "--json",
        "--ephemeral", "--ignore-user-config",
        "-c", "sandbox_workspace_write.network_access=false",
        "-c", "sandbox_workspace_write.writable_roots=[]",
        "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
        "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "-c", "tools.web_search=false",
        "-",
    ]
    try:
        child_env = _child_environment()
    except (ValueError, OSError):
        return _result(CodexFailureCategory.PROCESS_FAILURE)
    try:
        completed = subprocess.run(
            argv, input=instruction, cwd=root, capture_output=True,
            text=True, encoding="utf-8", errors="strict", shell=False,
            timeout=settings["timeout_seconds"], env=child_env,
        )
    except FileNotFoundError:
        return _result(CodexFailureCategory.EXECUTABLE_UNAVAILABLE)
    except subprocess.TimeoutExpired:
        return _result(CodexFailureCategory.TIMEOUT)
    except UnicodeError:
        return _result(CodexFailureCategory.MALFORMED_OUTPUT)
    except OSError:
        return _result(CodexFailureCategory.PROCESS_FAILURE)
    return _parse_output(completed.stdout, completed.returncode, expected_commands)
