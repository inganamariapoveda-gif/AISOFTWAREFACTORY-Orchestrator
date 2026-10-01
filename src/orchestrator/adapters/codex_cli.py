"""Disabled-by-default Codex CLI foundation; no policy, persistence or retries.

JSONL assumptions are deliberately isolated here pending activation validation.
subprocess.run kills/waits for its direct child on timeout. Descendant cleanup
and effective Windows sandbox boundaries remain activation-review limitations.
"""
from __future__ import annotations

import enum
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config_loader import ConfigError, validate_codex_execution_config


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
    if os.name == "nt" and not any(
        key.upper() == "SYSTEMROOT" and value.strip() for key, value in child.items()
    ):
        raise ValueError("missing Windows execution context")
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


def _parse_output(stdout: str, returncode: int) -> CodexResult:
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
    except (ValueError, TypeError, RecursionError):
        return _result(CodexFailureCategory.MALFORMED_OUTPUT, returncode)
    if not seen or terminal is None:
        return _result(CodexFailureCategory.MALFORMED_OUTPUT, returncode)
    if terminal == "turn.failed":
        return _result(CodexFailureCategory.UNKNOWN, returncode, terminal,
                       **counts, action_evidence_observed=bool(action_ids))
    return _result(CodexFailureCategory.SUCCESS, returncode, terminal,
                   **counts, action_evidence_observed=bool(action_ids))


def run_codex_task(*, repository_root: Path, authorized_root: Path,
                   instruction: str, execution_config: dict[str, Any]) -> CodexResult:
    try:
        settings = validate_codex_execution_config(execution_config)
        root = Path(repository_root).resolve(strict=True)
        allowed = Path(authorized_root).resolve(strict=True)
        if root != allowed or not root.is_dir() or execution_config["enabled"] is not True:
            return _result(CodexFailureCategory.UNKNOWN)
        if not isinstance(instruction, str) or not instruction.strip():
            return _result(CodexFailureCategory.UNKNOWN)
    except (ConfigError, OSError, ValueError, TypeError):
        return _result(CodexFailureCategory.UNKNOWN)
    executable = shutil.which(execution_config["executable"])
    if executable is None:
        return _result(CodexFailureCategory.EXECUTABLE_UNAVAILABLE)
    argv = [
        executable, "-a", settings["approval_policy"], "exec",
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
    return _parse_output(completed.stdout, completed.returncode)
