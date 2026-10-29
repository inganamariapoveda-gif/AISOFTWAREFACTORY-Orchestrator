"""Durable dispatch coordination only; no engine wiring or execution approval."""

from dataclasses import dataclass
import hashlib
import json
import re

from .github_actions_backend import (
    CONCLUSIONS, DispatchRequest, DispatchResponse, GitHubActionsTransport,
    GitHubTransportError, WorkflowRunSnapshot,
)
from .store import Store


class GitHubOperationError(Exception):
    """Controlled coordination failure without provider or persistence details."""


@dataclass(frozen=True, slots=True)
class GitHubOperationResult:
    operation_id: int
    phase: str
    disposition: str
    remote_operation_id: str | None
    terminal_status: str | None
    terminal_result: str | None

    def __post_init__(self):
        dispositions = {
            "PREPARED": "PRE_SEND_BLOCKED",
            "DISPATCH_ATTEMPTED": "BLOCKED_UNKNOWN",
            "RUN_IDENTIFIED": "OBSERVATION_PENDING",
            "TERMINAL_OBSERVED": "TERMINAL_OBSERVED",
        }
        if (type(self.operation_id) is not int or self.operation_id <= 0
                or self.phase not in dispositions or dispositions[self.phase] != self.disposition):
            raise GitHubOperationError("Invalid durable operation evidence")
        known = self.phase in ("RUN_IDENTIFIED", "TERMINAL_OBSERVED")
        if known:
            if (type(self.remote_operation_id) is not str
                    or re.fullmatch(r"[1-9][0-9]{0,63}", self.remote_operation_id) is None):
                raise GitHubOperationError("Invalid durable operation evidence")
        elif self.remote_operation_id is not None:
            raise GitHubOperationError("Invalid durable operation evidence")
        if self.phase == "TERMINAL_OBSERVED":
            if self.terminal_status != "completed" or self.terminal_result not in CONCLUSIONS:
                raise GitHubOperationError("Invalid durable operation evidence")
        elif self.terminal_status is not None or self.terminal_result is not None:
            raise GitHubOperationError("Invalid durable operation evidence")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _result(row):
    return GitHubOperationResult(
        row["id"], row["phase"], {
            "PREPARED": "PRE_SEND_BLOCKED", "DISPATCH_ATTEMPTED": "BLOCKED_UNKNOWN",
            "RUN_IDENTIFIED": "OBSERVATION_PENDING", "TERMINAL_OBSERVED": "TERMINAL_OBSERVED",
        }[row["phase"]], row["remote_operation_id"], row["terminal_status"], row["terminal_result"],
    )


def coordinate_github_operation(
    store: Store, transport: GitHubActionsTransport, task_id: str, request: DispatchRequest, *,
    request_timeout_seconds: float, overall_timeout_seconds: float, poll_interval_seconds: float,
) -> GitHubOperationResult:
    """At most one dispatch under a durable claim; known IDs are observe-only.

    Time limits apply to each transport operation. A terminal replay uses only
    persisted evidence. Conflicts stop closed, without task or budget changes.
    """
    try:
        return _coordinate(store, transport, task_id, request, request_timeout_seconds,
                           overall_timeout_seconds, poll_interval_seconds)
    except Exception:
        pass
    # No underlying exception chain, SQLite text, callback or provider data.
    raise GitHubOperationError("External operation coordination blocked")


def _coordinate(store, transport, task_id, request, request_timeout, overall_timeout, poll_interval):
    if type(request) is not DispatchRequest:
        raise GitHubOperationError("Invalid dispatch identity")
    request.__post_init__()
    config = transport.config
    identity = dict(task_id=task_id, provider="github_actions", operation_type="workflow_dispatch",
                    candidate_sha=request.candidate_sha, logical_test_id=request.logical_test_id,
                    argv_sha256=request.argv_sha256)
    fingerprint = dict(identity, trusted={name: getattr(config, name) for name in (
        "repository", "workflow_id", "workflow_ref", "workflow_source_sha", "api_version",
        "return_run_details",
    )})
    row = store.prepare_external_operation(
        task_id, provider="github_actions", operation_type="workflow_dispatch",
        operation_key=_digest(identity), request_fingerprint=_digest(fingerprint),
    )
    operation_id = row["id"]
    if row["phase"] == "PREPARED":
        acquired = False
        barrier_called = False

        def before_post():
            nonlocal acquired, barrier_called
            if barrier_called:
                return False
            barrier_called = True
            acquired = store.claim_external_dispatch(operation_id)
            return acquired

        run_id = None
        try:
            response = transport.dispatch(request, request_timeout_seconds=request_timeout,
                                          overall_timeout_seconds=overall_timeout, before_post=before_post)
            if type(response) is DispatchResponse:
                response.__post_init__()
                run_id = response.workflow_run_id
        except GitHubTransportError as error:
            run_id = error.workflow_run_id
        except Exception:
            pass
        # Evidence from a dispatch belongs to this caller only after its claim.
        if acquired and type(run_id) is int and run_id > 0:
            row = store.bind_external_operation(operation_id, remote_operation_id=str(run_id))
        else:
            # One read after rejection/failure; never wait for a competing caller.
            row = store.get_external_operation(operation_id)

    result = _result(row)
    if result.phase != "RUN_IDENTIFIED":
        return result
    snapshot = None
    try:
        observed = transport.observe(int(result.remote_operation_id),
                                     request_timeout_seconds=request_timeout,
                                     overall_timeout_seconds=overall_timeout,
                                     poll_interval_seconds=poll_interval)
        if type(observed) is WorkflowRunSnapshot:
            observed.__post_init__()
            if (observed.run_id == int(result.remote_operation_id)
                    and observed.head_sha == config.workflow_source_sha
                    and observed.repository_full_name == config.repository
                    and observed.status == "completed"):
                snapshot = observed
    except Exception:
        pass
    if snapshot is None:
        return result
    return _result(store.complete_external_operation(
        operation_id, remote_operation_id=result.remote_operation_id,
        terminal_status="completed", terminal_result=snapshot.conclusion,
    ))
