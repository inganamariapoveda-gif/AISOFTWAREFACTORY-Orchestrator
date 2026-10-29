"""Disconnected GitHub transport and contracts; backend activation stays disabled.

PAT != test authorization; backend != authorization. A workflow result is
neither technical nor security approval. No operational port is installed.
"""

from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Any, Callable
from urllib import request as http
from urllib.error import HTTPError

from .config_loader import ConfigError, validate_safe_test_backend


@dataclass(frozen=True, slots=True)
class GitHubBackendConfig:
    provider: str
    activation: str
    mvp: str
    production_required: str
    github_app_required_before: tuple[str, ...]
    repository: str
    workflow_id: str
    workflow_ref: str
    workflow_source_sha: str
    api_version: str
    return_run_details: bool

    def __post_init__(self):
        if type(self.github_app_required_before) is not tuple:
            raise ConfigError("migration gates must be immutable")
        validate_safe_test_backend({"safe_test_backend": {
            "provider": self.provider, "activation": self.activation,
            "credential_strategy": {
                "mvp": self.mvp, "production_required": self.production_required,
                "github_app_required_before": list(self.github_app_required_before),
            },
            "github": {key: getattr(self, key) for key in (
                "repository", "workflow_id", "workflow_ref", "workflow_source_sha",
                "api_version", "return_run_details",
            )},
        }})

    @classmethod
    def from_policies(cls, policies: dict[str, Any]) -> "GitHubBackendConfig":
        block = validate_safe_test_backend(policies)
        if block is None:
            raise ConfigError("safe test backend configuration unavailable")
        strategy = block["credential_strategy"]
        return cls(
            provider=block["provider"], activation=block["activation"],
            mvp=strategy["mvp"], production_required=strategy["production_required"],
            github_app_required_before=tuple(strategy["github_app_required_before"]),
            **block["github"],
        )


def argv_sha256(argv: tuple[str, ...]) -> str:
    """Identity only, not authorization; compact UTF-8 JSON preserves boundaries."""
    if type(argv) is not tuple or not argv or any(type(arg) is not str for arg in argv):
        raise ValueError("argv must be a nonempty tuple of strings")
    encoded = json.dumps(list(argv), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class DispatchRequest:
    candidate_sha: str
    logical_test_id: str
    argv_sha256: str

    def __post_init__(self):
        for value, pattern in (
            (self.candidate_sha, r"[0-9a-f]{40}"),
            (self.logical_test_id, r"[A-Za-z][A-Za-z0-9_-]*"),
            (self.argv_sha256, r"[0-9a-f]{64}"),
        ):
            if type(value) is not str or re.fullmatch(pattern, value) is None:
                raise ValueError("invalid dispatch identity")


@dataclass(frozen=True, slots=True)
class DispatchResponse:
    workflow_run_id: int
    run_url: str
    html_url: str

    def __post_init__(self):
        _positive_id(self.workflow_run_id)
        if (type(self.run_url) is not str or self.run_url != _run_url(self.workflow_run_id)
                or type(self.html_url) is not str
                or self.html_url != f"https://github.com/{REPOSITORY}/actions/runs/{self.workflow_run_id}"):
            raise GitHubTransportError("Invalid dispatch response identity")


@dataclass(frozen=True, slots=True)
class WorkflowRunSnapshot:
    """Run metadata: head_sha identifies the workflow source/ref, not candidate."""
    run_id: int
    event: str
    status: str
    conclusion: str | None
    head_sha: str
    run_attempt: int
    workflow_id: int
    repository_full_name: str

    def __post_init__(self):
        _positive_id(self.run_id)
        _positive_id(self.workflow_id)
        if (type(self.event) is not str or self.event != "workflow_dispatch"
                or type(self.head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", self.head_sha) is None
                or type(self.run_attempt) is not int or self.run_attempt != 1
                or type(self.repository_full_name) is not str or self.repository_full_name != REPOSITORY):
            raise GitHubTransportError("Invalid workflow run identity")
        if type(self.status) is not str or self.status not in NONTERMINAL | {"completed"}:
            raise GitHubTransportError("Invalid workflow run status")
        if self.status == "completed":
            if type(self.conclusion) is not str or self.conclusion not in CONCLUSIONS:
                raise GitHubTransportError("Invalid workflow run conclusion")
        elif self.conclusion is not None:
            raise GitHubTransportError("Invalid workflow run conclusion")


API_BASE = "https://api.github.com"
REPOSITORY = "inganamariapoveda-gif/AISOFTWAREFACTORY-Orchestrator"
WORKFLOW_PATH = ".github/workflows/safe-test-runner.yml"
NONTERMINAL = frozenset({"queued", "in_progress", "requested", "waiting", "pending"})
CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out", "action_required",
                         "neutral", "skipped", "stale"})
MAX_RESPONSE_BYTES = 1_048_576


class GitHubTransportError(Exception):
    """Public failures contain only controlled messages, never remote data."""

    def __init__(self, message: str, *, workflow_run_id: int | None = None):
        if workflow_run_id is not None and (type(workflow_run_id) is not int or workflow_run_id <= 0):
            raise ValueError("Invalid failure run identity")
        super().__init__(message)
        # Reconciliation evidence only; never approval or a retry instruction.
        self.workflow_run_id = workflow_run_id


def _positive_id(value):
    if type(value) is not int or value <= 0:
        raise GitHubTransportError("Invalid numeric identity")


def _run_url(run_id: int) -> str:
    _positive_id(run_id)
    return f"{API_BASE}/repos/{REPOSITORY}/actions/runs/{run_id}"


@dataclass(frozen=True, slots=True)
class WorkflowIdentity:
    workflow_id: int
    path: str
    state: str

    def __post_init__(self):
        _positive_id(self.workflow_id)
        if (type(self.path) is not str or self.path != WORKFLOW_PATH
                or type(self.state) is not str or self.state != "active"):
            raise GitHubTransportError("Invalid workflow identity")


class _NoRedirect(http.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GitHubTransportError("HTTP redirect rejected")


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Invalid JSON constant")


class GitHubActionsTransport:
    """Explicit REST operation only; not an IsolatedTestBackend or authorization.

    No engine installs this transport. A completed success is remote metadata,
    never technical, security or human approval. Injected dependencies are trusted
    control-plane dependencies, not values taken from a task or remote response.
    """

    def __init__(self, config: GitHubBackendConfig, credential_provider: Callable[[], str],
                 *, opener=None, monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if type(config) is not GitHubBackendConfig or not all(
                callable(value) for value in (credential_provider, monotonic, sleep)):
            raise GitHubTransportError("Invalid transport dependencies")
        config.__post_init__()
        self._config = config
        self._credential_provider = credential_provider
        self._monotonic = monotonic
        self._sleep = sleep
        # Disable implicit environment proxy discovery; never follow redirects.
        self._opener = opener if opener is not None else http.build_opener(http.ProxyHandler({}), _NoRedirect())
        if not callable(getattr(self._opener, "open", None)):
            raise GitHubTransportError("Invalid HTTP dependency")

    @property
    def config(self) -> GitHubBackendConfig:
        """Immutable trusted configuration actually used by this transport."""
        return self._config

    def _remaining(self, deadline):
        remaining = deadline - self._monotonic()
        if not math.isfinite(remaining) or remaining <= 0:
            raise GitHubTransportError("Overall deadline exceeded")
        return remaining

    def _request(self, url, payload, deadline, request_timeout):
        # Bind the actual HTTP method to an exact destination before obtaining
        # any credential. Do not normalize or resolve untrusted URL strings.
        method = "GET" if payload is None else "POST"
        base = f"{API_BASE}/repos/{REPOSITORY}"
        workflow = base + "/actions/workflows/safe-test-runner.yml"
        allowed = type(url) is str and (
            (method == "GET" and (
                url in (workflow, base + "/git/ref/tags/safe-test-runner-v1")
                or re.fullmatch(re.escape(base + "/actions/runs/") + r"[1-9][0-9]*", url) is not None
            )) or (method == "POST" and url == workflow + "/dispatches")
        )
        if not allowed:
            raise GitHubTransportError("HTTP destination or operation rejected")
        self._remaining(deadline)
        token = None
        try:
            token = self._credential_provider()
        except Exception:
            pass
        # Raise outside the provider's exception context: no secret exception chain.
        if type(token) is not str or not token or "\r" in token or "\n" in token:
            raise GitHubTransportError("Credential unavailable")
        data = None if payload is None else json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        result = None
        observed_run_id = None
        try:
            req = http.Request(url, data=data, method=method, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "X-GitHub-Api-Version": self._config.api_version,
                "User-Agent": "AISOFTWAREFACTORY-Orchestrator",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            })
            with self._opener.open(req, timeout=min(request_timeout, self._remaining(deadline))) as response:
                self._remaining(deadline)
                if response.status != 200 or type(response.status) is not int or response.geturl() != url:
                    raise GitHubTransportError("Unexpected HTTP response")
                chunks = []
                remaining = MAX_RESPONSE_BYTES + 1
                while remaining > 0:
                    self._remaining(deadline)
                    size = min(65_536, remaining)
                    chunk = response.read(size)
                    self._remaining(deadline)
                    if type(chunk) is not bytes or len(chunk) > size:
                        raise GitHubTransportError("Invalid HTTP response chunk")
                    if chunk == b"":
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                body = b"".join(chunks)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise GitHubTransportError("Invalid HTTP response size")
                result = json.loads(body.decode("utf-8"), object_pairs_hook=_json_object,
                                    parse_constant=_reject_constant)
                if method == "POST" and type(result) is dict:
                    value = result.get("workflow_run_id")
                    if type(value) is int and value > 0:
                        observed_run_id = value
        except Exception as error:
            # HTTPError owns a response stream; close it without emitting its
            # remote reason/body (including deferred resource warnings).
            if isinstance(error, HTTPError):
                try:
                    error.close()
                except Exception:
                    pass
            result = None
        finally:
            token = None
        # No HTTP retry, remote body, URL, header or exception detail escapes.
        if type(result) is not dict:
            raise GitHubTransportError("HTTP response rejected", workflow_run_id=observed_run_id)
        # A decoded successful dispatch response must reach the caller so its
        # exact run ID is retained even if the absolute deadline just expired.
        if method != "POST":
            self._remaining(deadline)
        return result

    def _deadline(self, request_timeout, overall_timeout, poll_interval):
        self._config.__post_init__()
        for value, minimum, maximum in ((request_timeout, 0, 30),
                                        (overall_timeout, 0, 600), (poll_interval, 1, 30)):
            if (type(value) not in (int, float) or not minimum <= value <= maximum
                    or value == 0):
                raise GitHubTransportError("Invalid timeout")
        return self._monotonic() + overall_timeout

    def _workflow_identity(self, deadline, request_timeout):
        workflow_url = f"{API_BASE}/repos/{REPOSITORY}/actions/workflows/{self._config.workflow_id}"
        metadata = self._request(workflow_url, None, deadline, request_timeout)
        workflow = WorkflowIdentity(metadata.get("id"), metadata.get("path"), metadata.get("state"))
        source = self._request(f"{API_BASE}/repos/{REPOSITORY}/git/ref/tags/safe-test-runner-v1",
                               None, deadline, request_timeout)
        obj = source.get("object")
        if (source.get("ref") != "refs/tags/safe-test-runner-v1" or type(obj) is not dict
                or obj.get("type") != "commit" or type(obj.get("sha")) is not str
                or obj["sha"] != self._config.workflow_source_sha):
            raise GitHubTransportError("Workflow source tag identity mismatch")
        return workflow

    def _dispatch_once(self, request, deadline, request_timeout):
        payload = {
            "ref": self._config.workflow_ref,
            "return_run_details": self._config.return_run_details,
            "inputs": {"candidate_sha": request.candidate_sha,
                       "logical_test_id": request.logical_test_id,
                       "argv_sha256": request.argv_sha256,
                       "workflow_source_sha": self._config.workflow_source_sha},
        }
        workflow_run_id = None
        try:
            url = f"{API_BASE}/repos/{REPOSITORY}/actions/workflows/{self._config.workflow_id}/dispatches"
            data = self._request(url, payload, deadline, request_timeout)
            _positive_id(data.get("workflow_run_id"))
            workflow_run_id = data["workflow_run_id"]
            result = DispatchResponse(workflow_run_id, data.get("run_url"), data.get("html_url"))
            self._remaining(deadline)
            return result
        except GitHubTransportError as error:
            if workflow_run_id is None:
                workflow_run_id = error.workflow_run_id
        except Exception:
            pass
        # None after a POST attempt does NOT prove the server did not receive it.
        raise GitHubTransportError("Dispatch or run observation failed", workflow_run_id=workflow_run_id)

    def _wait_existing(self, workflow_run_id, workflow, deadline, request_timeout, poll_interval):
        # This path has no dispatch call and all HTTP calls have payload=None (GET).
        run_url = _run_url(workflow_run_id)
        while True:
            data = self._request(run_url, None, deadline, request_timeout)
            required = {"id", "event", "status", "conclusion", "head_sha", "run_attempt",
                        "workflow_id", "repository"}
            if not required <= data.keys() or type(data["repository"]) is not dict:
                raise GitHubTransportError("Incomplete workflow run metadata")
            snapshot = WorkflowRunSnapshot(
                data["id"], data["event"], data["status"], data["conclusion"], data["head_sha"],
                data["run_attempt"], data["workflow_id"], data["repository"].get("full_name"),
            )
            if (snapshot.run_id != workflow_run_id or snapshot.workflow_id != workflow.workflow_id
                    or snapshot.head_sha != self._config.workflow_source_sha):
                raise GitHubTransportError("Workflow run continuity mismatch")
            remaining = self._remaining(deadline)
            if snapshot.status == "completed":
                return snapshot
            self._sleep(min(poll_interval, remaining))

    def dispatch(self, request: DispatchRequest, *, request_timeout_seconds: float,
                 overall_timeout_seconds: float,
                 before_post: Callable[[], bool] | None = None) -> DispatchResponse:
        """One validated dispatch, no polling or retry.

        The optional caller-owned barrier runs after trusted preflight and must
        return True exactly. No missing ID authorizes redispatch; this transport
        does not persist evidence or grant execution authority.
        """
        if type(request) is not DispatchRequest:
            raise GitHubTransportError("Invalid dispatch request")
        request.__post_init__()
        deadline = self._deadline(request_timeout_seconds, overall_timeout_seconds, 1)
        self._workflow_identity(deadline, request_timeout_seconds)
        if before_post is not None:
            authorized = False
            try:
                authorized = before_post() is True
            except Exception:
                pass
            # Outside callback exception context; no arbitrary details escape.
            if not authorized:
                raise GitHubTransportError("Dispatch barrier rejected")
        return self._dispatch_once(request, deadline, request_timeout_seconds)

    def observe(self, workflow_run_id: int, *, request_timeout_seconds: float,
                overall_timeout_seconds: float, poll_interval_seconds: float) -> WorkflowRunSnapshot:
        """GET-only observation of an existing ID; no approval or redispatch.

        The caller must obtain the ID from trusted operational evidence. There
        is no run discovery by time, branch or latest-result heuristics.
        """
        _positive_id(workflow_run_id)
        deadline = self._deadline(request_timeout_seconds, overall_timeout_seconds, poll_interval_seconds)
        try:
            workflow = self._workflow_identity(deadline, request_timeout_seconds)
            return self._wait_existing(workflow_run_id, workflow, deadline,
                                       request_timeout_seconds, poll_interval_seconds)
        except Exception:
            pass
        raise GitHubTransportError("Dispatch or run observation failed", workflow_run_id=workflow_run_id)

    def dispatch_and_wait(self, request: DispatchRequest, *,
                          request_timeout_seconds: float,
                          overall_timeout_seconds: float, poll_interval_seconds: float) -> WorkflowRunSnapshot:
        """Compatibility composition with one shared deadline and at most one POST."""
        if type(request) is not DispatchRequest:
            raise GitHubTransportError("Invalid dispatch request")
        request.__post_init__()
        deadline = self._deadline(request_timeout_seconds, overall_timeout_seconds, poll_interval_seconds)
        workflow = self._workflow_identity(deadline, request_timeout_seconds)
        dispatch = self._dispatch_once(request, deadline, request_timeout_seconds)
        try:
            return self._wait_existing(dispatch.workflow_run_id, workflow, deadline,
                                       request_timeout_seconds, poll_interval_seconds)
        except Exception:
            pass
        raise GitHubTransportError("Dispatch or run observation failed", workflow_run_id=dispatch.workflow_run_id)
