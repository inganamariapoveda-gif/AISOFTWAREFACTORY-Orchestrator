"""Disabled GitHub contract only: no transport, credentials or executor.

PAT != test authorization; backend != authorization. A workflow result is
neither technical nor security approval. No operational port is installed.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

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
                "repository", "workflow_id", "workflow_ref", "api_version", "return_run_details",
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
    workflow_ref: str = "main"
    return_run_details: bool = True

    def __post_init__(self):
        for value, pattern in (
            (self.candidate_sha, r"[0-9a-f]{40}"),
            (self.logical_test_id, r"[A-Za-z][A-Za-z0-9_-]*"),
            (self.argv_sha256, r"[0-9a-f]{64}"),
        ):
            if type(value) is not str or re.fullmatch(pattern, value) is None:
                raise ValueError("invalid dispatch identity")
        if self.workflow_ref != "main" or self.return_run_details is not True:
            raise ValueError("invalid dispatch control")

    def to_payload(self) -> dict[str, Any]:
        """Future payload only; no dispatch or execution is performed."""
        return {"ref": self.workflow_ref, "return_run_details": self.return_run_details,
                "inputs": {"candidate_sha": self.candidate_sha,
                           "logical_test_id": self.logical_test_id,
                           "argv_sha256": self.argv_sha256}}


@dataclass(frozen=True, slots=True)
class DispatchResponse:
    workflow_run_id: int
    run_url: str
    html_url: str


@dataclass(frozen=True, slots=True)
class WorkflowRunSnapshot:
    run_id: int
    event: str
    status: str
    conclusion: str | None
    head_sha: str
    run_attempt: int
    workflow_id: str | None = None
    workflow_ref: str | None = None
