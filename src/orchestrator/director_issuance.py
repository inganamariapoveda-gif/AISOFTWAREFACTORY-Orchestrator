"""Publication ledger data only; no authenticated issuance or execution.

LEDGER_RECORD_EXISTS != TRUSTED_APPROVAL.
UNPROTECTED_STORE_ROW != PUBLICATION_AUTHORITY.
IMPORTABLE != AUTHORITY. DIGEST != SIGNATURE; DIGEST != AUTHENTICATED ISSUER.
The future publisher requires a Store admitted by a future trusted_runtime.
This module supplies neither that boundary nor a conversion to execution approval.
"""

from dataclasses import asdict, dataclass, fields
import hashlib
import json
import re


class LedgerValidationError(ValueError):
    """Invalid ledger data, with no caller-controlled diagnostic payload."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerValidationError(message)


def validate_identifier(value: str) -> None:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value) is not None,
            "invalid ledger identifier")


def validate_digest(value: str, length: int = 64) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None
            and value != "0" * length, "invalid ledger digest")


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ApprovalBindings:
    schema_version: int
    approval_id: str
    director_request_id: str
    project_id: str
    repository_identity: str
    task_id: str
    task_packet_sha256: str
    builder_id: str
    action: str
    branch: str
    candidate_head_sha: str
    remote_name: str
    effective_push_url: str
    target_ref: str
    permissions_sha256: str
    policies_sha256: str
    gates_sha256: str
    director_profile_id: str
    director_profile_version: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for name in ("approval_id", "director_request_id", "director_profile_id", "director_profile_version"):
            validate_identifier(getattr(self, name))
        validate_material_fields({name: getattr(self, name) for name in OPERATION_FIELDS})


BINDING_FIELDS = tuple(field.name for field in fields(ApprovalBindings))
# Identity excludes issuance/correlation IDs and Director profile metadata.
# Changing those cannot reserve the same publication a second time.
OPERATION_FIELDS = (
    "schema_version", "project_id", "repository_identity", "task_id", "task_packet_sha256",
    "builder_id", "action", "branch", "candidate_head_sha", "remote_name", "effective_push_url",
    "target_ref", "permissions_sha256", "policies_sha256", "gates_sha256",
)


def validate_material_fields(values: dict) -> None:
    """Validate material DATA without constructing approval/profile identities."""
    require(type(values) is dict and set(values) == set(OPERATION_FIELDS), "invalid material fields")
    require(type(values["schema_version"]) is int and values["schema_version"] == 1, "unsupported ledger version")
    for name in ("project_id", "repository_identity", "task_id", "builder_id"):
        validate_identifier(values[name])
    for name in ("task_packet_sha256", "permissions_sha256", "policies_sha256", "gates_sha256"):
        validate_digest(values[name])
    validate_digest(values["candidate_head_sha"], 40)
    require(type(values["action"]) is str and values["action"] == "git_publish_task_branch", "unsupported ledger action")
    require(type(values["branch"]) is str and values["branch"].startswith("task/") and len(values["branch"]) <= 255,
            "invalid ledger branch")
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part) is not None
                and ".." not in part and not part.endswith((".lock", "."))
                for part in values["branch"].split("/")), "invalid ledger branch")
    require(type(values["target_ref"]) is str and values["target_ref"] == "refs/heads/" + values["branch"],
            "ledger branch/ref mismatch")
    require(type(values["remote_name"]) is str
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", values["remote_name"]) is not None,
            "invalid ledger remote")
    require(type(values["effective_push_url"]) is str and len(values["effective_push_url"]) <= 2048
            and re.fullmatch(r"https://[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                             r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
                             r"/[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\.git",
                             values["effective_push_url"]) is not None
            and ".." not in values["effective_push_url"], "invalid ledger URL")


def material_operation_key(values: dict) -> str:
    validate_material_fields(values)
    return hashlib.sha256(canonical_bytes({"domain": "publication-operation-v1", "bindings": values})).hexdigest()


def operation_key(bindings: ApprovalBindings) -> str:
    require(type(bindings) is ApprovalBindings, "ledger bindings required")
    bindings.validate()
    payload = {name: getattr(bindings, name) for name in OPERATION_FIELDS}
    return material_operation_key(payload)


def decision_digest(bindings: ApprovalBindings, decision: str = "APPROVE") -> str:
    require(type(bindings) is ApprovalBindings, "ledger bindings required")
    bindings.validate()
    require(type(decision) is str and decision == "APPROVE", "approval decision required")
    # Correlation, all bindings (including approval/profile IDs), and decision
    # are explicit. This reproducible hash does not authenticate any caller.
    return hashlib.sha256(canonical_bytes({"domain": "publication-decision-v1", "decision": decision,
                                          "bindings": asdict(bindings)})).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovalIntent:
    bindings: ApprovalBindings
    operation_key: str
    decision_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        require(type(self.bindings) is ApprovalBindings, "ledger bindings required")
        self.bindings.validate()
        validate_digest(self.operation_key)
        validate_digest(self.decision_digest)
        require(self.operation_key == operation_key(self.bindings), "operation key mismatch")
        require(self.decision_digest == decision_digest(self.bindings), "decision digest mismatch")

    @classmethod
    def from_bindings(cls, bindings: ApprovalBindings) -> "ApprovalIntent":
        """Construct reproducible data, never trusted approval."""
        return cls(bindings, operation_key(bindings), decision_digest(bindings))
