"""Validated request DATA only. IMPORTABLE_FOUNDATION != TRUSTED_RUNTIME.

REQUEST_CAPTURED != REQUEST_TRUSTED; REQUEST_VALIDATED != DIRECTOR_APPROVED.
DIGEST != AUTHENTICATION. No transport, issuer, credentials or authority.
"""
from dataclasses import dataclass, asdict
import hashlib
import json

from .director_issuance import (
    OPERATION_FIELDS, LedgerValidationError, canonical_bytes,
    validate_identifier, validate_material_fields, material_operation_key,
)

MAX_REQUEST_BYTES = 16384
REQUEST_FIELDS = frozenset(OPERATION_FIELDS) | {"request_id"}


class RequestError(ValueError):
    def __init__(self, code, request_id=None):
        super().__init__(code)
        self.code = code
        # Only a structurally valid ID from unambiguous JSON, never diagnostics.
        self.request_id = request_id


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("INVALID_JSON")
        result[key] = value
    return result


def _reject_number(value):
    raise RequestError("INVALID_JSON")


def _integer(value):
    if len(value) > 2:
        raise RequestError("INVALID_SCHEMA")
    return int(value)


def _check_depth(text):
    # Flat schema: reject nesting before json.loads can recurse. Brackets in
    # strings are data, including escaped quotes/backslashes.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 1:
                raise RequestError("INVALID_JSON")
        elif char in "]}":
            depth -= 1


@dataclass(frozen=True, slots=True)
class TrustedRequest:
    """Immutable validated data; the name does NOT assert Windows admission."""
    schema_version: int
    request_id: str
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

    def __post_init__(self):
        try:
            validate_identifier(self.request_id)
            validate_material_fields(self.material_fields())
            if len(self.remote_name) > 64:
                raise LedgerValidationError("invalid remote length")
        except LedgerValidationError:
            raise RequestError("INVALID_SCHEMA") from None

    def material_fields(self):
        return {key: getattr(self, key) for key in OPERATION_FIELDS}

    @property
    def operation_key(self):
        return material_operation_key(self.material_fields())


def parse_captured_request(raw: bytes) -> TrustedRequest:
    """Parse bytes supplied by capture/readback; no file/path access or trust."""
    if type(raw) is not bytes or len(raw) > MAX_REQUEST_BYTES:
        raise RequestError("INVALID_SIZE")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise RequestError("INVALID_ENCODING")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise RequestError("INVALID_ENCODING") from None
    _check_depth(text)
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_reject_number,
                           parse_float=_reject_number, parse_int=_integer)
    except (ValueError, RecursionError):
        raise RequestError("INVALID_JSON") from None
    if type(value) is not dict:
        raise RequestError("INVALID_SCHEMA")
    request_id = value.get("request_id")
    try:
        validate_identifier(request_id)
    except LedgerValidationError:
        request_id = None
    if set(value) != REQUEST_FIELDS:
        raise RequestError("INVALID_SCHEMA", request_id)
    try:
        return TrustedRequest(**value)
    except RequestError:
        raise RequestError("INVALID_SCHEMA", request_id) from None


def request_digest(raw: bytes) -> str:
    request = parse_captured_request(raw)
    return hashlib.sha256(canonical_bytes({
        "domain": "trusted-publication-request-v1",
        "captured_sha256": hashlib.sha256(raw).hexdigest(),
        "request": asdict(request),
    })).hexdigest()
