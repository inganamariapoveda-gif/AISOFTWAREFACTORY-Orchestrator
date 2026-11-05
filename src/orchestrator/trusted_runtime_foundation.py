"""Capture mechanics and consistency observations, NOT an installed runtime.

IMPORTABLE_FOUNDATION != TRUSTED_RUNTIME.
FOUNDATION_TESTS_PASS != WINDOWS_BOUNDARY_PROVEN.
REQUEST_CAPTURED != REQUEST_TRUSTED; REQUEST_VALIDATED != DIRECTOR_APPROVED.
LEDGER_ROW != PUBLICATION_AUTHORITY; DIGEST != AUTHENTICATION.
DESTINATION_PATH_PROVIDED != WINDOWS_PROTECTED_DESTINATION.
Root/ancestor/principal/ACL admission is a future host responsibility. No atomic
source snapshot or filesystem + SQLite atomicity is asserted. No orphan cleanup.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import PureWindowsPath
import re
import uuid

from .trusted_request import MAX_REQUEST_BYTES


class CaptureError(Exception):
    """Fixed categories only; never expose source paths, bytes or OS messages."""


def validate_filename(name):
    if (type(name) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", name) is None
            or ".." in name or name.endswith(".")
            or re.fullmatch(r"(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])", name.split(".")[0])):
        raise CaptureError("SOURCE_INVALID")


def _absolute(value):
    if type(value) is not str or any(ord(c) < 32 for c in value):
        raise ValueError
    path = PureWindowsPath(value)
    if (not path.is_absolute() or re.fullmatch(r"[A-Za-z]:", path.drive) is None
            or any(p in (".", "..") or p.endswith((".", " ")) or ":" in p
                   for p in value.replace("/", "\\").split("\\")[1:] if p)):
        raise ValueError
    return path


def _path(root, name):
    validate_filename(name)
    try:
        return str(_absolute(root) / name)
    except ValueError:
        raise CaptureError("SOURCE_INVALID") from None


@dataclass(frozen=True, slots=True)
class FileObservation:
    volume: int
    file_id: int
    size: int
    attributes: int
    links: int
    last_write: int


@dataclass(frozen=True, slots=True)
class CaptureEvidence:
    """Copy evidence only; caller construction never grants authority."""
    capture_id: str
    captured_sha256: str
    captured_size: int
    identity: FileObservation

    @property
    def filename(self):
        if type(self.capture_id) is not str or re.fullmatch(r"[0-9a-f]{32}", self.capture_id) is None:
            raise CaptureError("COPY_INTEGRITY_FAILURE")
        return self.capture_id + ".bin"


class _FileInformation(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
                ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                ("id_high", wintypes.DWORD), ("id_low", wintypes.DWORD)]


class WindowsFileIO:
    """Narrow synchronous file APIs. No fallback, impersonation or ACL changes."""
    def __init__(self):
        if os.name != "nt":
            raise CaptureError("CAPTURE_UNAVAILABLE")
        try:
            # System32 search only; never resolve a DLL from the checkout/PATH.
            self.api = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
            declarations = {
                "CreateFileW": ([wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
                "GetFileType": ([wintypes.HANDLE], wintypes.DWORD),
                "GetFileInformationByHandle": ([wintypes.HANDLE, ctypes.POINTER(_FileInformation)], wintypes.BOOL),
                "GetFileSizeEx": ([wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)], wintypes.BOOL),
                "ReadFile": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
                "WriteFile": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
                "FlushFileBuffers": ([wintypes.HANDLE], wintypes.BOOL),
                "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            }
            for name, (arguments, result) in declarations.items():
                function = getattr(self.api, name)
                function.argtypes, function.restype = arguments, result
        except (OSError, AttributeError):
            raise CaptureError("CAPTURE_UNAVAILABLE") from None

    def open_read(self, root, name):
        # GENERIC_READ; FILE_SHARE_READ only; OPEN_EXISTING; open reparse object.
        # BACKUP_SEMANTICS permits inspection/rejection of a directory handle;
        # it does not enable a privilege. NULL SECURITY_ATTRIBUTES: no inheritance.
        handle = self.api.CreateFileW(_path(root, name), 0x80000000, 1, None, 3,
                                      0x00200000 | 0x02000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise CaptureError("SOURCE_INVALID")
        return handle

    def create(self, root, name):
        # GENERIC_READ|GENERIC_WRITE for write + handle metadata; no sharing;
        # CREATE_NEW; no overwrite/replace/delete.
        handle = self.api.CreateFileW(_path(root, name), 0xC0000000, 0, None, 1,
                                      0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            code = ctypes.get_last_error()
            raise CaptureError("DESTINATION_EXISTS" if code in (80, 183) else "DESTINATION_WRITE_FAILED")
        return handle

    def info(self, handle):
        info, size = _FileInformation(), ctypes.c_longlong()
        if (self.api.GetFileType(handle) != 1
                or not self.api.GetFileInformationByHandle(handle, ctypes.byref(info))
                or not self.api.GetFileSizeEx(handle, ctypes.byref(size))):
            raise CaptureError("SOURCE_INVALID")
        if size.value != (info.size_high << 32) | info.size_low:
            raise CaptureError("CAPTURE_SOURCE_CHANGED")
        return FileObservation(info.volume, (info.id_high << 32) | info.id_low, size.value,
                               info.attributes, info.links,
                               (info.written.dwHighDateTime << 32) | info.written.dwLowDateTime)

    def read(self, handle, size):
        buffer, count = ctypes.create_string_buffer(size), wintypes.DWORD()
        if not self.api.ReadFile(handle, buffer, size, ctypes.byref(count), None) or count.value > size:
            raise CaptureError("SOURCE_INVALID")
        return buffer.raw[:count.value]

    def write(self, handle, data):
        buffer, count = ctypes.create_string_buffer(data), wintypes.DWORD()
        if not self.api.WriteFile(handle, buffer, len(data), ctypes.byref(count), None):
            raise CaptureError("DESTINATION_WRITE_FAILED")
        return count.value

    def flush(self, handle):
        if not self.api.FlushFileBuffers(handle):
            raise CaptureError("DESTINATION_FLUSH_FAILED")

    def close(self, handle):
        if not self.api.CloseHandle(handle):
            raise CaptureError("CAPTURE_CLOSE_FAILED")


@contextmanager
def _opened(io, root, name, *, create=False):
    handle = io.create(root, name) if create else io.open_read(root, name)
    try:
        yield handle
    finally:
        io.close(handle)


def _validate_observation(info):
    if type(info) is not FileObservation or info.attributes & (0x10 | 0x400) or info.links != 1 or info.size < 0:
        raise CaptureError("SOURCE_INVALID")
    if info.size > MAX_REQUEST_BYTES:
        raise CaptureError("SOURCE_TOO_LARGE")


def read_bounded(io, root, name):
    """Endpoint continuity on one handle, not an atomic snapshot assertion."""
    _path(root, name)
    with _opened(io, root, name) as handle:
        before = io.info(handle)
        _validate_observation(before)
        chunks, remaining = [], MAX_REQUEST_BYTES + 1
        while remaining:
            chunk = io.read(handle, remaining)
            if type(chunk) is not bytes or len(chunk) > remaining:
                raise CaptureError("SOURCE_INVALID")
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = io.info(handle)
        if before != after:
            raise CaptureError("CAPTURE_SOURCE_CHANGED")
        if len(raw) > MAX_REQUEST_BYTES:
            raise CaptureError("SOURCE_TOO_LARGE")
        if len(raw) != before.size:
            raise CaptureError("CAPTURE_SOURCE_CHANGED")
        return raw, after


def _copy_bytes(raw, destination_root, io):
    capture_id = uuid.uuid4().hex
    name = capture_id + ".bin"
    with _opened(io, destination_root, name, create=True) as handle:
        if io.write(handle, raw) != len(raw):
            raise CaptureError("DESTINATION_WRITE_FAILED")
        io.flush(handle)
        written = io.info(handle)
        _validate_observation(written)
    try:
        copied, observed = read_bounded(io, destination_root, name)
        # Last-write timestamp may be finalized on closing the writer.
        if ((written.volume, written.file_id, written.attributes, written.links, written.size)
                != (observed.volume, observed.file_id, observed.attributes, observed.links, observed.size)
                or copied != raw or hashlib.sha256(copied).digest() != hashlib.sha256(raw).digest()):
            raise CaptureError("COPY_INTEGRITY_FAILURE")
    except CaptureError:
        raise CaptureError("COPY_INTEGRITY_FAILURE") from None
    return CaptureEvidence(capture_id, hashlib.sha256(copied).hexdigest(), len(copied), observed)


def capture_file(source_root, filename, destination_root, *, io=None):
    """Copy mechanics only. Caller roots are NOT admitted Windows boundaries."""
    io = WindowsFileIO() if io is None else io
    raw, _ = read_bounded(io, source_root, filename)
    return _copy_bytes(raw, destination_root, io)


def read_capture_copy(record, destination_root, *, io=None):
    io = WindowsFileIO() if io is None else io
    try:
        capture_id = record["capture_id"]
        if type(capture_id) is not str or re.fullmatch(r"[0-9a-f]{32}", capture_id) is None:
            raise CaptureError("COPY_INTEGRITY_FAILURE")
        if (type(record["captured_size"]) is not int or not 0 <= record["captured_size"] <= MAX_REQUEST_BYTES
                or type(record["captured_sha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", record["captured_sha256"]) is None):
            raise CaptureError("COPY_INTEGRITY_FAILURE")
        raw, _ = read_bounded(io, destination_root, capture_id + ".bin")
        if len(raw) != record["captured_size"] or hashlib.sha256(raw).hexdigest() != record["captured_sha256"]:
            raise CaptureError("COPY_INTEGRITY_FAILURE")
        return raw
    except (CaptureError, KeyError, TypeError):
        raise CaptureError("COPY_INTEGRITY_FAILURE") from None


def capture_request(store, source_root, filename, destination_root, *, io=None):
    """Capture/readmit data, never call issuance, claim, Director or publisher."""
    io = WindowsFileIO() if io is None else io
    raw, _ = read_bounded(io, source_root, filename)
    digest = hashlib.sha256(raw).hexdigest()
    existing = store.get_request_capture_by_sha(digest)
    if existing is not None:
        if read_capture_copy(existing, destination_root, io=io) != raw:
            raise CaptureError("COPY_INTEGRITY_FAILURE")
        return store.parse_request_capture(existing["capture_id"], destination_root, io=io)
    evidence = _copy_bytes(raw, destination_root, io)
    # A concurrent winner can leave this verified file orphaned. Preserve it;
    # never adopt/delete automatically. Store readmits both copies on replay.
    row = store.record_request_capture(evidence, destination_root, io=io)
    return store.parse_request_capture(row["capture_id"], destination_root, io=io)


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    interpreter: str
    code_root: str
    cwd: str
    module_roots: tuple[str, ...]
    checkout_roots: tuple[str, ...]
    project_venvs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    interpreter: str
    code_root: str
    cwd: str
    sys_path: tuple[str, ...]
    user_site_enabled: bool
    isolated: bool
    ignore_environment: bool
    pythonpath_present: bool
    editable_paths: tuple[str, ...]


def validate_runtime_observation(observation, expected):
    """Pure consistency only. These caller-supplied observations prove no ACL."""
    if type(observation) is not RuntimeObservation or type(expected) is not RuntimeLayout:
        return "REJECTED"
    try:
        for key in ("interpreter", "code_root", "cwd"):
            if _absolute(getattr(observation, key)) != _absolute(getattr(expected, key)):
                return "REJECTED"
        if (observation.user_site_enabled is not False or observation.isolated is not True
                or observation.ignore_environment is not True or observation.pythonpath_present is not False
                or observation.editable_paths != () or type(observation.editable_paths) is not tuple):
            return "REJECTED"
        groups = (observation.sys_path, expected.module_roots, expected.checkout_roots, expected.project_venvs)
        if any(type(group) is not tuple for group in groups) or not observation.sys_path or not expected.module_roots:
            return "REJECTED"
        allowed = tuple(_absolute(p) for p in expected.module_roots)
        forbidden = tuple(_absolute(p) for p in expected.checkout_roots + expected.project_venvs)
        paths = tuple(_absolute(p) for p in observation.sys_path)
        all_paths = paths + tuple(_absolute(getattr(expected, k)) for k in ("interpreter", "code_root", "cwd")) + allowed
        if any(p == f or f in p.parents or p in f.parents for p in all_paths for f in forbidden):
            return "REJECTED"
        if any(not any(p == a or a in p.parents for a in allowed) for p in paths):
            return "REJECTED"
        return "CONSISTENT"
    except (ValueError, TypeError):
        return "REJECTED"
