"""Closed, non-authoritative Windows bootstrap models and read-only COM.

CODE_EXISTS != WINDOWS_MUTATION_AUTHORIZED. Observation data is not a token.
No account, rights, ACL, registry, DPAPI or task mutation API exists here.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import PureWindowsPath
import re
import xml.etree.ElementTree as ET


class AdmissionError(ValueError):
    """Fixed public categories; never include provider diagnostics."""


def require(condition, code='INVALID_CONTRACT'):
    if not condition:
        raise AdmissionError(code)


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def digest(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value)
            and value != '0' * length)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= 4_194_304 and not raw.startswith(b'\xef\xbb\xbf'))
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise AdmissionError('INVALID_CONTRACT')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=invalid, parse_float=invalid)
    except (UnicodeError, ValueError, RecursionError):
        raise AdmissionError('INVALID_CONTRACT') from None


def relative_path(value):
    require(type(value) is str and 0 < len(value) <= 240, 'INVALID_PATH')
    require('\\' not in value and not PureWindowsPath(value).is_absolute(), 'INVALID_PATH')
    for part in value.split('/'):
        require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', part) is not None
                and part not in ('.', '..') and not part.endswith(('.', ' '))
                and re.fullmatch(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])', part.split('.')[0]) is None,
                'INVALID_PATH')
    return value.casefold()


ROOTS = {
    'runtime_root': r'C:\Program Files\AISOFTWAREFACTORY\TrustedRuntime',
    'authority_root': r'C:\ProgramData\AISOFTWAREFACTORY\Authority',
    'captures_root': r'C:\ProgramData\AISOFTWAREFACTORY\Authority\Captures',
    'inbox_root': r'C:\ProgramData\AISOFTWAREFACTORY\Inbox',
    'secrets_root': r'C:\ProgramData\AISOFTWAREFACTORY\Secrets',
}
TASK_NAME = r'\AISOFTWAREFACTORY\TrustedRuntime'
REPOSITORY = 'https://github.com/inganamariapoveda-gif/AISOFTWAREFACTORY-Orchestrator.git'
APPLICATION_FILES = tuple('app/orchestrator/' + n + '.py' for n in (
    '__init__', 'trusted_runtime_entrypoint', 'trusted_runtime_windows',
    'trusted_runtime_foundation', 'trusted_request', 'director_issuance', 'store', 'state_machine'))
APPLICATION_FILES += ('app/orchestrator/trusted_runtime_windows_native.py',
                      'trusted_runtime_gate1_bootstrap.py')
ROLES = frozenset(('PYTHON_EXECUTABLE', 'PYTHON_LIBRARY', 'NATIVE_LIBRARY',
                   'STDLIB_ARCHIVE', 'APPLICATION_MODULE', 'ENTRYPOINT',
                   'IMPORT_CONFIG', 'STATIC_DATA', 'LICENSE'))
WORK_LIMITS = dict(max_request_bytes=16384, max_active_entries_examined=64,
                   max_candidates_processed=8, soft_budget_seconds=40, scheduler_limit_seconds=50)
PROVENANCE_KEYS = ('release_url_identity', 'artifact_filename', 'artifact_size',
                   'published_sha256', 'calculated_sha256', 'sigstore_verified',
                   'sigstore_identity', 'sigstore_issuer', 'independent_verifier_verified')


def validate_provenance(p):
    closed(p, PROVENANCE_KEYS)
    require(p['release_url_identity'] == 'https://www.python.org/downloads/release/python-31410/')
    require(p['artifact_filename'] == 'python-3.14.10-embed-amd64.zip')
    require(type(p['artifact_size']) is int and p['artifact_size'] > 0)
    digest(p['published_sha256']); digest(p['calculated_sha256'])
    require(p['published_sha256'] == p['calculated_sha256'], 'PYTHON_HASH_MISMATCH')
    require(p['sigstore_verified'] is True and p['independent_verifier_verified'] is True,
            'INDEPENDENT_PROVENANCE_REQUIRED')
    for key in ('sigstore_identity', 'sigstore_issuer'):
        require(type(p[key]) is str and 0 < len(p[key]) <= 512
                and all(ord(c) >= 32 for c in p[key]))
    # These are evidence fields, not a cryptographic Sigstore verifier.


MANIFEST_KEYS = ('schema_version', 'installable', 'runtime_version', 'source_repository',
    'source_commit_sha', 'source_tree_sha', 'manifest_generator_version', 'python_version',
    'architecture', 'python_provenance', *ROOTS, 'entrypoint_relative_path',
    'python_relative_path', 'python_arguments', 'allowed_import_roots', 'work_limits', 'files')


def validate_manifest(m):
    require(type(m) is dict, 'INVALID_CONTRACT')
    if m.get('installable') is False:
        raise AdmissionError('NOT_INSTALLABLE_TEMPLATE')
    closed(m, MANIFEST_KEYS)
    require(m['schema_version'] == 'trusted-runtime-install-manifest-v1' and m['installable'] is True)
    require(m['runtime_version'] == '001B' and m['manifest_generator_version'] == '1')
    require(m['source_repository'] == REPOSITORY)
    digest(m['source_commit_sha'], 40); digest(m['source_tree_sha'], 40)
    require(m['python_version'] == '3.14.10' and m['architecture'] == 'amd64')
    validate_provenance(m['python_provenance'])
    require(all(m[k] == v for k, v in ROOTS.items()))
    require(m['entrypoint_relative_path'] == 'app/orchestrator/trusted_runtime_entrypoint.py')
    require(m['python_relative_path'] == 'python/python.exe' and m['python_arguments'] == ['-I', '-B'])
    require(m['allowed_import_roots'] == ['python', 'python/python314.zip', 'app'])
    require(m['work_limits'] == WORK_LIMITS)
    require(type(m['files']) is list and 1 <= len(m['files']) <= 4096)
    seen = set()
    for entry in m['files']:
        closed(entry, ('relative_path', 'size', 'sha256', 'role'))
        key = relative_path(entry['relative_path'])
        require(key not in seen, 'DUPLICATE_PATH'); seen.add(key)
        require(type(entry['size']) is int and entry['size'] >= 0)
        digest(entry['sha256']); require(entry['role'] in ROLES)
    required = set(APPLICATION_FILES) | {'python/python.exe', 'python/python314.zip', 'python/python314._pth'}
    require(required <= seen, 'MISSING_REQUIRED_FILE')
    return m


# File-specific rights, deliberately not generic Modify.
DELETE = 0x10000
READ_CONTROL = 0x20000
WRITE_DAC = 0x40000
WRITE_OWNER = 0x80000
SYNCHRONIZE = 0x100000
READ = 0x89 | READ_CONTROL | SYNCHRONIZE
WRITE = 0x116 | READ_CONTROL | SYNCHRONIZE
CAPTURE_ACCESS = READ | WRITE  # no FILE_DELETE_CHILD (0x40)
AUTHORITY_ACCESS = (CAPTURE_ACCESS | 0x20) & ~0x4  # traverse, no create-subdirectory
SQLITE_FILE_ACCESS = CAPTURE_ACCESS | DELETE
OBJECT_INHERIT = 0x1
NO_PROPAGATE_INHERIT = 0x4
INHERIT_ONLY = 0x8
EXECUTE_ACCESS = READ | 0x20
BUILDER_INBOX_ACCESS = 0x22 | READ_CONTROL | SYNCHRONIZE
ADMIN = 'S-1-5-32-544'
SYSTEM = 'S-1-5-18'
OWNER_RIGHTS = 'S-1-3-4'
FULL_ACCESS = 0x1F01FF


def sid(value):
    require(type(value) is str and re.fullmatch(r'S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}', value))


@dataclass(frozen=True)
class Ace:
    sid: str
    mask: int
    flags: int = 3  # OBJECT_INHERIT | CONTAINER_INHERIT


@dataclass(frozen=True)
class Descriptor:
    owner: str
    protected: bool
    aces: tuple


def expected_descriptor(kind, runtime_sid, builder_sid):
    sid(runtime_sid); sid(builder_sid); require(runtime_sid != builder_sid)
    masks = {'runtime': EXECUTE_ACCESS, 'control': READ, 'authority': AUTHORITY_ACCESS,
             'captures': CAPTURE_ACCESS, 'secrets': CAPTURE_ACCESS,
             'validation': CAPTURE_ACCESS, 'operational': CAPTURE_ACCESS,
             'task': READ_CONTROL | 1, 'folder': READ_CONTROL | 1, 'inbox': READ}
    require(kind in masks)
    flags = 0 if kind in ('task', 'folder') else 3
    aces = [Ace(ADMIN, FULL_ACCESS, flags), Ace(SYSTEM, FULL_ACCESS, flags),
            Ace(runtime_sid, masks[kind], 0 if kind == 'authority' else flags),
            Ace(OWNER_RIGHTS, READ_CONTROL, flags)]
    if kind == 'authority':
        # DELETE is effective on inherited files only, never this container.
        # Protected child roots (including Captures) admit no inherited ACEs.
        aces.append(Ace(runtime_sid, SQLITE_FILE_ACCESS, OBJECT_INHERIT | NO_PROPAGATE_INHERIT | INHERIT_ONLY))
    if kind == 'inbox':
        aces.append(Ace(builder_sid, BUILDER_INBOX_ACCESS, 0))
    return Descriptor(ADMIN, True, tuple(aces))


def validate_descriptor(actual, expected):
    require(type(actual) is Descriptor and type(expected) is Descriptor, 'ACL_MISMATCH')
    require(actual.owner == expected.owner and actual.protected is True
            and len(actual.aces) == len(expected.aces)
            and frozenset(actual.aces) == frozenset(expected.aces), 'ACL_MISMATCH')


RECEIPT_KEYS = ('installation_id', 'generation', 'previous_receipt_sha256', 'manifest_sha256',
 'source_commit_sha', 'source_tree_sha', 'bootstrap_script_sha256', 'builder_sid', 'runtime_sid',
 'machine_guid', 'machine_sid', 'windows_build', 'volume_guid', 'volume_serial', 'runtime_profile_path',
 *ROOTS, 'task_identifier', 'task_definition_digest', 'installation_timestamp_utc', 'bootstrap_result')


def utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value))
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise AdmissionError('INVALID_CONTRACT') from None


def validate_receipt(r):
    closed(r, RECEIPT_KEYS)
    digest(r['installation_id'], 32)
    require(type(r['generation']) is int and r['generation'] == 1 and r['previous_receipt_sha256'] is None)
    for k in ('manifest_sha256', 'bootstrap_script_sha256', 'task_definition_digest'):
        digest(r[k])
    for k in ('source_commit_sha', 'source_tree_sha'):
        digest(r[k], 40)
    sid(r['builder_sid']); sid(r['runtime_sid']); require(r['builder_sid'] != r['runtime_sid'])
    require(all(r[k] == v for k, v in ROOTS.items()))
    require(r['task_identifier'] == TASK_NAME)
    require(type(r['volume_serial']) is int and 0 <= r['volume_serial'] <= 0xffffffff)
    require(re.fullmatch(r'S-1-5-21-(?:[0-9]+-){2}[0-9]+', r['machine_sid']) is not None)
    for k in ('machine_guid', 'volume_guid', 'windows_build'):
        require(type(r[k]) is str and 0 < len(r[k]) <= 128 and all(ord(c) >= 32 for c in r[k]))
    require(r['runtime_profile_path'] == r'C:\Users\ASFTrustedRuntime')
    utc(r['installation_timestamp_utc'])
    require(r['bootstrap_result'] in ('TASK_REGISTERED_DISABLED', 'BOUNDARY_VALIDATED', 'BOUNDARY_ACTIVE'))
    return r


def check_initial_install(completed):
    require(completed is False, 'EXISTING_COMPLETED_INSTALLATION_STATE')


def validate_activation(a, receipt, expected_digest, task_digest, now):
    closed(a, ('installation_id', 'generation', 'mode', 'valid_from_utc', 'valid_until_utc',
               'expected_task_digest', 'fixture_set_digest'))
    validate_receipt(receipt); digest(expected_digest); digest(task_digest)
    require(hashlib.sha256(canonical(a)).hexdigest() == expected_digest, 'STALE_ACTIVATION')
    require(a['installation_id'] == receipt['installation_id'] and type(a['generation']) is int
            and a['generation'] == 1 and a['mode'] == 'VALIDATION', 'ACTIVATION_REJECTED')
    digest(a['fixture_set_digest'])
    require(a['expected_task_digest'] == task_digest, 'SCHEDULER_MISMATCH')
    require(now.tzinfo is not None and utc(a['valid_from_utc']) <= now < utc(a['valid_until_utc']),
            'OUTSIDE_VALIDATION_WINDOW')


LAUNCH_SIGNALS = ('COR_*', 'COMPLUS_*', 'DOTNET_*', 'APPDOMAIN_MANAGER_*', 'user_PATH',
 'user_PSModulePath', 'PowerShell_profiles', 'HKCU_Run', 'HKCU_RunOnce', 'HKCU_Environment',
 'Startup', 'user_tasks', 'HKCU_COM', 'Windows_Terminal', 'CLR_configuration')


def validate_launch_audit(audit):
    closed(audit, LAUNCH_SIGNALS)
    require(all(v == 'VERIFIED_CLEAR' for v in audit.values()), 'BLOCKED_PRIVILEGED_LAUNCH_ENVIRONMENT')


def effective_batch_rights(principals, assignments):
    require(type(principals) is frozenset and type(assignments) is dict)
    require(set(assignments) == {'SeBatchLogonRight', 'SeDenyBatchLogonRight'})
    require(all(type(v) is frozenset for v in assignments.values()))
    require(bool(principals & assignments['SeBatchLogonRight'])
            and not principals & assignments['SeDenyBatchLogonRight'], 'BATCH_LOGON_BLOCKED')


@dataclass(frozen=True)
class HostObservation:
    process_sid: str
    admin_account: bool
    elevated: bool
    enabled_privileges: frozenset
    volume: str
    filesystem: str
    reparse_ancestor: bool
    descriptors: dict
    file_hashes: dict
    cwd: str
    import_roots: tuple
    isolated: bool
    user_site: bool
    safe_environment: bool
    task: dict


def admit_host(o, receipt, manifest, expected_task):
    validate_receipt(receipt); validate_manifest(manifest)
    require(type(o) is HostObservation, 'HOST_UNVERIFIED')
    require(o.process_sid == receipt['runtime_sid'] and o.admin_account is False
            and o.elevated is False, 'IDENTITY_REJECTED')
    require(type(o.enabled_privileges) is frozenset
            and o.enabled_privileges <= {'SeChangeNotifyPrivilege', 'SeIncreaseWorkingSetPrivilege'}, 'PRIVILEGE_REJECTED')
    require(o.volume == receipt['volume_guid'] and o.filesystem == 'NTFS'
            and o.reparse_ancestor is False, 'PATH_BOUNDARY_REJECTED')
    require(set(o.descriptors) == {'runtime', 'control', 'authority', 'captures', 'secrets', 'inbox', 'task', 'folder'})
    for kind, descriptor in o.descriptors.items():
        validate_descriptor(descriptor, expected_descriptor(kind, receipt['runtime_sid'], receipt['builder_sid']))
    expected_files = {f['relative_path']: (f['size'], f['sha256']) for f in manifest['files']}
    require(o.file_hashes == expected_files, 'RUNTIME_TREE_MISMATCH')
    roots = tuple(str(PureWindowsPath(ROOTS['runtime_root']) / p) for p in manifest['allowed_import_roots'])
    require(o.cwd == ROOTS['runtime_root'] and o.import_roots == roots
            and o.isolated is True and o.user_site is False and o.safe_environment is True, 'LOAD_ENVIRONMENT_REJECTED')
    require(o.task == expected_task, 'SCHEDULER_MISMATCH')
    require(receipt['manifest_sha256'] == hashlib.sha256(canonical(manifest)).hexdigest()
            and receipt['source_commit_sha'] == manifest['source_commit_sha']
            and receipt['source_tree_sha'] == manifest['source_tree_sha'], 'INSTALLATION_BINDING_MISMATCH')
    return 'PREFLIGHT_CONSISTENT_NOT_AUTHORIZED'


def active_candidate(name):
    return type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.request', name) is not None


def retirement_plan(name, capture_id, phase, opened_identity, current_identity):
    """Plan DATA only: never renames or deletes any source."""
    require(active_candidate(name), 'INVALID_CANDIDATE')
    digest(capture_id, 32)
    require(phase in ('PARSED', 'REJECTED'), 'TERMINAL_EVIDENCE_REQUIRED')
    require(opened_identity is not None and opened_identity == current_identity, 'SOURCE_IDENTITY_CHANGED')
    return {'operation': 'RENAME_SAME_HANDLE', 'destination': name + '.processed.' + capture_id,
            'delete': False, 'failure': 'LIFECYCLE_FAILURE_EVIDENCE_PRESERVED'}


def bounded_candidate_plan(names):
    """Bounded candidate selection; no Inbox access or processing."""
    selected = []
    examined = 0
    for name in names:
        if not active_candidate(name):
            continue
        examined += 1
        if len(selected) < 8:
            selected.append(name)
        if examined == 64:
            break
    return tuple(selected), examined


# IDispatch automation ABI. Native calls are limited to Scheduler observations.
class _GUID(ctypes.Structure):
    _fields_ = [('a', ctypes.c_uint32), ('b', ctypes.c_uint16), ('c', ctypes.c_uint16),
                ('d', ctypes.c_ubyte * 8)]


class _VariantData(ctypes.Union):
    _fields_ = [('integer', ctypes.c_int32), ('boolean', ctypes.c_int16),
                ('pointer', ctypes.c_void_p), ('record', ctypes.c_void_p * 2)]


class _Variant(ctypes.Structure):
    _anonymous_ = ('data',)
    _fields_ = [('vt', ctypes.c_uint16), ('r1', ctypes.c_uint16),
                ('r2', ctypes.c_uint16), ('r3', ctypes.c_uint16), ('data', _VariantData)]


class _Params(ctypes.Structure):
    _fields_ = [('arguments', ctypes.POINTER(_Variant)),
                ('named', ctypes.POINTER(ctypes.c_int32)),
                ('count', ctypes.c_uint32), ('named_count', ctypes.c_uint32)]


class _ExceptionInfo(ctypes.Structure):
    _fields_ = [('code', ctypes.c_uint16), ('reserved', ctypes.c_uint16),
                ('source', ctypes.c_void_p), ('description', ctypes.c_void_p),
                ('help_file', ctypes.c_void_p), ('help_context', ctypes.c_uint32),
                ('reserved_pointer', ctypes.c_void_p), ('deferred', ctypes.c_void_p),
                ('status', ctypes.c_int32)]


def _hresult(value):
    require(value >= 0, 'SCHEDULER_OBSERVATION_FAILED')


def _method(pointer, index, result, *args):
    require(bool(pointer), 'SCHEDULER_OBSERVATION_FAILED')
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return ctypes.WINFUNCTYPE(result, ctypes.c_void_p, *args)(table[index])


class _Dispatch:
    def __init__(self, pointer, automation):
        self.pointer = pointer
        self.automation = automation

    def close(self):
        if self.pointer:
            _method(self.pointer, 2, ctypes.c_uint32)(self.pointer)
            self.pointer = None

    def read(self, name, *arguments, property_get=False):
        require(name in ('Connect', 'GetFolder', 'GetTask', 'Xml', 'Enabled', 'GetSecurityDescriptor'),
                'SCHEDULER_METHOD_FORBIDDEN')
        require(len(arguments) <= 4)
        null = _GUID()
        names = (ctypes.c_wchar_p * 1)(name)
        identifier = ctypes.c_int32()
        _hresult(_method(self.pointer, 5, ctypes.c_int32, ctypes.POINTER(_GUID),
            ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_int32))(self.pointer, ctypes.byref(null), names, 1, 0,
                                           ctypes.byref(identifier)))
        values = (_Variant * len(arguments))()
        result = _Variant(); exception = _ExceptionInfo(); bad_argument = ctypes.c_uint32()
        try:
            for item, value in zip(values, reversed(arguments)):
                if type(value) is str:
                    item.vt = 8
                    item.pointer = self.automation.SysAllocString(value)
                    require(bool(item.pointer), 'SCHEDULER_OBSERVATION_FAILED')
                elif type(value) is int:
                    item.vt = 3; item.integer = value
                else:
                    raise AdmissionError('SCHEDULER_OBSERVATION_FAILED')
            params = _Params(values, None, len(arguments), 0)
            status = _method(self.pointer, 6, ctypes.c_int32, ctypes.c_int32,
                ctypes.POINTER(_GUID), ctypes.c_uint32, ctypes.c_uint16,
                ctypes.POINTER(_Params), ctypes.POINTER(_Variant),
                ctypes.POINTER(_ExceptionInfo), ctypes.POINTER(ctypes.c_uint32))(
                    self.pointer, identifier, ctypes.byref(null), 0, 2 if property_get else 1,
                    ctypes.byref(params), ctypes.byref(result), ctypes.byref(exception),
                    ctypes.byref(bad_argument))
            _hresult(status)
            if result.vt == 9 and result.pointer:
                pointer = result.pointer
                result.vt = 0; result.pointer = None  # transfer owning reference
                return _Dispatch(pointer, self.automation)
            if result.vt == 8:
                length = self.automation.SysStringLen(result.pointer)
                require(length <= 1_048_576, 'SCHEDULER_OBSERVATION_FAILED')
                return ctypes.wstring_at(result.pointer, length) if result.pointer else ''
            if result.vt == 11:
                require(result.boolean in (0, -1), 'SCHEDULER_OBSERVATION_FAILED')
                return result.boolean == -1
            require(result.vt == 0, 'SCHEDULER_OBSERVATION_FAILED')
            return None
        finally:
            for value in values:
                self.automation.VariantClear(ctypes.byref(value))
            self.automation.VariantClear(ctypes.byref(result))
            for pointer in (exception.source, exception.description, exception.help_file):
                if pointer:
                    self.automation.SysFreeString(pointer)


class WindowsTaskScheduler:
    """Read-only local COM via IDispatch. No registration, Run or fallback."""
    def observe(self):
        require(os.name == 'nt' and ctypes.sizeof(ctypes.c_void_p) == 8, 'SCHEDULER_UNAVAILABLE')
        ole = ctypes.WinDLL('ole32.dll', winmode=0x800)
        auto = ctypes.WinDLL('oleaut32.dll', winmode=0x800)
        ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        ole.CoInitializeEx.restype = ctypes.c_int32
        ole.CoUninitialize.argtypes = []; ole.CoUninitialize.restype = None
        ole.CLSIDFromString.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_GUID)]
        ole.CLSIDFromString.restype = ctypes.c_int32
        ole.CoCreateInstance.argtypes = [ctypes.POINTER(_GUID), ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)]
        ole.CoCreateInstance.restype = ctypes.c_int32
        auto.SysAllocString.argtypes = [ctypes.c_wchar_p]; auto.SysAllocString.restype = ctypes.c_void_p
        auto.SysFreeString.argtypes = [ctypes.c_void_p]; auto.SysFreeString.restype = None
        auto.SysStringLen.argtypes = [ctypes.c_void_p]; auto.SysStringLen.restype = ctypes.c_uint32
        auto.VariantClear.argtypes = [ctypes.POINTER(_Variant)]; auto.VariantClear.restype = ctypes.c_int32
        initialized = False
        objects = []
        try:
            _hresult(ole.CoInitializeEx(None, 2)); initialized = True
            clsid, iid = _GUID(), _GUID()
            _hresult(ole.CLSIDFromString('{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}', ctypes.byref(clsid)))
            _hresult(ole.CLSIDFromString('{00020400-0000-0000-C000-000000000046}', ctypes.byref(iid)))
            pointer = ctypes.c_void_p()
            _hresult(ole.CoCreateInstance(ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(pointer)))
            service = _Dispatch(pointer, auto); objects.append(service)
            service.read('Connect')
            folder = service.read('GetFolder', r'\AISOFTWAREFACTORY')
            require(type(folder) is _Dispatch, 'SCHEDULER_OBSERVATION_FAILED'); objects.append(folder)
            task = folder.read('GetTask', 'TrustedRuntime')
            require(type(task) is _Dispatch, 'SCHEDULER_OBSERVATION_FAILED'); objects.append(task)
            return task_observation(task.read('Xml', property_get=True),
                task.read('Enabled', property_get=True), task.read('GetSecurityDescriptor', 7),
                folder.read('GetSecurityDescriptor', 7))
        except (OSError, ValueError, AttributeError, TypeError):
            raise AdmissionError('SCHEDULER_OBSERVATION_FAILED') from None
        finally:
            for item in reversed(objects):
                item.close()
            if initialized:
                ole.CoUninitialize()


def task_observation(xml, enabled, task_sd, folder_sd):
    require(type(xml) is str and len(xml) <= 1_048_576 and '<!' not in xml,
            'SCHEDULER_XML_REJECTED')
    require(type(enabled) is bool and type(task_sd) is str and bool(task_sd)
            and type(folder_sd) is str and bool(folder_sd), 'SCHEDULER_OBSERVATION_FAILED')
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        raise AdmissionError('SCHEDULER_XML_REJECTED') from None
    ns = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'
    require(root.tag == ns + 'Task', 'SCHEDULER_XML_REJECTED')
    def text(path):
        nodes = root.findall('/'.join(ns + p for p in path.split('/')))
        require(len(nodes) == 1 and nodes[0].text is not None, 'SCHEDULER_XML_REJECTED')
        return nodes[0].text
    def shape(node, permitted):
        require(node is not None and len(node) == len(permitted)
                and {c.tag.removeprefix(ns) for c in node} == set(permitted), 'SCHEDULER_XML_REJECTED')
    shape(root.find(ns+'Actions'), ('Exec',))
    shape(root.find(ns+'Actions/'+ns+'Exec'), ('Command', 'Arguments', 'WorkingDirectory'))
    shape(root.find(ns+'Principals'), ('Principal',))
    shape(root.find(ns+'Principals/'+ns+'Principal'), ('UserId', 'LogonType', 'RunLevel'))
    shape(root.find(ns+'Triggers'), ('TimeTrigger',))
    trigger = root.find(ns+'Triggers/'+ns+'TimeTrigger')
    require({c.tag.removeprefix(ns) for c in trigger} <=
            {'StartBoundary', 'EndBoundary', 'Enabled', 'Repetition'}, 'SCHEDULER_XML_REJECTED')
    fields = {
        'principal_sid': 'Principals/Principal/UserId', 'logon_type': 'Principals/Principal/LogonType',
        'run_level': 'Principals/Principal/RunLevel', 'executable': 'Actions/Exec/Command',
        'arguments': 'Actions/Exec/Arguments', 'cwd': 'Actions/Exec/WorkingDirectory',
        'start': 'Triggers/TimeTrigger/StartBoundary', 'trigger_enabled': 'Triggers/TimeTrigger/Enabled',
        'interval': 'Triggers/TimeTrigger/Repetition/Interval',
        'execution_limit': 'Settings/ExecutionTimeLimit', 'demand_start': 'Settings/AllowStartOnDemand',
        'multiple_instances': 'Settings/MultipleInstancesPolicy',
        'start_when_available': 'Settings/StartWhenAvailable', 'wake': 'Settings/WakeToRun',
        'network': 'Settings/RunOnlyIfNetworkAvailable', 'battery_start': 'Settings/DisallowStartIfOnBatteries',
        'battery_stop': 'Settings/StopIfGoingOnBatteries', 'hard_terminate': 'Settings/AllowHardTerminate',
    }
    result = {k: text(v) for k, v in fields.items()}
    sid(result['principal_sid'])
    require(root.find(ns+'Settings/'+ns+'RestartOnFailure') is None, 'SCHEDULER_XML_REJECTED')
    result.update(exists=True, enabled=enabled, task_sd=task_sd, folder_sd=folder_sd,
                  xml_sha256=hashlib.sha256(xml.encode('utf-8')).hexdigest())
    for key, path in (('end', 'Triggers/TimeTrigger/EndBoundary'),
                      ('duration', 'Triggers/TimeTrigger/Repetition/Duration')):
        nodes = root.findall('/'.join(ns+p for p in path.split('/')))
        require(len(nodes) <= 1, 'SCHEDULER_XML_REJECTED')
        result[key] = nodes[0].text if nodes else None
    return result


def compare_task(observed, expected):
    # XML whitespace is evidence, not semantic task identity.
    require(type(observed) is dict and type(expected) is dict)
    require({k: v for k, v in observed.items() if k != 'xml_sha256'} ==
            {k: v for k, v in expected.items() if k != 'xml_sha256'}, 'SCHEDULER_MISMATCH')


# 001D closed DATA contracts. No host observation or mutation is performed here.
GATE1_PYTHON_SHA256 = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'


def gate1_contract_template():
    return {
        'schema_version': 'trusted-runtime-gate1-v1',
        'phase1a': dict(builder_account_name='ASFBuilder', expected_standard_user=True,
                       required_session_switch=True, own_profile_required=True,
                       own_workspace_required=True),
        'phase1b': dict(trusted_runtime_account_name='ASFTrustedRuntime',
                       trusted_runtime_root=ROOTS['runtime_root'],
                       program_files_parent=r'C:\Program Files\AISOFTWAREFACTORY',
                       control_root=r'C:\ProgramData\AISOFTWAREFACTORY',
                       runtime_profile_path=r'C:\Users\ASFTrustedRuntime',
                       **{k: v for k, v in ROOTS.items() if k != 'runtime_root'}),
        'scheduler': dict(folder=r'\AISOFTWAREFACTORY', task_name='TrustedRuntime',
                          logon_type='TASK_LOGON_PASSWORD', run_level='LeastPrivilege',
                          enabled_initially=False, allow_demand_start=False,
                          execution_time_limit_seconds=50, multiple_instances_policy='IgnoreNew',
                          repetition_interval='PT1M'),
        'python': dict(version='3.14.10', architecture='amd64',
                       artifact_filename='python-3.14.10-embed-amd64.zip',
                       published_sha256=GATE1_PYTHON_SHA256, sigstore_required=True),
        'uac': dict(expected_before=dict(EnableLUA=1, ConsentPromptBehaviorAdmin=5,
                                        ConsentPromptBehaviorUser=3, PromptOnSecureDesktop=1),
                    target_standard_user_behavior=0),
        'receipt': dict(generation=1, reinstall_allowed=False),
        'network_allowed': False, 'antivirus_bypass_allowed': False,
        'authorization': dict(path=r'C:\Program Files\AISOFTWAREFACTORY\GateStaging\gate1_authorization.json',
                              action='TRUSTED_RUNTIME_GATE1_PHASE1B',
                              schema_version='human-gate-authorization-v1',
                              confirmation_digest_field='human_confirmation_sha256',
                              confirmation_format='32_UPPERCASE_HEX_ASCII',
                              console_required=True, confirmation_attempts=1),
        'effective_access': dict(runtime_logon='BATCH', runtime_api='AccessCheck',
                                 builder_api='AuthzAccessCheck', builder_skip_token_groups=True,
                                 descriptor_admission_required=True),
    }


def exact_data(actual, expected, code='INVALID_CONTRACT'):
    """Type-sensitive recursive equality, including bool versus int."""
    require(type(actual) is type(expected), code)
    if type(expected) is dict:
        require(set(actual) == set(expected), code)
        for key in expected:
            exact_data(actual[key], expected[key], code)
    elif type(expected) in (list, tuple):
        require(len(actual) == len(expected), code)
        for a, e in zip(actual, expected):
            exact_data(a, e, code)
    else:
        require(actual == expected, code)


def validate_gate1_contract(value):
    exact_data(value, gate1_contract_template())
    return value


def gate1_local_path(value):
    require(type(value) is str and 0 < len(value) <= 1024, 'INVALID_PATH')
    p = PureWindowsPath(value)
    require(p.is_absolute() and p.drive.upper() == 'C:' and '/' not in value
            and str(p) == value and all(part not in ('.', '..') for part in p.parts),
            'INVALID_PATH')
    for part in p.parts[1:]:
        require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_. -]*', part) is not None
                and not part.endswith(('.', ' ')) and part not in ('.', '..')
                and re.fullmatch(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])',
                                 part.split('.')[0]) is None, 'INVALID_PATH')
    return p


@dataclass(frozen=True)
class BuilderCheckpoint:
    exists: bool
    account_name: str
    account_sid: str
    enabled: bool
    administrator: bool
    profile: str
    profile_exists: bool
    interactive_sid: str
    interactive_session: bool
    session_switched: bool
    workspace: str
    workspace_owner_sid: str
    builder_writable: bool
    runtime_writable: bool
    other_nonadmin_writers: frozenset
    ancestors_reparse: bool
    codex_available: bool
    git_available: bool


def validate_builder_checkpoint(o):
    require(type(o) is BuilderCheckpoint, 'BUILDER_CHECKPOINT_REJECTED')
    require(o.exists is True and o.account_name == 'ASFBuilder' and o.enabled is True
            and o.administrator is False, 'BUILDER_IDENTITY_REJECTED')
    sid(o.account_sid)
    require(o.interactive_sid == o.account_sid and o.interactive_session is True
            and o.session_switched is True, 'SESSION_SWITCH_REQUIRED')
    profile = gate1_local_path(o.profile)
    workspace = gate1_local_path(o.workspace)
    require(o.profile == r'C:\Users\ASFBuilder' and o.profile_exists is True
            and profile in workspace.parents and o.ancestors_reparse is False,
            'BUILDER_WORKSPACE_REJECTED')
    require(o.workspace_owner_sid == o.account_sid and o.builder_writable is True
            and o.runtime_writable is False and type(o.other_nonadmin_writers) is frozenset
            and not o.other_nonadmin_writers, 'SHARED_WORKSPACE_REJECTED')
    require(o.codex_available is True and o.git_available is True, 'BUILDER_TOOLING_NOT_AVAILABLE')
    return 'PHASE1A_CHECKPOINT_CONSISTENT_NOT_AUTHORIZED'


def validate_gate1_batch_rights(direct, effective, *, after=False):
    """Native LSA readback model: unknown, extra and deny rights fail closed."""
    require(type(direct) is frozenset and type(effective) is frozenset, 'LSA_RIGHTS_REJECTED')
    expected = frozenset({'SeBatchLogonRight'}) if after else frozenset()
    require(direct == expected and direct <= effective
            and effective <= {'SeBatchLogonRight', 'SeChangeNotifyPrivilege',
                              'SeIncreaseWorkingSetPrivilege'}, 'LSA_RIGHTS_REJECTED')
    if after:
        require('SeBatchLogonRight' in effective, 'LSA_RIGHTS_REJECTED')
