"""Gate 1 model and guarded native coordinator entrypoint.

The sequence below is executable against an explicitly supplied port for tests.
The legacy run_sequence port is MODEL ONLY and is never used by production CLI.
No caller-controlled JSON/argv can select a backend or authorize real execution.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import copy
import hashlib
import json
from pathlib import PureWindowsPath
import uuid
import sys


# Minimal pre-import fence. This is deliberately in the already externally pinned
# bootstrap, not in the as-yet-unadmitted project modules it must verify.
# It performs ONE fixed read-only operation and retains handles across imports.
_seed_resources = None


def _close_seed_resources():
    global _seed_resources
    if _seed_resources is None:
        return True
    kernel, handles = _seed_resources
    ok = True
    for handle in reversed(handles):
        if not kernel.CloseHandle(handle): ok = False
    _seed_resources = None
    return ok


def _phase1b_preimport_fence():
    import ctypes as c
    from ctypes import wintypes as t
    import os
    global _seed_resources
    def require(value):
        if not value: raise ValueError('PREIMPORT_ADMISSION_REJECTED')
    stage = PureWindowsPath(r'C:\Program Files\AISOFTWAREFACTORY\GateStaging')
    require(sys.platform == 'win32' and sys.version_info[:3] == (3, 14, 10)
            and sys.flags.isolated == 1 and sys.flags.no_user_site == 1
            and sys.flags.dont_write_bytecode == 1 and c.sizeof(c.c_void_p) == 8)
    require(PureWindowsPath(__file__) == stage / 'trusted_runtime_gate1_bootstrap.py'
            and PureWindowsPath(sys.executable) == stage / 'python/python.exe'
            and 'PYTHONPATH' not in os.environ)
    require(all(PureWindowsPath(p).is_absolute() and
                (PureWindowsPath(p) == stage or stage in PureWindowsPath(p).parents) for p in sys.path))
    require(not any(name == 'orchestrator' or name.startswith('orchestrator.') for name in sys.modules))
    k = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    a = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
    P, D = c.c_void_p, t.DWORD
    def bind(dll, name, restype, *args):
        f = getattr(dll, name); f.restype = restype; f.argtypes = list(args)
        return f
    bind(k, 'CreateFileW', t.HANDLE, t.LPCWSTR, D, D, P, D, D, t.HANDLE)
    bind(k, 'CloseHandle', t.BOOL, t.HANDLE)
    bind(k, 'GetCurrentProcess', t.HANDLE)
    bind(k, 'GetFileInformationByHandleEx', t.BOOL, t.HANDLE, c.c_int, P, D)
    bind(k, 'ReadFile', t.BOOL, t.HANDLE, P, D, c.POINTER(D), P)
    bind(k, 'LocalFree', P, P)
    bind(a, 'OpenProcessToken', t.BOOL, t.HANDLE, D, c.POINTER(t.HANDLE))
    bind(a, 'GetTokenInformation', t.BOOL, t.HANDLE, c.c_int, P, D, c.POINTER(D))
    bind(a, 'ConvertSidToStringSidW', t.BOOL, P, c.POINTER(t.LPWSTR))
    bind(a, 'GetSecurityInfo', D, t.HANDLE, c.c_int, D, c.POINTER(P), P, c.POINTER(P), P, c.POINTER(P))
    bind(a, 'GetSecurityDescriptorControl', t.BOOL, P, c.POINTER(c.c_uint16), c.POINTER(D))
    bind(a, 'GetAce', t.BOOL, P, D, c.POINTER(P))
    handles = []; _seed_resources = (k, handles)
    def sid_string(pointer):
        text = t.LPWSTR()
        require(a.ConvertSidToStringSidW(pointer, c.byref(text)))
        try: return text.value
        finally: k.LocalFree(c.cast(text, P))
    token = t.HANDLE()
    require(a.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token)))
    try:
        size = D()
        a.GetTokenInformation(token, 1, None, 0, c.byref(size))
        require(0 < size.value <= 65536)
        data = c.create_string_buffer(size.value)
        require(a.GetTokenInformation(token, 1, data, size, c.byref(size)))
        human = sid_string(c.cast(data, c.POINTER(P))[0])
        elevated = D(); size = D()
        require(a.GetTokenInformation(token, 20, c.byref(elevated), c.sizeof(elevated), c.byref(size)))
        require(elevated.value != 0)
    finally:
        require(k.CloseHandle(token))
    def security(handle, strict):
        owner, dacl, sd = P(), P(), P()
        require(a.GetSecurityInfo(handle, 1, 5, c.byref(owner), None,
                                  c.byref(dacl), None, c.byref(sd)) == 0)
        try:
            require(bool(dacl))
            control, revision = c.c_uint16(), D()
            require(a.GetSecurityDescriptorControl(sd, c.byref(control), c.byref(revision)))
            if strict:
                require(control.value & 0x1000 and sid_string(owner) in (human, 'S-1-5-32-544', 'S-1-5-18'))
            count = c.c_uint16.from_address(dacl.value + 4).value
            require(count <= 1024)
            for i in range(count):
                ace = P(); require(a.GetAce(dacl, i, c.byref(ace)))
                kind, flags = c.c_ubyte.from_address(ace.value).value, c.c_ubyte.from_address(ace.value+1).value
                require(kind == 0 and c.c_uint16.from_address(ace.value+2).value >= 16)
                mask = c.c_uint32.from_address(ace.value+4).value
                sid = sid_string(ace.value+8)
                if strict:
                    require(not mask & 0x500d0156 or sid in (human, 'S-1-5-32-544', 'S-1-5-18'))
                elif not flags & 8 and sid in ('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'):
                    require(not mask & 0x500d0040)
        finally:
            k.LocalFree(sd)
    opened = {}
    def open_read(path, directory=False):
        key = str(path)
        if key in opened: return opened[key]
        handle = k.CreateFileW(key, 0x80020000, 1, None, 3,
                              0x00200000 | (0x02000000 if directory else 0), None)
        require(handle not in (None, c.c_void_p(-1).value)); handles.append(handle)
        tag = (D*2)()
        require(k.GetFileInformationByHandleEx(handle, 9, tag, c.sizeof(tag)))
        require(not tag[0] & 0x400 and tag[1] == 0)
        info = c.create_string_buffer(24)
        require(k.GetFileInformationByHandleEx(handle, 1, info, len(info)))
        require(bool(info.raw[21]) == directory and info.raw[20] == 0)
        if not directory: require(c.c_uint32.from_buffer(info, 16).value == 1)
        strict = path == stage.parent or path == stage or stage in path.parents
        security(handle, strict)
        opened[key] = handle
        return handle
    for ancestor in reversed(stage.parents): open_read(ancestor, True)
    open_read(stage, True)
    def read(path):
        for ancestor in reversed(path.parents):
            if ancestor == stage or stage in ancestor.parents: open_read(ancestor, True)
        handle = open_read(path)
        raw = bytearray(); buffer = c.create_string_buffer(65536)
        while True:
            count = D(); require(k.ReadFile(handle, buffer, len(buffer), c.byref(count), None))
            if not count.value: break
            raw.extend(buffer.raw[:count.value]); require(len(raw) <= 64*1024*1024)
        return bytes(raw)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result); result[key] = value
        return result
    def decode(raw):
        require(not raw.startswith(b'\xef\xbb\xbf'))
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs)
    auth = decode(read(stage/'gate1_authorization.json'))
    require(type(auth) is dict and auth.get('human_admin_sid') == human)
    def pinned(path, digest):
        require(type(digest) is str and len(digest) == 64 and all(x in '0123456789abcdef' for x in digest))
        raw = read(path); require(hashlib.sha256(raw).hexdigest() == digest); return raw
    manifest = decode(pinned(stage/'trusted_runtime_manifest.json', auth['manifest_sha256']))
    inventory = {entry['relative_path']: entry['sha256'] for entry in manifest['files']}
    bindings = {'trusted_runtime_gate1_bootstrap.py':'bootstrap_sha256',
                'app/orchestrator/trusted_runtime_windows.py':'validator_module_sha256',
                'app/orchestrator/trusted_runtime_windows_native.py':'native_backend_sha256'}
    for relative, field in bindings.items():
        require(inventory.get(relative) == auth[field]); pinned(stage/relative, auth[field])
    pinned(stage/'app/orchestrator/__init__.py', inventory['app/orchestrator/__init__.py'])
    pinned(stage/'python/python.exe', inventory['python/python.exe'])
    # Python may READ caches despite -B, and extension modules can shadow .py.
    # Reject every non-source entry in the application package before importing.
    for path, permitted in ((stage/'app', {'orchestrator'}),
                            (stage/'app/orchestrator', {PureWindowsPath(p).name for p in inventory
                             if PureWindowsPath(p).parent == PureWindowsPath('app/orchestrator')})):
        handle = open_read(path, True); buffer = c.create_string_buffer(65536); restart = True
        while True:
            ok = k.GetFileInformationByHandleEx(handle, 11 if restart else 10, buffer, len(buffer)); restart=False
            if not ok:
                require(c.get_last_error() == 18); break
            offset = 0
            while True:
                require(offset+104 <= len(buffer))
                address = c.addressof(buffer)+offset
                next_offset = c.c_uint32.from_address(address).value
                length = c.c_uint32.from_address(address+60).value
                require(length % 2 == 0 and 0 < length <= 510 and offset+104+length <= len(buffer))
                name = c.string_at(address+104, length).decode('utf-16-le')
                if name not in ('.','..'):
                    require(name in permitted and (path.name == 'app' or name.endswith('.py')))
                if not next_offset: break
                require(next_offset >= 104+length and next_offset % 8 == 0); offset += next_offset


if __name__ == '__main__' and '--phase1b' in sys.argv[1:]:
    try:
        _phase1b_preimport_fence()
    except BaseException:
        _close_seed_resources()
        print('HUMAN_GATE_NOT_AUTHORIZED_PREIMPORT_ADMISSION')
        raise SystemExit(2) from None


from orchestrator import trusted_runtime_windows as w


STEPS = (
    'REVALIDATE', 'CREATE_RUNTIME_ACCOUNT', 'FREEZE_RUNTIME_SID',
    'VERIFY_STANDARD_ACCOUNT', 'GRANT_BATCH_RIGHT', 'CREATE_ROOTS',
    'APPLY_DACLS', 'VERIFY_DACLS', 'MATERIALIZE_FILES', 'VERIFY_FILES',
    'REGISTER_DISABLED_TASK', 'VERIFY_TASK', 'SET_STANDARD_USER_UAC',
    'VERIFY_UAC', 'WRITE_RECEIPT', 'FINAL_READBACK', 'STOP',
)
ROOT_KINDS = ('control', 'runtime', 'authority', 'captures', 'inbox', 'secrets')


@dataclass(frozen=True)
class AdmissionSnapshot:
    """Observation DATA, never an authenticated authorization token."""
    human_gate_approved: bool
    phase1a: w.BuilderCheckpoint
    current_sid: str
    human_admin_sid: str
    elevated: bool
    administrator: bool
    agents_absent: bool
    script_path: str
    staging_root: str
    staging_protected: bool
    staging_reparse: bool
    script_reparse: bool
    script_bytes: bytes
    approved_script_sha256: str
    contract_path: str
    contract_protected: bool
    contract_reparse: bool
    contract_bytes: bytes
    approved_contract_sha256: str
    source_commit_sha: str
    source_tree_sha: str
    source_independently_verified: bool
    receipt_exists: bool
    runtime_account_exists: bool
    roots_present: tuple
    task_exists: bool
    task_folder_exists: bool
    filesystem: str
    ancestors_reparse: bool
    python_protected: bool
    python_version: str
    python_architecture: str
    python_executable: str
    python_executable_sha256: str
    approved_python_executable_sha256: str
    python_tree_digest: str
    approved_python_tree_digest: str
    python_provenance: dict
    manifest: dict
    manifest_independently_verified: bool
    network_allowed: bool
    antivirus_bypass: bool
    launch_audit: dict
    uac: dict


def sha(raw):
    w.require(type(raw) is bytes, 'INVALID_BYTES')
    return hashlib.sha256(raw).hexdigest()


def admit(snapshot):
    """Validate every modeled prerequisite before asking a port to mutate."""
    w.require(type(snapshot) is AdmissionSnapshot, 'ADMISSION_REQUIRED')
    s = snapshot
    w.require(s.human_gate_approved is True, 'HUMAN_GATE_NOT_AUTHORIZED')
    w.validate_builder_checkpoint(s.phase1a)
    w.sid(s.current_sid); w.sid(s.human_admin_sid)
    w.require(s.current_sid == s.human_admin_sid and s.current_sid != s.phase1a.account_sid
              and s.elevated is True and s.administrator is True and s.agents_absent is True,
              'HUMAN_ADMIN_REQUIRED')
    staging = w.gate1_local_path(s.staging_root)
    script = w.gate1_local_path(s.script_path)
    contract_path = w.gate1_local_path(s.contract_path)
    w.require(staging.parts[1:2] == ('Program Files',)
              and script.parent == staging and script.name == 'trusted_runtime_gate1_bootstrap.py'
              and contract_path.parent == staging and contract_path.name == 'gate1_contract.json'
              and s.staging_protected is True and s.staging_reparse is False
              and s.script_reparse is False and s.contract_reparse is False
              and s.contract_protected is True, 'PROTECTED_STAGING_REQUIRED')
    w.digest(s.approved_script_sha256); w.digest(s.approved_contract_sha256)
    w.require(sha(s.script_bytes) == s.approved_script_sha256
              and sha(s.contract_bytes) == s.approved_contract_sha256, 'APPROVED_HASH_MISMATCH')
    contract = w.validate_gate1_contract(w.strict_json(s.contract_bytes))
    w.digest(s.source_commit_sha, 40); w.digest(s.source_tree_sha, 40)
    w.require(s.source_independently_verified is True, 'SOURCE_NOT_ADMITTED')
    w.require(s.receipt_exists is False, 'REINSTALL_NOT_SUPPORTED')
    w.require(s.runtime_account_exists is False, 'EXISTING_ACCOUNT')
    w.require(type(s.roots_present) is tuple and s.roots_present == (), 'EXISTING_ROOT')
    w.require(s.task_exists is False and s.task_folder_exists is False, 'EXISTING_TASK')
    w.require(s.filesystem == 'NTFS' and s.ancestors_reparse is False, 'PATH_BOUNDARY_REJECTED')
    executable = w.gate1_local_path(s.python_executable)
    w.require(s.python_protected is True and staging in executable.parents
              and executable.name == 'python.exe' and s.python_version == '3.14.10'
              and s.python_architecture == 'amd64', 'PROTECTED_PYTHON_REQUIRED')
    for value in (s.python_executable_sha256, s.approved_python_executable_sha256,
                  s.python_tree_digest, s.approved_python_tree_digest):
        w.digest(value)
    w.require(s.python_executable_sha256 == s.approved_python_executable_sha256
              and s.python_tree_digest == s.approved_python_tree_digest, 'PYTHON_HASH_MISMATCH')
    w.validate_provenance(s.python_provenance)
    w.require(s.python_provenance['published_sha256'] == w.GATE1_PYTHON_SHA256,
              'PYTHON_HASH_MISMATCH')
    w.validate_manifest(s.manifest)
    w.require(s.manifest_independently_verified is True
              and s.manifest['source_commit_sha'] == s.source_commit_sha
              and s.manifest['source_tree_sha'] == s.source_tree_sha
              and s.manifest['python_provenance'] == s.python_provenance,
              'MANIFEST_BINDING_REJECTED')
    w.require(s.network_allowed is False and s.antivirus_bypass is False, 'SECURITY_POLICY_REJECTED')
    w.validate_launch_audit(s.launch_audit)
    w.exact_data(s.uac, contract['uac']['expected_before'], 'UNEXPECTED_UAC_STATE')
    return contract


def plan(contract):
    w.validate_gate1_contract(contract)
    return dict(classification='PLAN_DATA_NOT_AUTHORIZATION', phase1a='HUMAN_ACTION_THEN_SESSION_SWITCH',
                phase1b=list(STEPS), task_enabled=False, demand_start=False,
                human_gate_authorized=False, host_boundary_proven=False)


class TransientCredential:
    """Mutable buffer owned by the future backend; no printable/serialized secret."""
    __slots__ = ('_buffer',)

    def __init__(self, buffer):
        w.require(type(buffer) is bytearray and len(buffer) >= 32, 'CREDENTIAL_BUFFER_REQUIRED')
        self._buffer = buffer

    def __repr__(self):
        return '<TransientCredential redacted>'

    def __reduce_ex__(self, protocol):
        raise TypeError('CREDENTIAL_SERIALIZATION_FORBIDDEN')

    def clear(self):
        for i in range(len(self._buffer)):
            self._buffer[i] = 0


@dataclass(frozen=True)
class SequenceEvidence:
    status: str
    completed_steps: tuple
    attempted_step: str | None
    mutation_attempted: bool
    director_recovery_required: bool


def task_definition(runtime_sid, builder_sid, contract):
    w.sid(runtime_sid); w.sid(builder_sid)
    return dict(identity=w.TASK_NAME, principal_sid=runtime_sid,
                logon_type='TASK_LOGON_PASSWORD', run_level='LeastPrivilege',
                interactive=False, enabled=False, allow_demand_start=False,
                multiple_instances_policy='IgnoreNew', execution_time_limit_seconds=50,
                executable=str(PureWindowsPath(w.ROOTS['runtime_root']) / 'python/python.exe'),
                arguments=('-I', '-B', str(PureWindowsPath(w.ROOTS['runtime_root']) /
                                           'app/orchestrator/trusted_runtime_entrypoint.py')),
                cwd=w.ROOTS['runtime_root'],
                task_sd=w.expected_descriptor('task', runtime_sid, builder_sid),
                folder_sd=w.expected_descriptor('folder', runtime_sid, builder_sid))


def run_sequence(port):
    """Future sequence exercised with substituted APIs, never wired to CLI.

    Port observations must eventually come from an independently admitted native
    backend holding protected handles throughout the operation. DATA booleans
    cannot implement that host boundary. No such backend is installed by 001D.
    Failed writes may have taken effect: record ATTEMPTED, never undo or retry.
    """
    completed = []
    attempted = None
    mutation_attempted = False
    credential = None
    try:
        attempted = 'REVALIDATE'
        s = copy.deepcopy(port.observe_admission())
        contract = admit(s)
        # Freeze nested data against accidental mutation by later port calls.
        manifest = w.strict_json(w.canonical(s.manifest))
        contract_digest = sha(s.contract_bytes)
        source_commit, source_tree = s.source_commit_sha, s.source_tree_sha
        bootstrap_digest = s.approved_script_sha256
        builder_sid, human_sid = s.phase1a.account_sid, s.human_admin_sid
        expected_files = {f['relative_path']: (f['size'], f['sha256']) for f in manifest['files']}
        completed.append(attempted)
        credential = port.new_transient_credential()
        w.require(type(credential) is TransientCredential, 'CREDENTIAL_BUFFER_REQUIRED')
        # Revalidate immediately before first host mutation, after secret acquisition.
        fresh = port.observe_admission()
        admit(fresh)
        w.require(fresh == s, 'ADMISSION_CHANGED')
        attempted = 'CREATE_RUNTIME_ACCOUNT'; mutation_attempted = True
        port.create_standard_account('ASFTrustedRuntime', credential)
        completed.append(attempted)
        attempted = 'FREEZE_RUNTIME_SID'
        runtime_sid = port.resolve_runtime_sid()
        w.sid(runtime_sid)
        w.require(runtime_sid not in (builder_sid, human_sid), 'IDENTITY_COLLISION')
        completed.append(attempted)
        attempted = 'VERIFY_STANDARD_ACCOUNT'
        w.exact_data(port.read_runtime_account(),
                     dict(name='ASFTrustedRuntime', sid=runtime_sid, enabled=True,
                          administrator=False, groups=('S-1-5-32-545',)), 'ACCOUNT_READBACK_FAILED')
        completed.append(attempted)
        attempted = 'GRANT_BATCH_RIGHT'
        direct, effective = port.read_lsa_rights(runtime_sid)
        w.validate_gate1_batch_rights(direct, effective)
        port.add_lsa_right(runtime_sid, 'SeBatchLogonRight')
        direct, effective = port.read_lsa_rights(runtime_sid)
        w.validate_gate1_batch_rights(direct, effective, after=True)
        completed.append(attempted)
        roots = dict(control=r'C:\ProgramData\AISOFTWAREFACTORY',
                     **{k.removesuffix('_root'): v for k, v in w.ROOTS.items()})
        descriptors = {k: w.expected_descriptor(k, runtime_sid, builder_sid) for k in ROOT_KINDS}
        attempted = 'CREATE_ROOTS'
        # Port must create exclusively with restrictive initial security, never
        # expose a default-DACL window before the explicit apply/readback step.
        port.create_protected_roots(roots, descriptors)
        completed.append(attempted)
        attempted = 'APPLY_DACLS'; port.apply_descriptors(roots, descriptors)
        completed.append(attempted)
        attempted = 'VERIFY_DACLS'
        observed = port.read_descriptors(roots)
        w.require(type(observed) is dict and set(observed) == set(descriptors), 'ACL_MISMATCH')
        for kind in descriptors:
            w.validate_descriptor(observed[kind], descriptors[kind])
        completed.append(attempted)
        attempted = 'MATERIALIZE_FILES'
        port.materialize_admitted_files(manifest)
        completed.append(attempted)
        attempted = 'VERIFY_FILES'
        w.exact_data(port.read_runtime_files(), expected_files, 'RUNTIME_TREE_MISMATCH')
        completed.append(attempted)
        task = task_definition(runtime_sid, builder_sid, contract)
        attempted = 'REGISTER_DISABLED_TASK'
        port.register_disabled_password_task(task, credential)
        credential.clear(); credential = None
        completed.append(attempted)
        attempted = 'VERIFY_TASK'
        w.exact_data(port.read_task(), task, 'SCHEDULER_MISMATCH')
        completed.append(attempted)
        attempted = 'SET_STANDARD_USER_UAC'
        before = contract['uac']['expected_before']
        w.exact_data(port.read_uac(), before, 'UNEXPECTED_UAC_STATE')
        port.set_consent_prompt_behavior_user(expected=3, target=0)
        completed.append(attempted)
        attempted = 'VERIFY_UAC'
        after = dict(before, ConsentPromptBehaviorUser=0)
        w.exact_data(port.read_uac(), after, 'UAC_READBACK_FAILED')
        completed.append(attempted)
        receipt = dict(schema_version='trusted-runtime-gate1-receipt-v1', generation=1,
                       installation_id=uuid.uuid4().hex,
                       created_at_utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                       source_commit_sha=source_commit, source_tree_sha=source_tree,
                       gate1_contract_sha256=contract_digest, bootstrap_sha256=bootstrap_digest,
                       python_artifact_sha256=w.GATE1_PYTHON_SHA256,
                       runtime_tree_digest=sha(w.canonical(expected_files)), builder_sid=builder_sid,
                       trusted_runtime_sid=runtime_sid, task_identity=w.TASK_NAME,
                       uac_before=before, uac_after=after, completed_steps=list(completed),
                       final_status='INSTALLATION_WRITES_COMPLETED_PENDING_FINAL_READBACK')
        attempted = 'WRITE_RECEIPT'
        port.write_protected_receipt_exclusive(receipt)
        completed.append(attempted)
        attempted = 'FINAL_READBACK'
        w.exact_data(port.read_receipt(), receipt, 'RECEIPT_READBACK_FAILED')
        w.exact_data(port.read_runtime_files(), expected_files, 'RUNTIME_TREE_MISMATCH')
        w.exact_data(port.read_uac(), after, 'UAC_READBACK_FAILED')
        w.require(port.read_task() == task, 'SCHEDULER_MISMATCH')
        final_descriptors = port.read_descriptors(roots)
        w.require(type(final_descriptors) is dict and set(final_descriptors) == set(descriptors), 'ACL_MISMATCH')
        for kind, descriptor in final_descriptors.items():
            w.validate_descriptor(descriptor, descriptors[kind])
        w.exact_data(port.read_runtime_account(),
                     dict(name='ASFTrustedRuntime', sid=runtime_sid, enabled=True,
                          administrator=False, groups=('S-1-5-32-545',)), 'ACCOUNT_READBACK_FAILED')
        direct, effective = port.read_lsa_rights(runtime_sid)
        w.validate_gate1_batch_rights(direct, effective, after=True)
        completed.extend((attempted, 'STOP'))
        return SequenceEvidence('SEQUENCE_READBACK_COMPLETE_NOT_GATE_AUTHORITY',
                                tuple(completed), None, True, False)
    except Exception:
        # No provider text, traceback, repr, exception chain or secret leaves
        # this boundary. Completed/attempted names are closed internal literals.
        return SequenceEvidence('PARTIAL_STATE_REQUIRES_DIRECTOR_RECOVERY' if mutation_attempted
                                else 'ADMISSION_REJECTED_NO_MUTATION', tuple(completed),
                                attempted, mutation_attempted, mutation_attempted)
    finally:
        if credential is not None:
            credential.clear()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Gate 1 guarded native coordinator and model plan', allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    for mode in ('preflight', 'plan', 'phase1b'):
        modes.add_argument('--' + mode, action='store_true')
    args = parser.parse_args(argv)
    if args.phase1b:
        if _seed_resources is None:
            print('HUMAN_GATE_NOT_AUTHORIZED_PREIMPORT_ADMISSION')
            return 2
        if not (sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
                and sys.flags.no_user_site == 1):
            print('HUMAN_GATE_NOT_AUTHORIZED_IMPORT_ENVIRONMENT')
            return 2
        from orchestrator.trusted_runtime_windows_native import run_native_gate
        result = run_native_gate()
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] == 'TASK_REGISTERED_DISABLED' else 2
    # These modes inspect only immutable contract DATA, never the host.
    result = plan(w.gate1_contract_template())
    result['mode'] = 'preflight' if args.preflight else 'plan'
    result['host_admission'] = 'NOT_PERFORMED'
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        result = main()
    finally:
        seed_closed = _close_seed_resources()
    raise SystemExit(result if seed_closed else 2)
