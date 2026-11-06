"""Native Gate 1 primitives. Never loaded or instantiated as a side effect.

CODE_EXISTS != HUMAN_GATE_AUTHORIZED. All DLLs resolve from System32 only.
Native errors contain operation/category/code only, never provider text.
"""
from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import ctypes as c
from ctypes import wintypes as t
import hashlib
import sys
from pathlib import PureWindowsPath

from orchestrator import trusted_runtime_windows as w

STAGING = r'C:\Program Files\AISOFTWAREFACTORY\GateStaging'
AUTHORIZATION_PATH = STAGING + r'\gate1_authorization.json'
USERS = 'S-1-5-32-545'
UF_SCRIPT = 0x0001
UF_PASSWD_CANT_CHANGE = 0x0040
UF_NORMAL_ACCOUNT = 0x0200
UF_DONT_EXPIRE_PASSWD = 0x10000
RUNTIME_ACCOUNT_FLAGS = (UF_SCRIPT | UF_NORMAL_ACCOUNT |
                         UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD)
BROAD = frozenset({'S-1-1-0', 'S-1-5-11', USERS})
WRITE_MASK = 0x40000000 | 0x10000000 | 0x000d0156


class NativeError(Exception):
    def __init__(self, operation, code=0, mutation_possible=False):
        self.operation = operation
        self.code = int(code) & 0xffffffff
        self.mutation_possible = mutation_possible
        super().__init__(operation, self.code, mutation_possible)


@dataclass(frozen=True)
class HumanGateAuthorization:
    schema_version: str
    action: str
    generation: int
    machine_sid: str
    volume_guid: str
    human_admin_sid: str
    human_confirmation_sha256: str
    builder_sid: str
    builder_workspace_path: str
    source_commit_sha: str
    source_tree_sha: str
    bootstrap_sha256: str
    native_backend_sha256: str
    validator_module_sha256: str
    contract_sha256: str
    manifest_sha256: str
    python_artifact_filename: str
    python_artifact_sha256: str
    python_runtime_tree_digest: str
    authorization_nonce: str
    issued_at_utc: str
    expires_at_utc: str

    @classmethod
    def parse(cls, raw, now):
        value = w.strict_json(raw)
        w.closed(value, tuple(f.name for f in fields(cls)))
        w.require(value['schema_version'] == 'human-gate-authorization-v1'
                  and value['action'] == 'TRUSTED_RUNTIME_GATE1_PHASE1B'
                  and type(value['generation']) is int and value['generation'] == 1,
                  'AUTHORIZATION_REJECTED')
        for key in ('human_admin_sid', 'builder_sid'):
            w.sid(value[key])
        w.require(value['human_admin_sid'] != value['builder_sid'], 'AUTHORIZATION_REJECTED')
        workspace = w.gate1_local_path(value['builder_workspace_path'])
        w.require(PureWindowsPath(r'C:\Users\ASFBuilder') in workspace.parents, 'AUTHORIZATION_REJECTED')
        import re
        w.require(type(value['machine_sid']) is str and re.fullmatch(
            r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+', value['machine_sid']) is not None)
        w.require(type(value['volume_guid']) is str and re.fullmatch(
            r'\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\', value['volume_guid']) is not None)
        for key in ('source_commit_sha', 'source_tree_sha'):
            w.digest(value[key], 40)
        for key in ('bootstrap_sha256', 'native_backend_sha256', 'validator_module_sha256',
                    'contract_sha256', 'manifest_sha256', 'python_artifact_sha256',
                    'python_runtime_tree_digest', 'authorization_nonce', 'human_confirmation_sha256'):
            w.digest(value[key])
        w.require(value['python_artifact_filename'] == 'python-3.14.10-embed-amd64.zip'
                  and value['python_artifact_sha256'] == w.GATE1_PYTHON_SHA256,
                  'PYTHON_HASH_MISMATCH')
        issued, expires = w.utc(value['issued_at_utc']), w.utc(value['expires_at_utc'])
        w.require(now.tzinfo is not None and issued <= now < expires, 'AUTHORIZATION_EXPIRED')
        return cls(**value)


def required_project_import_closure():
    return ('tools/windows/trusted_runtime_gate1_bootstrap.py',
            'src/orchestrator/__init__.py',
            'src/orchestrator/trusted_runtime_windows.py',
            'src/orchestrator/trusted_runtime_windows_native.py')


@dataclass(frozen=True)
class NativeAce:
    sid: str
    mask: int
    flags: int
    ace_type: int


@dataclass(frozen=True)
class NativeDescriptor:
    owner: str
    protected: bool
    dacl_present: bool
    null_dacl: bool
    aces: tuple


def admit_descriptor(actual, expected):
    w.require(type(actual) is NativeDescriptor and actual.dacl_present is True
              and actual.null_dacl is False and actual.protected is True, 'ACL_MISMATCH')
    w.require(all(type(a) is NativeAce and a.ace_type == 0 for a in actual.aces), 'ACL_MISMATCH')
    modeled = w.Descriptor(actual.owner, actual.protected,
                           tuple(w.Ace(a.sid, a.mask, a.flags) for a in actual.aces))
    w.validate_descriptor(modeled, expected)


def admit_authorization_descriptor(sd, human_sid):
    w.require(type(sd) is NativeDescriptor and sd.dacl_present is True
              and sd.null_dacl is False and sd.protected is True
              and sd.owner in (human_sid, w.ADMIN, w.SYSTEM), 'AUTHORIZATION_ACL_REJECTED')
    for ace in sd.aces:
        w.require(ace.ace_type == 0, 'AUTHORIZATION_ACL_REJECTED')
        # Reject unknown writers rather than attempting incomplete group expansion.
        w.require(not ace.mask & WRITE_MASK or ace.sid in (human_sid, w.ADMIN, w.SYSTEM),
                  'AUTHORIZATION_ACL_REJECTED')


def validate_direct_batch_rights(rights, after=False):
    w.require(type(rights) is frozenset and rights ==
              (frozenset({'SeBatchLogonRight'}) if after else frozenset()), 'LSA_RIGHTS_REJECTED')


def validate_group_batch_rights(assignments):
    w.require(type(assignments) is dict and all(type(v) is frozenset for v in assignments.values()),
              'LSA_RIGHTS_REJECTED')
    w.require(all('SeDenyBatchLogonRight' not in v for v in assignments.values()), 'BATCH_LOGON_BLOCKED')


class USER_INFO_1(c.Structure):
    _fields_ = [('name', t.LPWSTR), ('password', c.POINTER(c.c_uint16)),
                ('password_age', t.DWORD), ('privilege', t.DWORD), ('home', t.LPWSTR),
                ('comment', t.LPWSTR), ('flags', t.DWORD), ('script', t.LPWSTR)]


class LSA_STRING(c.Structure):
    _fields_ = [('Length', c.c_uint16), ('MaximumLength', c.c_uint16), ('Buffer', c.c_void_p)]


@contextmanager
def lsa_unicode_string(text):
    """Retain a NUL-terminated UTF-16LE buffer throughout the native call."""
    w.require(type(text) is str and '\0' not in text, 'LSA_STRING_REJECTED')
    encoded = text.encode('utf-16-le')
    nul = bytes(2)
    length = len(encoded)
    maximum = length + len(nul)
    w.require(maximum <= 0xffff, 'LSA_STRING_REJECTED')
    buffer = (c.c_uint16 * (maximum // 2)).from_buffer_copy(encoded + nul)
    yield LSA_STRING(length, maximum, c.cast(buffer, c.c_void_p))


class LSA_OBJECT_ATTRIBUTES(c.Structure):
    _fields_ = [('Length', t.ULONG), ('RootDirectory', t.HANDLE), ('ObjectName', c.c_void_p),
                ('Attributes', t.ULONG), ('SecurityDescriptor', c.c_void_p),
                ('SecurityQualityOfService', c.c_void_p)]


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [('nLength', t.DWORD), ('lpSecurityDescriptor', c.c_void_p), ('bInheritHandle', t.BOOL)]


class NativeCredential:
    """WCHAR storage only. BEST_EFFORT_USERSPACE_ZEROIZATION != GUARANTEED_SECRET_ERASURE."""
    __slots__ = ('buffer', 'length')

    def __init__(self, bcrypt):
        self.length = 48
        self.buffer = (c.c_uint16 * (self.length + 1))()
        random = (c.c_ubyte * self.length)()
        try:
            status = bcrypt.BCryptGenRandom(None, random, len(random), 2)
            if status < 0:
                raise NativeError('CREDENTIAL_RANDOM', status)
            # Four classes plus 44 CSPRNG-derived ASCII characters. No secret str.
            alphabet = b'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@'
            for i in range(self.length):
                self.buffer[i] = alphabet[random[i] % len(alphabet)]
            for i, value in enumerate((65, 97, 50, 33)):
                self.buffer[i] = value
        except BaseException:
            self.clear()
            raise
        finally:
            c.memset(c.addressof(random), 0, c.sizeof(random))

    def __repr__(self):
        return '<NativeCredential redacted>'

    def __reduce_ex__(self, protocol):
        raise TypeError('CREDENTIAL_SERIALIZATION_FORBIDDEN')

    def clear(self):
        c.memset(c.addressof(self.buffer), 0, c.sizeof(self.buffer))

    @contextmanager
    def bstr(self, automation):
        # One unavoidable native copy for Scheduler. Never convert it to str.
        pointer = automation.SysAllocStringLen(c.cast(self.buffer, t.LPCWSTR), self.length)
        if not pointer:
            raise NativeError('CREDENTIAL_BSTR')
        try:
            yield pointer
        finally:
            c.memset(pointer, 0, self.length * 2)
            automation.SysFreeString(pointer)


class NativeBindings:
    """DLL binding alone performs no Windows state mutation."""
    def __init__(self):
        w.require(sys.platform == 'win32' and c.sizeof(c.c_void_p) == 8, 'NATIVE_PLATFORM_REJECTED')
        self.kernel = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
        self.advapi = c.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
        self.net = c.WinDLL('netapi32.dll', use_last_error=True, winmode=0x800)
        self.bcrypt = c.WinDLL('bcrypt.dll', use_last_error=True, winmode=0x800)
        def bind(dll, name, result, *args):
            f = getattr(dll, name)
            f.restype = result; f.argtypes = list(args)
        P = c.c_void_p; PP = c.POINTER(P); D = t.DWORD; PD = c.POINTER(D)
        bind(self.kernel, 'CloseHandle', t.BOOL, t.HANDLE)
        bind(self.kernel, 'GetCurrentProcess', t.HANDLE)
        bind(self.kernel, 'GetCurrentThread', t.HANDLE)
        bind(self.advapi, 'OpenThreadToken', t.BOOL, t.HANDLE, D, t.BOOL, c.POINTER(t.HANDLE))
        bind(self.kernel, 'LocalFree', P, P)
        bind(self.advapi, 'OpenProcessToken', t.BOOL, t.HANDLE, D, c.POINTER(t.HANDLE))
        bind(self.advapi, 'GetTokenInformation', t.BOOL, t.HANDLE, c.c_int, P, D, PD)
        bind(self.advapi, 'CheckTokenMembership', t.BOOL, t.HANDLE, P, c.POINTER(t.BOOL))
        bind(self.advapi, 'ConvertSidToStringSidW', t.BOOL, P, c.POINTER(t.LPWSTR))
        bind(self.advapi, 'ConvertStringSidToSidW', t.BOOL, t.LPCWSTR, PP)
        bind(self.advapi, 'LookupAccountNameW', t.BOOL, t.LPCWSTR, t.LPCWSTR, P, PD,
             t.LPWSTR, PD, c.POINTER(c.c_int))
        bind(self.advapi, 'LookupAccountSidW', t.BOOL, t.LPCWSTR, P, t.LPWSTR, PD,
             t.LPWSTR, PD, c.POINTER(c.c_int))
        bind(self.net, 'NetUserGetInfo', D, t.LPCWSTR, t.LPCWSTR, D, PP)
        bind(self.net, 'NetUserAdd', D, t.LPCWSTR, D, P, PD)
        bind(self.net, 'NetUserGetLocalGroups', D, t.LPCWSTR, t.LPCWSTR, D, D, PP, D, PD, PD)
        bind(self.net, 'NetLocalGroupAddMembers', D, t.LPCWSTR, t.LPCWSTR, D, P, D)
        bind(self.net, 'NetApiBufferFree', D, P)
        bind(self.advapi, 'LsaOpenPolicy', c.c_int32, P, c.POINTER(LSA_OBJECT_ATTRIBUTES), D, c.POINTER(t.HANDLE))
        bind(self.advapi, 'LsaEnumerateAccountRights', c.c_int32, t.HANDLE, P, PP, PD)
        bind(self.advapi, 'LsaAddAccountRights', c.c_int32, t.HANDLE, P, c.POINTER(LSA_STRING), D)
        bind(self.advapi, 'LsaNtStatusToWinError', D, c.c_int32)
        bind(self.advapi, 'LsaFreeMemory', c.c_int32, P)
        bind(self.advapi, 'LsaClose', c.c_int32, t.HANDLE)
        bind(self.bcrypt, 'BCryptGenRandom', c.c_int32, t.HANDLE, P, D, D)

    def check(self, result, operation, mutation=False):
        if not result:
            raise NativeError(operation, c.get_last_error(), mutation)

    @contextmanager
    def sid_pointer(self, value):
        pointer = c.c_void_p()
        self.check(self.advapi.ConvertStringSidToSidW(value, c.byref(pointer)), 'SID_PARSE')
        try:
            yield pointer
        finally:
            self.kernel.LocalFree(pointer)

    def sid_string(self, pointer):
        text = t.LPWSTR()
        self.check(self.advapi.ConvertSidToStringSidW(pointer, c.byref(text)), 'SID_READ')
        try:
            return text.value
        finally:
            self.kernel.LocalFree(c.cast(text, c.c_void_p))

    def token(self):
        thread_token = t.HANDLE()
        if self.advapi.OpenThreadToken(self.kernel.GetCurrentThread(), 8, True, c.byref(thread_token)):
            self.kernel.CloseHandle(thread_token)
            raise NativeError('IMPERSONATION_REJECTED')
        if c.get_last_error() != 1008:
            raise NativeError('THREAD_TOKEN_QUERY', c.get_last_error())
        handle = t.HANDLE()
        self.check(self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, c.byref(handle)), 'TOKEN_OPEN')
        try:
            def info(kind):
                size = t.DWORD()
                self.advapi.GetTokenInformation(handle, kind, None, 0, c.byref(size))
                w.require(0 < size.value <= 65536, 'TOKEN_REJECTED')
                buffer = c.create_string_buffer(size.value)
                self.check(self.advapi.GetTokenInformation(handle, kind, buffer, size, c.byref(size)), 'TOKEN_READ')
                return buffer
            user = info(1)
            current = self.sid_string(c.cast(user, c.POINTER(c.c_void_p))[0])
            elevated = c.cast(info(20), c.POINTER(t.DWORD))[0] != 0
            member = t.BOOL()
            with self.sid_pointer(w.ADMIN) as admin:
                # NULL token asks Windows for the effective thread/process token.
                self.check(self.advapi.CheckTokenMembership(None, admin, c.byref(member)), 'TOKEN_MEMBERSHIP')
            return current, elevated, bool(member.value)
        finally:
            self.kernel.CloseHandle(handle)

    def account_absent(self):
        buffer = c.c_void_p()
        result = self.net.NetUserGetInfo(None, 'ASFTrustedRuntime', 0, c.byref(buffer))
        if buffer:
            self.net.NetApiBufferFree(buffer)
        if result == 2221:  # NERR_UserNotFound, not arbitrary failure
            return True
        if result:
            raise NativeError('ACCOUNT_QUERY', result)
        return False

    def account(self, name='ASFTrustedRuntime'):
        pointer = c.c_void_p()
        result = self.net.NetUserGetInfo(None, name, 1, c.byref(pointer))
        try:
            if result:
                raise NativeError('ACCOUNT_READBACK', result)
            info = c.cast(pointer, c.POINTER(USER_INFO_1)).contents
            return dict(sid=self.resolve_sid(name), standard=info.privilege == 1,
                        enabled=not bool(info.flags & 2), groups=frozenset(self.local_groups(name)))
        finally:
            if pointer:
                self.net.NetApiBufferFree(pointer)

    def machine(self):
        # Local SAM domain is authoritative; do not infer it from an account SID.
        class DOMAIN(c.Structure):
            _fields_ = [('name', LSA_STRING), ('sid', c.c_void_p)]
        api = self.advapi
        api.LsaQueryInformationPolicy.argtypes = [t.HANDLE, c.c_int, c.POINTER(c.c_void_p)]
        api.LsaQueryInformationPolicy.restype = c.c_int32
        attributes = LSA_OBJECT_ATTRIBUTES(); attributes.Length = c.sizeof(attributes)
        handle = t.HANDLE(); pointer = c.c_void_p()
        status = api.LsaOpenPolicy(None, c.byref(attributes), 1, c.byref(handle))
        if status:
            raise NativeError('MACHINE_POLICY_OPEN', api.LsaNtStatusToWinError(status))
        try:
            status = api.LsaQueryInformationPolicy(handle, 5, c.byref(pointer))
            if status:
                raise NativeError('MACHINE_SID', api.LsaNtStatusToWinError(status))
            machine_sid = self.sid_string(c.cast(pointer, c.POINTER(DOMAIN)).contents.sid)
        finally:
            if pointer: api.LsaFreeMemory(pointer)
            api.LsaClose(handle)
        k = self.kernel
        k.GetVolumeNameForVolumeMountPointW.argtypes = [t.LPCWSTR, t.LPWSTR, t.DWORD]
        k.GetVolumeNameForVolumeMountPointW.restype = t.BOOL
        k.GetVolumeInformationW.argtypes = [t.LPCWSTR, t.LPWSTR, t.DWORD, c.POINTER(t.DWORD),
            c.POINTER(t.DWORD), c.POINTER(t.DWORD), t.LPWSTR, t.DWORD]
        k.GetVolumeInformationW.restype = t.BOOL
        volume, filesystem = c.create_unicode_buffer(64), c.create_unicode_buffer(32)
        serial, maximum, flags = t.DWORD(), t.DWORD(), t.DWORD()
        self.check(k.GetVolumeNameForVolumeMountPointW('C:\\', volume, 64), 'VOLUME_GUID')
        self.check(k.GetVolumeInformationW('C:\\', None, 0, c.byref(serial), c.byref(maximum),
                                         c.byref(flags), filesystem, 32), 'VOLUME_INFO')
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography', 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            machine_guid, kind = winreg.QueryValueEx(key, 'MachineGuid')
            w.require(kind == winreg.REG_SZ, 'MACHINE_GUID_REJECTED')
        return dict(machine_sid=machine_sid, volume_guid=volume.value, volume_serial=serial.value,
                    filesystem=filesystem.value, machine_guid=machine_guid,
                    windows_build=str(sys.getwindowsversion().build))

    def create_account(self, secret):
        w.require(type(secret) is NativeCredential and self.account_absent(), 'EXISTING_ACCOUNT')
        info = USER_INFO_1()
        info.name = 'ASFTrustedRuntime'; info.password = secret.buffer
        info.privilege = 1  # USER_PRIV_USER
        info.flags = RUNTIME_ACCOUNT_FLAGS  # standard account; generated password remains durable
        error = t.DWORD()
        result = self.net.NetUserAdd(None, 1, c.byref(info), c.byref(error))
        if result:
            raise NativeError('ACCOUNT_CREATE', result, True)

    def resolve_sid(self, name):
        size, domain_size, use = t.DWORD(), t.DWORD(), c.c_int()
        self.advapi.LookupAccountNameW(None, name, None, c.byref(size), None, c.byref(domain_size), c.byref(use))
        w.require(0 < size.value <= 65536 and domain_size.value <= 32768, 'SID_RESOLUTION_FAILED')
        data, domain = c.create_string_buffer(size.value), c.create_unicode_buffer(domain_size.value)
        self.check(self.advapi.LookupAccountNameW(None, name, data, c.byref(size), domain,
                   c.byref(domain_size), c.byref(use)), 'SID_RESOLVE')
        return self.sid_string(data)

    def local_groups(self, name='ASFTrustedRuntime', *, indirect=False):
        buffer = c.c_void_p(); count, total = t.DWORD(), t.DWORD()
        result = self.net.NetUserGetLocalGroups(None, name, 0, 1 if indirect else 0,
                    c.byref(buffer), 0xffffffff, c.byref(count), c.byref(total))
        try:
            if result:
                raise NativeError('GROUP_QUERY', result)
            w.require(count.value == total.value and count.value <= 1024, 'GROUP_QUERY_FAILED')
            names = c.cast(buffer, c.POINTER(t.LPWSTR))
            return {self.resolve_sid(names[i]): names[i] for i in range(count.value)}
        finally:
            if buffer:
                self.net.NetApiBufferFree(buffer)

    def ensure_users_membership(self, runtime_sid):
        groups = self.local_groups()
        w.require(set(groups) <= {USERS}, 'UNEXPECTED_LOCAL_GROUP')
        if USERS not in groups:
            with self.sid_pointer(USERS) as users:
                name_size, domain_size, use = t.DWORD(), t.DWORD(), c.c_int()
                self.advapi.LookupAccountSidW(None, users, None, c.byref(name_size), None,
                                             c.byref(domain_size), c.byref(use))
                w.require(0 < name_size.value <= 32768 and domain_size.value <= 32768,
                          'GROUP_RESOLUTION_FAILED')
                name, domain = c.create_unicode_buffer(name_size.value), c.create_unicode_buffer(domain_size.value)
                self.check(self.advapi.LookupAccountSidW(None, users, name, c.byref(name_size),
                           domain, c.byref(domain_size), c.byref(use)), 'GROUP_RESOLVE')
                w.require(self.resolve_sid(domain.value + '\\' + name.value) == USERS,
                          'GROUP_RESOLUTION_FAILED')
                with self.sid_pointer(runtime_sid) as pointer:
                    # LOCALGROUP_MEMBERS_INFO_0 is one SID pointer. Add exactly one member.
                    member = c.c_void_p(pointer.value)
                    result = self.net.NetLocalGroupAddMembers(None, name.value, 0, c.byref(member), 1)
                    if result:
                        raise NativeError('GROUP_ADD_USERS', result, True)
        w.require(set(self.local_groups()) == {USERS}, 'UNEXPECTED_LOCAL_GROUP')

    @contextmanager
    def lsa(self, write=False):
        attributes = LSA_OBJECT_ATTRIBUTES(); attributes.Length = c.sizeof(attributes)
        handle = t.HANDLE()
        access = 0x800 | (0x10 if write else 0)  # LOOKUP_NAMES, CREATE_ACCOUNT for new assignment
        status = self.advapi.LsaOpenPolicy(None, c.byref(attributes), access, c.byref(handle))
        if status:
            raise NativeError('LSA_OPEN', self.advapi.LsaNtStatusToWinError(status))
        try:
            yield handle
        finally:
            self.advapi.LsaClose(handle)

    def direct_rights(self, sid):
        with self.lsa() as policy, self.sid_pointer(sid) as pointer:
            buffer, count = c.c_void_p(), t.DWORD()
            status = self.advapi.LsaEnumerateAccountRights(policy, pointer, c.byref(buffer), c.byref(count))
            try:
                if status:
                    error = self.advapi.LsaNtStatusToWinError(status)
                    if status & 0xffffffff == 0xc0000034 and error == 2:
                        return frozenset()
                    raise NativeError('LSA_ENUMERATE', error)
                w.require(count.value <= 256, 'LSA_RIGHTS_REJECTED')
                values = c.cast(buffer, c.POINTER(LSA_STRING))
                result = []
                for i in range(count.value):
                    v = values[i]
                    w.require(v.Length % 2 == 0 and v.Length <= v.MaximumLength and v.Length <= 512)
                    result.append(c.wstring_at(v.Buffer, v.Length // 2))
                return frozenset(result)
            finally:
                if buffer:
                    self.advapi.LsaFreeMemory(buffer)

    def grant_batch(self, sid, groups):
        validate_direct_batch_rights(self.direct_rights(sid))
        validate_group_batch_rights({group: self.direct_rights(group) for group in groups})
        with self.lsa(write=True) as policy, self.sid_pointer(sid) as pointer, \
                lsa_unicode_string('SeBatchLogonRight') as right:
            status = self.advapi.LsaAddAccountRights(policy, pointer, c.byref(right), 1)
            if status:
                raise NativeError('LSA_ADD_BATCH', self.advapi.LsaNtStatusToWinError(status), True)
        validate_direct_batch_rights(self.direct_rights(sid), after=True)


class FILE_STANDARD_INFO(c.Structure):
    _fields_ = [('AllocationSize', c.c_int64), ('EndOfFile', c.c_int64),
                ('NumberOfLinks', t.DWORD), ('DeletePending', c.c_ubyte), ('Directory', c.c_ubyte)]


class FILE_ATTRIBUTE_TAG_INFO(c.Structure):
    _fields_ = [('FileAttributes', t.DWORD), ('ReparseTag', t.DWORD)]


class ACL_HEADER(c.Structure):
    _fields_ = [('revision', c.c_ubyte), ('reserved', c.c_ubyte), ('size', c.c_uint16),
                ('count', c.c_uint16), ('reserved2', c.c_uint16)]


class ACE_HEADER(c.Structure):
    _fields_ = [('kind', c.c_ubyte), ('flags', c.c_ubyte), ('size', c.c_uint16)]


class NativeFiles:
    def __init__(self, bindings):
        self.b = bindings
        k, a = bindings.kernel, bindings.advapi
        P, D = c.c_void_p, t.DWORD
        def bind(dll, name, result, *args):
            f = getattr(dll, name); f.restype = result; f.argtypes = list(args)
        bind(k, 'CreateFileW', t.HANDLE, t.LPCWSTR, D, D, c.POINTER(SECURITY_ATTRIBUTES), D, D, t.HANDLE)
        bind(k, 'CreateDirectoryW', t.BOOL, t.LPCWSTR, c.POINTER(SECURITY_ATTRIBUTES))
        bind(k, 'GetFileInformationByHandleEx', t.BOOL, t.HANDLE, c.c_int, P, D)
        bind(k, 'ReadFile', t.BOOL, t.HANDLE, P, D, c.POINTER(D), P)
        bind(k, 'WriteFile', t.BOOL, t.HANDLE, P, D, c.POINTER(D), P)
        bind(k, 'SetFilePointerEx', t.BOOL, t.HANDLE, c.c_int64, c.POINTER(c.c_int64), D)
        bind(k, 'FlushFileBuffers', t.BOOL, t.HANDLE)
        bind(a, 'GetSecurityInfo', D, t.HANDLE, c.c_int, D, c.POINTER(P), c.POINTER(P),
             c.POINTER(P), c.POINTER(P), c.POINTER(P))
        bind(a, 'SetSecurityInfo', D, t.HANDLE, c.c_int, D, P, P, P, P)
        bind(a, 'GetSecurityDescriptorControl', t.BOOL, P, c.POINTER(c.c_uint16), c.POINTER(D))
        bind(a, 'GetSecurityDescriptorOwner', t.BOOL, P, c.POINTER(P), c.POINTER(t.BOOL))
        bind(a, 'GetSecurityDescriptorDacl', t.BOOL, P, c.POINTER(t.BOOL), c.POINTER(P), c.POINTER(t.BOOL))
        bind(a, 'GetAce', t.BOOL, P, D, c.POINTER(P))
        bind(a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', t.BOOL,
             t.LPCWSTR, D, c.POINTER(P), c.POINTER(D))
        self.held = []
        self.directories = {}

    def close(self):
        success = True
        for handle in reversed(self.held):
            if not self.b.kernel.CloseHandle(handle): success = False
        self.held.clear()
        self.directories.clear()
        return success

    def open(self, path, directory=False, access=0x80020000):
        # READ_CONTROL + GENERIC_READ. Share READ only; deny write/delete opens.
        handle = self.b.kernel.CreateFileW(path, access, 1, None, 3,
                                           0x00200000 | (0x02000000 if directory else 0), None)
        if handle in (None, c.c_void_p(-1).value):
            raise NativeError('FILE_OPEN', c.get_last_error())
        self.held.append(handle)
        self.inspect(handle, directory)
        if directory: self.directories[path] = handle
        return handle

    def inspect(self, handle, directory=False):
        standard, attrs = FILE_STANDARD_INFO(), FILE_ATTRIBUTE_TAG_INFO()
        self.b.check(self.b.kernel.GetFileInformationByHandleEx(handle, 1, c.byref(standard),
                     c.sizeof(standard)), 'FILE_INFORMATION')
        self.b.check(self.b.kernel.GetFileInformationByHandleEx(handle, 9, c.byref(attrs),
                     c.sizeof(attrs)), 'FILE_INFORMATION')
        w.require(not attrs.FileAttributes & 0x400 and not attrs.ReparseTag
                  and bool(standard.Directory) == directory and not standard.DeletePending,
                  'REPARSE_OR_FILE_TYPE_REJECTED')
        if not directory:
            w.require(standard.NumberOfLinks == 1 and standard.EndOfFile >= 0, 'FILE_LINKS_REJECTED')
        return standard.EndOfFile

    def read(self, handle, maximum=64 * 1024 * 1024):
        size = self.inspect(handle)
        w.require(size <= maximum, 'FILE_TOO_LARGE')
        self.b.check(self.b.kernel.SetFilePointerEx(handle, 0, None, 0), 'FILE_SEEK')
        output = bytearray(); buffer = c.create_string_buffer(65536)
        while True:
            count = t.DWORD()
            self.b.check(self.b.kernel.ReadFile(handle, buffer, min(65536, size+1-len(output)),
                         c.byref(count), None), 'FILE_READ')
            if not count.value:
                break
            output.extend(buffer.raw[:count.value])
            w.require(len(output) <= size, 'SOURCE_CHANGED')
        w.require(len(output) == size and self.inspect(handle) == size, 'SOURCE_CHANGED')
        return bytes(output)

    def descriptor(self, handle):
        sd = c.c_void_p()
        status = self.b.advapi.GetSecurityInfo(handle, 1, 5, None, None, None, None, c.byref(sd))
        if status:
            raise NativeError('SECURITY_READ', status)
        try:
            return self.decode_descriptor(sd)
        finally:
            if sd: self.b.kernel.LocalFree(sd)

    def descriptor_from_sddl(self, text):
        w.require(type(text) is str and len(text) <= 65536, 'ACL_MISMATCH')
        pointer = c.c_void_p()
        self.b.check(self.b.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                     text, 1, c.byref(pointer), None), 'SECURITY_PARSE')
        try:
            return self.decode_descriptor(pointer)
        finally:
            self.b.kernel.LocalFree(pointer)

    def decode_descriptor(self, sd):
        owner, dacl = c.c_void_p(), c.c_void_p()
        control, revision = c.c_uint16(), t.DWORD()
        present, defaulted = t.BOOL(), t.BOOL()
        self.b.check(self.b.advapi.GetSecurityDescriptorOwner(sd, c.byref(owner),
                     c.byref(defaulted)), 'SECURITY_OWNER')
        self.b.check(self.b.advapi.GetSecurityDescriptorControl(sd, c.byref(control),
                     c.byref(revision)), 'SECURITY_CONTROL')
        self.b.check(self.b.advapi.GetSecurityDescriptorDacl(sd, c.byref(present),
                     c.byref(dacl), c.byref(defaulted)), 'SECURITY_DACL')
        aces = []
        if dacl:
            header = c.cast(dacl, c.POINTER(ACL_HEADER)).contents
            w.require(header.count <= 1024, 'ACL_TOO_LARGE')
            for i in range(header.count):
                pointer = c.c_void_p()
                self.b.check(self.b.advapi.GetAce(dacl, i, c.byref(pointer)), 'ACE_READ')
                ace = c.cast(pointer, c.POINTER(ACE_HEADER)).contents
                if ace.kind not in (0, 1):
                    aces.append(NativeAce('', 0, ace.flags, ace.kind))
                    continue
                w.require(ace.size >= 16, 'ACE_MALFORMED')
                mask = c.c_uint32.from_address(pointer.value+4).value
                aces.append(NativeAce(self.b.sid_string(pointer.value+8), mask, ace.flags, ace.kind))
        return NativeDescriptor(self.b.sid_string(owner), bool(control.value & 0x1000),
                                bool(present.value), not bool(dacl), tuple(aces))

    @contextmanager
    def security_attributes(self, descriptor):
        text = descriptor_sddl(descriptor)
        pointer = c.c_void_p()
        self.b.check(self.b.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                     text, 1, c.byref(pointer), None), 'SECURITY_BUILD')
        try:
            yield SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), pointer, False)
        finally:
            self.b.kernel.LocalFree(pointer)

    def create_directory(self, path, descriptor):
        # Win32 has no CreateDirectory relative-to-handle primitive here. Caller
        # must hold admitted ancestors without delete sharing through readback.
        with self.security_attributes(descriptor) as attributes:
            self.b.check(self.b.kernel.CreateDirectoryW(path, c.byref(attributes)), 'DIRECTORY_CREATE', True)
        handle = self.open(path, directory=True)
        admit_descriptor(self.descriptor(handle), descriptor)
        return handle

    def copy_exclusive(self, source_handle, destination, expected_size, expected_sha, descriptor):
        raw = self.read(source_handle)
        w.require(len(raw) == expected_size and hashlib.sha256(raw).hexdigest() == expected_sha,
                  'SOURCE_BYTES_MISMATCH')
        return self.write_exclusive(destination, raw, expected_sha, descriptor)

    def write_exclusive(self, destination, raw, expected_sha, descriptor):
        w.require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == expected_sha,
                  'WRITE_BYTES_MISMATCH')
        with self.security_attributes(descriptor) as attrs:
            handle = self.b.kernel.CreateFileW(destination, 0xc0020000, 1, c.byref(attrs),
                                               1, 0x00200000, None)
        if handle in (None, c.c_void_p(-1).value):
            raise NativeError('DESTINATION_CREATE', c.get_last_error(), True)
        try:
            buffer = c.create_string_buffer(raw); written = t.DWORD()
            self.b.check(self.b.kernel.WriteFile(handle, buffer, len(raw), c.byref(written), None),
                         'DESTINATION_WRITE', True)
            w.require(written.value == len(raw), 'SHORT_WRITE')
            self.b.check(self.b.kernel.FlushFileBuffers(handle), 'DESTINATION_FLUSH', True)
            w.require(self.read(handle) == raw, 'DESTINATION_READBACK_MISMATCH')
            admit_descriptor(self.descriptor(handle), descriptor)
        finally:
            self.b.check(self.b.kernel.CloseHandle(handle), 'DESTINATION_CLOSE', True)
        reopened = self.open(destination)
        w.require(hashlib.sha256(self.read(reopened)).hexdigest() == expected_sha,
                  'DESTINATION_READBACK_MISMATCH')
        return reopened

    def absent(self, path, directory=True):
        try:
            self.open(path, directory=directory)
        except NativeError as error:
            if error.operation == 'FILE_OPEN' and error.code in (2, 3):
                return True
            raise
        return False

    def inventory(self, path):
        # GetFileInformationByHandleEx enumerates through retained directory
        # handles, not a path-based reopen. Every child is opened no-delete-share.
        result = {}
        def visit(directory, prefix):
            handle = self.open(directory, directory=True)
            buffer = c.create_string_buffer(65536)
            restart = True
            while True:
                ok = self.b.kernel.GetFileInformationByHandleEx(handle, 11 if restart else 10,
                                                               buffer, len(buffer))
                restart = False
                if not ok:
                    error = c.get_last_error()
                    if error == 18: break  # ERROR_NO_MORE_FILES only
                    raise NativeError('DIRECTORY_ENUMERATE', error)
                offset = 0
                while True:
                    w.require(offset + 104 <= len(buffer), 'DIRECTORY_RECORD_REJECTED')
                    base = c.addressof(buffer) + offset
                    next_offset = c.c_uint32.from_address(base).value
                    attrs = c.c_uint32.from_address(base + 56).value
                    length = c.c_uint32.from_address(base + 60).value
                    w.require(length % 2 == 0 and 0 < length <= 510
                              and offset + 104 + length <= len(buffer), 'DIRECTORY_RECORD_REJECTED')
                    name = c.string_at(base + 104, length).decode('utf-16-le', errors='strict')
                    if name not in ('.', '..'):
                        w.require(not attrs & 0x400, 'REPARSE_OR_FILE_TYPE_REJECTED')
                        relative = prefix + name
                        w.relative_path(relative)
                        child = str(PureWindowsPath(directory) / name)
                        if attrs & 0x10:
                            visit(child, relative + '/')
                        else:
                            w.require(relative not in result, 'DUPLICATE_PATH')
                            result[relative] = self.open(child)
                    if not next_offset: break
                    w.require(next_offset >= 104 + length and next_offset % 8 == 0,
                              'DIRECTORY_RECORD_REJECTED')
                    offset += next_offset
        visit(path, '')
        return result


def descriptor_sddl(descriptor):
    w.require(type(descriptor) is w.Descriptor and descriptor.protected is True, 'ACL_MISMATCH')
    flags = {0: '', 1: 'OI', 3: 'OICI', 13: 'OINPIO'}
    rows = []
    for ace in descriptor.aces:
        w.require(ace.flags in flags, 'ACL_FLAGS_REJECTED')
        rows.append('(A;' + flags[ace.flags] + ';0x' + format(ace.mask, 'x') + ';;;' + ace.sid + ')')
    return 'O:' + descriptor.owner + 'D:P' + ''.join(rows)


def validate_token(observation, authorization):
    sid, elevated, admin = observation
    w.require(type(authorization) is HumanGateAuthorization and sid == authorization.human_admin_sid
              and sid != authorization.builder_sid and elevated is True and admin is True,
              'HUMAN_ADMIN_REQUIRED')


def validate_isolation(workspace, protected, runtime_sid, builder_sid):
    for sd, excluded in [(workspace, {runtime_sid})] + [(x, {builder_sid}) for x in protected]:
        w.require(type(sd) is NativeDescriptor and sd.dacl_present and not sd.null_dacl, 'ISOLATION_REJECTED')
        for ace in sd.aces:
            w.require(ace.ace_type == 0, 'ISOLATION_REJECTED')
            w.require(not (ace.mask & WRITE_MASK and ace.sid in (excluded | BROAD)), 'ISOLATION_REJECTED')


def validate_import_closure(authorization, manifest, observed, *, isolated, user_site, paths, staging):
    w.require(isolated is True and user_site is False, 'IMPORT_ENVIRONMENT_REJECTED')
    root = PureWindowsPath(staging)
    for path in paths:
        p = PureWindowsPath(path)
        w.require(p.is_absolute() and (p == root or root in p.parents), 'IMPORT_ENVIRONMENT_REJECTED')
    w.require(type(observed) is dict and set(observed) == set(required_project_import_closure()),
              'IMPORT_CLOSURE_REJECTED')
    pins = {'tools/windows/trusted_runtime_gate1_bootstrap.py': authorization.bootstrap_sha256,
            'src/orchestrator/trusted_runtime_windows.py': authorization.validator_module_sha256,
            'src/orchestrator/trusted_runtime_windows_native.py': authorization.native_backend_sha256}
    for path, digest in pins.items():
        w.require(observed[path] == digest, 'IMPORT_HASH_MISMATCH')
    # Package __init__ must be independently pinned by the admitted manifest too.
    layout = {p: ('trusted_runtime_gate1_bootstrap.py' if p.startswith('tools/')
                  else p.replace('src/', 'app/', 1)) for p in required_project_import_closure()}
    files = {entry['relative_path']: entry['sha256'] for entry in manifest['files']}
    w.require(all(files.get(layout[p]) == digest for p, digest in observed.items()),
              'IMPORT_CLOSURE_REJECTED')


def task_xml(runtime_sid, start):
    import xml.etree.ElementTree as ET
    w.sid(runtime_sid); w.utc(start)
    ns = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    ET.register_namespace('', ns)
    root = ET.Element('{'+ns+'}Task', version='1.4')
    def node(parent, tag, text=None, **attrs):
        el = ET.SubElement(parent, '{'+ns+'}'+tag, attrs)
        if text is not None: el.text = text
        return el
    triggers = node(root, 'Triggers'); trigger = node(triggers, 'TimeTrigger')
    repetition = node(trigger, 'Repetition'); node(repetition, 'Interval', 'PT1M')
    node(trigger, 'StartBoundary', start); node(trigger, 'Enabled', 'false')
    principal = node(node(root, 'Principals'), 'Principal', id='Runtime')
    node(principal, 'UserId', runtime_sid); node(principal, 'LogonType', 'Password')
    node(principal, 'RunLevel', 'LeastPrivilege')
    settings = node(root, 'Settings')
    for key, value in (('MultipleInstancesPolicy', 'IgnoreNew'), ('DisallowStartIfOnBatteries', 'false'),
        ('StopIfGoingOnBatteries', 'false'), ('AllowHardTerminate', 'true'),
        ('StartWhenAvailable', 'false'), ('RunOnlyIfNetworkAvailable', 'false'),
        ('AllowStartOnDemand', 'false'), ('Enabled', 'false'), ('WakeToRun', 'false'),
        ('ExecutionTimeLimit', 'PT50S')):
        node(settings, key, value)
    action = node(node(root, 'Actions', Context='Runtime'), 'Exec')
    base = w.ROOTS['runtime_root']
    node(action, 'Command', base + r'\python\python.exe')
    node(action, 'Arguments', '-I -B "' + base + r'\app\orchestrator\trusted_runtime_entrypoint.py"')
    node(action, 'WorkingDirectory', base)
    return ET.tostring(root, encoding='unicode')


def expected_task(runtime_sid, builder_sid, start):
    return w.task_observation(task_xml(runtime_sid, start), False,
        descriptor_sddl(w.expected_descriptor('task', runtime_sid, builder_sid)),
        descriptor_sddl(w.expected_descriptor('folder', runtime_sid, builder_sid)))


def final_receipt(auth, manifest, runtime_sid, task, host):
    import uuid
    result = dict(installation_id=uuid.uuid4().hex, generation=1, previous_receipt_sha256=None,
        manifest_sha256=auth.manifest_sha256, source_commit_sha=auth.source_commit_sha,
        source_tree_sha=auth.source_tree_sha, bootstrap_script_sha256=auth.bootstrap_sha256,
        builder_sid=auth.builder_sid, runtime_sid=runtime_sid,
        machine_guid=host['machine_guid'], machine_sid=auth.machine_sid,
        windows_build=host['windows_build'], volume_guid=auth.volume_guid,
        volume_serial=host['volume_serial'], runtime_profile_path=r'C:\Users\ASFTrustedRuntime',
        **w.ROOTS, task_identifier=w.TASK_NAME,
        task_definition_digest=hashlib.sha256(w.canonical(
            {k: v for k, v in task.items() if k != 'xml_sha256'})).hexdigest(),
        installation_timestamp_utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        bootstrap_result='TASK_REGISTERED_DISABLED')
    w.validate_receipt(result)
    return result


class SchedulerDispatch:
    """Explicit local COM automation; no dynamic method names from external data."""
    METHODS = frozenset({'Connect', 'GetFolder', 'GetTask', 'CreateFolder', 'RegisterTask',
                         'Xml', 'Enabled', 'GetSecurityDescriptor', 'SetSecurityDescriptor'})

    def __init__(self, pointer, auto):
        self.pointer, self.auto = pointer, auto

    def close(self):
        if self.pointer:
            w._method(self.pointer, 2, c.c_uint32)(self.pointer)
            self.pointer = None

    def invoke(self, name, *arguments, property_get=False):
        w.require(name in self.METHODS, 'COM_METHOD_FORBIDDEN')
        mutation = name in ('CreateFolder', 'RegisterTask', 'SetSecurityDescriptor')
        null = w._GUID(); identifier = c.c_int32(); names = (c.c_wchar_p * 1)(name)
        status = w._method(self.pointer, 5, c.c_int32, c.POINTER(w._GUID),
            c.POINTER(c.c_wchar_p), c.c_uint32, c.c_uint32, c.POINTER(c.c_int32))(
                self.pointer, c.byref(null), names, 1, 0, c.byref(identifier))
        if status < 0: raise NativeError('COM_NAME', status)
        values = (w._Variant * len(arguments))(); result = w._Variant()
        exception = w._ExceptionInfo(); bad = c.c_uint32(); secret_indices = []
        transferred = None
        try:
            for i, value in enumerate(reversed(arguments)):
                item = values[i]
                if type(value) is NativeCredential:
                    item.vt = 8
                    item.pointer = self.auto.SysAllocStringLen(c.cast(value.buffer, t.LPCWSTR), value.length)
                    secret_indices.append((i, value.length))
                    if not item.pointer: raise NativeError('CREDENTIAL_BSTR')
                elif type(value) is str:
                    item.vt = 8; item.pointer = self.auto.SysAllocString(value)
                    if not item.pointer: raise NativeError('COM_ALLOCATION')
                elif type(value) is int:
                    item.vt = 3; item.integer = value
                else:
                    raise NativeError('COM_ARGUMENT')
            params = w._Params(values, None, len(arguments), 0)
            status = w._method(self.pointer, 6, c.c_int32, c.c_int32, c.POINTER(w._GUID),
                c.c_uint32, c.c_uint16, c.POINTER(w._Params), c.POINTER(w._Variant),
                c.POINTER(w._ExceptionInfo), c.POINTER(c.c_uint32))(
                    self.pointer, identifier, c.byref(null), 0, 2 if property_get else 1,
                    c.byref(params), c.byref(result), c.byref(exception), c.byref(bad))
            if status < 0:
                numeric = exception.status if status & 0xffffffff == 0x80020009 and exception.status else status
                raise NativeError('COM_INVOKE', numeric, mutation)
            if result.vt == 9 and result.pointer:
                ptr = result.pointer; result.vt = 0; result.pointer = None
                transferred = SchedulerDispatch(ptr, self.auto)
                return transferred
            if result.vt == 8:
                length = self.auto.SysStringLen(result.pointer)
                w.require(length <= 1048576, 'COM_RESULT_TOO_LARGE')
                return c.wstring_at(result.pointer, length) if result.pointer else ''
            if result.vt == 11:
                w.require(result.boolean in (0, -1), 'COM_RESULT_REJECTED')
                return result.boolean == -1
            w.require(result.vt == 0, 'COM_RESULT_REJECTED')
            return None
        finally:
            for i, length in secret_indices:
                if values[i].pointer:
                    c.memset(values[i].pointer, 0, length * 2)
            cleanup_failed = False
            for value in values:
                if self.auto.VariantClear(c.byref(value)) < 0:
                    cleanup_failed = True  # continue releasing the remaining owners
            if self.auto.VariantClear(c.byref(result)) < 0:
                cleanup_failed = True
            for ptr in (exception.source, exception.description, exception.help_file):
                if ptr:
                    # Provider diagnostics might contain credential material. Never decode.
                    c.memset(ptr, 0, self.auto.SysStringLen(ptr) * 2)
                    self.auto.SysFreeString(ptr)
            if cleanup_failed:
                if transferred is not None: transferred.close()
                raise NativeError('COM_RESOURCE_CLEANUP', mutation_possible=mutation) from None


class NativeScheduler:
    @contextmanager
    def connection(self):
        ole = c.WinDLL('ole32.dll', use_last_error=True, winmode=0x800)
        auto = c.WinDLL('oleaut32.dll', use_last_error=True, winmode=0x800)
        ole.CoInitializeEx.argtypes = [c.c_void_p, c.c_uint32]; ole.CoInitializeEx.restype = c.c_int32
        ole.CoUninitialize.argtypes = []; ole.CoUninitialize.restype = None
        ole.CLSIDFromString.argtypes = [t.LPCWSTR, c.POINTER(w._GUID)]; ole.CLSIDFromString.restype = c.c_int32
        ole.CoCreateInstance.argtypes = [c.POINTER(w._GUID), c.c_void_p, c.c_uint32,
                                        c.POINTER(w._GUID), c.POINTER(c.c_void_p)]
        ole.CoCreateInstance.restype = c.c_int32
        auto.SysAllocString.argtypes = [t.LPCWSTR]; auto.SysAllocString.restype = c.c_void_p
        auto.SysAllocStringLen.argtypes = [t.LPCWSTR, c.c_uint32]; auto.SysAllocStringLen.restype = c.c_void_p
        auto.SysStringLen.argtypes = [c.c_void_p]; auto.SysStringLen.restype = c.c_uint32
        auto.SysFreeString.argtypes = [c.c_void_p]; auto.SysFreeString.restype = None
        auto.VariantClear.argtypes = [c.POINTER(w._Variant)]; auto.VariantClear.restype = c.c_int32
        status = ole.CoInitializeEx(None, 2)
        if status < 0: raise NativeError('COM_INITIALIZE', status)
        service = None
        try:
            clsid, iid = w._GUID(), w._GUID()
            for text, target in (('{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}', clsid),
                                 ('{00020400-0000-0000-C000-000000000046}', iid)):
                status = ole.CLSIDFromString(text, c.byref(target))
                if status < 0: raise NativeError('COM_GUID', status)
            pointer = c.c_void_p()
            status = ole.CoCreateInstance(c.byref(clsid), None, 1, c.byref(iid), c.byref(pointer))
            if status < 0: raise NativeError('COM_CREATE', status)
            service = SchedulerDispatch(pointer, auto); service.invoke('Connect')
            yield service
        finally:
            if service: service.close()
            ole.CoUninitialize()

    def absent(self):
        with self.connection() as service:
            try:
                folder = service.invoke('GetFolder', r'\AISOFTWAREFACTORY')
            except NativeError as error:
                if error.code in (0x80070002, 0x80070003): return True
                raise
            else:
                folder.close()
                return False

    def register(self, runtime_sid, builder_sid, start, secret):
        xml = task_xml(runtime_sid, start)
        folder_sd = descriptor_sddl(w.expected_descriptor('folder', runtime_sid, builder_sid))
        task_sd = descriptor_sddl(w.expected_descriptor('task', runtime_sid, builder_sid))
        with self.connection() as service:
            objects = []
            def retain(obj):
                w.require(type(obj) is SchedulerDispatch, 'COM_OBJECT_REJECTED')
                objects.append(obj)
                return obj
            try:
                root = retain(service.invoke('GetFolder', '\\'))
                folder = retain(root.invoke('CreateFolder', 'AISOFTWAREFACTORY', folder_sd))
                # TASK_CREATE=2 | TASK_DISABLE=8 | TASK_DONT_ADD_PRINCIPAL_ACE=16.
                # TASK_LOGON_PASSWORD=1. No update flag; no Run method exists here.
                task = folder.invoke('RegisterTask', 'TrustedRuntime', xml, 26, runtime_sid, secret, 1, task_sd)
                retain(task)
            finally:
                for obj in reversed(objects): obj.close()

    def observe(self):
        # One authoritative observer schema, reused unchanged from 001B.
        return w.WindowsTaskScheduler().observe()


class NativeUac:
    PATH = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    def read(self):
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.PATH, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY) as key:
            result = {}
            for name in w.gate1_contract_template()['uac']['expected_before']:
                value, kind = winreg.QueryValueEx(key, name)
                w.require(kind == winreg.REG_DWORD, 'UAC_TYPE_REJECTED')
                result[name] = value
            return result

    def harden(self):
        import winreg
        before = w.gate1_contract_template()['uac']['expected_before']
        w.exact_data(self.read(), before, 'UNEXPECTED_UAC_STATE')
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.PATH, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, 'ConsentPromptBehaviorUser', 0, winreg.REG_DWORD, 0)
            winreg.FlushKey(key)
        w.exact_data(self.read(), dict(before, ConsentPromptBehaviorUser=0), 'UAC_READBACK_FAILED')


ROOT_LAYOUT = (
    ('runtime', w.ROOTS['runtime_root']),
    ('control', r'C:\ProgramData\AISOFTWAREFACTORY'),
    ('authority', w.ROOTS['authority_root']),
    ('captures', w.ROOTS['captures_root']),
    ('inbox', w.ROOTS['inbox_root']),
    ('secrets', w.ROOTS['secrets_root']),
)
PROFILE = r'C:\Users\ASFTrustedRuntime'
PROGRAM_PARENT = r'C:\Program Files\AISOFTWAREFACTORY'
RECEIPT_PATH = w.ROOTS['authority_root'] + r'\installation_receipt.json'
_CONTEXT_SEAL = object()


def closure_layout():
    return {path: ('trusted_runtime_gate1_bootstrap.py' if path.startswith('tools/')
                   else path.replace('src/', 'app/', 1)) for path in required_project_import_closure()}


def tree_digest(files):
    return hashlib.sha256(w.canonical(files)).hexdigest()


def file_descriptor(kind, runtime_sid, builder_sid):
    d = w.expected_descriptor(kind, runtime_sid, builder_sid)
    return w.Descriptor(d.owner, True, tuple(w.Ace(a.sid, a.mask, 0) for a in d.aces))


def admit_ancestor(sd):
    w.require(type(sd) is NativeDescriptor and sd.dacl_present and not sd.null_dacl,
              'ANCESTOR_ACL_REJECTED')
    for ace in sd.aces:
        w.require(ace.ace_type == 0, 'ANCESTOR_ACL_REJECTED')
        # Inherit-only creation grants on C:/ProgramData are not authority to
        # delete/replace an existing protected child. They never admit that child.
        if not ace.flags & w.INHERIT_ONLY and ace.sid in BROAD:
            w.require(not ace.mask & (w.DELETE | 0x40 | w.WRITE_DAC | w.WRITE_OWNER |
                                      0x10000000 | 0x40000000), 'ANCESTOR_ACL_REJECTED')


@dataclass(frozen=True)
class _AdmittedContext:
    authority: HumanGateAuthorization
    contract: dict
    manifest: dict
    host: dict
    bindings: object
    files: object
    scheduler: object
    uac: object
    source_handles: dict
    source_inventory: dict
    workspace_handle: object
    authorization_handle: object
    authorization_bytes: bytes
    seal: object


def _read_pinned(files, handle, expected, maximum=64*1024*1024):
    raw = files.read(handle, maximum)
    w.require(hashlib.sha256(raw).hexdigest() == expected, 'APPROVED_HASH_MISMATCH')
    return raw


def admit_native_gate():
    """Read-only production factory. No mutation backend exists until return.

    There is no caller-selected path, authorization dict, environment flag, port
    or backend selector. Test seams substitute components in the test process.
    """
    import os
    w.require(sys.platform == 'win32' and sys.flags.isolated == 1
              and sys.flags.dont_write_bytecode == 1 and sys.flags.no_user_site == 1,
              'IMPORT_ENVIRONMENT_REJECTED')
    w.require(sys.version_info[:3] == (3, 14, 10) and c.sizeof(c.c_void_p) == 8,
              'PROTECTED_PYTHON_REQUIRED')
    w.require('PYTHONPATH' not in os.environ, 'IMPORT_ENVIRONMENT_REJECTED')
    w.require(PureWindowsPath(sys.executable) == PureWindowsPath(STAGING) / 'python/python.exe',
              'PROTECTED_PYTHON_REQUIRED')
    # Fixed production components, never selected by argv or imported plugins.
    bindings = NativeBindings()
    files = NativeFiles(bindings)
    try:
        token = bindings.token()
        w.require(token[1] is True and token[2] is True, 'HUMAN_ADMIN_REQUIRED')
        for path in ('C:\\', r'C:\Program Files', r'C:\ProgramData', r'C:\Users'):
            admit_ancestor(files.descriptor(files.open(path, directory=True)))
        # Program Files parent already contains protected GateStaging. It cannot
        # be required absent; admit it, never recreate or silently harden it.
        for path in (PROGRAM_PARENT, STAGING):
            admit_authorization_descriptor(files.descriptor(files.open(path, directory=True)), token[0])
        authorization_handle = files.open(AUTHORIZATION_PATH)
        admit_authorization_descriptor(files.descriptor(authorization_handle), token[0])
        authorization_raw = files.read(authorization_handle, 65536)
        auth = HumanGateAuthorization.parse(authorization_raw, datetime.now(timezone.utc))
        validate_token(token, auth)
        host = bindings.machine()
        w.require(host['machine_sid'] == auth.machine_sid and host['volume_guid'] == auth.volume_guid
                  and host['filesystem'] == 'NTFS', 'MACHINE_BINDING_REJECTED')
        contract_handle = files.open(STAGING + r'\gate1_contract.json')
        manifest_handle = files.open(STAGING + r'\trusted_runtime_manifest.json')
        for handle in (contract_handle, manifest_handle):
            admit_authorization_descriptor(files.descriptor(handle), auth.human_admin_sid)
        contract = w.validate_gate1_contract(w.strict_json(_read_pinned(files, contract_handle, auth.contract_sha256)))
        manifest = w.validate_manifest(w.strict_json(_read_pinned(files, manifest_handle, auth.manifest_sha256)))
        w.require(manifest['source_commit_sha'] == auth.source_commit_sha
                  and manifest['source_tree_sha'] == auth.source_tree_sha, 'SOURCE_BINDING_REJECTED')
        provenance = manifest['python_provenance']
        w.require(provenance['artifact_filename'] == auth.python_artifact_filename
                  and provenance['published_sha256'] == auth.python_artifact_sha256
                  and provenance['calculated_sha256'] == auth.python_artifact_sha256,
                  'PYTHON_HASH_MISMATCH')
        # Enumerate once through held handles; an extra file (including pyc or
        # user startup material) cannot silently join the privileged import tree.
        inventory = files.inventory(STAGING)
        for path, handle in files.directories.items():
            if PureWindowsPath(path) == PureWindowsPath(STAGING) or PureWindowsPath(STAGING) in PureWindowsPath(path).parents:
                admit_authorization_descriptor(files.descriptor(handle), auth.human_admin_sid)
        declared = {f['relative_path']: (f['size'], f['sha256']) for f in manifest['files']}
        extras = {'gate1_authorization.json', 'gate1_contract.json', 'trusted_runtime_manifest.json',
                  auth.python_artifact_filename}
        w.require(set(inventory) == set(declared) | extras, 'STAGING_TREE_MISMATCH')
        for relative, handle in inventory.items():
            admit_authorization_descriptor(files.descriptor(handle), auth.human_admin_sid)
        _read_pinned(files, inventory[auth.python_artifact_filename], auth.python_artifact_sha256)
        for relative, (size, digest) in declared.items():
            raw = _read_pinned(files, inventory[relative], digest)
            w.require(len(raw) == size, 'SOURCE_BYTES_MISMATCH')
        python_tree = {p: values for p, values in declared.items() if p.startswith('python/')}
        w.require(tree_digest(python_tree) == auth.python_runtime_tree_digest, 'PYTHON_TREE_MISMATCH')
        layout = closure_layout()
        observed_closure = {source: hashlib.sha256(files.read(inventory[dest])).hexdigest()
                            for source, dest in layout.items()}
        validate_import_closure(auth, manifest, observed_closure, isolated=True, user_site=False,
                                paths=tuple(sys.path), staging=STAGING)
        expected_modules = {'orchestrator': 'app/orchestrator/__init__.py',
                            'orchestrator.trusted_runtime_windows': 'app/orchestrator/trusted_runtime_windows.py',
                            'orchestrator.trusted_runtime_windows_native': 'app/orchestrator/trusted_runtime_windows_native.py'}
        loaded = {name for name in sys.modules if name == 'orchestrator' or name.startswith('orchestrator.')}
        w.require(loaded == set(expected_modules), 'IMPORT_CLOSURE_REJECTED')
        for name, relative in expected_modules.items():
            w.require(PureWindowsPath(getattr(sys.modules[name], '__file__', '')) ==
                      PureWindowsPath(STAGING) / relative, 'IMPORT_CLOSURE_REJECTED')
        # The production bootstrap is executed only from its admitted absolute path.
        w.require(PureWindowsPath(sys.argv[0]) == PureWindowsPath(STAGING) /
                  'trusted_runtime_gate1_bootstrap.py', 'IMPORT_CLOSURE_REJECTED')
        builder = bindings.account('ASFBuilder')
        w.require(builder['sid'] == auth.builder_sid and builder['enabled'] is True
                  and builder['standard'] is True and w.ADMIN not in builder['groups'],
                  'BUILDER_IDENTITY_REJECTED')
        profile_handle = files.open(r'C:\Users\ASFBuilder', directory=True)
        profile_sd = files.descriptor(profile_handle)
        w.require(profile_sd.owner == auth.builder_sid, 'BUILDER_PROFILE_REJECTED')
        profile = PureWindowsPath(r'C:\Users\ASFBuilder')
        workspace = PureWindowsPath(auth.builder_workspace_path)
        for ancestor in reversed(workspace.parents):
            if ancestor == profile or profile in ancestor.parents:
                files.open(str(ancestor), directory=True)
        workspace_handle = files.open(str(workspace), directory=True)
        workspace_sd = files.descriptor(workspace_handle)
        w.require(workspace_sd.owner == auth.builder_sid and workspace_sd.dacl_present
                  and not workspace_sd.null_dacl, 'BUILDER_WORKSPACE_REJECTED')
        w.require(any(a.sid == auth.builder_sid and a.ace_type == 0 and a.mask & WRITE_MASK
                      for a in workspace_sd.aces), 'BUILDER_WORKSPACE_REJECTED')
        validate_isolation(workspace_sd, (), '__RUNTIME_NOT_CREATED__', auth.builder_sid)
        scheduler, uac = NativeScheduler(), NativeUac()
        context = _AdmittedContext(auth, contract, manifest, host, bindings, files, scheduler, uac,
            {p: inventory[p] for p in declared}, declared, workspace_handle,
            authorization_handle, authorization_raw, _CONTEXT_SEAL)
        validate_pre_mutation(context)
        return context
    except BaseException:
        if files.close() is not True:
            raise NativeError('ADMISSION_RESOURCE_CLEANUP') from None
        raise


def validate_pre_mutation(context):
    w.require(type(context) is _AdmittedContext and context.seal is _CONTEXT_SEAL,
              'PROTECTED_AUTHORIZATION_REQUIRED')
    auth, files, bindings = context.authority, context.files, context.bindings
    validate_token(bindings.token(), auth)
    w.require(files.read(context.authorization_handle, 65536) == context.authorization_bytes,
              'AUTHORIZATION_CHANGED')
    w.require(HumanGateAuthorization.parse(context.authorization_bytes, datetime.now(timezone.utc)) == auth,
              'AUTHORIZATION_CHANGED')
    for relative, (size, digest) in context.source_inventory.items():
        raw = _read_pinned(files, context.source_handles[relative], digest)
        w.require(len(raw) == size, 'SOURCE_BYTES_MISMATCH')
    _read_pinned(files, files.open(STAGING + r'\gate1_contract.json'), auth.contract_sha256)
    _read_pinned(files, files.open(STAGING + r'\trusted_runtime_manifest.json'), auth.manifest_sha256)
    w.require(bindings.account_absent(), 'EXISTING_ACCOUNT')
    w.require(files.absent(PROFILE), 'EXISTING_RUNTIME_PROFILE')
    for _, path in ROOT_LAYOUT:
        w.require(files.absent(path), 'EXISTING_ROOT')
    w.require(context.scheduler.absent(), 'EXISTING_TASK')
    w.exact_data(context.uac.read(), context.contract['uac']['expected_before'], 'UNEXPECTED_UAC_STATE')
    machine = bindings.machine()
    w.require(machine == context.host, 'MACHINE_BINDING_REJECTED')


class NativeGateBackend:
    """Production backend: constructor accepts only the admitted retained context.

    This is a control-flow capability inside protected code, not a cryptographic
    token or a public authorization API. Production CLI never accepts a context.
    """
    def __init__(self, context, confirmation=None):
        w.require(confirmation is _CONFIRMATION_SEAL, 'HUMAN_CONFIRMATION_REQUIRED')
        w.require(type(context) is _AdmittedContext and context.seal is _CONTEXT_SEAL,
                  'PROTECTED_AUTHORIZATION_REQUIRED')
        validate_pre_mutation(context)
        self.context = context
        self.runtime_sid = None
        self.effective_access = None
        self.roots = {}
        self.destinations = {}
        self.expected_task = None
        self._final_readback_complete = False

    def create_account(self, credential):
        # Last readmission happens after password acquisition, before first write.
        validate_pre_mutation(self.context)
        self.context.bindings.create_account(credential)

    def freeze_sid(self):
        sid = self.context.bindings.resolve_sid('ASFTrustedRuntime')
        w.sid(sid)
        w.require(sid not in (self.context.authority.builder_sid, self.context.authority.human_admin_sid)
                  and sid.startswith(self.context.authority.machine_sid + '-'), 'RUNTIME_SID_REJECTED')
        self.runtime_sid = sid

    def account_readback(self, final=False):
        actual = self.context.bindings.account()
        w.require(actual['sid'] == self.runtime_sid and actual['standard'] is True
                  and actual['enabled'] is True and set(actual['groups']) <= {USERS},
                  'ACCOUNT_READBACK_FAILED')
        if final:
            w.require(actual['groups'] == frozenset({USERS}), 'UNEXPECTED_LOCAL_GROUP')

    def normalize_groups(self):
        self.context.bindings.ensure_users_membership(self.runtime_sid)
        self.account_readback(final=True)

    def grant_batch(self):
        groups = set(self.context.bindings.local_groups()) | {'S-1-1-0', 'S-1-5-11'}
        self.context.bindings.grant_batch(self.runtime_sid, groups)

    def verify_lsa(self):
        b = self.context.bindings
        validate_direct_batch_rights(b.direct_rights(self.runtime_sid), after=True)
        groups = set(b.local_groups()) | {'S-1-1-0', 'S-1-5-11'}
        validate_group_batch_rights({sid: b.direct_rights(sid) for sid in groups})

    def prepare_effective_access(self, credential):
        w.require(self.effective_access is None, 'EFFECTIVE_ACCESS_ALREADY_CREATED')
        self.effective_access = EffectiveAccess(self.context, self.runtime_sid, credential)

    def create_roots(self):
        for kind, path in ROOT_LAYOUT:
            expected = w.expected_descriptor(kind, self.runtime_sid, self.context.authority.builder_sid)
            self.roots[kind] = self.context.files.create_directory(path, expected)

    def verify_roots_and_isolation(self):
        files = self.context.files
        w.require(set(self.roots) == {k for k, _ in ROOT_LAYOUT}, 'ROOT_READBACK_FAILED')
        observed = {}
        for kind, handle in self.roots.items():
            files.inspect(handle, directory=True)
            observed[kind] = files.descriptor(handle)
            admit_descriptor(observed[kind], w.expected_descriptor(kind, self.runtime_sid,
                                                                 self.context.authority.builder_sid))
        workspace = files.descriptor(self.context.workspace_handle)
        w.require(workspace.owner == self.context.authority.builder_sid, 'ISOLATION_REJECTED')
        validate_isolation(workspace, tuple(observed[k] for k in ('runtime', 'authority', 'captures', 'secrets')),
                           self.runtime_sid, self.context.authority.builder_sid)
        w.require(self.effective_access is not None, 'EFFECTIVE_ACCESS_REQUIRED')
        self.effective_access.verify(self.roots)

    def materialize(self):
        files, base = self.context.files, PureWindowsPath(w.ROOTS['runtime_root'])
        dirs = set()
        for relative in self.context.source_inventory:
            parent = PureWindowsPath(relative).parent
            while str(parent) != '.':
                dirs.add(parent); parent = parent.parent
        descriptor = w.expected_descriptor('runtime', self.runtime_sid, self.context.authority.builder_sid)
        for directory in sorted(dirs, key=lambda p: (len(p.parts), str(p))):
            files.create_directory(str(base / directory), descriptor)
        file_sd = file_descriptor('runtime', self.runtime_sid, self.context.authority.builder_sid)
        for relative, (size, digest) in sorted(self.context.source_inventory.items()):
            self.destinations[relative] = files.copy_exclusive(self.context.source_handles[relative],
                                                str(base / relative), size, digest, file_sd)

    def verify_tree(self):
        files = self.context.files
        inventory = files.inventory(w.ROOTS['runtime_root'])
        w.require(set(inventory) == set(self.context.source_inventory), 'RUNTIME_TREE_MISMATCH')
        base = PureWindowsPath(w.ROOTS['runtime_root'])
        expected_dirs = {base}
        for relative in self.context.source_inventory:
            parent = (base / relative).parent
            while parent == base or base in parent.parents:
                expected_dirs.add(parent)
                parent = parent.parent
        actual_dirs = {PureWindowsPath(p) for p in files.directories
                       if PureWindowsPath(p) == base or base in PureWindowsPath(p).parents}
        w.require(actual_dirs == expected_dirs, 'RUNTIME_TREE_MISMATCH')
        directory_sd = w.expected_descriptor('runtime', self.runtime_sid, self.context.authority.builder_sid)
        for path, handle in files.directories.items():
            if PureWindowsPath(path) in expected_dirs:
                admit_descriptor(files.descriptor(handle), directory_sd)
        expected_sd = file_descriptor('runtime', self.runtime_sid, self.context.authority.builder_sid)
        for relative, handle in inventory.items():
            size, digest = self.context.source_inventory[relative]
            raw = _read_pinned(files, handle, digest)
            w.require(len(raw) == size, 'RUNTIME_TREE_MISMATCH')
            admit_descriptor(files.descriptor(handle), expected_sd)

    def register_task(self, credential):
        auth = self.context.authority
        self.expected_task = expected_task(self.runtime_sid, auth.builder_sid, auth.issued_at_utc)
        self.context.scheduler.register(self.runtime_sid, auth.builder_sid, auth.issued_at_utc, credential)

    def verify_task(self):
        actual = self.context.scheduler.observe()
        # Normalize textual SDDL only AFTER exact native ACE/owner/protection
        # readback. Do not drop deny, unknown, inherited or extra ACEs.
        for key, kind in (('task_sd', 'task'), ('folder_sd', 'folder')):
            expected_sd = w.expected_descriptor(kind, self.runtime_sid, self.context.authority.builder_sid)
            admit_descriptor(self.context.files.descriptor_from_sddl(actual[key]), expected_sd)
            actual[key] = descriptor_sddl(expected_sd)
        w.compare_task(actual, self.expected_task)

    def harden_uac(self):
        self.context.uac.harden()

    def verify_uac(self):
        expected = dict(self.context.contract['uac']['expected_before'], ConsentPromptBehaviorUser=0)
        w.exact_data(self.context.uac.read(), expected, 'UAC_READBACK_FAILED')

    def final_readback(self):
        validate_token(self.context.bindings.token(), self.context.authority)
        self.account_readback(final=True)
        self.verify_lsa()
        self.verify_roots_and_isolation()
        self.verify_tree()
        self.verify_task()
        self.verify_uac()
        w.require(self.context.bindings.machine() == self.context.host, 'MACHINE_BINDING_REJECTED')
        w.require(self.context.files.read(self.context.authorization_handle, 65536) ==
                  self.context.authorization_bytes, 'AUTHORIZATION_CHANGED')
        self._final_readback_complete = True

    def write_receipt(self):
        w.require(self._final_readback_complete is True, 'FINAL_READBACK_REQUIRED')
        self._final_readback_complete = False
        receipt = final_receipt(self.context.authority, self.context.manifest, self.runtime_sid,
                                self.expected_task, self.context.host)
        raw = w.canonical(receipt)
        descriptor = file_descriptor('control', self.runtime_sid, self.context.authority.builder_sid)
        handle = self.context.files.write_exclusive(RECEIPT_PATH, raw, hashlib.sha256(raw).hexdigest(), descriptor)
        readback = self.context.files.read(handle)
        w.require(readback == raw, 'RECEIPT_READBACK_FAILED')
        w.validate_receipt(w.strict_json(readback))


PRODUCTION_STEPS = (
    'AUTHORIZATION_ADMISSION', 'HUMAN_CONFIRMATION', 'BACKEND_CONSTRUCTION', 'CREDENTIAL_ACQUISITION',
    'CREATE_RUNTIME_ACCOUNT', 'FREEZE_RUNTIME_SID', 'ACCOUNT_READBACK',
    'GROUP_NORMALIZATION', 'GRANT_BATCH', 'LSA_READBACK', 'BATCH_TOKEN_AND_AUTHZ', 'CREATE_PROTECTED_ROOTS',
    'ROOTS_AND_ISOLATION_READBACK', 'MATERIALIZE', 'TREE_READBACK',
    'REGISTER_DISABLED_TASK', 'TASK_READBACK', 'UAC_HARDEN', 'UAC_READBACK',
    'FINAL_HOST_READBACK', 'WRITE_AND_VERIFY_FINAL_RECEIPT', 'STOP',
)


def run_native_gate():
    """No injected port/factory/approval input. Tests patch module-local seams.

    This function is reachable from production CLI only through explicit Phase1B;
    real admission must succeed before the mutation backend is constructed.
    """
    context = credential = backend = None
    stage = PRODUCTION_STEPS[0]
    completed = []
    may_have_mutated = False
    result = None
    try:
        context = admit_native_gate(); completed.append(stage)
        stage = 'HUMAN_CONFIRMATION'
        confirmation = confirm_human(context); completed.append(stage)
        stage = 'BACKEND_CONSTRUCTION'
        backend = NativeGateBackend(context, confirmation); completed.append(stage)
        stage = 'CREDENTIAL_ACQUISITION'
        credential = NativeCredential(context.bindings.bcrypt); completed.append(stage)
        operations = (
            ('CREATE_RUNTIME_ACCOUNT', lambda: backend.create_account(credential)),
            ('FREEZE_RUNTIME_SID', backend.freeze_sid),
            ('ACCOUNT_READBACK', backend.account_readback),
            ('GROUP_NORMALIZATION', backend.normalize_groups),
            ('GRANT_BATCH', backend.grant_batch), ('LSA_READBACK', backend.verify_lsa),
            ('BATCH_TOKEN_AND_AUTHZ', lambda: backend.prepare_effective_access(credential)),
            ('CREATE_PROTECTED_ROOTS', backend.create_roots),
            ('ROOTS_AND_ISOLATION_READBACK', backend.verify_roots_and_isolation),
            ('MATERIALIZE', backend.materialize), ('TREE_READBACK', backend.verify_tree),
            ('REGISTER_DISABLED_TASK', lambda: backend.register_task(credential)),
            ('TASK_READBACK', backend.verify_task), ('UAC_HARDEN', backend.harden_uac),
            ('UAC_READBACK', backend.verify_uac), ('FINAL_HOST_READBACK', backend.final_readback),
            ('WRITE_AND_VERIFY_FINAL_RECEIPT', backend.write_receipt),
        )
        for stage, operation in operations:
            if stage == 'CREATE_RUNTIME_ACCOUNT': may_have_mutated = True
            operation(); completed.append(stage)
            if stage == 'REGISTER_DISABLED_TASK':
                credential.clear(); credential = None
        completed.append('STOP')
        result = dict(status='TASK_REGISTERED_DISABLED', stage='STOP', error_code=None,
                      native_status=None, mutation_may_have_occurred=True,
                      completed_steps=completed, director_recovery_required=False)
    except BaseException as error:
        result = dict(status='PARTIAL_STATE_REQUIRES_DIRECTOR_RECOVERY' if may_have_mutated else 'ADMISSION_REJECTED',
                      stage=stage, error_code='NATIVE_API_FAILURE' if type(error) is NativeError else 'GATE_REJECTED',
                      native_status=error.code if type(error) is NativeError else None,
                      mutation_may_have_occurred=may_have_mutated,
                      completed_steps=completed, director_recovery_required=may_have_mutated)
    finally:
        cleanup_ok = True
        try:
            if backend is not None and backend.effective_access is not None:
                backend.effective_access.close()
        except BaseException:
            cleanup_ok = False
        try:
            if credential is not None: credential.clear()
        except BaseException:
            cleanup_ok = False
        try:
            if context is not None and context.files.close() is not True:
                cleanup_ok = False
        except BaseException:
            cleanup_ok = False
        if not cleanup_ok:
            result = dict(status='PARTIAL_STATE_REQUIRES_DIRECTOR_RECOVERY' if may_have_mutated else 'ADMISSION_REJECTED',
                          stage=stage, error_code='RESOURCE_CLEANUP_FAILURE', native_status=None,
                          mutation_may_have_occurred=may_have_mutated, completed_steps=completed,
                          director_recovery_required=True)
    return result


# 001F confirmation is an in-process ordering guard, not a bearer token API.
_CONFIRMATION_SEAL = object()


class KEY_EVENT_RECORD(c.Structure):
    _fields_ = [('KeyDown', t.BOOL), ('RepeatCount', t.WORD), ('VirtualKey', t.WORD),
                ('VirtualScan', t.WORD), ('UnicodeChar', c.c_uint16), ('ControlKeyState', t.DWORD)]


class INPUT_EVENT(c.Union):
    _fields_ = [('KeyEvent', KEY_EVENT_RECORD), ('padding', c.c_ubyte * 16)]


class INPUT_RECORD(c.Structure):
    _fields_ = [('EventType', t.WORD), ('Event', INPUT_EVENT)]


class ConsoleConfirmation:
    """One bounded raw-key attempt; no cooked-line submission or secret string."""
    def __init__(self, kernel):
        self.kernel = kernel
        D = t.DWORD
        for name, restype, args in (
            ('GetStdHandle', t.HANDLE, [D]),
            ('GetConsoleMode', t.BOOL, [t.HANDLE, c.POINTER(D)]),
            ('SetConsoleMode', t.BOOL, [t.HANDLE, D]),
            ('ReadConsoleInputW', t.BOOL, [t.HANDLE, c.POINTER(INPUT_RECORD), D, c.POINTER(D)]),
        ):
            api = getattr(kernel, name); api.argtypes = args; api.restype = restype

    def verify(self, expected_digest):
        import hmac
        w.digest(expected_digest)
        wide = (c.c_uint16 * 32)()
        scratch = (c.c_ubyte * 32)()
        record = INPUT_RECORD()
        original = t.DWORD()
        handle = self.kernel.GetStdHandle(0xfffffff6)  # borrowed STD_INPUT_HANDLE
        mode_known = False
        try:
            w.require(handle not in (None, c.c_void_p(-1).value), 'CONSOLE_REQUIRED')
            w.require(self.kernel.GetConsoleMode(handle, c.byref(original)), 'CONSOLE_REQUIRED')
            mode_known = True
            # Raw input: no processed Ctrl+C, line editing, echo, VT or QuickEdit.
            mode = (original.value & ~(1 | 2 | 4 | 0x200 | 0x40)) | 0x80
            w.require(self.kernel.SetConsoleMode(handle, mode), 'CONSOLE_MODE_FAILED')
            length = 0
            for _ in range(128):  # bounded events within ONE attempt, never restart
                c.memset(c.addressof(record), 0, c.sizeof(record))
                count = t.DWORD()
                w.require(self.kernel.ReadConsoleInputW(handle, c.byref(record), 1, c.byref(count)),
                          'CONSOLE_READ_FAILED')
                w.require(count.value == 1 and record.EventType == 1, 'CONSOLE_EVENT_REJECTED')
                key = record.Event.KeyEvent
                if not key.KeyDown: continue
                # Reject auto-repeat, Ctrl/Alt commands and detectable paste shortcuts.
                w.require(key.RepeatCount == 1 and not key.ControlKeyState & 0xf,
                          'CONSOLE_EVENT_REJECTED')
                value = key.UnicodeChar
                if value == 13:
                    w.require(key.VirtualKey == 13 and length == 32, 'CONFIRMATION_REJECTED')
                    break
                w.require(length < 32 and (48 <= value <= 57 or 65 <= value <= 70),
                          'CONFIRMATION_REJECTED')
                wide[length] = value
                scratch[length] = value
                length += 1
            else:
                raise w.AdmissionError('CONSOLE_EVENT_LIMIT')
            actual = hashlib.sha256(memoryview(scratch)).digest()
            w.require(hmac.compare_digest(actual, bytes.fromhex(expected_digest)), 'CONFIRMATION_REJECTED')
        finally:
            for buffer in (wide, scratch, record):
                c.memset(c.addressof(buffer), 0, c.sizeof(buffer))
            if mode_known:
                w.require(self.kernel.SetConsoleMode(handle, original.value), 'CONSOLE_RESTORE_FAILED')


def confirm_human(context):
    validate_pre_mutation(context)
    ConsoleConfirmation(context.bindings.kernel).verify(context.authority.human_confirmation_sha256)
    # Expiry and pinned inputs are rechecked after the potentially slow human read.
    validate_pre_mutation(context)
    return _CONFIRMATION_SEAL


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [('Sid', c.c_void_p), ('Attributes', t.DWORD)]


class TOKEN_GROUPS_HEADER(c.Structure):
    _fields_ = [('GroupCount', t.DWORD), ('Groups', SID_AND_ATTRIBUTES * 1)]


class GENERIC_MAPPING(c.Structure):
    _fields_ = [('GenericRead', t.DWORD), ('GenericWrite', t.DWORD),
                ('GenericExecute', t.DWORD), ('GenericAll', t.DWORD)]


class LUID(c.Structure):
    _fields_ = [('LowPart', t.DWORD), ('HighPart', t.LONG)]


class AUTHZ_ACCESS_REQUEST(c.Structure):
    _fields_ = [('DesiredAccess', t.DWORD), ('PrincipalSelfSid', c.c_void_p),
                ('ObjectTypeList', c.c_void_p), ('ObjectTypeListLength', t.DWORD),
                ('OptionalArguments', c.c_void_p)]


class AUTHZ_ACCESS_REPLY(c.Structure):
    _fields_ = [('ResultListLength', t.DWORD), ('GrantedAccessMask', c.POINTER(t.DWORD)),
                ('SaclEvaluationResults', c.POINTER(t.DWORD)), ('Error', c.POINTER(t.DWORD))]


RUNTIME_REQUIRED_GROUPS = frozenset({'S-1-5-3', 'S-1-5-11', USERS, 'S-1-5-113'})
BUILDER_CHARACTERISTICS = frozenset({'S-1-1-0', 'S-1-5-11', USERS, 'S-1-5-113', 'S-1-5-4'})
MAXIMUM_ALLOWED = 0x02000000
FILE_GENERIC_MAPPING = (w.READ, w.WRITE, w.READ_CONTROL | w.SYNCHRONIZE | 0xa0, w.FULL_ACCESS)


def validate_batch_token(user, groups, expected_sid):
    import re
    w.require(user == expected_sid and type(groups) is dict, 'BATCH_TOKEN_REJECTED')
    w.require(RUNTIME_REQUIRED_GROUPS <= set(groups), 'BATCH_TOKEN_REJECTED')
    w.require(w.ADMIN not in groups and 'S-1-5-4' not in groups, 'BATCH_TOKEN_REJECTED')
    for sid in RUNTIME_REQUIRED_GROUPS:
        w.require(groups[sid] & 4 and not groups[sid] & 0x10, 'BATCH_TOKEN_REJECTED')
    permitted = RUNTIME_REQUIRED_GROUPS | {'S-1-1-0', 'S-1-2-0', 'S-1-5-15', 'S-1-18-1', 'S-1-16-8192'}
    for sid, attributes in groups.items():
        # Per-logon SID carries no authorization on the admitted exact root SDs.
        logon = re.fullmatch(r'S-1-5-5-[0-9]+-[0-9]+', sid) is not None
        w.require(sid in permitted or (logon and attributes & 0xc0000000 == 0xc0000000),
                  'UNEXPECTED_TOKEN_GROUP')


@contextmanager
def held_security_descriptor(files, handle):
    pointer = c.c_void_p()
    status = files.b.advapi.GetSecurityInfo(handle, 1, 7, None, None, None, None, c.byref(pointer))
    if status: raise NativeError('ACCESS_SD_READ', status)
    try:
        w.require(bool(pointer), 'ACCESS_SD_REJECTED')
        yield pointer
    finally:
        if files.b.kernel.LocalFree(pointer): raise NativeError('ACCESS_SD_FREE')


def _bounded_sid(raw, pointer, minimum_offset, sid_string):
    base = c.addressof(raw)
    w.require(type(pointer) is int and base + minimum_offset <= pointer <= base + c.sizeof(raw) - 8,
              'TOKEN_SID_BOUNDS_REJECTED')
    revision = c.c_ubyte.from_address(pointer).value
    count = c.c_ubyte.from_address(pointer + 1).value
    w.require(revision == 1 and count <= 15 and pointer + 8 + count * 4 <= base + c.sizeof(raw),
              'TOKEN_SID_BOUNDS_REJECTED')
    return sid_string(pointer)


def parse_token_groups(raw, sid_string):
    offset = TOKEN_GROUPS_HEADER.Groups.offset
    w.require(c.sizeof(raw) >= offset, 'TOKEN_GROUPS_BOUNDS_REJECTED')
    count = c.c_uint32.from_buffer(raw).value
    end = offset + count * c.sizeof(SID_AND_ATTRIBUTES)
    w.require(count <= 512 and end <= c.sizeof(raw), 'TOKEN_GROUPS_BOUNDS_REJECTED')
    groups = {}
    for i in range(count):
        item = SID_AND_ATTRIBUTES.from_buffer(raw, offset + i*c.sizeof(SID_AND_ATTRIBUTES))
        sid = _bounded_sid(raw, item.Sid, end, sid_string)
        w.require(sid not in groups, 'TOKEN_GROUPS_DUPLICATE')
        groups[sid] = item.Attributes
    return groups


def observe_native_token(bindings, handle):
    def info(kind):
        size = t.DWORD()
        bindings.advapi.GetTokenInformation(handle, kind, None, 0, c.byref(size))
        w.require(0 < size.value <= 1024*1024, 'TOKEN_INFORMATION_REJECTED')
        buffer = c.create_string_buffer(size.value)
        bindings.check(bindings.advapi.GetTokenInformation(handle, kind, buffer, len(buffer),
                       c.byref(size)), 'TOKEN_INFORMATION_READ')
        w.require(0 < size.value <= len(buffer), 'TOKEN_INFORMATION_REJECTED')
        return buffer
    user = info(1)
    w.require(len(user) >= c.sizeof(SID_AND_ATTRIBUTES), 'TOKEN_USER_BOUNDS_REJECTED')
    pointer = SID_AND_ATTRIBUTES.from_buffer(user).Sid
    sid = _bounded_sid(user, pointer, c.sizeof(SID_AND_ATTRIBUTES), bindings.sid_string)
    return sid, parse_token_groups(info(2), bindings.sid_string)


def access_check(bindings, token, descriptor, desired=MAXIMUM_ALLOWED):
    api = bindings.advapi.AccessCheck
    api.argtypes = [c.c_void_p, t.HANDLE, t.DWORD, c.POINTER(GENERIC_MAPPING), c.c_void_p,
                    c.POINTER(t.DWORD), c.POINTER(t.DWORD), c.POINTER(t.BOOL)]
    api.restype = t.BOOL
    privileges = c.create_string_buffer(65536)
    size, granted, allowed = t.DWORD(len(privileges)), t.DWORD(), t.BOOL()
    mapping = GENERIC_MAPPING(*FILE_GENERIC_MAPPING)
    bindings.check(api(descriptor, token, desired, c.byref(mapping), privileges,
                       c.byref(size), c.byref(granted), c.byref(allowed)), 'ACCESS_CHECK_API')
    w.require(8 <= size.value <= len(privileges), 'ACCESS_ABI_REJECTED')
    count = c.c_uint32.from_buffer(privileges).value
    w.require(count <= (size.value - 8) // 12, 'ACCESS_PRIVILEGES_REJECTED')
    return granted.value if allowed.value else 0


@contextmanager
def current_process_access_token(bindings):
    a = bindings.advapi
    a.DuplicateToken.argtypes = [t.HANDLE, c.c_int, c.POINTER(t.HANDLE)]
    a.DuplicateToken.restype = t.BOOL
    primary, duplicate = t.HANDLE(), t.HANDLE()
    try:
        bindings.check(a.OpenProcessToken(bindings.kernel.GetCurrentProcess(), 0x0a,
                       c.byref(primary)), 'PREFLIGHT_TOKEN_OPEN')  # QUERY | DUPLICATE
        bindings.check(a.DuplicateToken(primary, 2, c.byref(duplicate)), 'PREFLIGHT_TOKEN_DUPLICATE')
        yield duplicate
    finally:
        ok = True
        for handle in (duplicate, primary):
            if handle and not bindings.kernel.CloseHandle(handle): ok = False
        if not ok: raise NativeError('PREFLIGHT_TOKEN_CLOSE')


class RuntimeBatchToken:
    """Own primary and duplicated token handles; never impersonate a thread."""
    def __init__(self, bindings, credential, expected_sid):
        self.b = bindings
        self.primary, self.token = t.HANDLE(), t.HANDLE()
        a = bindings.advapi
        a.LogonUserW.argtypes = [t.LPCWSTR, t.LPCWSTR, c.POINTER(c.c_uint16), t.DWORD,
                                t.DWORD, c.POINTER(t.HANDLE)]
        a.LogonUserW.restype = t.BOOL
        a.DuplicateToken.argtypes = [t.HANDLE, c.c_int, c.POINTER(t.HANDLE)]
        a.DuplicateToken.restype = t.BOOL
        a.AccessCheck.argtypes = [c.c_void_p, t.HANDLE, t.DWORD, c.POINTER(GENERIC_MAPPING),
                                 c.c_void_p, c.POINTER(t.DWORD), c.POINTER(t.DWORD), c.POINTER(t.BOOL)]
        a.AccessCheck.restype = t.BOOL
        try:
            w.require(type(credential) is NativeCredential, 'CREDENTIAL_REQUIRED')
            bindings.check(a.LogonUserW('ASFTrustedRuntime', '.', credential.buffer, 4, 0,
                                       c.byref(self.primary)), 'BATCH_LOGON')
            self.validate(self.primary, expected_sid)
            bindings.check(a.DuplicateToken(self.primary, 2, c.byref(self.token)), 'BATCH_DUPLICATE')
            self.validate(self.token, expected_sid)
        except BaseException:
            self.close()
            raise

    def validate(self, handle, expected_sid):
        sid, groups = observe_native_token(self.b, handle)
        validate_batch_token(sid, groups, expected_sid)

    def access(self, descriptor):
        return access_check(self.b, self.token, descriptor)

    def close(self):
        ok = True
        for name in ('token', 'primary'):
            handle = getattr(self, name)
            if handle:
                if not self.b.kernel.CloseHandle(handle): ok = False
                setattr(self, name, t.HANDLE())
        if not ok: raise NativeError('BATCH_TOKEN_CLOSE')


class BuilderAuthz:
    """Explicit group context, no S4U, no credentials, no context from metadata flags."""
    def __init__(self, bindings, sid, groups):
        self.b = bindings
        self.manager, self.base, self.context = c.c_void_p(), c.c_void_p(), c.c_void_p()
        w.require(type(groups) is frozenset and BUILDER_CHARACTERISTICS <= groups
                  and 'S-1-5-3' not in groups and w.ADMIN not in groups, 'BUILDER_CONTEXT_REJECTED')
        self.api = c.WinDLL('authz.dll', use_last_error=True, winmode=0x800)
        P, D = c.c_void_p, t.DWORD
        def bind(name, result, *args):
            f = getattr(self.api, name); f.restype = result; f.argtypes = list(args)
        bind('AuthzInitializeResourceManager', t.BOOL, D, P, P, P, t.LPCWSTR, c.POINTER(P))
        bind('AuthzInitializeContextFromSid', t.BOOL, D, P, P, P, LUID, P, c.POINTER(P))
        bind('AuthzAddSidsToContext', t.BOOL, P, c.POINTER(SID_AND_ATTRIBUTES), D,
             c.POINTER(SID_AND_ATTRIBUTES), D, c.POINTER(P))
        bind('AuthzAccessCheck', t.BOOL, D, P, c.POINTER(AUTHZ_ACCESS_REQUEST), P, P,
             c.POINTER(P), D, c.POINTER(AUTHZ_ACCESS_REPLY), c.POINTER(P))
        bind('AuthzFreeContext', t.BOOL, P)
        bind('AuthzFreeResourceManager', t.BOOL, P)
        from contextlib import ExitStack
        try:
            bindings.check(self.api.AuthzInitializeResourceManager(1, None, None, None, None,
                            c.byref(self.manager)), 'AUTHZ_MANAGER')
            with bindings.sid_pointer(sid) as pointer:
                # AUTHZ_SKIP_TOKEN_GROUPS: never resolve a hidden S4U token.
                bindings.check(self.api.AuthzInitializeContextFromSid(2, pointer, self.manager,
                                None, LUID(), None, c.byref(self.base)), 'AUTHZ_CONTEXT')
            with ExitStack() as stack:
                entries = (SID_AND_ATTRIBUTES * len(groups))()
                for i, group in enumerate(sorted(groups)):
                    pointer = stack.enter_context(bindings.sid_pointer(group))
                    entries[i] = SID_AND_ATTRIBUTES(pointer, 7)  # mandatory/default-enabled/enabled
                bindings.check(self.api.AuthzAddSidsToContext(self.base, entries, len(entries), None, 0,
                                c.byref(self.context)), 'AUTHZ_GROUPS')
        except BaseException:
            self.close()
            raise

    def access(self, descriptor, desired=MAXIMUM_ALLOWED):
        granted, error = t.DWORD(), t.DWORD()
        request = AUTHZ_ACCESS_REQUEST(desired, None, None, 0, None)
        reply = AUTHZ_ACCESS_REPLY(1, c.pointer(granted), None, c.pointer(error))
        self.b.check(self.api.AuthzAccessCheck(0, self.context, c.byref(request), None, descriptor,
                     None, 0, c.byref(reply), None), 'BUILDER_ACCESS_CHECK')
        if error.value == 5:
            w.require(granted.value == 0, 'AUTHZ_ACCESS_RESULT_REJECTED')
            return 0  # documented per-result access denial
        if error.value: raise NativeError('AUTHZ_ACCESS_RESULT', error.value)
        return granted.value

    def close(self):
        ok = True
        for name in ('context', 'base'):
            handle = getattr(self, name)
            if handle:
                if not self.api.AuthzFreeContext(handle): ok = False
                setattr(self, name, c.c_void_p())
        if self.manager:
            if not self.api.AuthzFreeResourceManager(self.manager): ok = False
            self.manager = c.c_void_p()
        if not ok: raise NativeError('AUTHZ_CLOSE')


def builder_context_groups(bindings, builder_sid):
    observed = bindings.account('ASFBuilder')
    machine_sid = bindings.machine()['machine_sid']
    w.require(builder_sid.startswith(machine_sid + '-'), 'BUILDER_NOT_LOCAL')
    w.require(observed['sid'] == builder_sid and observed['standard'] and observed['enabled'],
              'BUILDER_CONTEXT_REJECTED')
    indirect = bindings.local_groups('ASFBuilder', indirect=True)
    # The approved standard-user model is exactly Users, including indirect groups.
    # Unknown/custom groups are not silently approximated.
    w.require(set(indirect) == {USERS}, 'BUILDER_CONTEXT_REJECTED')
    groups = BUILDER_CHARACTERISTICS
    dangerous = {'SeTakeOwnershipPrivilege', 'SeRestorePrivilege', 'SeBackupPrivilege',
                 'SeSecurityPrivilege', 'SeRelabelPrivilege', 'SeTcbPrivilege',
                 'SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeCreateTokenPrivilege',
                 'SeAssignPrimaryTokenPrivilege'}
    for principal in groups | {builder_sid}:
        w.require(not bindings.direct_rights(principal) & dangerous, 'BUILDER_PRIVILEGE_REJECTED')
    return groups


class EffectiveAccess:
    def __init__(self, context, runtime_sid, credential):
        self.context = context
        self.runtime = self.builder = None
        self.runtime_sid = runtime_sid
        try:
            groups = builder_context_groups(context.bindings, context.authority.builder_sid)
            self.runtime = RuntimeBatchToken(context.bindings, credential, runtime_sid)
            self.builder = BuilderAuthz(context.bindings, context.authority.builder_sid, groups)
        except BaseException:
            self.close()
            raise

    def verify(self, roots):
        files = self.context.files
        w.require(builder_context_groups(self.context.bindings, self.context.authority.builder_sid) ==
                  BUILDER_CHARACTERISTICS, 'BUILDER_CONTEXT_REJECTED')
        self.runtime.validate(self.runtime.token, self.runtime_sid)
        with held_security_descriptor(files, self.context.workspace_handle) as sd:
            w.require(not self.runtime.access(sd) & WRITE_MASK, 'RUNTIME_WORKSPACE_ACCESS_REJECTED')
        parent = str(PureWindowsPath(self.context.authority.builder_workspace_path).parent)
        w.require(parent in files.directories, 'WORKSPACE_PARENT_NOT_HELD')
        with held_security_descriptor(files, files.directories[parent]) as sd:
            w.require(not self.runtime.access(sd) & (0x40 | w.WRITE_DAC | w.WRITE_OWNER),
                      'RUNTIME_WORKSPACE_PARENT_ACCESS_REJECTED')
        runtime_masks = {'runtime':w.EXECUTE_ACCESS, 'control':w.READ, 'authority':w.AUTHORITY_ACCESS,
                         'captures':w.CAPTURE_ACCESS, 'inbox':w.READ, 'secrets':w.CAPTURE_ACCESS}
        w.require(set(roots) == set(runtime_masks), 'ACCESS_ROOTS_REJECTED')
        for kind, handle in roots.items():
            with held_security_descriptor(files, handle) as sd:
                w.require(self.runtime.access(sd) == runtime_masks[kind], 'RUNTIME_ACCESS_REJECTED')
                granted = self.builder.access(sd)
                expected = w.BUILDER_INBOX_ACCESS if kind == 'inbox' else 0
                w.require(granted == expected, 'BUILDER_ACCESS_REJECTED')

    def close(self):
        failed = False
        for name in ('builder', 'runtime'):
            resource = getattr(self, name)
            if resource is not None:
                try: resource.close()
                except BaseException: failed = True
                setattr(self, name, None)
        if failed: raise NativeError('EFFECTIVE_ACCESS_CLOSE')
