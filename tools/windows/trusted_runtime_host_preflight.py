"""001F read-only host ABI probe. Never authorizes or invokes Human Gate 1."""
import argparse
import ctypes as c
from ctypes import wintypes as t
import json
from orchestrator import trusted_runtime_windows as w
from orchestrator import trusted_runtime_windows_native as n


CATEGORIES = ('DLL_ABI', 'TOKEN_READ', 'ACCESSCHECK_ABI', 'CONSOLE_ABI', 'NETAPI_READ', 'LSA_READ', 'FILESYSTEM_SD_READ',
              'SDDL_ROUNDTRIP', 'AUTHZ_ACCESSCHECK', 'TASK_SCHEDULER_READ', 'UAC_READ')


# Complete owner/group/DACL. Everyone has READ; WRITE_DATA is denied by omission.
# No SACL or persistent object is created. LocalFree owns the native allocation.
CONTROLLED_SDDL = 'O:SYG:SYD:P(A;;0x120089;;;WD)'


from contextlib import contextmanager


@contextmanager
def controlled_descriptor(bindings):
    pointer = c.c_void_p()
    bindings.check(bindings.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                   CONTROLLED_SDDL,1,c.byref(pointer),None), 'PREFLIGHT_SD_BUILD')
    try:
        w.require(bool(pointer), 'PREFLIGHT_SD_REJECTED')
        yield pointer
    finally:
        if bindings.kernel.LocalFree(pointer): raise n.NativeError('PREFLIGHT_SD_FREE')


class ReadOnlyHostProbe:
    def __init__(self):
        self.bindings = self.files = None

    def dll_abi(self):
        w.require(c.sizeof(c.c_void_p) == 8 and c.sizeof(c.c_wchar) == 2, 'ABI_REJECTED')
        for structure, size in ((n.LSA_STRING,16), (n.USER_INFO_1,56),
                                (n.SID_AND_ATTRIBUTES,16), (n.GENERIC_MAPPING,16),
                                (n.AUTHZ_ACCESS_REQUEST,40), (n.AUTHZ_ACCESS_REPLY,32),
                                (w._GUID,16), (w._Variant,24), (n.KEY_EVENT_RECORD,16),
                                (n.INPUT_RECORD,20)):
            w.require(c.sizeof(structure) == size, 'ABI_REJECTED')
        self.bindings = n.NativeBindings()  # System32 bindings only; no mutation calls
        self.files = n.NativeFiles(self.bindings)
        return True

    def token_read(self):
        observed = self.bindings.token()
        w.require(type(observed) is tuple and len(observed) == 3, 'TOKEN_ABI_REJECTED')
        return True

    def netapi_read(self):
        # Name is consumed locally by read-only NetAPI, never returned in evidence.
        api = self.bindings.advapi.GetUserNameW
        api.argtypes = [t.LPWSTR,c.POINTER(t.DWORD)]; api.restype = t.BOOL
        text = c.create_unicode_buffer(257); length = t.DWORD(len(text))
        self.bindings.check(api(text,c.byref(length)), 'CURRENT_ACCOUNT_QUERY')
        self.bindings.account(text.value)
        return True

    def lsa_read(self):
        sid, _, _ = self.bindings.token()
        self.bindings.direct_rights(sid)
        return True

    def filesystem_sd_read(self):
        handle = self.files.open(r'C:\Windows\System32', directory=True)
        sd = self.files.descriptor(handle)
        w.require(sd.dacl_present and not sd.null_dacl, 'SD_READ_REJECTED')
        return True

    def sddl_roundtrip(self):
        handle = self.files.open(r'C:\Windows\System32', directory=True)
        api = self.bindings.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
        api.argtypes = [c.c_void_p,t.DWORD,t.DWORD,c.POINTER(t.LPWSTR),c.POINTER(t.DWORD)]
        api.restype = t.BOOL
        with n.held_security_descriptor(self.files, handle) as raw:
            output = t.LPWSTR()
            self.bindings.check(api(raw,1,5,c.byref(output),None), 'SDDL_CONVERT')
            try:
                original = self.files.decode_descriptor(raw)
                decoded = self.files.descriptor_from_sddl(output.value)
                w.require(original == decoded, 'SDDL_ROUNDTRIP_REJECTED')
            finally:
                if self.bindings.kernel.LocalFree(c.cast(output,c.c_void_p)):
                    raise n.NativeError('SDDL_FREE')
        return True

    def accesscheck_abi(self):
        with n.current_process_access_token(self.bindings) as token:
            # ABI only; current process groups are NOT a future Batch-token assertion.
            sid, groups = n.observe_native_token(self.bindings, token)
            w.require(type(sid) is str and type(groups) is dict, 'TOKEN_ABI_REJECTED')
            with controlled_descriptor(self.bindings) as sd:
                w.require(n.access_check(self.bindings, token, sd, w.READ) == w.READ,
                          'ACCESSCHECK_ALLOW_REJECTED')
                w.require(n.access_check(self.bindings, token, sd, 2) == 0,
                          'ACCESSCHECK_DENY_REJECTED')
        return True

    def console_abi(self):
        api = self.bindings.kernel
        api.GetStdHandle.argtypes = [t.DWORD]; api.GetStdHandle.restype = t.HANDLE
        api.GetConsoleMode.argtypes = [t.HANDLE,c.POINTER(t.DWORD)]; api.GetConsoleMode.restype = t.BOOL
        handle = api.GetStdHandle(0xfffffff6)
        if handle in (None,c.c_void_p(-1).value): return None
        mode = t.DWORD()
        if not api.GetConsoleMode(handle,c.byref(mode)): return None
        return True  # borrowed handle; no read, mode change or CloseHandle

    def authz_accesscheck(self):
        # Synthetic well-known principal/context, no observed user identity required.
        context = n.BuilderAuthz(self.bindings,'S-1-5-19',n.BUILDER_CHARACTERISTICS)
        try:
            with controlled_descriptor(self.bindings) as sd:
                w.require(context.access(sd,w.READ) == w.READ, 'AUTHZ_ALLOW_REJECTED')
                w.require(context.access(sd,2) == 0, 'AUTHZ_DENY_REJECTED')
        finally:
            context.close()
        return True

    def task_scheduler_read(self):
        with n.NativeScheduler().connection() as service:
            folder = service.invoke('GetFolder', '\\')
            w.require(type(folder) is n.SchedulerDispatch, 'COM_FOLDER_REJECTED')
            try:
                text = folder.invoke('GetSecurityDescriptor', 7)
                sd = self.files.descriptor_from_sddl(text)
                w.require(sd.dacl_present and not sd.null_dacl, 'COM_SD_REJECTED')
            finally:
                folder.close()
        return True

    def uac_read(self):
        values = n.NativeUac().read()
        w.exact_data(values, w.gate1_contract_template()['uac']['expected_before'], 'UAC_BASELINE_REJECTED')
        return True

    def close(self):
        if self.files is not None and self.files.close() is not True:
            raise n.NativeError('PROBE_CLOSE')


def run_preflight():
    results = dict.fromkeys(CATEGORIES, 'NOT_VERIFIED')
    probe = ReadOnlyHostProbe()
    cleanup = 'PASS'
    try:
        for category in CATEGORIES:
            if category != 'DLL_ABI' and results['DLL_ABI'] != 'PASS': continue
            try:
                value = getattr(probe, category.lower())()
                results[category] = 'PASS' if value is True else 'NOT_VERIFIED'
            except Exception:
                # No provider text, identifiers, paths, usernames or exception chains.
                results[category] = 'FAIL'
    finally:
        try: probe.close()
        except Exception: cleanup = 'FAIL'
    final = ('FAIL' if cleanup == 'FAIL' or 'FAIL' in results.values() else
             'INCOMPLETE' if 'NOT_VERIFIED' in results.values() else 'PASS')
    return dict(checks=results, RESOURCE_CLEANUP=cleanup, READ_ONLY_HOST_PREFLIGHT=final,
                HUMAN_GATE_1_AUTHORIZED='NO', REAL_WINDOWS_MUTATION_AUTHORIZED='NO',
                REAL_REGISTER_TASK_WITH_PASSWORD_NOT_YET_EXECUTED=True,
                REAL_TASK_XML_NORMALIZATION_NOT_YET_PROVEN=True,
                REAL_TASK_SDDL_AFTER_REGISTRATION_NOT_YET_PROVEN=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only native host boundary probe', allow_abbrev=False)
    parser.add_argument('--read-only', action='store_true', required=True)
    parser.parse_args(argv)
    result = run_preflight()
    print(json.dumps(result, sort_keys=True))
    return 0 if result['READ_ONLY_HOST_PREFLIGHT'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
