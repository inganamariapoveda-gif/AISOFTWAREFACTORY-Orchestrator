"""001F probe tests; all host APIs replaced, no real-host preflight."""
import ctypes as c
from contextlib import nullcontext
import importlib.util
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from tests.test_trusted_runtime_windows_native import n, w, HUMAN, synthetic_token_bindings

ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('host_preflight_fixture',ROOT/'tools/windows/trusted_runtime_host_preflight.py')
p=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=p;_spec.loader.exec_module(p)


class ReadOnlyPreflightTests(unittest.TestCase):
    def test_all_probes_reject_any_mutating_call(self):
        forbidden=Mock(side_effect=AssertionError('FORBIDDEN_MUTATION'))
        kernel=SimpleNamespace(LocalFree=Mock(return_value=None),WriteFile=forbidden,CreateDirectoryW=forbidden,
            SetConsoleMode=forbidden,ReadConsoleInputW=forbidden,GetCurrentProcess=Mock(return_value=1),
            CloseHandle=Mock(return_value=1),GetStdHandle=Mock(return_value=12),GetConsoleMode=Mock(return_value=1))
        advapi=SimpleNamespace(LsaAddAccountRights=forbidden,SetSecurityInfo=forbidden,LogonUserW=forbidden)
        def username(buffer,size):buffer.value='synthetic';return 1
        advapi.GetUserNameW=Mock(side_effect=username)
        text=c.create_unicode_buffer('synthetic-sddl')
        def to_string(sd,revision,flags,out,size):
            c.cast(out,c.POINTER(c.c_void_p))[0]=c.addressof(text);return 1
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW=Mock(side_effect=to_string)
        seed=synthetic_token_bindings({'S-1-5-4':7},HUMAN)
        advapi.GetTokenInformation=seed.advapi.GetTokenInformation
        def open_token(handle,access,out):
            self.assertEqual(access,0x0a);c.cast(out,c.POINTER(n.t.HANDLE))[0]=21;return 1
        def duplicate(handle,level,out):
            self.assertEqual(level,2);c.cast(out,c.POINTER(n.t.HANDLE))[0]=22;return 1
        def check_access(sd,token,desired,mapping,privileges,size,granted,status):
            c.cast(size,c.POINTER(n.t.DWORD))[0]=8
            c.cast(granted,c.POINTER(n.t.DWORD))[0]=w.READ if desired==w.READ else 0
            c.cast(status,c.POINTER(n.t.BOOL))[0]=int(desired==w.READ);return 1
        def build_sd(sddl,revision,out,length):
            self.assertEqual(sddl,'O:SYG:SYD:P(A;;0x120089;;;WD)')
            c.cast(out,c.POINTER(c.c_void_p))[0]=333;return 1
        advapi.OpenProcessToken=Mock(side_effect=open_token)
        advapi.DuplicateToken=Mock(side_effect=duplicate)
        advapi.AccessCheck=Mock(side_effect=check_access)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW=Mock(side_effect=build_sd)
        b=SimpleNamespace(sid_string=seed.sid_string,kernel=kernel,advapi=advapi,net=SimpleNamespace(NetUserAdd=forbidden,NetLocalGroupAddMembers=forbidden),
            token=lambda:(HUMAN,False,False),account=Mock(return_value={}),direct_rights=Mock(return_value=frozenset()),
            check=lambda result,*args:w.require(result,'SYNTHETIC_API_FAILURE'))
        sd=n.NativeDescriptor(w.ADMIN,True,True,False,())
        files=SimpleNamespace(open=Mock(return_value=10),descriptor=lambda handle:sd,decode_descriptor=lambda raw:sd,
            descriptor_from_sddl=lambda value:sd,security_attributes=lambda value:nullcontext(SimpleNamespace(lpSecurityDescriptor=10)),
            close=Mock(return_value=True),write_exclusive=forbidden,create_directory=forbidden)
        folder=n.SchedulerDispatch(None,None)
        def folder_invoke(name,*args):
            if name!='GetSecurityDescriptor':forbidden()
            return 'synthetic-sddl'
        folder.invoke=folder_invoke;folder.close=Mock()
        def service_invoke(name,*args):
            if name!='GetFolder' or args!=('\\',):forbidden()
            return folder
        scheduler=SimpleNamespace(connection=lambda:nullcontext(SimpleNamespace(invoke=service_invoke)),register=forbidden)
        authz=SimpleNamespace(access=Mock(side_effect=lambda sd,desired:w.READ if desired==w.READ else 0),close=Mock())
        uac=SimpleNamespace(read=lambda:w.gate1_contract_template()['uac']['expected_before'],harden=forbidden)
        with patch.object(n,'NativeBindings',return_value=b),patch.object(n,'NativeFiles',return_value=files),\
             patch.object(n,'held_security_descriptor',side_effect=lambda files,handle:nullcontext(10)),\
             patch.object(n,'BuilderAuthz',return_value=authz),patch.object(n,'NativeScheduler',return_value=scheduler),\
             patch.object(n,'NativeUac',return_value=uac),patch.object(n,'run_native_gate',forbidden),\
             patch.object(n.c,'WinDLL',side_effect=AssertionError('REAL_DLL_FORBIDDEN')):
            result=p.run_preflight()
        self.assertEqual(result['READ_ONLY_HOST_PREFLIGHT'],'PASS',result)
        self.assertEqual(result['HUMAN_GATE_1_AUTHORIZED'],'NO')
        self.assertNotIn('synthetic',repr(result))
        forbidden.assert_not_called();files.close.assert_called_once();authz.close.assert_called_once();folder.close.assert_called_once()
        self.assertEqual(advapi.AccessCheck.call_count,2)
        self.assertEqual(authz.access.call_count,2)
        self.assertEqual(kernel.CloseHandle.call_count,2)
        self.assertEqual(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_count,2)

    def test_partial_unknown_cleanup_failure_never_pass(self):
        for mode in ('partial','unknown_abi','cleanup','api_failure'):
            with self.subTest(mode=mode):
                probe=SimpleNamespace(**{category.lower():Mock(return_value=True) for category in p.CATEGORIES},close=Mock())
                if mode=='partial':probe.netapi_read.return_value=None
                if mode=='unknown_abi':probe.dll_abi.return_value='unknown'
                if mode=='cleanup':probe.close.side_effect=RuntimeError('private-provider-detail')
                if mode=='api_failure':probe.authz_accesscheck.side_effect=RuntimeError('private-provider-detail')
                with patch.object(p,'ReadOnlyHostProbe',return_value=probe):result=p.run_preflight()
                self.assertNotEqual(result['READ_ONLY_HOST_PREFLIGHT'],'PASS')
                self.assertNotIn('private-provider-detail',repr(result))
                if mode=='unknown_abi':probe.token_read.assert_not_called()

    def test_cli_no_bypass_selector_or_abbreviation(self):
        for argv in ([],['--read'],['--read-only','--force'],['--read-only','--backend','fake'],['--phase1b']):
            with self.subTest(argv=argv),patch('sys.stderr',new=io.StringIO()),patch.object(p,'run_preflight') as run:
                with self.assertRaises(SystemExit):p.main(argv)
                run.assert_not_called()


class AdditionalPreflightAbiTests(unittest.TestCase):
    def test_console_read_only_abi_and_nonconsole_not_verified(self):
        for console in (True,False):
            with self.subTest(console=console):
                kernel=Mock();kernel.GetStdHandle.return_value=12;kernel.GetConsoleMode.return_value=console
                probe=p.ReadOnlyHostProbe();probe.bindings=SimpleNamespace(kernel=kernel)
                self.assertIs(probe.console_abi(),True if console else None)
                kernel.SetConsoleMode.assert_not_called();kernel.ReadConsoleInputW.assert_not_called()
                kernel.CloseHandle.assert_not_called()

    def test_accesscheck_probe_failure_is_not_denial_or_pass_and_handles_close(self):
        for fail in ('api','malformed','close'):
            with self.subTest(fail=fail):
                b=synthetic_token_bindings({'S-1-5-4':7},HUMAN)
                def open_token(handle,access,out):c.cast(out,c.POINTER(n.t.HANDLE))[0]=21;return 1
                def duplicate(handle,level,out):c.cast(out,c.POINTER(n.t.HANDLE))[0]=22;return 1
                b.advapi.OpenProcessToken.side_effect=open_token;b.advapi.DuplicateToken.side_effect=duplicate
                def sd(text,revision,out,length):c.cast(out,c.POINTER(c.c_void_p))[0]=33;return 1
                b.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect=sd
                b.kernel.LocalFree.return_value=None
                def check(sd,token,desired,mapping,privileges,size,granted,status):
                    c.cast(size,c.POINTER(n.t.DWORD))[0]=8
                    c.cast(granted,c.POINTER(n.t.DWORD))[0]=w.READ if desired==w.READ else 0
                    c.cast(status,c.POINTER(n.t.BOOL))[0]=int(desired==w.READ)
                    return fail!='api'
                b.advapi.AccessCheck.side_effect=check
                if fail=='malformed':
                    original=b.advapi.GetTokenInformation.side_effect
                    def info(handle,kind,out,size,needed):
                        result=original(handle,kind,out,size,needed)
                        if kind==2 and out is not None:c.c_uint32.from_buffer(out).value=513
                        return result
                    b.advapi.GetTokenInformation.side_effect=info
                if fail=='close':b.kernel.CloseHandle.return_value=0
                probe=p.ReadOnlyHostProbe();probe.bindings=b
                with self.assertRaises((n.NativeError,w.AdmissionError)):probe.accesscheck_abi()
                self.assertEqual(b.kernel.CloseHandle.call_count,2)
