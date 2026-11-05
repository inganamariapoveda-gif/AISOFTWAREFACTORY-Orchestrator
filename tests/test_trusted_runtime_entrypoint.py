import ast
from contextlib import redirect_stdout
import inspect
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT/'src') not in sys.path:
    sys.path.insert(0, str(ROOT/'src'))
from orchestrator import trusted_runtime_entrypoint as entry
from orchestrator import trusted_runtime_windows as w

POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


class EntrypointTests(unittest.TestCase):
    def test_no_public_injection_or_roots(self):
        self.assertEqual(list(inspect.signature(entry.main).parameters), [])
        for kwargs in ({'io': object()}, {'root': 'C:\\repo'}):
            with self.assertRaises(TypeError): entry.main(**kwargs)

    def test_operational_and_arbitrary_argv_never_observe_or_open_store(self):
        for args in ([], ['--operational'], ['--preflight', 'C:\\repo'], ['--io=fake']):
            with self.subTest(args=args), mock.patch.object(sys, 'argv', ['entry']+args), \
                    mock.patch.object(entry, 'WindowsFileIO') as capture, \
                    mock.patch.object(entry, 'WindowsTaskScheduler') as scheduler, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(entry.main(), 2)
                self.assertEqual(output.getvalue().strip(), 'BLOCKED_REAL_MUTATION_NOT_IMPLEMENTED')
                capture.assert_not_called(); scheduler.assert_not_called()

    def test_observation_failure_sanitized(self):
        with mock.patch.object(sys, 'argv', ['entry', '--preflight']), \
                mock.patch.object(entry, 'WindowsFileIO'), \
                mock.patch.object(entry, 'WindowsTaskScheduler') as scheduler, redirect_stdout(io.StringIO()) as output:
            scheduler.return_value.observe.side_effect = w.AdmissionError('sensitive-provider-data')
            self.assertEqual(entry.main(), 2)
            self.assertNotIn('sensitive', output.getvalue())

    def test_successful_observation_still_never_processes_inbox(self):
        with mock.patch.object(sys, 'argv', ['entry', '--dry-run']), \
                mock.patch.object(entry, 'WindowsFileIO') as capture, \
                mock.patch.object(entry, 'WindowsTaskScheduler') as scheduler, redirect_stdout(io.StringIO()) as output:
            scheduler.return_value.observe.return_value = {'exists': True}
            self.assertEqual(entry.main(), 2)
            capture.return_value.open_read.assert_not_called()
            self.assertIn('NOT_AUTHORIZED', output.getvalue())

    def test_production_imports_have_no_forbidden_facilities(self):
        forbidden = {'subprocess', 'socket', 'requests', 'http', 'yaml', 'config_loader',
                     'task_packet', 'app', 'adapters', 'importlib'}
        for path in ('trusted_runtime_entrypoint.py', 'trusted_runtime_windows.py'):
            tree = ast.parse((ROOT/'src/orchestrator'/path).read_text())
            for node in ast.walk(tree):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                        [node.module or ''] if isinstance(node, ast.ImportFrom) else []
                self.assertFalse(any(set(n.split('.')) & forbidden for n in names))
                if isinstance(node, ast.Call):
                    self.assertNotIn(ast.unparse(node.func), ('eval', 'exec', '__import__', 'os.system'))

    def test_import_closure_in_clean_synthetic_process(self):
        # Test harness only. Production entrypoint never starts a process.
        code = """
import sys
sys.path.insert(0, 'src')
from orchestrator import trusted_runtime_entrypoint, store
from unittest import mock
with mock.patch.object(trusted_runtime_entrypoint, 'WindowsFileIO'), mock.patch.object(trusted_runtime_entrypoint, 'WindowsTaskScheduler') as scheduler:
    scheduler.return_value.observe.return_value = {'exists': True}
    sys.argv = ['entry', '--preflight']
    assert trusted_runtime_entrypoint.main() == 2
bad = ('orchestrator.config_loader', 'orchestrator.task_packet', 'yaml', 'orchestrator.app', 'orchestrator.adapters')
assert not any(n == b or n.startswith(b+'.') for n in sys.modules for b in bad)
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


class LifecycleTests(unittest.TestCase):
    def test_active_suffix_and_closed_names(self):
        self.assertTrue(w.active_candidate('r_123.request'))
        for name in ('r.txt', 'r.request.processed.'+'a'*32, '../r.request', 'a:b.request', 'r.REQUEST'):
            self.assertFalse(w.active_candidate(name))

    def test_retirement_requires_terminal_and_same_object(self):
        for phase in ('CAPTURED', 'OPENED', 'COPIED'):
            with self.assertRaisesRegex(w.AdmissionError, 'TERMINAL_EVIDENCE_REQUIRED'):
                w.retirement_plan('r.request', 'a'*32, phase, (1,2), (1,2))
        with self.assertRaisesRegex(w.AdmissionError, 'SOURCE_IDENTITY_CHANGED'):
            w.retirement_plan('r.request', 'a'*32, 'PARSED', (1,2), (1,3))

    def test_retirement_plan_never_deletes_evidence(self):
        for phase in ('PARSED', 'REJECTED'):
            p = w.retirement_plan('r.request', 'a'*32, phase, (1,2), (1,2))
            self.assertFalse(p['delete'])
            self.assertFalse(w.active_candidate(p['destination']))
            self.assertEqual(p['failure'], 'LIFECYCLE_FAILURE_EVIDENCE_PRESERVED')

    def test_retired_does_not_count_and_limits(self):
        names = ['r.request.processed.'+'a'*32]*100 + ['r%d.request'%i for i in range(100)]
        selected, examined = w.bounded_candidate_plan(names)
        self.assertEqual(len(selected), 8); self.assertEqual(examined, 64)


@unittest.skipUnless(Path(POWERSHELL).is_file(), 'Windows PowerShell not available')
class PowerShellDryRunTests(unittest.TestCase):
    def run_script(self, name, *args):
        return subprocess.run([POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-File',
            str(ROOT/'tools/windows'/name), *args], cwd=ROOT, capture_output=True, text=True, timeout=30)

    def test_bootstrap_default_rejects(self):
        r = self.run_script('bootstrap_trusted_runtime.ps1')
        self.assertEqual(r.returncode, 2)
        self.assertIn('BLOCKED_REAL_MUTATION_NOT_IMPLEMENTED', r.stdout)

    def test_bootstrap_preflight_template_rejected(self):
        r = self.run_script('bootstrap_trusted_runtime.ps1', '-Preflight', '-ManifestPath',
                            str(ROOT/'tools/windows/trusted_runtime_manifest.json'))
        self.assertEqual(r.returncode, 2)
        self.assertIn('NOT_INSTALLABLE_TEMPLATE', r.stdout)

    def test_conflicting_and_unknown_modes(self):
        for args in (('-Preflight', '-DryRun'), ('-Install',)):
            r = self.run_script('bootstrap_trusted_runtime.ps1', *args)
            self.assertNotEqual(r.returncode, 0)

    def test_probe_plan_has_policy_and_acl_split(self):
        r = self.run_script('probe_trusted_runtime.ps1', '-ProbePlan')
        self.assertEqual(r.returncode, 0, r.stderr)
        entries = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        names = {e['probe'] for e in entries}
        self.assertIn('task-policy-demand-disabled', names)
        self.assertIn('canary-task-DACL-Run-RunEx', names)
        self.assertTrue(all(e['mode'] == 'PLAN_ONLY_NOT_EXECUTED' for e in entries))

    def test_sanitized_input_failure(self):
        r = self.run_script('bootstrap_trusted_runtime.ps1', '-Preflight', '-ManifestPath', 'SECRET-MARKER-nonexistent')
        self.assertEqual(r.returncode, 2)
        self.assertNotIn('SECRET-MARKER', r.stdout+r.stderr)

    def test_powershell_contains_no_mutation_commands(self):
        for name in ('bootstrap_trusted_runtime.ps1', 'probe_trusted_runtime.ps1'):
            text = (ROOT/'tools/windows'/name).read_text()
            executable = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
            for forbidden in ('New-LocalUser', 'Set-Acl', 'Register-ScheduledTask', 'Set-ItemProperty',
                              'LsaAddAccountRights(', 'CryptProtectData(', 'Invoke-WebRequest', 'RunAs'):
                self.assertNotIn(forbidden, executable)


if __name__ == '__main__':
    unittest.main()
