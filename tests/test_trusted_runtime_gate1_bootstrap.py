"""Synthetic Gate 1 model tests: no Windows mutation backend is instantiated."""
from contextlib import redirect_stdout
from dataclasses import replace
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import pickle
import sys
import unittest
from unittest.mock import patch

from tests.test_trusted_runtime_windows import w, build, provenance, BUILDER, RUNTIME

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('gate1_bootstrap_fixture',
    ROOT / 'tools/windows/trusted_runtime_gate1_bootstrap.py')
g = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = g
_spec.loader.exec_module(g)
HUMAN = 'S-1-5-21-1-2-3-1001'


def checkpoint():
    return w.BuilderCheckpoint(True, 'ASFBuilder', BUILDER, True, False,
        r'C:\Users\ASFBuilder', True, BUILDER, True, True,
        r'C:\Users\ASFBuilder\workspace', BUILDER, True, False, frozenset(), False, True, True)


def admission():
    raw = (ROOT / 'tools/windows/gate1_contract.json').read_bytes()
    proof = provenance()
    proof.update(published_sha256=w.GATE1_PYTHON_SHA256, calculated_sha256=w.GATE1_PYTHON_SHA256)
    return g.AdmissionSnapshot(
        human_gate_approved=True, phase1a=checkpoint(), current_sid=HUMAN, human_admin_sid=HUMAN,
        elevated=True, administrator=True, agents_absent=True,
        script_path=r'C:\Program Files\GateStaging\trusted_runtime_gate1_bootstrap.py',
        staging_root=r'C:\Program Files\GateStaging', staging_protected=True,
        staging_reparse=False, script_reparse=False, script_bytes=b'synthetic-reviewed-script',
        approved_script_sha256=g.sha(b'synthetic-reviewed-script'),
        contract_path=r'C:\Program Files\GateStaging\gate1_contract.json',
        contract_protected=True, contract_reparse=False, contract_bytes=raw,
        approved_contract_sha256=g.sha(raw), source_commit_sha='a'*40, source_tree_sha='b'*40,
        source_independently_verified=True, receipt_exists=False, runtime_account_exists=False,
        roots_present=(), task_exists=False, task_folder_exists=False, filesystem='NTFS',
        ancestors_reparse=False, python_protected=True, python_version='3.14.10',
        python_architecture='amd64', python_executable=r'C:\Program Files\GateStaging\python\python.exe',
        python_executable_sha256='c'*64, approved_python_executable_sha256='c'*64,
        python_tree_digest='d'*64, approved_python_tree_digest='d'*64,
        python_provenance=proof, manifest=json.loads(build(proof=proof)),
        manifest_independently_verified=True, network_allowed=False, antivirus_bypass=False,
        launch_audit=dict.fromkeys(w.LAUNCH_SIGNALS, 'VERIFIED_CLEAR'),
        uac=w.gate1_contract_template()['uac']['expected_before'])


class FakePort:
    """In-memory side effects only. No native API or filesystem writes."""
    def __init__(self, observation=None, fail=None):
        self.snapshot = admission() if observation is None else observation
        self.fail = fail
        self.calls = []
        self.effects = []
        self.rights = frozenset()
        self.buffer = None
        self.uac = dict(self.snapshot.uac)

    def call(self, name, mutation=False):
        self.calls.append(name)
        if mutation:
            self.effects.append(name)  # failures may happen AFTER a side effect
        if self.fail == name:
            raise RuntimeError('SYNTHETIC_SECRET https://provider.invalid/private raw provider body')

    def observe_admission(self):
        self.call('observe')
        return copy.deepcopy(self.snapshot)

    def new_transient_credential(self):
        self.call('credential')
        self.buffer = bytearray(b'SYNTHETIC_SECRET_NOT_A_CREDENTIAL' * 2)
        return g.TransientCredential(self.buffer)

    def create_standard_account(self, name, credential):
        assert name == 'ASFTrustedRuntime' and type(credential) is g.TransientCredential
        self.call('account', True)

    def resolve_runtime_sid(self):
        self.call('sid')
        return RUNTIME

    def read_runtime_account(self):
        self.call('account_readback')
        return dict(name='ASFTrustedRuntime', sid=RUNTIME, enabled=True,
                    administrator=False, groups=('S-1-5-32-545',))

    def read_lsa_rights(self, sid):
        assert sid == RUNTIME
        self.call('lsa_readback')
        return self.rights, self.rights | {'SeChangeNotifyPrivilege'}

    def add_lsa_right(self, sid, right):
        assert sid == RUNTIME and right == 'SeBatchLogonRight'
        self.call('lsa_add', True)
        self.rights = frozenset({right})

    def create_protected_roots(self, roots, descriptors):
        assert set(roots) == set(descriptors)
        self.call('roots', True)

    def apply_descriptors(self, roots, descriptors):
        self.call('acls', True)
        self.descriptors = copy.deepcopy(descriptors)

    def read_descriptors(self, roots):
        self.call('acl_readback')
        return copy.deepcopy(self.descriptors)

    def materialize_admitted_files(self, manifest):
        self.call('files', True)
        self.files = {f['relative_path']: (f['size'], f['sha256']) for f in manifest['files']}

    def read_runtime_files(self):
        self.call('file_readback')
        return copy.deepcopy(self.files)

    def register_disabled_password_task(self, task, credential):
        assert type(credential) is g.TransientCredential
        self.call('task', True)
        self.task = copy.deepcopy(task)

    def read_task(self):
        self.call('task_readback')
        return copy.deepcopy(self.task)

    def read_uac(self):
        self.call('uac_readback')
        return dict(self.uac)

    def set_consent_prompt_behavior_user(self, *, expected, target):
        assert expected == 3 and target == 0 and self.uac['ConsentPromptBehaviorUser'] == expected
        self.call('uac', True)
        self.uac['ConsentPromptBehaviorUser'] = target

    def write_protected_receipt_exclusive(self, receipt):
        self.call('receipt', True)
        assert not hasattr(self, 'receipt')
        self.receipt = copy.deepcopy(receipt)

    def read_receipt(self):
        self.call('receipt_readback')
        return copy.deepcopy(self.receipt)


class ContractTests(unittest.TestCase):
    def test_committed_contract_matches_closed_template(self):
        w.validate_gate1_contract(json.loads((ROOT/'tools/windows/gate1_contract.json').read_bytes()))

    def test_unknown_missing_and_wrong_types_rejected_at_every_level(self):
        template = w.gate1_contract_template()
        paths = [()] + [(k,) for k, v in template.items() if type(v) is dict] + [('uac', 'expected_before')]
        for path in paths:
            for operation in ('extra', 'missing'):
                c = copy.deepcopy(template); node = c
                for k in path: node = node[k]
                if operation == 'extra': node['unexpected'] = True
                else: del node[next(iter(node))]
                with self.subTest(path=path, operation=operation), self.assertRaises(w.AdmissionError):
                    w.validate_gate1_contract(c)
        c = copy.deepcopy(template); c['receipt']['generation'] = True
        with self.assertRaises(w.AdmissionError): w.validate_gate1_contract(c)

    def test_canonical_captures_path(self):
        c = w.gate1_contract_template()
        self.assertEqual(c['phase1b']['captures_root'], r'C:\ProgramData\AISOFTWAREFACTORY\Authority\Captures')
        c['phase1b']['captures_root'] = r'C:\ProgramData\AISOFTWAREFACTORY\Captures'
        with self.assertRaises(w.AdmissionError): w.validate_gate1_contract(c)

    def test_exact_python_filename_no_alias_or_normalization(self):
        s = admission()
        g.admit(s)
        c = w.gate1_contract_template()
        c['python']['artifact_filename'] = 'python-3.14.10-embeddable-amd64.zip'
        with self.assertRaises(w.AdmissionError): w.validate_gate1_contract(c)
        p = dict(s.python_provenance, artifact_filename='python-3.14.10-embeddable-amd64.zip')
        with self.assertRaises(w.AdmissionError): g.admit(replace(s, python_provenance=p))

    def test_duplicate_json_rejected(self):
        with self.assertRaises(w.AdmissionError): w.strict_json(b'{"generation":1,"generation":1}')


class Phase1ATests(unittest.TestCase):
    def test_valid_checkpoint_is_data_not_authority(self):
        self.assertEqual(w.validate_builder_checkpoint(checkpoint()), 'PHASE1A_CHECKPOINT_CONSISTENT_NOT_AUTHORIZED')

    def test_identity_and_admin_rejected(self):
        for change in ({'exists': False}, {'administrator': True}, {'enabled': False},
                       {'account_name': 'anapo'}, {'account_sid': 'invalid'}):
            with self.subTest(change=change), self.assertRaises(w.AdmissionError):
                w.validate_builder_checkpoint(replace(checkpoint(), **change))

    def test_actual_session_switch_required(self):
        for change in ({'interactive_sid': HUMAN}, {'interactive_session': False}, {'session_switched': False}):
            with self.subTest(change=change), self.assertRaises(w.AdmissionError):
                w.validate_builder_checkpoint(replace(checkpoint(), **change))

    def test_shared_workspace_rejected(self):
        for change in ({'workspace': r'C:\Users\anapo\workspace'}, {'runtime_writable': True},
                       {'other_nonadmin_writers': frozenset({HUMAN})}, {'workspace_owner_sid': HUMAN},
                       {'builder_writable': False}, {'ancestors_reparse': True}, {'profile_exists': False},
                       {'workspace': r'C:\Users\ASFBuilderX\workspace'}):
            with self.subTest(change=change), self.assertRaises(w.AdmissionError):
                w.validate_builder_checkpoint(replace(checkpoint(), **change))

    def test_builder_tooling_unavailable_stops(self):
        for name in ('codex_available', 'git_available'):
            with self.subTest(name=name), self.assertRaisesRegex(w.AdmissionError, 'BUILDER_TOOLING_NOT_AVAILABLE'):
                w.validate_builder_checkpoint(replace(checkpoint(), **{name: False}))


class AdmissionTests(unittest.TestCase):
    def reject(self, **change):
        p = FakePort(replace(admission(), **change))
        result = g.run_sequence(p)
        self.assertEqual(result.status, 'ADMISSION_REJECTED_NO_MUTATION')
        self.assertEqual(p.effects, [])
        self.assertEqual(p.calls, ['observe'])

    def test_non_elevated_and_wrong_identity(self):
        for change in ({'elevated': False}, {'current_sid': BUILDER}, {'current_sid': RUNTIME},
                       {'administrator': False}, {'agents_absent': False}, {'human_gate_approved': False}):
            with self.subTest(change=change): self.reject(**change)

    def test_wrong_staging_and_reparse(self):
        for change in ({'script_path': r'C:\Users\anapo\script.py'}, {'staging_protected': False},
                       {'staging_reparse': True}, {'script_reparse': True}, {'contract_reparse': True},
                       {'contract_protected': False}, {'ancestors_reparse': True}, {'filesystem': 'FAT32'}):
            with self.subTest(change=change): self.reject(**change)

    def test_approved_hash_mismatch(self):
        for change in ({'approved_script_sha256': 'e'*64}, {'approved_contract_sha256': 'e'*64}):
            with self.subTest(change=change): self.reject(**change)

    def test_existing_accounts_roots_tasks_receipt(self):
        for change in ({'runtime_account_exists': True}, {'roots_present': ('authority',)},
                       {'task_exists': True}, {'task_folder_exists': True}, {'receipt_exists': True}):
            with self.subTest(change=change): self.reject(**change)

    def test_source_and_manifest_binding(self):
        for change in ({'source_commit_sha': ''}, {'source_tree_sha': ''},
                       {'source_independently_verified': False}, {'source_commit_sha': 'c'*40},
                       {'manifest_independently_verified': False}):
            with self.subTest(change=change): self.reject(**change)

    def test_python_version_protection_and_hashes(self):
        for change in ({'python_version': '3.14.4'}, {'python_architecture': 'x86'},
                       {'python_protected': False}, {'python_executable_sha256': 'e'*64},
                       {'python_tree_digest': 'e'*64},
                       {'python_executable': r'C:\Users\anapo\python.exe'}):
            with self.subTest(change=change): self.reject(**change)

    def test_wrong_artifact_hash_and_sigstore_absence(self):
        for change in ({'published_sha256': 'e'*64, 'calculated_sha256': 'e'*64},
                       {'sigstore_verified': False}, {'independent_verifier_verified': False}):
            with self.subTest(change=change):
                self.reject(python_provenance=dict(admission().python_provenance, **change))

    def test_network_antivirus_and_launch_unknown(self):
        for change in ({'network_allowed': True}, {'antivirus_bypass': True}, {'launch_audit': {}}):
            with self.subTest(change=change): self.reject(**change)

    def test_initial_uac_exact(self):
        for key in admission().uac:
            uac = dict(admission().uac); uac[key] = 0
            with self.subTest(key=key): self.reject(uac=uac)

    def test_readmission_before_first_mutation(self):
        p = FakePort(); original = p.observe_admission; count = 0
        def observe():
            nonlocal count
            count += 1
            s = original()
            return replace(s, task_exists=True) if count == 2 else s
        p.observe_admission = observe
        result = g.run_sequence(p)
        self.assertFalse(result.mutation_attempted)
        self.assertEqual(p.effects, [])
        self.assertFalse(any(p.buffer))


class SequenceTests(unittest.TestCase):
    def test_mutation_order_and_all_readbacks(self):
        p = FakePort(); result = g.run_sequence(p)
        self.assertEqual(result.completed_steps, g.STEPS)
        self.assertFalse(result.director_recovery_required)
        self.assertEqual(p.calls, ['observe', 'credential', 'observe', 'account', 'sid',
            'account_readback', 'lsa_readback', 'lsa_add', 'lsa_readback', 'roots', 'acls',
            'acl_readback', 'files', 'file_readback', 'task', 'task_readback', 'uac_readback',
            'uac', 'uac_readback', 'receipt', 'receipt_readback', 'file_readback', 'uac_readback',
            'task_readback', 'acl_readback', 'account_readback', 'lsa_readback'])

    def test_lsa_only_batch_and_dangerous_rights_rejected(self):
        for bad in ('SeServiceLogonRight', 'SeDebugPrivilege', 'SeTcbPrivilege',
                    'SeAssignPrimaryTokenPrivilege', 'SeDenyBatchLogonRight', 'SeImpersonatePrivilege'):
            with self.subTest(right=bad):
                p = FakePort(); p.rights = frozenset({bad})
                result = g.run_sequence(p)
                self.assertTrue(result.director_recovery_required)
                self.assertNotIn('lsa_add', p.effects)
        p = FakePort(); g.run_sequence(p)
        self.assertEqual(p.rights, frozenset({'SeBatchLogonRight'}))

    def test_unexpected_account_membership_stops(self):
        p = FakePort()
        p.read_runtime_account = lambda: dict(name='ASFTrustedRuntime', sid=RUNTIME,
            enabled=True, administrator=True, groups=('S-1-5-32-544',))
        result = g.run_sequence(p)
        self.assertEqual(result.attempted_step, 'VERIFY_STANDARD_ACCOUNT')
        self.assertEqual(p.effects, ['account'])

    def test_scheduler_disabled_contract(self):
        p = FakePort(); g.run_sequence(p)
        self.assertFalse(p.task['enabled']); self.assertFalse(p.task['allow_demand_start'])
        self.assertFalse(p.task['interactive'])
        self.assertEqual(p.task['logon_type'], 'TASK_LOGON_PASSWORD')
        self.assertEqual(p.task['run_level'], 'LeastPrivilege')
        self.assertEqual(p.task['execution_time_limit_seconds'], 50)
        self.assertEqual(p.task['multiple_instances_policy'], 'IgnoreNew')

    def test_task_mismatch_prevents_uac(self):
        p = FakePort(); original = p.read_task
        p.read_task = lambda: dict(original(), enabled=True)
        result = g.run_sequence(p)
        self.assertEqual(result.attempted_step, 'VERIFY_TASK')
        self.assertNotIn('uac', p.effects)

    def test_uac_changes_only_standard_user_and_late(self):
        p = FakePort(); g.run_sequence(p)
        self.assertEqual(p.uac, dict(admission().uac, ConsentPromptBehaviorUser=0))
        self.assertLess(p.calls.index('task_readback'), p.calls.index('uac'))
        self.assertLess(p.calls.index('uac'), p.calls.index('receipt'))

    def test_uac_drift_before_write_stops(self):
        p = FakePort(); p.uac['ConsentPromptBehaviorUser'] = 1
        result = g.run_sequence(p)
        self.assertEqual(result.attempted_step, 'SET_STANDARD_USER_UAC')
        self.assertNotIn('uac', p.effects)

    def test_partial_failure_no_rollback_retry_or_secret(self):
        for failure in ('account', 'sid', 'lsa_add', 'roots', 'acls', 'files',
                        'task', 'task_readback', 'uac', 'receipt', 'receipt_readback'):
            with self.subTest(failure=failure):
                p = FakePort(fail=failure)
                output = io.StringIO()
                with redirect_stdout(output): result = g.run_sequence(p)
                self.assertTrue(result.director_recovery_required)
                self.assertTrue(result.mutation_attempted)
                self.assertEqual(p.calls.count(failure), 1)
                self.assertFalse(any(p.buffer))
                self.assertNotIn('SYNTHETIC_SECRET', repr(result))
                self.assertNotIn('provider.invalid', repr(result))
                self.assertEqual(output.getvalue(), '')
                self.assertFalse(any('delete' in x or 'rollback' in x for x in p.calls))

    def test_secret_buffer_cleared_and_not_serializable(self):
        b = bytearray(b'x'*32); secret = g.TransientCredential(b)
        self.assertNotIn('xxxx', repr(secret))
        with self.assertRaises(TypeError): pickle.dumps(secret)
        secret.clear(); self.assertEqual(b, bytearray(32))
        p = FakePort(); g.run_sequence(p)
        self.assertFalse(any(p.buffer))
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(p.receipt))
        self.assertNotIn('credential', json.dumps(p.receipt))

    def test_receipt_bound_to_exact_inputs_and_generation(self):
        p = FakePort(); g.run_sequence(p); r = p.receipt
        self.assertEqual(r['generation'], 1)
        self.assertEqual(r['gate1_contract_sha256'], p.snapshot.approved_contract_sha256)
        self.assertEqual(r['bootstrap_sha256'], p.snapshot.approved_script_sha256)
        self.assertEqual(r['python_artifact_sha256'], w.GATE1_PYTHON_SHA256)
        self.assertEqual(r['source_commit_sha'], p.snapshot.source_commit_sha)
        self.assertEqual(r['source_tree_sha'], p.snapshot.source_tree_sha)
        self.assertEqual(r['builder_sid'], BUILDER); self.assertEqual(r['trusted_runtime_sid'], RUNTIME)
        self.assertEqual(len(r['installation_id']), 32)
        self.assertIn('PENDING_FINAL_READBACK', r['final_status'])

    def test_acl_readback_failure_stops_materialization(self):
        p = FakePort(); p.read_descriptors = lambda roots: {}
        result = g.run_sequence(p)
        self.assertEqual(result.attempted_step, 'VERIFY_DACLS')
        self.assertNotIn('files', p.effects)

    def test_file_readback_failure_stops_registration(self):
        p = FakePort(); p.read_runtime_files = lambda: {}
        result = g.run_sequence(p)
        self.assertEqual(result.attempted_step, 'VERIFY_FILES')
        self.assertNotIn('task', p.effects)


class CliSafetyTests(unittest.TestCase):
    def test_phase1b_has_no_backend_or_authority_injection(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(g.main(['--phase1b']), 2)
        self.assertIn('HUMAN_GATE_NOT_AUTHORIZED', output.getvalue())

    def test_plan_and_preflight_only_return_data(self):
        for mode in ('--preflight', '--plan'):
            with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(g.main([mode]), 0)
            data = json.loads(output.getvalue())
            self.assertFalse(data['human_gate_authorized'])
            self.assertEqual(data['host_admission'], 'NOT_PERFORMED')

    def test_no_fallback_imports_or_destructive_methods(self):
        import ast
        tree = ast.parse((ROOT/'tools/windows/trusted_runtime_gate1_bootstrap.py').read_text())
        imported = {alias.name.split('.')[0] for node in ast.walk(tree)
                    if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse(imported & {'subprocess', 'socket', 'requests', 'urllib'})
        called = {node.func.attr for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(called & {'system', 'remove', 'rmdir', 'unlink', 'Run', 'Delete',
                                  'CryptProtectData', 'CryptUnprotectData'})
