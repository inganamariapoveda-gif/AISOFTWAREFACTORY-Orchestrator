"""Pure/fake-ABI coverage only. Never instantiate real NativeBindings here."""
import ctypes as c
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import pickle
import unittest
from unittest.mock import Mock

from tests.test_trusted_runtime_windows import w, BUILDER, RUNTIME, build
from orchestrator import trusted_runtime_windows_native as n

HUMAN = 'S-1-5-21-1-2-3-1001'


def authorization():
    return dict(schema_version='human-gate-authorization-v1', action='TRUSTED_RUNTIME_GATE1_PHASE1B',
        generation=1, machine_sid='S-1-5-21-1-2-3',
        volume_guid='\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\',
        human_admin_sid=HUMAN, human_confirmation_sha256=hashlib.sha256(b'0123456789ABCDEF0123456789ABCDEF').hexdigest(), builder_sid=BUILDER, builder_workspace_path=r'C:\Users\ASFBuilder\workspace', source_commit_sha='a'*40,
        source_tree_sha='b'*40, bootstrap_sha256='c'*64, native_backend_sha256='d'*64,
        validator_module_sha256='e'*64, contract_sha256='f'*64, manifest_sha256='a'*64,
        python_artifact_filename='python-3.14.10-embed-amd64.zip',
        python_artifact_sha256=w.GATE1_PYTHON_SHA256, python_runtime_tree_digest='b'*64,
        authorization_nonce='1'*64, issued_at_utc='2026-11-05T00:00:00Z',
        expires_at_utc='2026-11-06T00:00:00Z')


def auth():
    return n.HumanGateAuthorization.parse(w.canonical(authorization()),
                                        datetime(2026, 11, 5, 12, tzinfo=timezone.utc))


def descriptor(kind='authority'):
    d = w.expected_descriptor(kind, RUNTIME, BUILDER)
    return n.NativeDescriptor(d.owner, d.protected, True, False,
                              tuple(n.NativeAce(a.sid, a.mask, a.flags, 0) for a in d.aces))


class AuthorizationTests(unittest.TestCase):
    def test_closed_type_and_expiry(self):
        self.assertEqual(auth().action, 'TRUSTED_RUNTIME_GATE1_PHASE1B')
        for patch in ({'extra': True}, {'generation': True}, {'generation': 2},
                      {'action': 'OTHER'}, {'expires_at_utc': '2026-11-05T01:00:00Z'},
                      {'python_artifact_filename': 'python-3.14.10-embeddable-amd64.zip'},
                      {'python_artifact_sha256': '2'*64}):
            with self.subTest(patch=patch), self.assertRaises(w.AdmissionError):
                n.HumanGateAuthorization.parse(w.canonical(dict(authorization(), **patch)),
                    datetime(2026, 11, 5, 12, tzinfo=timezone.utc))

    def test_missing_expected_never_inferred(self):
        a = authorization(); del a['bootstrap_sha256']
        with self.assertRaises(w.AdmissionError):
            n.HumanGateAuthorization.parse(w.canonical(a), datetime.now(timezone.utc))

    def test_file_owner_and_writer_rules(self):
        good = n.NativeDescriptor(w.ADMIN, True, True, False,
            (n.NativeAce(w.ADMIN, w.FULL_ACCESS, 0, 0), n.NativeAce(w.SYSTEM, w.FULL_ACCESS, 0, 0)))
        n.admit_authorization_descriptor(good, HUMAN)
        for bad in (replace(good, owner=BUILDER), replace(good, null_dacl=True),
                    replace(good, dacl_present=False), replace(good, protected=False)):
            with self.subTest(bad=bad), self.assertRaises(w.AdmissionError):
                n.admit_authorization_descriptor(bad, HUMAN)
        for writer in (BUILDER, RUNTIME, *n.BROAD):
            with self.subTest(writer=writer), self.assertRaises(w.AdmissionError):
                n.admit_authorization_descriptor(replace(good, aces=good.aces+
                    (n.NativeAce(writer, w.WRITE, 0, 0),)), HUMAN)

    def test_token_independent_expected_identity(self):
        a = auth(); n.validate_token((HUMAN, True, True), a)
        for value in ((BUILDER, True, True), (HUMAN, False, True), (HUMAN, True, False)):
            with self.subTest(value=value), self.assertRaises(w.AdmissionError):
                n.validate_token(value, a)


class DescriptorTests(unittest.TestCase):
    def test_null_deny_unknown_and_inherited_ace_rejected(self):
        expected = w.expected_descriptor('authority', RUNTIME, BUILDER)
        good = descriptor(); n.admit_descriptor(good, expected)
        for bad in (replace(good, null_dacl=True), replace(good, aces=()),
                    replace(good, aces=(replace(good.aces[0], ace_type=1),)+good.aces[1:]),
                    replace(good, aces=(replace(good.aces[0], ace_type=17),)+good.aces[1:]),
                    replace(good, aces=(replace(good.aces[0], flags=0x13),)+good.aces[1:])):
            with self.subTest(bad=bad), self.assertRaises(w.AdmissionError):
                n.admit_descriptor(bad, expected)

    def test_no_propagate_exact(self):
        d = w.expected_descriptor('authority', RUNTIME, BUILDER)
        files = [a for a in d.aces if a.sid == RUNTIME and a.flags]
        self.assertEqual(len(files), 1); self.assertEqual(files[0].flags, 0x0d)
        self.assertIn('OINPIO', n.descriptor_sddl(d))

    def test_isolation_rejects_runtime_and_broad_writers(self):
        workspace = n.NativeDescriptor(BUILDER, True, True, False,
                                      (n.NativeAce(BUILDER, w.FULL_ACCESS, 3, 0),))
        n.validate_isolation(workspace, (descriptor(),), RUNTIME, BUILDER)
        for writer in (RUNTIME, *n.BROAD):
            bad = replace(workspace, aces=workspace.aces+(n.NativeAce(writer, w.WRITE, 3, 0),))
            with self.subTest(writer=writer), self.assertRaises(w.AdmissionError):
                n.validate_isolation(bad, (descriptor(),), RUNTIME, BUILDER)


class LsaTests(unittest.TestCase):
    def test_direct_only_batch(self):
        n.validate_direct_batch_rights(frozenset())
        n.validate_direct_batch_rights(frozenset({'SeBatchLogonRight'}), after=True)
        for right in ('SeDebugPrivilege', 'SeServiceLogonRight', 'SeTcbPrivilege',
                      'SeAssignPrimaryTokenPrivilege'):
            with self.subTest(right=right), self.assertRaises(w.AdmissionError):
                n.validate_direct_batch_rights(frozenset({right}), after=True)

    def test_no_invented_effective_right_allowlist(self):
        n.validate_group_batch_rights({n.USERS: frozenset({'SeInteractiveLogonRight'})})
        with self.assertRaises(w.AdmissionError):
            n.validate_group_batch_rights({n.USERS: frozenset({'SeDenyBatchLogonRight'})})


class CredentialTests(unittest.TestCase):
    def test_mutable_native_buffer_and_cleanup(self):
        api = Mock()
        def random(_algorithm, buffer, size, flags):
            self.assertEqual(flags, 2)
            for i in range(size): buffer[i] = i
            return 0
        api.BCryptGenRandom.side_effect = random
        secret = n.NativeCredential(api)
        self.assertIsInstance(secret.buffer, c.Array)
        self.assertEqual(c.sizeof(secret.buffer), 98)
        self.assertEqual(repr(secret), '<NativeCredential redacted>')
        with self.assertRaises(TypeError): pickle.dumps(secret)
        secret.clear(); self.assertFalse(any(secret.buffer))

    def test_random_failure_is_sanitized(self):
        api = Mock(); api.BCryptGenRandom.return_value = -1
        with self.assertRaises(n.NativeError) as context: n.NativeCredential(api)
        self.assertEqual(context.exception.operation, 'CREDENTIAL_RANDOM')


class SchedulerReceiptTests(unittest.TestCase):
    def test_registration_xml_uses_existing_observer(self):
        start = '2026-11-05T12:00:00Z'
        expected = n.expected_task(RUNTIME, BUILDER, start)
        observed = w.task_observation(n.task_xml(RUNTIME, start), False,
                                     expected['task_sd'], expected['folder_sd'])
        w.compare_task(observed, expected)
        self.assertEqual(observed['interval'], 'PT1M')
        self.assertEqual(observed['execution_limit'], 'PT50S')
        self.assertEqual(observed['logon_type'], 'Password')
        for key, bad in (('enabled', True), ('demand_start', 'true'), ('principal_sid', BUILDER),
                         ('run_level', 'HighestAvailable'), ('interval', 'PT2M'),
                         ('executable', 'other.exe'), ('arguments', 'other'), ('task_sd', 'other')):
            with self.subTest(key=key), self.assertRaises(w.AdmissionError):
                w.compare_task(dict(observed, **{key: bad}), expected)

    def test_final_receipt_accepted_by_existing_validator(self):
        a = auth(); task = n.expected_task(RUNTIME, BUILDER, a.issued_at_utc)
        receipt = n.final_receipt(a, json.loads(build()), RUNTIME, task,
            dict(machine_guid='synthetic-guid', windows_build='synthetic-build', volume_serial=42))
        self.assertIs(w.validate_receipt(receipt), receipt)
        self.assertEqual(set(receipt), set(w.RECEIPT_KEYS))
        self.assertFalse(any('password' in k or 'secret' in k for k in receipt if k != 'secrets_root'))


# These fixtures substitute native boundary components, not the coordinator or
# authorization parser. The production argv has no way to select this fixture.
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch
import copy
import os
from tests.test_trusted_runtime_windows import materials, provenance


class IntegratedFixture:
    def __init__(self, fail=None):
        self.fail = fail
        self.sys_override = {}
        self.events = []
        self.account_created = False
        self.groups = frozenset()
        self.rights = frozenset()
        self.task = None
        self.closed = False
        self.final_seen = False
        self.secret = None
        self.uac_values = copy.deepcopy(w.gate1_contract_template()['uac']['expected_before'])
        self.host = dict(machine_sid='S-1-5-21-1-2-3',
                        volume_guid=authorization()['volume_guid'], volume_serial=42,
                        filesystem='NTFS', machine_guid='synthetic-machine', windows_build='synthetic-build')
        proof = provenance(); proof.update(published_sha256=w.GATE1_PYTHON_SHA256,
                                           calculated_sha256=w.GATE1_PYTHON_SHA256)
        self.manifest = json.loads(build(proof=proof))
        material_bytes = {m.relative_path: m.content for m in materials()}
        self.data = {str(n.PureWindowsPath(n.STAGING)/p): raw for p, raw in material_bytes.items()}
        contract_raw = w.canonical(w.gate1_contract_template())
        manifest_raw = w.canonical(self.manifest)
        self.data[n.STAGING+r'\gate1_contract.json'] = contract_raw
        self.data[n.STAGING+r'\trusted_runtime_manifest.json'] = manifest_raw
        self.data[n.STAGING+r'\python-3.14.10-embed-amd64.zip'] = b'SYNTHETIC_OFFICIAL_ARTIFACT'
        a = authorization()
        a['issued_at_utc'] = '2026-11-05T00:00:00Z'
        a['contract_sha256'] = hashlib.sha256(contract_raw).hexdigest()
        a['manifest_sha256'] = hashlib.sha256(manifest_raw).hexdigest()
        a['bootstrap_sha256'] = hashlib.sha256(material_bytes['trusted_runtime_gate1_bootstrap.py']).hexdigest()
        a['validator_module_sha256'] = hashlib.sha256(material_bytes['app/orchestrator/trusted_runtime_windows.py']).hexdigest()
        a['native_backend_sha256'] = hashlib.sha256(material_bytes['app/orchestrator/trusted_runtime_windows_native.py']).hexdigest()
        a['python_runtime_tree_digest'] = n.tree_digest({f['relative_path']: (f['size'], f['sha256'])
                    for f in self.manifest['files'] if f['relative_path'].startswith('python/')})
        self.expected_authorization = a
        self.data[n.AUTHORIZATION_PATH] = w.canonical(a)
        self.dirs = {'C:\\', r'C:\Program Files', r'C:\ProgramData', r'C:\Users', n.PROGRAM_PARENT,
                     n.STAGING, r'C:\Users\ASFBuilder', a['builder_workspace_path']}
        for path in self.data:
            for parent in n.PureWindowsPath(path).parents:
                self.dirs.add(str(parent))
        self.directories = {}
        self.sd = {}
        admin_sd = n.NativeDescriptor(w.ADMIN, True, True, False,
            (n.NativeAce(w.ADMIN, w.FULL_ACCESS, 0, 0), n.NativeAce(w.SYSTEM, w.FULL_ACCESS, 0, 0)))
        for path in self.dirs | set(self.data): self.sd[path] = admin_sd
        for path in (r'C:\Users\ASFBuilder', a['builder_workspace_path']):
            self.sd[path] = n.NativeDescriptor(BUILDER, True, True, False,
                                               (n.NativeAce(BUILDER, w.FULL_ACCESS, 3, 0),))
        self.bcrypt = SimpleNamespace(BCryptGenRandom=self.random)
        self.bindings = SimpleNamespace(kernel=SimpleNamespace(), token=self.token, machine=lambda: dict(self.host),
            account=self.account, account_absent=lambda: not self.account_created,
            create_account=self.create_account, resolve_sid=lambda name: RUNTIME,
            ensure_users_membership=self.ensure_users, local_groups=lambda: dict.fromkeys(self.groups, 'Users'),
            direct_rights=self.direct_rights, grant_batch=self.grant_batch, bcrypt=self.bcrypt)
        self.files = SimpleNamespace(open=self.open, read=self.read, descriptor=lambda h:self.sd[h],
            absent=lambda path: path not in self.dirs and path not in self.data,
            inventory=self.inventory, directories=self.directories, close=self.close,
            create_directory=self.create_directory, inspect=lambda h,directory=False:0,
            copy_exclusive=self.copy_exclusive, write_exclusive=self.write_exclusive,
            descriptor_from_sddl=self.parse_sd)
        self.scheduler = SimpleNamespace(absent=lambda:self.task is None,
                                        register=self.register, observe=self.observe_task)
        self.uac = SimpleNamespace(read=lambda:dict(self.uac_values), harden=self.harden)

    def event(self, name):
        self.events.append(name)
        if name == self.fail:
            raise n.NativeError('FAKE_ONLY', 5, True)

    def random(self, algorithm, buffer, size, flags):
        self.event('random')
        for i in range(size): buffer[i] = i
        return 0

    def token(self):
        self.event('token')
        return HUMAN, True, True

    def account(self, name='ASFTrustedRuntime'):
        if name == 'ASFBuilder':
            return dict(sid=BUILDER, standard=True, enabled=True, groups=frozenset({n.USERS}))
        self.event('account_readback')
        return dict(sid=RUNTIME, standard=True, enabled=True, groups=self.groups)

    def create_account(self, credential):
        self.secret = credential
        self.event('account_create')
        self.account_created = True

    def ensure_users(self, sid):
        self.event('groups')
        self.groups = frozenset({n.USERS})

    def direct_rights(self, sid):
        return self.rights if sid == RUNTIME else frozenset({'SeInteractiveLogonRight'})

    def grant_batch(self, sid, groups):
        self.event('lsa')
        n.validate_direct_batch_rights(self.rights)
        self.rights = frozenset({'SeBatchLogonRight'})

    def open(self, path, directory=False, **kwargs):
        if directory:
            if path not in self.dirs: raise n.NativeError('FILE_OPEN', 3)
            self.directories[path] = path
        elif path not in self.data:
            raise n.NativeError('FILE_OPEN', 2)
        return path

    def read(self, handle, maximum=None):
        return self.data[handle]

    def inventory(self, path):
        rootpath = n.PureWindowsPath(path)
        result = {}
        for directory in self.dirs:
            if n.PureWindowsPath(directory) == rootpath or rootpath in n.PureWindowsPath(directory).parents:
                self.directories[directory] = directory
        for name in self.data:
            p = n.PureWindowsPath(name)
            if rootpath in p.parents: result[p.relative_to(rootpath).as_posix()] = name
        return result

    def convert(self, descriptor):
        return n.NativeDescriptor(descriptor.owner, descriptor.protected, True, False,
                                  tuple(n.NativeAce(a.sid,a.mask,a.flags,0) for a in descriptor.aces))

    def create_directory(self, path, descriptor):
        self.event('directory')
        if path in self.dirs: raise n.NativeError('DIRECTORY_CREATE', 183, True)
        self.dirs.add(path); self.directories[path] = path; self.sd[path] = self.convert(descriptor)
        return path

    def copy_exclusive(self, handle, destination, size, digest, descriptor):
        self.event('copy')
        raw = self.read(handle)
        w.require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, 'SOURCE_BYTES_MISMATCH')
        return self.write_exclusive(destination, raw, digest, descriptor)

    def write_exclusive(self, destination, raw, digest, descriptor):
        if destination == n.RECEIPT_PATH:
            self.event('receipt')
            if not self.final_seen: raise AssertionError('RECEIPT_BEFORE_FINAL_READBACK')
        if destination in self.data: raise n.NativeError('DESTINATION_CREATE', 80, True)
        self.data[destination] = raw; self.sd[destination] = self.convert(descriptor)
        return destination

    def register(self, runtime, builder, start, credential):
        self.event('register')
        if not any(credential.buffer): raise AssertionError('SECRET_CLEARED_TOO_EARLY')
        self.task = n.expected_task(runtime, builder, start)

    def observe_task(self):
        self.event('task_readback')
        return copy.deepcopy(self.task)

    def parse_sd(self, text):
        for kind in ('task', 'folder'):
            descriptor = w.expected_descriptor(kind, RUNTIME, BUILDER)
            if text == n.descriptor_sddl(descriptor): return self.convert(descriptor)
        raise w.AdmissionError('ACL_MISMATCH')

    def harden(self):
        self.event('uac')
        w.exact_data(self.uac_values, w.gate1_contract_template()['uac']['expected_before'])
        self.uac_values['ConsentPromptBehaviorUser'] = 0

    def close(self):
        self.closed = True
        return True

    def run(self):
        actual_read_pinned = n._read_pinned
        def pinned(files, handle, expected, maximum=64*1024*1024):
            if handle.endswith('python-3.14.10-embed-amd64.zip'):
                # Synthetic artifact oracle only. No real artifact is acquired.
                w.require(expected == w.GATE1_PYTHON_SHA256 and
                          self.data[handle] == b'SYNTHETIC_OFFICIAL_ARTIFACT', 'PYTHON_HASH_MISMATCH')
                return self.data[handle]
            return actual_read_pinned(files, handle, expected, maximum)
        fake_sys = SimpleNamespace(platform='win32', flags=SimpleNamespace(isolated=1,dont_write_bytecode=1,no_user_site=1),
            version_info=(3,14,10), executable=n.STAGING+r'\python\python.exe',
            argv=[n.STAGING+r'\trusted_runtime_gate1_bootstrap.py', '--phase1b'],
            path=[n.STAGING+r'\python', n.STAGING+r'\python\python314.zip', n.STAGING+r'\app'],
            modules={name: SimpleNamespace(__file__=n.STAGING+'\\'+path) for name,path in {
                'orchestrator':r'app\orchestrator\__init__.py',
                'orchestrator.trusted_runtime_windows':r'app\orchestrator\trusted_runtime_windows.py',
                'orchestrator.trusted_runtime_windows_native':r'app\orchestrator\trusted_runtime_windows_native.py'}.items()})
        for key, value in self.sys_override.items(): setattr(fake_sys, key, value)
        original_final = n.NativeGateBackend.final_readback
        def final(backend):
            self.event('final')
            original_final(backend)
            self.final_seen = True
        with ExitStack() as stack:
            for name, value in (('NativeBindings', lambda:self.bindings), ('NativeFiles', lambda b:self.files),
                ('NativeScheduler', lambda:self.scheduler), ('NativeUac', lambda:self.uac),
                ('ConsoleConfirmation', lambda kernel:SimpleNamespace(verify=lambda digest:self.event('confirmation'))),
                ('EffectiveAccess', lambda context,sid,credential:SimpleNamespace(verify=lambda roots:self.event('effective_access'),close=lambda:None)),
                ('sys', fake_sys), ('_read_pinned', pinned),
                ('datetime', SimpleNamespace(now=lambda tz:datetime(2026,11,5,12,tzinfo=timezone.utc)))):
                stack.enter_context(patch.object(n, name, value))
            stack.enter_context(patch.object(n.NativeGateBackend, 'final_readback', final))
            stack.enter_context(patch.dict(os.environ, {}, clear=True))
            return n.run_native_gate()


class ProductionIntegrationTests(unittest.TestCase):
    def test_real_coordinator_to_existing_receipt_schema(self):
        fixture = IntegratedFixture(); result = fixture.run()
        self.assertEqual(result['status'], 'TASK_REGISTERED_DISABLED', result)
        self.assertEqual(tuple(result['completed_steps']), n.PRODUCTION_STEPS)
        self.assertLess(fixture.events.index('final'), fixture.events.index('receipt'))
        receipt = w.strict_json(fixture.data[n.RECEIPT_PATH]); w.validate_receipt(receipt)
        self.assertEqual(receipt['bootstrap_result'], 'TASK_REGISTERED_DISABLED')
        activation = dict(installation_id=receipt['installation_id'], generation=1, mode='VALIDATION',
            valid_from_utc='2026-11-05T00:00:00Z', valid_until_utc='2026-11-06T00:00:00Z',
            expected_task_digest=receipt['task_definition_digest'], fixture_set_digest='e'*64)
        w.validate_activation(activation, receipt, hashlib.sha256(w.canonical(activation)).hexdigest(),
            receipt['task_definition_digest'], datetime(2026,11,5,12,tzinfo=timezone.utc))
        self.assertTrue(fixture.closed); self.assertFalse(any(fixture.secret.buffer))

    def test_authorization_and_import_failure_before_backend_construction(self):
        for failure in ('missing_auth', 'writable_auth', 'source_change', 'manifest_change', 'artifact_change'):
            with self.subTest(failure=failure):
                f = IntegratedFixture()
                if failure == 'missing_auth': del f.data[n.AUTHORIZATION_PATH]
                if failure == 'writable_auth':
                    d = f.sd[n.AUTHORIZATION_PATH]
                    f.sd[n.AUTHORIZATION_PATH] = replace(d, aces=d.aces+(n.NativeAce(BUILDER,w.WRITE,0,0),))
                path = {'source_change':n.STAGING+r'\app\orchestrator\trusted_runtime_windows_native.py',
                        'manifest_change':n.STAGING+r'\trusted_runtime_manifest.json',
                        'artifact_change':n.STAGING+r'\python-3.14.10-embed-amd64.zip'}.get(failure)
                if path: f.data[path] += b'changed'
                result = f.run()
                self.assertEqual(result['status'], 'ADMISSION_REJECTED')
                self.assertNotIn('BACKEND_CONSTRUCTION', result['completed_steps'])
                self.assertNotIn('account_create', f.events)
                self.assertTrue(f.closed)

    def test_existing_profile_and_root_block_before_mutation(self):
        for path in (n.PROFILE, w.ROOTS['runtime_root'], w.ROOTS['control_root'] if 'control_root' in w.ROOTS
                     else r'C:\ProgramData\AISOFTWAREFACTORY'):
            with self.subTest(path=path):
                f = IntegratedFixture(); f.dirs.add(path)
                result = f.run()
                self.assertEqual(result['status'], 'ADMISSION_REJECTED')
                self.assertNotIn('account_create', f.events)

    def test_failure_at_every_mutation_stage_preserves_state_and_cleans_secret(self):
        for stage in ('account_create', 'groups', 'lsa', 'directory', 'copy', 'register', 'task_readback', 'uac', 'final', 'receipt'):
            with self.subTest(stage=stage):
                f = IntegratedFixture(fail=stage); result = f.run()
                self.assertTrue(result['mutation_may_have_occurred'])
                self.assertTrue(result['director_recovery_required'])
                self.assertEqual(result['native_status'], 5)
                self.assertEqual(f.events.count(stage), 1)
                if f.secret: self.assertFalse(any(f.secret.buffer))
                self.assertTrue(f.closed)
                self.assertNotIn(n.RECEIPT_PATH, f.data)

    def test_failed_final_readback_never_creates_receipt(self):
        f = IntegratedFixture(fail='final'); result = f.run()
        self.assertEqual(result['stage'], 'FINAL_HOST_READBACK')
        self.assertNotIn('receipt', f.events)
        self.assertNotIn(n.RECEIPT_PATH, f.data)

    def test_no_context_or_observation_boolean_can_construct_backend(self):
        for value in (None, {'human_gate_approved':True}, {'approved_hash':'x'}):
            with self.subTest(value=value), self.assertRaises(w.AdmissionError):
                n.NativeGateBackend(value)

    def test_runtime_cannot_write_builder_workspace_after_sid_freeze(self):
        f = IntegratedFixture()
        workspace = f.expected_authorization['builder_workspace_path']
        original = f.create_account
        def create(credential):
            original(credential)
            d = f.sd[workspace]
            f.sd[workspace] = replace(d, aces=d.aces+(n.NativeAce(RUNTIME,w.WRITE,3,0),))
        f.bindings.create_account = create
        result = f.run()
        self.assertEqual(result['stage'], 'ROOTS_AND_ISOLATION_READBACK')
        self.assertNotIn('copy', f.events)
        self.assertNotIn(n.RECEIPT_PATH, f.data)

    def test_production_root_descriptor_consumes_no_propagate(self):
        f = IntegratedFixture(); result = f.run()
        self.assertEqual(result['status'], 'TASK_REGISTERED_DISABLED', result)
        sd = f.sd[w.ROOTS['authority_root']]
        self.assertEqual([a.flags for a in sd.aces if a.sid == RUNTIME and a.flags], [0x0D])


class AdditionalIntegrationTests(unittest.TestCase):
    def test_import_environment_rejects_before_backend(self):
        cases = [dict(flags=SimpleNamespace(isolated=0,dont_write_bytecode=1,no_user_site=1)),
                 dict(flags=SimpleNamespace(isolated=1,dont_write_bytecode=0,no_user_site=1)),
                 dict(path=[r'C:\DEV\repository']), dict(path=[r'C:\Users\test\site-packages']),
                 dict(path=[r'C:\Users\test\AppData\Local\Temp']),
                 dict(modules={'orchestrator.unapproved': SimpleNamespace(__file__='unapproved.py')})]
        for override in cases:
            with self.subTest(override=override):
                f = IntegratedFixture(); f.sys_override = override
                result = f.run()
                self.assertEqual(result['status'], 'ADMISSION_REJECTED')
                self.assertNotIn('BACKEND_CONSTRUCTION', result['completed_steps'])
                self.assertNotIn('account_create', f.events)

    def test_final_tree_rejects_extra_empty_directory_and_changed_directory_acl(self):
        for extra in (True, False):
            with self.subTest(extra=extra):
                f = IntegratedFixture()
                old = f.harden
                def harden():
                    old()
                    path = w.ROOTS['runtime_root'] + (r'\extra' if extra else r'\app')
                    f.dirs.add(path)
                    f.sd[path] = descriptor('runtime') if extra else descriptor('inbox')
                f.uac.harden = harden
                result = f.run()
                self.assertEqual(result['stage'], 'FINAL_HOST_READBACK')
                self.assertTrue(result['director_recovery_required'])
                self.assertNotIn(n.RECEIPT_PATH, f.data)

    def test_held_source_change_before_copy_fails_without_receipt(self):
        f = IntegratedFixture(); old = f.create_account
        def create(credential):
            old(credential)
            f.data[n.STAGING+r'\app\orchestrator\trusted_runtime_windows.py'] += b'changed'
        f.bindings.create_account = create
        result = f.run()
        self.assertEqual(result['stage'], 'MATERIALIZE')
        self.assertNotIn(n.RECEIPT_PATH, f.data)
        self.assertFalse(any(f.secret.buffer))

    def test_existing_account_and_unexpected_membership_fail_closed(self):
        f = IntegratedFixture(); f.account_created = True
        self.assertEqual(f.run()['status'], 'ADMISSION_REJECTED')
        f = IntegratedFixture(); f.groups = frozenset({w.ADMIN})
        result = f.run()
        self.assertEqual(result['stage'], 'ACCOUNT_READBACK')
        self.assertNotIn('groups', f.events)
        self.assertNotIn(n.RECEIPT_PATH, f.data)

    def test_cleanup_failure_cannot_report_success(self):
        f = IntegratedFixture(); f.files.close = lambda:False
        result = f.run()
        self.assertEqual(result['error_code'], 'RESOURCE_CLEANUP_FAILURE')
        self.assertTrue(result['director_recovery_required'])


class NativeAbiTests(unittest.TestCase):
    def test_account_create_uses_mutable_password_and_user_priv_user(self):
        api = Mock(); api.BCryptGenRandom.side_effect = lambda _, buf, size, flags:0
        secret = n.NativeCredential(api)
        b = object.__new__(n.NativeBindings)
        b.account_absent = lambda:True
        def add(server, level, pointer, error):
            info = c.cast(pointer, c.POINTER(n.USER_INFO_1)).contents
            self.assertIsNone(server); self.assertEqual(level, 1)
            self.assertEqual(info.privilege, 1)  # USER_PRIV_USER, not USER_PRIV_ADMIN (2)
            self.assertNotEqual(info.privilege, 2)
            self.assertEqual(info.flags, 0x10241)
            self.assertEqual(info.flags & 0x0200, 0x0200)  # UF_NORMAL_ACCOUNT
            self.assertEqual(info.flags & 0x10000, 0x10000)  # UF_DONT_EXPIRE_PASSWD
            self.assertEqual(info.flags & 0x0040, 0x0040)  # UF_PASSWD_CANT_CHANGE
            self.assertEqual(info.flags & 0x0002, 0)  # UF_ACCOUNTDISABLE absent
            self.assertEqual(info.flags & 0x0020, 0)  # UF_PASSWD_NOTREQD absent
            self.assertEqual(c.addressof(info.password.contents), c.addressof(secret.buffer))
            return 0
        b.net = SimpleNamespace(NetUserAdd=add)
        try: b.create_account(secret)
        finally: secret.clear()
        self.assertFalse(any(secret.buffer))

    def test_lsa_only_documented_no_rights_status_is_empty(self):
        from contextlib import nullcontext
        b = object.__new__(n.NativeBindings)
        b.lsa = lambda:nullcontext(1); b.sid_pointer = lambda sid:nullcontext(c.c_void_p(2))
        for status, translated, empty in ((0xc0000034,2,True),(0xc0000022,5,False),(0xc0000034,5,False)):
            with self.subTest(status=status, translated=translated):
                b.advapi = SimpleNamespace(LsaEnumerateAccountRights=lambda *args:status,
                    LsaNtStatusToWinError=lambda value:translated)
                if empty: self.assertEqual(b.direct_rights(RUNTIME), frozenset())
                else:
                    with self.assertRaises(n.NativeError): b.direct_rights(RUNTIME)

    def test_native_acl_parser_preserves_null_empty_deny_unknown_inherited(self):
        f = object.__new__(n.NativeFiles)
        def set_pointer(output, value): c.cast(output, c.POINTER(c.c_void_p))[0] = value
        for kind in ('null','empty',0,1,17):
            with self.subTest(kind=kind):
                acl = n.ACL_HEADER(); acl.count = 0 if kind in ('null','empty') else 1
                ace = c.create_string_buffer(24)
                if type(kind) is int:
                    n.ACE_HEADER.from_buffer(ace).kind = kind
                    n.ACE_HEADER.from_buffer(ace).flags = 0x10
                    n.ACE_HEADER.from_buffer(ace).size = 24
                    c.c_uint32.from_buffer(ace,4).value = w.WRITE
                def owner(sd, out, defaulted): set_pointer(out, 123); return 1
                def control(sd, out, revision): c.cast(out,c.POINTER(c.c_uint16))[0]=0x1000; return 1
                def dacl(sd, present, out, defaulted):
                    c.cast(present,c.POINTER(n.t.BOOL))[0]=1
                    set_pointer(out, None if kind=='null' else c.addressof(acl)); return 1
                def getace(sd, index, out): set_pointer(out,c.addressof(ace)); return 1
                f.b = SimpleNamespace(advapi=SimpleNamespace(GetSecurityDescriptorOwner=owner,
                    GetSecurityDescriptorControl=control,GetSecurityDescriptorDacl=dacl,GetAce=getace),
                    check=lambda value,*args:self.assertTrue(value),sid_string=lambda ptr:w.ADMIN)
                parsed = f.decode_descriptor(c.c_void_p(1))
                self.assertEqual(parsed.null_dacl,kind=='null')
                if type(kind) is int:
                    self.assertEqual(parsed.aces[0].ace_type,kind)
                    self.assertEqual(parsed.aces[0].flags,0x10)
                else: self.assertEqual(parsed.aces,())
                with self.assertRaises(w.AdmissionError):
                    n.admit_descriptor(parsed,w.expected_descriptor('runtime',RUNTIME,BUILDER))

    def test_com_bstr_zeroed_before_variant_clear_on_success_and_failure(self):
        for failure in (False,True):
            with self.subTest(failure=failure):
                buffers = []; secret_addresses = set(); cleared = []; freed_diagnostics = []
                def alloc(pointer, length):
                    buf = c.create_string_buffer(length*2+2)
                    c.memmove(buf,pointer,length*2); buffers.append(buf)
                    address = c.addressof(buf); secret_addresses.add(address); return address
                def clear(pointer):
                    value = c.cast(pointer,c.POINTER(w._Variant)).contents
                    if value.vt == 8 and value.pointer in secret_addresses:
                        self.assertEqual(c.string_at(value.pointer,96), b'\0'*96)
                        cleared.append(value.pointer)
                    return 0
                diagnostic = c.create_string_buffer(b'x'*10+b'\0\0'); buffers.append(diagnostic)
                def free(pointer):
                    self.assertEqual(c.string_at(pointer,10),b'\0'*10); freed_diagnostics.append(pointer)
                auto = SimpleNamespace(SysAllocStringLen=alloc,VariantClear=clear,
                    SysStringLen=lambda ptr:5,SysFreeString=free)
                api = Mock()
                def random(_,buf,size,flags):
                    for i in range(size): buf[i]=i
                    return 0
                api.BCryptGenRandom.side_effect=random
                secret=n.NativeCredential(api)
                def method(pointer,slot,*signature):
                    if slot==5: return lambda *args:0
                    if slot==6:
                        def invoke(*args):
                            if failure:
                                info=c.cast(args[7],c.POINTER(w._ExceptionInfo)).contents
                                info.description=c.addressof(diagnostic)
                                return -2147352567
                            return 0
                        return invoke
                    raise AssertionError(slot)
                with patch.object(w,'_method',method):
                    dispatch=n.SchedulerDispatch(1,auto)
                    if failure:
                        with self.assertRaises(n.NativeError): dispatch.invoke('RegisterTask',secret)
                    else: dispatch.invoke('RegisterTask',secret)
                self.assertEqual(len(cleared),1)
                self.assertEqual(len(freed_diagnostics),int(failure))
                self.assertTrue(any(secret.buffer))
                secret.clear(); self.assertFalse(any(secret.buffer))


class NativeCopyAndGroupTests(unittest.TestCase):
    def test_copy_uses_held_source_and_pinned_digest(self):
        f=object.__new__(n.NativeFiles); source=object(); raw=b'pinned source'
        f.read=Mock(return_value=raw); f.write_exclusive=Mock(return_value=123)
        digest=hashlib.sha256(raw).hexdigest(); sd=w.expected_descriptor('runtime',RUNTIME,BUILDER)
        self.assertEqual(f.copy_exclusive(source,'synthetic',len(raw),digest,sd),123)
        f.read.assert_called_once_with(source)
        f.write_exclusive.assert_called_once_with('synthetic',raw,digest,sd)
        f.write_exclusive.reset_mock(); f.read.return_value=b'changed'
        with self.assertRaises(w.AdmissionError): f.copy_exclusive(source,'synthetic',len(raw),digest,sd)
        f.write_exclusive.assert_not_called()

    def test_initial_security_flush_readback_and_close_on_mismatch(self):
        from contextlib import contextmanager
        for mismatch in (False,True):
            with self.subTest(mismatch=mismatch):
                f=object.__new__(n.NativeFiles); events=[]; raw=b'synthetic bytes'
                sd=w.expected_descriptor('runtime',RUNTIME,BUILDER)
                @contextmanager
                def attributes(descriptor):
                    self.assertEqual(descriptor,sd)
                    yield n.SECURITY_ATTRIBUTES(c.sizeof(n.SECURITY_ATTRIBUTES),123,False)
                def create(path,access,share,attrs,disposition,flags,template):
                    security=c.cast(attrs,c.POINTER(n.SECURITY_ATTRIBUTES)).contents
                    self.assertEqual(security.lpSecurityDescriptor,123)
                    self.assertEqual(disposition,1); self.assertEqual(share,1)
                    events.append('create'); return 99
                def write(handle,buffer,size,out,overlapped):
                    self.assertEqual(c.string_at(buffer,size),raw)
                    c.cast(out,c.POINTER(n.t.DWORD))[0]=size; events.append('write');return 1
                def flush(handle): events.append('flush');return 1
                def close(handle): events.append('close');return 1
                def read(handle): events.append('read');return b'wrong' if mismatch else raw
                f.b=SimpleNamespace(kernel=SimpleNamespace(CreateFileW=create,WriteFile=write,
                    FlushFileBuffers=flush,CloseHandle=close),check=lambda value,*args:self.assertTrue(value))
                f.security_attributes=attributes;f.read=read
                f.descriptor=lambda handle:descriptor('runtime')
                f.open=Mock(return_value=100)
                if mismatch:
                    with self.assertRaises(w.AdmissionError):
                        f.write_exclusive('synthetic',raw,hashlib.sha256(raw).hexdigest(),sd)
                    f.open.assert_not_called()
                else:
                    self.assertEqual(f.write_exclusive('synthetic',raw,hashlib.sha256(raw).hexdigest(),sd),100)
                self.assertEqual(events[:4],['create','write','flush','read'])
                self.assertIn('close',events)

    def test_users_normalization_is_driven_by_actual_readback(self):
        from contextlib import nullcontext
        for initial in ({n.USERS:'Users'},{},{w.ADMIN:'Administrators'}):
            with self.subTest(initial=initial):
                b=object.__new__(n.NativeBindings); groups=dict(initial); calls=[]
                b.local_groups=lambda:dict(groups)
                b.sid_pointer=lambda sid:nullcontext(c.c_void_p(123))
                b.resolve_sid=lambda name:n.USERS
                b.check=lambda value,*args:self.assertTrue(value)
                def lookup(system,sid,name,name_size,domain,domain_size,use):
                    if name is None:
                        c.cast(name_size,c.POINTER(n.t.DWORD))[0]=6
                        c.cast(domain_size,c.POINTER(n.t.DWORD))[0]=8
                        return 0
                    name.value='Users';domain.value='BUILTIN';return 1
                def add(system,name,level,member,count):
                    self.assertEqual((name,level,count),('Users',0,1))
                    calls.append('add');groups[n.USERS]='Users';return 0
                b.advapi=SimpleNamespace(LookupAccountSidW=lookup)
                b.net=SimpleNamespace(NetLocalGroupAddMembers=add)
                if w.ADMIN in initial:
                    with self.assertRaises(w.AdmissionError):b.ensure_users_membership(RUNTIME)
                else:
                    b.ensure_users_membership(RUNTIME)
                    self.assertEqual(set(groups),{n.USERS})
                self.assertEqual(len(calls),int(not initial))


class AdversarialCorrectionTests(unittest.TestCase):
    def test_grant_batch_passes_complete_lsa_unicode_string(self):
        from contextlib import nullcontext
        binding = object.__new__(n.NativeBindings)
        binding.lsa = lambda write=False: nullcontext(11)
        binding.sid_pointer = lambda sid: nullcontext(c.c_void_p(12))
        rights = [frozenset(), frozenset({'SeBatchLogonRight'})]
        binding.direct_rights = lambda sid: rights.pop(0)
        observed = []
        def add(policy, sid, pointer, count):
            value = c.cast(pointer, c.POINTER(n.LSA_STRING)).contents
            observed.append((value.Length, value.MaximumLength,
                             c.string_at(value.Buffer, value.Length).decode('utf-16-le')))
            self.assertEqual(count, 1)
            self.assertEqual(value.Length, 34)
            self.assertEqual(value.MaximumLength, 36)
            self.assertEqual(observed[-1][2], 'SeBatchLogonRight')
            self.assertEqual(c.string_at(value.Buffer + value.Length, 2), bytes(2))
            return 0
        binding.advapi = SimpleNamespace(LsaAddAccountRights=add)
        binding.grant_batch(RUNTIME, ())
        self.assertEqual(observed, [(34, 36, 'SeBatchLogonRight')])
        self.assertEqual(rights, [])


    def test_lsa_unicode_helper_counts_encoded_bytes_not_characters(self):
        for text in ('SeBatchLogonRight', 'A\u00e9\U0001f512', ''):
            with self.subTest(text=text), n.lsa_unicode_string(text) as value:
                encoded = text.encode('utf-16-le')
                self.assertEqual(value.Length, len(encoded))
                self.assertEqual(value.MaximumLength, len(encoded) + 2)
                self.assertEqual(c.string_at(value.Buffer, value.MaximumLength), encoded + bytes(2))
                self.assertEqual(c.string_at(value.Buffer, value.Length).decode('utf-16-le'), text)

    def test_lsa_unicode_helper_rejects_embedded_nul_and_ushort_overflow(self):
        for text in ('bad\0value', 'a' * 32767, None):
            with self.subTest(kind=type(text).__name__), self.assertRaises(w.AdmissionError):
                with n.lsa_unicode_string(text):
                    self.fail('Rejected input reached native structure consumer')


class Confirmation001FTests(unittest.TestCase):
    TOKEN = b'0123456789ABCDEF0123456789ABCDEF'  # synthetic, never a live authorization

    def kernel(self, outcome='success'):
        api = Mock(); api.GetStdHandle.return_value = 12
        modes = []; buffers = []
        def mode(handle, pointer):
            c.cast(pointer,c.POINTER(n.t.DWORD))[0]=7
            return outcome not in ('redirected','nonconsole')
        def set_mode(handle, value):
            modes.append(value)
            return not (outcome=='restore' and value==7)
        raw = self.TOKEN if outcome!='wrong' else b'F'*32
        events = list(raw)+[13]
        if outcome=='early':events=[13]
        if outcome=='extra':events=list(raw)+[65,13]
        if outcome=='lowercase':events=[97]
        if outcome=='nonhex':events=[71]
        if outcome=='ctrlc':events=[3]
        if outcome=='keyup':events=[None]+events
        def read(handle, pointer, limit, count):
            record=c.cast(pointer,c.POINTER(n.INPUT_RECORD)).contents
            if not buffers:buffers.append(record)
            c.cast(count,c.POINTER(n.t.DWORD))[0]=0 if outcome=='eof' else 1
            if outcome=='exception':raise RuntimeError('synthetic-read-failure')
            if outcome=='readfail':return 0
            value=events.pop(0)
            record.EventType=2 if outcome=='unexpected' else 1
            key=record.Event.KeyEvent
            key.KeyDown=value is not None
            key.RepeatCount=2 if outcome=='repeat' else 1
            key.UnicodeChar=0 if value is None else value
            key.VirtualKey=13 if value==13 else 65
            key.ControlKeyState=8 if outcome=='ctrlc' else 0
            return 1
        api.GetConsoleMode.side_effect=mode;api.SetConsoleMode.side_effect=set_mode
        api.ReadConsoleInputW.side_effect=read
        return api,modes,buffers

    def test_real_console_confirmation_success_and_failure_cleanup(self):
        expected=hashlib.sha256(self.TOKEN).hexdigest()
        for outcome in ('success','keyup','wrong','eof','readfail','exception','restore','redirected',
                        'nonconsole','hashfail','early','extra','lowercase','nonhex','unexpected','repeat','ctrlc'):
            with self.subTest(outcome=outcome):
                api,modes,buffers=self.kernel(outcome)
                verifier=n.ConsoleConfirmation(api)
                scratch=[];zeroed=[]
                original_sha=hashlib.sha256;original_memset=c.memset
                def sha(value):
                    scratch.append(value)
                    if outcome=='hashfail':raise ValueError('synthetic-hash-failure')
                    return original_sha(value)
                def zero(address,value,size):
                    result=original_memset(address,value,size)
                    if value==0:
                        self.assertEqual(c.string_at(address,size),bytes(size));zeroed.append(size)
                    return result
                with patch.object(n.hashlib,'sha256',sha),patch.object(n.c,'memset',side_effect=zero):
                    if outcome in ('success','keyup'):verifier.verify(expected)
                    else:
                        with self.assertRaises(Exception) as error:verifier.verify(expected)
                        self.assertNotIn(self.TOKEN.decode(),str(error.exception))
                self.assertLessEqual(api.ReadConsoleInputW.call_count,34)
                self.assertIn(64,zeroed);self.assertIn(32,zeroed);self.assertIn(c.sizeof(n.INPUT_RECORD),zeroed)
                if outcome not in ('redirected','nonconsole'):
                    self.assertEqual(modes,[128,7])
                else:self.assertEqual(api.ReadConsoleInputW.call_count,0)
                for value in scratch:self.assertEqual(value.tobytes(),bytes(32))
                if outcome in ('early','lowercase','nonhex','unexpected','repeat','ctrlc','eof','readfail','exception'):
                    self.assertEqual(api.ReadConsoleInputW.call_count,1)

    def test_confirmation_digest_required_closed_schema(self):
        value=authorization();del value['human_confirmation_sha256']
        with self.assertRaises(w.AdmissionError):
            n.HumanGateAuthorization.parse(w.canonical(value),datetime(2026,11,5,12,tzinfo=timezone.utc))
        value=authorization();value['raw_confirmation_token']='synthetic'
        with self.assertRaises(w.AdmissionError):
            n.HumanGateAuthorization.parse(w.canonical(value),datetime(2026,11,5,12,tzinfo=timezone.utc))

    def test_confirmation_failure_reaches_no_mutation_backend(self):
        f=IntegratedFixture(fail='confirmation');result=f.run()
        self.assertEqual(result['stage'],'HUMAN_CONFIRMATION')
        self.assertNotIn('BACKEND_CONSTRUCTION',result['completed_steps'])
        self.assertNotIn('account_create',f.events)
        self.assertFalse(result['mutation_may_have_occurred'])
        self.assertNotIn(self.TOKEN.decode(),repr(result))

    def test_expiry_before_first_mutation_blocks_but_postmutation_does_not(self):
        for before in (True,False):
            with self.subTest(before=before):
                f=IntegratedFixture(); original=f.create_account
                original_parse=n.HumanGateAuthorization.parse
                def parse(raw,now):
                    if before or f.account_created:
                        now=datetime(2026,11,7,tzinfo=timezone.utc)
                    return original_parse(raw,now)
                with patch.object(n.HumanGateAuthorization,'parse',side_effect=parse):result=f.run()
                if before:
                    self.assertEqual(result['status'],'ADMISSION_REJECTED')
                    self.assertFalse(f.account_created)
                else:
                    self.assertEqual(result['status'],'TASK_REGISTERED_DISABLED',result)
                    self.assertIn(n.RECEIPT_PATH,f.data)


class EffectiveAccess001FTests(unittest.TestCase):
    def fixture(self):
        from contextlib import nullcontext
        masks={'workspace':0,'parent':0,'runtime':w.EXECUTE_ACCESS,'control':w.READ,
               'authority':w.AUTHORITY_ACCESS,'captures':w.CAPTURE_ACCESS,'inbox':w.READ,'secrets':w.CAPTURE_ACCESS}
        builder_masks={name:(w.BUILDER_INBOX_ACCESS if name=='inbox' else 0) for name in masks}
        bindings=SimpleNamespace(machine=lambda:dict(machine_sid='S-1-5-21-1-2-3'),
            account=lambda name:dict(sid=BUILDER,standard=True,enabled=True),
            local_groups=lambda name,indirect=False:{n.USERS:'Users'},direct_rights=lambda sid:frozenset())
        context=SimpleNamespace(bindings=bindings,authority=SimpleNamespace(builder_sid=BUILDER,
            builder_workspace_path=r'C:\Users\ASFBuilder\workspace'),workspace_handle='workspace',
            files=SimpleNamespace(directories={r'C:\Users\ASFBuilder':'parent'}))
        runtime=SimpleNamespace(token=1,validate=lambda handle,sid:None,access=lambda sd:masks[sd],close=lambda:None)
        builder=SimpleNamespace(access=lambda sd:builder_masks[sd],close=lambda:None)
        return context,masks,builder_masks,runtime,builder

    def test_production_access_checks_exact_grants_and_denials(self):
        from contextlib import nullcontext
        for subject,kind,bits in [('runtime','workspace',value) for value in (2,w.WRITE_DAC,w.WRITE_OWNER,w.DELETE)]+[
            ('runtime','parent',0x40),('builder','runtime',2),('builder','authority',w.WRITE_DAC),
            ('builder','captures',w.WRITE_OWNER),('builder','secrets',w.DELETE),('builder','inbox',w.WRITE_DAC),
            ('runtime','authority',w.DELETE),('none','none',0)]:
            with self.subTest(subject=subject,kind=kind,bits=bits):
                ctx,rm,bm,rt,bt=self.fixture()
                if subject=='runtime':rm[kind]|=bits
                if subject=='builder':bm[kind]|=bits
                with patch.object(n,'RuntimeBatchToken',return_value=rt),patch.object(n,'BuilderAuthz',return_value=bt),\
                     patch.object(n,'held_security_descriptor',side_effect=lambda files,handle:nullcontext(handle)):
                    actual=n.EffectiveAccess(ctx,RUNTIME,object())
                    roots={name:name for name in ('runtime','control','authority','captures','inbox','secrets')}
                    if subject=='none':actual.verify(roots)
                    else:
                        with self.assertRaises(w.AdmissionError):actual.verify(roots)
                    actual.close()

    def test_authz_failure_has_no_descriptor_only_fallback(self):
        from contextlib import nullcontext
        ctx,rm,bm,rt,bt=self.fixture()
        bt.access=Mock(side_effect=n.NativeError('AUTHZ_ACCESS_RESULT',5))
        with patch.object(n,'RuntimeBatchToken',return_value=rt),patch.object(n,'BuilderAuthz',return_value=bt),\
             patch.object(n,'held_security_descriptor',side_effect=lambda files,handle:nullcontext(handle)):
            actual=n.EffectiveAccess(ctx,RUNTIME,object())
            with self.assertRaises(n.NativeError):actual.verify({name:name for name in ('runtime','control','authority','captures','inbox','secrets')})
            actual.close()

    def test_builder_indirect_privileged_group_rejected_before_context(self):
        ctx,*_=self.fixture()
        ctx.bindings.local_groups=lambda name,indirect=False:{n.USERS:'Users',w.ADMIN:'Administrators'}
        with patch.object(n,'BuilderAuthz') as constructor,patch.object(n,'RuntimeBatchToken') as logon:
            with self.assertRaises(w.AdmissionError):n.EffectiveAccess(ctx,RUNTIME,object())
        constructor.assert_not_called();logon.assert_not_called()

    def test_runtime_native_token_group_observations(self):
        for bad in ('none','missing_batch','interactive','admin','disabled_batch','unknown'):
            with self.subTest(bad=bad):
                groups={sid:7 for sid in n.RUNTIME_REQUIRED_GROUPS}
                if bad=='missing_batch':del groups['S-1-5-3']
                if bad=='disabled_batch':groups['S-1-5-3']=0
                if bad=='interactive':groups['S-1-5-4']=7
                if bad=='admin':groups[w.ADMIN]=0x10
                if bad=='unknown':groups['S-1-5-32-551']=7
                binding=synthetic_token_bindings(groups)
                token=object.__new__(n.RuntimeBatchToken);token.b=binding
                if bad=='none':token.validate(1,RUNTIME)
                else:
                    with self.assertRaises(w.AdmissionError):token.validate(1,RUNTIME)



class EffectiveAbi001FTests(unittest.TestCase):
    def test_batch_logon_native_arguments_and_token_ownership(self):
        for failure in ('none','logon','duplicate','access'):
            with self.subTest(failure=failure):
                api=Mock();kernel=Mock();kernel.CloseHandle.return_value=1
                b=SimpleNamespace(advapi=api,kernel=kernel,check=lambda value,*args:w.require(value,'FAKE_API_FAILURE'))
                credential=n.NativeCredential(SimpleNamespace(BCryptGenRandom=lambda *args:0))
                def logon(name,domain,password,kind,provider,out):
                    self.assertEqual((name,domain,kind,provider),('ASFTrustedRuntime','.',4,0))
                    self.assertEqual(c.addressof(password),c.addressof(credential.buffer))
                    if failure=='logon':return 0
                    c.cast(out,c.POINTER(n.t.HANDLE))[0]=101;return 1
                def duplicate(handle,level,out):
                    self.assertEqual(level,2)
                    if failure=='duplicate':return 0
                    c.cast(out,c.POINTER(n.t.HANDLE))[0]=102;return 1
                def access(sd,token,desired,mapping,privileges,size,granted,allowed):
                    self.assertEqual(desired,n.MAXIMUM_ALLOWED)
                    m=c.cast(mapping,c.POINTER(n.GENERIC_MAPPING)).contents
                    self.assertEqual(m.GenericExecute,0x1200a0)
                    c.cast(granted,c.POINTER(n.t.DWORD))[0]=w.READ
                    c.cast(allowed,c.POINTER(n.t.BOOL))[0]=1
                    return failure!='access'
                api.LogonUserW.side_effect=logon;api.DuplicateToken.side_effect=duplicate;api.AccessCheck.side_effect=access
                with patch.object(n.RuntimeBatchToken,'validate') as validate:
                    if failure in ('logon','duplicate'):
                        with self.assertRaises(w.AdmissionError):n.RuntimeBatchToken(b,credential,RUNTIME)
                    else:
                        token=n.RuntimeBatchToken(b,credential,RUNTIME)
                        if failure=='access':
                            with self.assertRaises(w.AdmissionError):token.access(1)
                        else:self.assertEqual(token.access(1),w.READ)
                        self.assertEqual(validate.call_count,2)
                        token.close();token.close()
                expected=0 if failure=='logon' else 1 if failure=='duplicate' else 2
                self.assertEqual(kernel.CloseHandle.call_count,expected)
                credential.clear()

    def test_authz_explicit_groups_skip_s4u_cleanup_and_error_handling(self):
        from contextlib import nullcontext
        for failure in ('none','manager','base','groups','access','denied','cleanup'):
            with self.subTest(failure=failure):
                api=Mock();api.AuthzFreeContext.return_value=1;api.AuthzFreeResourceManager.return_value=1
                b=SimpleNamespace(sid_pointer=lambda sid:nullcontext(c.c_void_p(123)),
                    check=lambda value,*args:w.require(value,'FAKE_API_FAILURE'))
                def manager(flags,*args):
                    self.assertEqual(flags,1)
                    if failure=='manager':return 0
                    c.cast(args[-1],c.POINTER(c.c_void_p))[0]=201;return 1
                def base(flags,sid,rm,expiry,identifier,args,out):
                    self.assertEqual(flags,2)  # AUTHZ_SKIP_TOKEN_GROUPS
                    if failure=='base':return 0
                    c.cast(out,c.POINTER(c.c_void_p))[0]=202;return 1
                def groups(ctx,entries,count,restricted,restricted_count,out):
                    self.assertEqual(count,len(n.BUILDER_CHARACTERISTICS))
                    self.assertEqual([entries[i].Attributes for i in range(count)],[7]*count)
                    self.assertIsNone(restricted);self.assertEqual(restricted_count,0)
                    if failure=='groups':return 0
                    c.cast(out,c.POINTER(c.c_void_p))[0]=203;return 1
                def access(flags,ctx,request,audit,sd,optional,count,reply,cache):
                    self.assertEqual(c.cast(request,c.POINTER(n.AUTHZ_ACCESS_REQUEST)).contents.DesiredAccess,n.MAXIMUM_ALLOWED)
                    result=c.cast(reply,c.POINTER(n.AUTHZ_ACCESS_REPLY)).contents
                    result.GrantedAccessMask[0]=0 if failure=='denied' else w.READ
                    result.Error[0]=5 if failure=='denied' else 0
                    return failure!='access'
                api.AuthzInitializeResourceManager.side_effect=manager
                api.AuthzInitializeContextFromSid.side_effect=base
                api.AuthzAddSidsToContext.side_effect=groups
                api.AuthzAccessCheck.side_effect=access
                with patch.object(n.c,'WinDLL',return_value=api) as dll:
                    if failure in ('manager','base','groups'):
                        with self.assertRaises(w.AdmissionError):n.BuilderAuthz(b,BUILDER,n.BUILDER_CHARACTERISTICS)
                    else:
                        context=n.BuilderAuthz(b,BUILDER,n.BUILDER_CHARACTERISTICS)
                        if failure=='access':
                            with self.assertRaises(w.AdmissionError):context.access(1)
                        else:self.assertEqual(context.access(1),0 if failure=='denied' else w.READ)
                        if failure=='cleanup':
                            api.AuthzFreeContext.return_value=0
                            with self.assertRaises(n.NativeError):context.close()
                        else:context.close()
                    dll.assert_called_once_with('authz.dll',use_last_error=True,winmode=0x800)
                self.assertEqual(api.AuthzFreeResourceManager.call_count,0 if failure=='manager' else 1)
                self.assertEqual(api.AuthzFreeContext.call_count,0 if failure in ('manager','base') else 1 if failure=='groups' else 2)

    def test_pinned_inputs_revalidated_after_confirmation_before_first_write(self):
        f=IntegratedFixture(); original=f.event
        def event(name):
            original(name)
            if name=='confirmation':
                f.data[n.STAGING+r'\app\orchestrator\trusted_runtime_windows.py']+=b'changed'
        f.event=event
        result=f.run()
        self.assertEqual(result['status'],'ADMISSION_REJECTED')
        self.assertFalse(f.account_created)
        self.assertNotIn('BACKEND_CONSTRUCTION',result['completed_steps'])


class ConfirmationDeadline001FTests(unittest.TestCase):
    def test_expiration_during_human_confirmation_prevents_first_mutation(self):
        f=IntegratedFixture();confirmed=False;original_event=f.event
        original_parse=n.HumanGateAuthorization.parse
        def event(name):
            nonlocal confirmed
            original_event(name)
            if name=='confirmation':confirmed=True
        def parse(raw,now):
            return original_parse(raw,datetime(2026,11,7,tzinfo=timezone.utc) if confirmed else now)
        f.event=event
        with patch.object(n.HumanGateAuthorization,'parse',side_effect=parse):result=f.run()
        self.assertEqual(result['stage'],'HUMAN_CONFIRMATION')
        self.assertFalse(f.account_created)
        self.assertFalse(result['mutation_may_have_occurred'])
        self.assertNotIn('BACKEND_CONSTRUCTION',result['completed_steps'])


def synthetic_token_bindings(groups, user=RUNTIME):
    """Native-layout buffers containing in-buffer SID pointers; no Windows API."""
    def encode(sid):
        parts=[int(p) for p in sid.split('-')[1:]]
        return bytes([parts[0],len(parts)-2])+parts[1].to_bytes(6,'big')+b''.join(x.to_bytes(4,'little') for x in parts[2:])
    def decode(pointer):
        header=c.string_at(pointer,8)
        return 'S-'+str(header[0])+'-'+str(int.from_bytes(header[2:8],'big'))+''.join(
            '-'+str(int.from_bytes(c.string_at(pointer+8+4*i,4),'little')) for i in range(header[1]))
    b=object.__new__(n.NativeBindings);b.advapi=Mock();b.kernel=Mock()
    b.kernel.CloseHandle.return_value=1;b.kernel.GetCurrentProcess.return_value=1
    b.sid_string=decode
    def info(handle,kind,out,size,needed):
        entries=[(user,0)] if kind==1 else list(groups.items())
        offset=0 if kind==1 else n.TOKEN_GROUPS_HEADER.Groups.offset
        end=offset+len(entries)*c.sizeof(n.SID_AND_ATTRIBUTES)
        length=end+sum(len(encode(sid)) for sid,_ in entries)
        c.cast(needed,c.POINTER(n.t.DWORD))[0]=length
        if out is None:return 0
        base=c.addressof(out);c.memset(base,0,length)
        if kind==2:c.c_uint32.from_address(base).value=len(entries)
        cursor=end
        for i,(sid,attributes) in enumerate(entries):
            raw=encode(sid)
            entry=n.SID_AND_ATTRIBUTES.from_address(base+offset+i*c.sizeof(n.SID_AND_ATTRIBUTES))
            entry.Sid=base+cursor;entry.Attributes=attributes
            c.memmove(base+cursor,raw,len(raw));cursor+=len(raw)
        return 1
    b.advapi.GetTokenInformation.side_effect=info
    return b


class AccessCheckCorrectionTests(unittest.TestCase):
    def test_production_wrapper_distinguishes_api_failure_denial_and_allow(self):
        for result in ('api_failure','deny','allow','oversize','bad_privileges'):
            with self.subTest(result=result):
                binding=object.__new__(n.NativeBindings);binding.advapi=Mock()
                def access(sd,handle,desired,mapping,privileges,size,granted,status):
                    m=c.cast(mapping,c.POINTER(n.GENERIC_MAPPING)).contents
                    self.assertEqual((m.GenericRead,m.GenericWrite,m.GenericExecute,m.GenericAll),
                                     (0x120089,0x120116,0x1200a0,0x1f01ff))
                    self.assertEqual(desired,n.MAXIMUM_ALLOWED)
                    self.assertEqual(c.cast(size,c.POINTER(n.t.DWORD))[0],65536)
                    c.cast(size,c.POINTER(n.t.DWORD))[0]=65537 if result=='oversize' else 8
                    c.c_uint32.from_buffer(privileges).value=1 if result=='bad_privileges' else 0
                    c.cast(granted,c.POINTER(n.t.DWORD))[0]=w.READ
                    c.cast(status,c.POINTER(n.t.BOOL))[0]=0 if result=='deny' else 1
                    return result!='api_failure'
                binding.advapi.AccessCheck.side_effect=access
                token=object.__new__(n.RuntimeBatchToken);token.b=binding;token.token=1
                if result=='api_failure':
                    with self.assertRaises(n.NativeError):token.access(2)
                elif result in ('oversize','bad_privileges'):
                    with self.assertRaises(w.AdmissionError):token.access(2)
                else:self.assertEqual(token.access(2),0 if result=='deny' else w.READ)
                binding.advapi.AccessCheck.assert_called_once()

    def test_real_parser_attributes_and_malformed_bounds(self):
        binding=synthetic_token_bindings({'S-1-5-3':7,'S-1-5-32-544':0x10})
        user,groups=n.observe_native_token(binding,1)
        self.assertEqual(user,RUNTIME)
        self.assertEqual(groups,{'S-1-5-3':7,'S-1-5-32-544':0x10})
        for malformed in ('short','count','null','external','truncated_sid'):
            with self.subTest(malformed=malformed):
                if malformed=='short':raw=c.create_string_buffer(1)
                else:
                    raw=c.create_string_buffer(40)
                    c.c_uint32.from_buffer(raw).value=513 if malformed=='count' else 1
                    item=n.SID_AND_ATTRIBUTES.from_buffer(raw,n.TOKEN_GROUPS_HEADER.Groups.offset)
                    item.Sid=None if malformed=='null' else 1 if malformed=='external' else c.addressof(raw)+32
                    if malformed=='truncated_sid':
                        c.c_ubyte.from_buffer(raw,32).value=1;c.c_ubyte.from_buffer(raw,33).value=15
                with self.assertRaises(w.AdmissionError):n.parse_token_groups(raw,binding.sid_string)
