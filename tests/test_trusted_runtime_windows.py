"""Synthetic evidence only; these tests do not install a Windows boundary."""
import ctypes
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src')) if str(ROOT / 'src') not in sys.path else None
from orchestrator import trusted_runtime_windows as w

spec = importlib.util.spec_from_file_location('manifest_builder_fixture', ROOT / 'tools/windows/build_trusted_runtime_manifest.py')
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)

RUNTIME = 'S-1-5-21-1-2-3-1005'
BUILDER = 'S-1-5-21-1-2-3-1004'


def provenance():
    return dict(release_url_identity='https://www.python.org/downloads/release/python-31410/',
        artifact_filename='python-3.14.10-embed-amd64.zip', artifact_size=100,
        published_sha256='a'*64, calculated_sha256='a'*64,
        sigstore_verified=True, sigstore_identity='synthetic-test-identity',
        sigstore_issuer='synthetic-test-issuer', independent_verifier_verified=True)


def source():
    return dict(repository=w.REPOSITORY, commit='a'*40, tree='b'*40, independently_verified=True)


def materials():
    items = []
    for path in w.APPLICATION_FILES:
        raw = b'# normative blob\n'
        sha = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        items.append(generator.Material(path, raw, 'APPLICATION_MODULE', 'git_blob', sha))
    for name, role in (('python.exe', 'PYTHON_EXECUTABLE'), ('python314.zip', 'STDLIB_ARCHIVE'),
                       ('python314._pth', 'IMPORT_CONFIG')):
        items.append(generator.Material('python/'+name, b'synthetic-not-executable', role, 'python_artifact'))
    return items


def build(items=None, inventory=None, src=None, proof=None):
    items = materials() if items is None else items
    inventory = {x.relative_path: x.role for x in materials()} if inventory is None else inventory
    return generator.generate(source() if src is None else src, provenance() if proof is None else proof,
                              items, inventory)


def receipt(manifest):
    return dict(installation_id='a'*32, generation=1, previous_receipt_sha256=None,
        manifest_sha256=hashlib.sha256(w.canonical(manifest)).hexdigest(), source_commit_sha='a'*40,
        source_tree_sha='b'*40, bootstrap_script_sha256='c'*64, builder_sid=BUILDER, runtime_sid=RUNTIME,
        machine_guid='machine-fixture', machine_sid='S-1-5-21-1-2-3', windows_build='26200.9711',
        volume_guid='volume-fixture', volume_serial=42, runtime_profile_path=r'C:\Users\ASFTrustedRuntime',
        **w.ROOTS, task_identifier=w.TASK_NAME, task_definition_digest='d'*64,
        installation_timestamp_utc='2026-11-05T00:00:00Z', bootstrap_result='TASK_REGISTERED_DISABLED')


def host(m):
    from pathlib import PureWindowsPath
    return w.HostObservation(RUNTIME, False, False, frozenset({'SeChangeNotifyPrivilege'}),
        'volume-fixture', 'NTFS', False,
        {k: w.expected_descriptor(k, RUNTIME, BUILDER) for k in
         ('runtime', 'control', 'authority', 'captures', 'secrets', 'inbox', 'task', 'folder')},
        {f['relative_path']: (f['size'], f['sha256']) for f in m['files']}, w.ROOTS['runtime_root'],
        tuple(str(PureWindowsPath(w.ROOTS['runtime_root']) / p) for p in m['allowed_import_roots']),
        True, False, True, {'exists': True})


class ManifestTests(unittest.TestCase):
    def test_deterministic_and_enumeration_independent(self):
        self.assertEqual(build(), build(list(reversed(materials()))))
        self.assertEqual(build(), build())

    def test_no_bom_time_or_builder_path(self):
        raw = build()
        self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
        self.assertNotIn(b'timestamp', raw)
        self.assertNotIn(b'Users', raw)

    def test_git_blob_bytes_not_crlf_checkout(self):
        items = materials()
        items[0] = replace(items[0], content=items[0].content.replace(b'\n', b'\r\n'))
        with self.assertRaisesRegex(w.AdmissionError, 'GIT_BLOB_MISMATCH'):
            build(items)

    def test_checkout_origin_cannot_substitute(self):
        items = materials(); items[0] = replace(items[0], origin='checkout')
        with self.assertRaisesRegex(w.AdmissionError, 'GIT_BLOB_BYTES_REQUIRED'):
            build(items)

    def test_duplicate_windows_path(self):
        items = materials(); items.append(replace(items[0], relative_path=items[0].relative_path.upper()))
        with self.assertRaisesRegex(w.AdmissionError, 'DUPLICATE_PATH'):
            build(items)

    def test_unsafe_paths(self):
        for path in ('C:/x', '/x', '../x', 'x/../y', 'x:stream', 'CON.txt', 'x/NUL',
                     'x.', 'x ', 'x//y', 'x\\y', 'x/COM1.py', 'x/LPT9.txt', 'x/~SHORT'):
            with self.subTest(path=path), self.assertRaises(w.AdmissionError):
                w.relative_path(path)

    def test_physical_rejections(self):
        for change in ({'links': 2}, {'reparse': True}, {'alternate_streams': ('x',)}, {'short_name': 'X~1'}):
            items = materials(); items[0] = replace(items[0], **change)
            with self.subTest(change=change), self.assertRaisesRegex(w.AdmissionError, 'UNSAFE_FILE_OBJECT'):
                build(items)

    def test_extra_file(self):
        with self.assertRaisesRegex(w.AdmissionError, 'UNEXPECTED_FILE'):
            build(materials()+[generator.Material('extra.dll', b'x', 'NATIVE_LIBRARY', 'python_artifact')])

    def test_missing_file(self):
        with self.assertRaisesRegex(w.AdmissionError, 'MISSING_REQUIRED_FILE'):
            build(materials()[1:])

    def test_required_file_cannot_be_removed_from_inventory(self):
        items = materials()[1:]
        with self.assertRaisesRegex(w.AdmissionError, 'MISSING_REQUIRED_FILE'):
            build(items, {x.relative_path: x.role for x in items})

    def test_manifest_closed(self):
        m = json.loads(build()); m['unexpected'] = True
        with self.assertRaises(w.AdmissionError): w.validate_manifest(m)

    def test_file_entry_closed(self):
        m = json.loads(build()); m['files'][0]['execute'] = True
        with self.assertRaises(w.AdmissionError): w.validate_manifest(m)

    def test_template_not_installable(self):
        template = json.loads((ROOT/'tools/windows/trusted_runtime_manifest.json').read_bytes())
        with self.assertRaisesRegex(w.AdmissionError, 'NOT_INSTALLABLE_TEMPLATE'):
            w.validate_manifest(template)

    def test_commit_tree_mandatory(self):
        for key in ('commit', 'tree'):
            s = source(); del s[key]
            with self.subTest(key=key), self.assertRaises(w.AdmissionError): build(src=s)

    def test_builder_only_provenance_rejected(self):
        s = source(); s['independently_verified'] = False
        with self.assertRaisesRegex(w.AdmissionError, 'INDEPENDENT_PROVENANCE_REQUIRED'): build(src=s)

    def test_python_fields_mandatory(self):
        for key in w.PROVENANCE_KEYS:
            p = provenance(); del p[key]
            with self.subTest(key=key), self.assertRaises(w.AdmissionError): build(proof=p)

    def test_sigstore_exact_true(self):
        for value in (False, 1, 'true', None):
            p = provenance(); p['sigstore_verified'] = value
            with self.subTest(value=value), self.assertRaises(w.AdmissionError): build(proof=p)

    def test_python_hashes_match(self):
        p = provenance(); p['calculated_sha256'] = 'b'*64
        with self.assertRaisesRegex(w.AdmissionError, 'PYTHON_HASH_MISMATCH'): build(proof=p)

    def test_independent_python_verification_required(self):
        p = provenance(); p['independent_verifier_verified'] = False
        with self.assertRaises(w.AdmissionError): build(proof=p)

    def test_json_duplicate_bom_extra_numbers_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'\xef\xbb\xbf{}', b'{"x":NaN}', b'{"x":1.0}'):
            with self.subTest(raw=raw), self.assertRaises(w.AdmissionError): w.strict_json(raw)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.m = json.loads(build()); self.r = receipt(self.m); self.h = host(self.m)

    def test_valid_model_not_authority(self):
        self.assertEqual(w.admit_host(self.h, self.r, self.m, {'exists': True}),
                         'PREFLIGHT_CONSISTENT_NOT_AUTHORIZED')

    def test_identity_token_privilege_rejections(self):
        for change in ({'process_sid': BUILDER}, {'admin_account': True}, {'elevated': True},
                       {'enabled_privileges': frozenset({'SeDebugPrivilege'})}):
            with self.subTest(change=change), self.assertRaises(w.AdmissionError):
                w.admit_host(replace(self.h, **change), self.r, self.m, self.h.task)

    def test_volume_filesystem_reparse_rejections(self):
        for change in ({'volume': 'other'}, {'filesystem': 'FAT32'}, {'reparse_ancestor': True}):
            with self.subTest(change=change), self.assertRaises(w.AdmissionError):
                w.admit_host(replace(self.h, **change), self.r, self.m, self.h.task)

    def test_owner_inheritance_broad_acl_rejections(self):
        d = self.h.descriptors['captures']
        for bad in (replace(d, owner=BUILDER), replace(d, protected=False),
                    replace(d, aces=d.aces+(w.Ace('S-1-1-0', w.READ),))):
            descriptors = dict(self.h.descriptors, captures=bad)
            with self.subTest(bad=bad), self.assertRaises(w.AdmissionError):
                w.admit_host(replace(self.h, descriptors=descriptors), self.r, self.m, self.h.task)

    def test_extra_and_corrupt_runtime_files(self):
        for files in (dict(self.h.file_hashes, extra=(1, 'a'*64)),
                      dict(self.h.file_hashes, **{next(iter(self.h.file_hashes)): (0, 'b'*64)})):
            with self.assertRaisesRegex(w.AdmissionError, 'RUNTIME_TREE_MISMATCH'):
                w.admit_host(replace(self.h, file_hashes=files), self.r, self.m, self.h.task)

    def test_environment_import_root_rejections(self):
        for change in ({'safe_environment': False}, {'import_roots': ('C:\\repo',)},
                       {'cwd': 'C:\\repo'}, {'isolated': False}, {'user_site': True}):
            with self.subTest(change=change), self.assertRaises(w.AdmissionError):
                w.admit_host(replace(self.h, **change), self.r, self.m, self.h.task)

    def test_scheduler_mismatch(self):
        with self.assertRaisesRegex(w.AdmissionError, 'SCHEDULER_MISMATCH'):
            w.admit_host(self.h, self.r, self.m, {'exists': False})

    def test_receipt_manifest_binding(self):
        self.r['manifest_sha256'] = 'f'*64
        with self.assertRaisesRegex(w.AdmissionError, 'INSTALLATION_BINDING_MISMATCH'):
            w.admit_host(self.h, self.r, self.m, self.h.task)

    def test_receipt_closed_generation_and_reinstall(self):
        for update in ({'extra': 1}, {'generation': 2}, {'generation': True}, {'previous_receipt_sha256': 'a'*64}):
            with self.subTest(update=update), self.assertRaises(w.AdmissionError):
                w.validate_receipt(dict(self.r, **update))
        with self.assertRaises(w.AdmissionError): w.check_initial_install(True)

    def test_effective_group_deny_wins(self):
        principals = frozenset({RUNTIME, 'S-1-5-32-545'})
        rights = {'SeBatchLogonRight': frozenset({RUNTIME}),
                  'SeDenyBatchLogonRight': frozenset({'S-1-5-32-545'})}
        with self.assertRaisesRegex(w.AdmissionError, 'BATCH_LOGON_BLOCKED'):
            w.effective_batch_rights(principals, rights)
        rights['SeDenyBatchLogonRight'] = frozenset()
        w.effective_batch_rights(principals, rights)

    def test_launch_audit_all_categories_required(self):
        audit = dict.fromkeys(w.LAUNCH_SIGNALS, 'VERIFIED_CLEAR')
        w.validate_launch_audit(audit)
        for key in audit:
            with self.subTest(key=key), self.assertRaises(w.AdmissionError):
                w.validate_launch_audit(dict(audit, **{key: 'NOT_VERIFIED'}))

    def test_activation_digest_rejects_rollback(self):
        a = dict(installation_id=self.r['installation_id'], generation=1, mode='VALIDATION',
            valid_from_utc='2026-11-05T00:00:00Z', valid_until_utc='2026-11-05T00:10:00Z',
            expected_task_digest='d'*64, fixture_set_digest='e'*64)
        approved = hashlib.sha256(w.canonical(a)).hexdigest()
        now = datetime(2026, 11, 5, 0, 1, tzinfo=timezone.utc)
        w.validate_activation(a, self.r, approved, 'd'*64, now)
        a['valid_until_utc'] = '2026-11-05T00:20:00Z'
        with self.assertRaisesRegex(w.AdmissionError, 'STALE_ACTIVATION'):
            w.validate_activation(a, self.r, approved, 'd'*64, now)


class ACLTests(unittest.TestCase):
    def test_captures_precise_rights(self):
        self.assertEqual(w.CAPTURE_ACCESS & (w.DELETE | 0x40 | w.WRITE_DAC | w.WRITE_OWNER), 0)
        self.assertEqual(w.CAPTURE_ACCESS & 7, 7)

    @staticmethod
    def effective_mask(descriptor, principal):
        # Closed model contains explicit ALLOW ACEs only. OWNER RIGHTS has no
        # WRITE_DAC, and root owner is Admin, not the runtime principal.
        mask = 0
        for ace in descriptor.aces:
            if ace.sid == principal and not ace.flags & 0x8:
                mask |= ace.mask
        return mask

    def test_authority_sqlite_lifecycle(self):
        authority = w.expected_descriptor('authority', RUNTIME, BUILDER)
        # Direct child files inherit OI ACEs; IO no longer applies on the file.
        file_aces = tuple(w.Ace(a.sid, a.mask, 0) for a in authority.aces if a.flags & 0x1)
        sqlite_file = w.Descriptor(RUNTIME, False, file_aces)
        mask = self.effective_mask(sqlite_file, RUNTIME)
        self.assertTrue(mask & w.DELETE)
        self.assertEqual(mask & 0x7, 0x7)  # read, write, append
        self.assertFalse(mask & (0x40 | w.WRITE_DAC | w.WRITE_OWNER))
        self.assertIn(w.Ace(w.OWNER_RIGHTS, w.READ_CONTROL, 0), file_aces)

    def test_authority_container_excludes_delete_rights(self):
        authority = w.expected_descriptor('authority', RUNTIME, BUILDER)
        mask = self.effective_mask(authority, RUNTIME)
        self.assertTrue(mask & 0x1)  # enumerate
        self.assertTrue(mask & 0x2)  # create file
        self.assertTrue(mask & 0x20)  # traverse
        self.assertFalse(mask & (w.DELETE | 0x40 | w.WRITE_DAC | w.WRITE_OWNER))
        self.assertFalse(mask & 0x4)  # cannot create child directories either

    def test_sqlite_delete_ace_is_inherit_only_object_not_container(self):
        authority = w.expected_descriptor('authority', RUNTIME, BUILDER)
        delete_aces = [a for a in authority.aces if a.sid == RUNTIME and a.mask & w.DELETE]
        self.assertEqual(len(delete_aces), 1)
        ace = delete_aces[0]
        self.assertEqual(ace.flags, 0x1 | 0x8)  # OI | IO, not CI
        self.assertFalse(ace.flags & 0x2)
        self.assertFalse(ace.mask & (0x40 | w.WRITE_DAC | w.WRITE_OWNER))

    def test_captures_effective_descriptor_preserves_boundary(self):
        captures = w.expected_descriptor('captures', RUNTIME, BUILDER)
        self.assertEqual(captures.owner, w.ADMIN)
        self.assertIs(captures.protected, True)
        mask = self.effective_mask(captures, RUNTIME)
        self.assertEqual(mask & 0x7, 0x7)
        self.assertFalse(mask & (w.DELETE | 0x40 | w.WRITE_DAC | w.WRITE_OWNER))
        self.assertEqual([a.mask for a in captures.aces if a.sid == w.OWNER_RIGHTS], [w.READ_CONTROL])

    def test_combined_authority_captures_prevents_ancestor_substitution(self):
        authority = w.expected_descriptor('authority', RUNTIME, BUILDER)
        captures = w.expected_descriptor('captures', RUNTIME, BUILDER)
        # Protected Captures ignores parent inheritance; no effective DELETE
        # from either the parent DELETE_CHILD route or the child's own DACL.
        inherited = () if captures.protected else tuple(a for a in authority.aces if a.flags & 0x2)
        child = w.Descriptor(captures.owner, captures.protected, captures.aces + inherited)
        parent_mask = self.effective_mask(authority, RUNTIME)
        child_mask = self.effective_mask(child, RUNTIME)
        can_delete_or_rename_child = bool(parent_mask & 0x40 or child_mask & w.DELETE)
        can_recreate_child = bool(parent_mask & 0x4)
        can_change_security = bool((parent_mask | child_mask) & (w.WRITE_DAC | w.WRITE_OWNER))
        self.assertFalse(can_delete_or_rename_child)
        self.assertFalse(can_recreate_child)
        self.assertFalse(can_change_security)
        weakened = w.Descriptor(authority.owner, True,
                                authority.aces + (w.Ace(RUNTIME, w.DELETE | 0x40, 0),))
        with self.assertRaisesRegex(w.AdmissionError, 'ACL_MISMATCH'):
            w.validate_descriptor(weakened, authority)

    def test_owner_rights_and_no_builder(self):
        for kind in ('runtime', 'control', 'authority', 'captures', 'secrets', 'task', 'folder'):
            d = w.expected_descriptor(kind, RUNTIME, BUILDER)
            self.assertNotIn(BUILDER, {a.sid for a in d.aces})
            self.assertEqual([a.mask for a in d.aces if a.sid == w.OWNER_RIGHTS], [w.READ_CONTROL])

    def test_inbox_builder_root_only(self):
        ace = next(a for a in w.expected_descriptor('inbox', RUNTIME, BUILDER).aces if a.sid == BUILDER)
        self.assertEqual(ace.flags, 0)
        self.assertFalse(ace.mask & (w.WRITE_DAC | w.WRITE_OWNER | w.DELETE | 0x40))


class SchedulerTests(unittest.TestCase):
    def test_com_abi_sizes(self):
        self.assertEqual(ctypes.sizeof(w._GUID), 16)
        self.assertEqual(ctypes.sizeof(w._Variant), 24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 16)
        self.assertEqual(w._Variant.data.offset, 8)

    def test_failed_hresult_sanitized(self):
        with self.assertRaisesRegex(w.AdmissionError, '^SCHEDULER_OBSERVATION_FAILED$'):
            w._hresult(-2147024891)

    def test_dispatch_no_mutation_members(self):
        obj = w._Dispatch(None, None)
        for name in ('Run', 'RunEx', 'RegisterTask', 'DeleteTask'):
            with self.subTest(name=name), self.assertRaisesRegex(w.AdmissionError, 'SCHEDULER_METHOD_FORBIDDEN'):
                obj.read(name)

    def test_null_vtable_fails_closed(self):
        with self.assertRaises(w.AdmissionError): w._method(None, 5, ctypes.c_int32)

    def test_semantic_comparison_ignores_only_xml_format_hash(self):
        w.compare_task({'enabled': True, 'task_sd': 'a', 'folder_sd': 'b', 'xml_sha256': 'x'},
                       {'enabled': True, 'task_sd': 'a', 'folder_sd': 'b', 'xml_sha256': 'y'})
        for key in ('enabled', 'task_sd', 'folder_sd'):
            original = dict(enabled=True, task_sd='a', folder_sd='b')
            with self.subTest(key=key), self.assertRaises(w.AdmissionError):
                w.compare_task(original, dict(original, **{key: 'different'}))

    def test_xml_rejects_dtd_and_missing_fields(self):
        for xml in ('<!DOCTYPE x><x/>', '<x/>', '<broken'):
            with self.subTest(xml=xml), self.assertRaises(w.AdmissionError):
                w.task_observation(xml, True, 'sd', 'sd')


if __name__ == '__main__':
    unittest.main()


class Gate1AclRegressionTests(unittest.TestCase):
    def test_gate1_preserves_authority_container_and_file_split(self):
        d = w.expected_descriptor('authority', RUNTIME, BUILDER)
        runtime_aces = [a for a in d.aces if a.sid == RUNTIME]
        container = next(a for a in runtime_aces if a.flags == 0)
        forbidden = w.DELETE | 0x40 | w.WRITE_DAC | w.WRITE_OWNER | 0x4
        self.assertEqual(container.mask & forbidden, 0)
        files = next(a for a in runtime_aces if a.flags != 0)
        self.assertEqual(files.flags, w.OBJECT_INHERIT | w.INHERIT_ONLY)
        self.assertTrue(files.mask & w.DELETE)
        self.assertFalse(files.flags & 0x2)

    def test_gate1_builder_has_no_protected_root_or_task_grant(self):
        for kind in ('authority', 'captures', 'secrets', 'runtime', 'task', 'folder'):
            with self.subTest(kind=kind):
                d = w.expected_descriptor(kind, RUNTIME, BUILDER)
                self.assertTrue(d.protected)
                self.assertFalse(any(a.sid == BUILDER for a in d.aces))
        captures = w.expected_descriptor('captures', RUNTIME, BUILDER)
        ace = next(a for a in captures.aces if a.sid == RUNTIME)
        self.assertEqual(ace.mask & (w.DELETE | 0x40 | w.WRITE_DAC | w.WRITE_OWNER), 0)

    def test_gate1_contract_reuses_exact_provenance_identity(self):
        proof = provenance()
        proof.update(published_sha256=w.GATE1_PYTHON_SHA256,
                     calculated_sha256=w.GATE1_PYTHON_SHA256)
        w.validate_provenance(proof)
        proof['artifact_filename'] = 'python-3.14.10-embeddable-amd64.zip'
        with self.assertRaises(w.AdmissionError):
            w.validate_provenance(proof)
