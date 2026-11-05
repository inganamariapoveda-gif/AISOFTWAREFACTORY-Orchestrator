from dataclasses import replace
import hashlib
import itertools
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))
from orchestrator import trusted_runtime_foundation as foundation
from tests.test_trusted_request import request_bytes

SOURCE = r'C:\fixture-input'
DESTINATION = r'C:\fixture-copy'


class MemoryFileIO:
    """Fixture storage only: no Windows protection claim."""
    def __init__(self):
        self.files = {}
        self.ids = itertools.count(1)
        self.lock = threading.Lock()
        self.chunk_limit = 16385
        self.source_override = None
        self.after_override = None
        self.read_limit = None
        self.short_write = False
        self.flush_failure = False
        self.corrupt_copy = False
        self.exists_failure = False
        self.read_sizes = []
        self.open_count = 0

    def put(self, root, name, raw):
        self.files[(root, name)] = [bytes(raw), next(self.ids)]

    def open_read(self, root, name):
        if (root, name) not in self.files:
            raise foundation.CaptureError('SOURCE_INVALID')
        self.open_count += 1
        return dict(root=root, name=name, position=0, info_count=0)

    def create(self, root, name):
        with self.lock:
            if self.exists_failure or (root, name) in self.files:
                raise foundation.CaptureError('DESTINATION_EXISTS')
            self.put(root, name, b'')
        return self.open_read(root, name)

    def info(self, handle):
        raw, identity = self.files[(handle['root'], handle['name'])]
        value = foundation.FileObservation(1, identity, len(raw), 0x20, 1, 0)
        if handle['root'] == SOURCE:
            if self.source_override:
                value = replace(value, **self.source_override)
            if handle['info_count'] and self.after_override:
                value = replace(value, **self.after_override)
        handle['info_count'] += 1
        return value

    def read(self, handle, size):
        self.read_sizes.append(size)
        raw = self.files[(handle['root'], handle['name'])][0]
        if self.read_limit is not None and handle['root'] == SOURCE:
            raw = raw[:self.read_limit]
        start = handle['position']
        result = raw[start:start+min(size, self.chunk_limit)]
        handle['position'] += len(result)
        return result

    def write(self, handle, raw):
        count = max(0, len(raw)-1) if self.short_write else len(raw)
        self.files[(handle['root'], handle['name'])][0] = raw[:count]
        return count

    def flush(self, handle):
        if self.flush_failure:
            raise foundation.CaptureError('DESTINATION_FLUSH_FAILED')
        if self.corrupt_copy:
            key = (handle['root'], handle['name'])
            raw = self.files[key][0]
            self.files[key][0] = b'X' + raw[1:]

    def close(self, handle):
        self.open_count -= 1


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.io = MemoryFileIO()
        self.raw = request_bytes()
        self.io.put(SOURCE, 'request.json', self.raw)

    def capture(self):
        return foundation.capture_file(SOURCE, 'request.json', DESTINATION, io=self.io)

    def test_exact_bytes_generated_name_and_readback(self):
        result = self.capture()
        self.assertRegex(result.capture_id, '^[0-9a-f]{32}$')
        self.assertEqual(result.captured_sha256, hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result.captured_size, len(self.raw))
        self.assertEqual(self.io.files[(DESTINATION, result.filename)][0], self.raw)
        self.assertEqual(self.io.open_count, 0)
        self.assertFalse(any(hasattr(result, name) for name in ('trusted', 'protected', 'authority')))

    def test_filename_ads_traversal_device_and_unicode_rejected(self):
        for name in ('../x', r'a\b', 'x:ads', '', 'x\x00', r'\\server\x', r'\\?\x', 'CON', 'nul.txt',
                     'COM1.json', 'a'*97, 'a.', '\u00e9.json'):
            with self.subTest(name=name), self.assertRaises(foundation.CaptureError):
                foundation.capture_file(SOURCE, name, DESTINATION, io=self.io)
        self.assertEqual(len(self.io.files), 1)

    def test_directory_reparse_and_hardlink_rejected(self):
        for change in ({'attributes': 0x10}, {'attributes': 0x400}, {'links': 2}):
            self.io.source_override = change
            with self.subTest(change=change), self.assertRaises(foundation.CaptureError):
                self.capture()
        self.assertEqual(len(self.io.files), 1)
        self.assertEqual(self.io.open_count, 0)

    def test_oversize_from_handle(self):
        self.io.source_override = {'size': 16385}
        with self.assertRaisesRegex(foundation.CaptureError, '^SOURCE_TOO_LARGE$'):
            self.capture()
        self.assertEqual(self.io.read_sizes, [])

    def test_n_plus_one_bounded_even_when_size_observation_lies(self):
        self.io.put(SOURCE, 'request.json', b'x'*20000)
        self.io.source_override = {'size': 16384}
        with self.assertRaisesRegex(foundation.CaptureError, '^SOURCE_TOO_LARGE$'):
            self.capture()
        self.assertEqual(self.io.read_sizes, [16385])

    def test_short_reads_are_accumulated(self):
        self.io.chunk_limit = 3
        self.assertEqual(self.capture().captured_size, len(self.raw))
        self.assertEqual(self.io.open_count, 0)

    def test_premature_eof_is_not_success(self):
        self.io.read_limit = len(self.raw)-1
        with self.assertRaisesRegex(foundation.CaptureError, '^CAPTURE_SOURCE_CHANGED$'):
            self.capture()
        self.assertEqual(len(self.io.files), 1)

    def test_source_identity_size_attribute_link_or_timestamp_change(self):
        for change in ({'file_id': 999}, {'volume': 9}, {'size': 1}, {'attributes': 0}, {'links': 2}, {'last_write': 1}):
            self.io.after_override = change
            with self.subTest(change=change), self.assertRaisesRegex(foundation.CaptureError, '^CAPTURE_SOURCE_CHANGED$'):
                self.capture()
        self.assertEqual(len(self.io.files), 1)

    def test_destination_exists_never_overwritten(self):
        self.io.exists_failure = True
        with self.assertRaisesRegex(foundation.CaptureError, '^DESTINATION_EXISTS$'):
            self.capture()
        self.assertEqual(len(self.io.files), 1)

    def test_short_write_retained_without_success(self):
        self.io.short_write = True
        with self.assertRaisesRegex(foundation.CaptureError, '^DESTINATION_WRITE_FAILED$'):
            self.capture()
        self.assertEqual(len(self.io.files), 2)
        self.assertEqual(self.io.open_count, 0)

    def test_flush_failure_retained_without_success(self):
        self.io.flush_failure = True
        with self.assertRaisesRegex(foundation.CaptureError, '^DESTINATION_FLUSH_FAILED$'):
            self.capture()
        self.assertEqual(len(self.io.files), 2)
        self.assertEqual(self.io.open_count, 0)

    def test_readback_mismatch_fails(self):
        self.io.corrupt_copy = True
        with self.assertRaisesRegex(foundation.CaptureError, '^COPY_INTEGRITY_FAILURE$'):
            self.capture()

    def test_reopen_substitution_even_with_identical_bytes_fails(self):
        original = self.io.open_read
        def substituted(root, name):
            if root == DESTINATION and self.io.files[(root, name)][0]:
                self.io.files[(root, name)][1] = 999
            return original(root, name)
        with mock.patch.object(self.io, 'open_read', side_effect=substituted):
            with self.assertRaisesRegex(foundation.CaptureError, '^COPY_INTEGRITY_FAILURE$'):
                self.capture()

    def test_unsupported_platform_has_no_fallback(self):
        with mock.patch.object(foundation.os, 'name', 'posix'):
            with self.assertRaisesRegex(foundation.CaptureError, '^CAPTURE_UNAVAILABLE$'):
                foundation.WindowsFileIO()


class WindowsAPIContractTests(unittest.TestCase):
    def setUp(self):
        self.api = mock.Mock()
        self.api.CreateFileW.return_value = 7
        with mock.patch.object(foundation.os, 'name', 'nt'), \
                mock.patch.object(foundation.ctypes, 'WinDLL', return_value=self.api, create=True) as loader:
            self.io = foundation.WindowsFileIO()
        loader.assert_called_once_with('kernel32.dll', use_last_error=True, winmode=0x800)

    def test_source_open_flags_no_write_delete_sharing_or_inheritance(self):
        self.assertEqual(self.io.open_read(SOURCE, 'request.json'), 7)
        args = self.api.CreateFileW.call_args.args
        self.assertEqual(args[1:], (0x80000000, 1, None, 3, 0x00200000 | 0x02000000, None))

    def test_destination_create_new_never_replace(self):
        self.io.create(DESTINATION, 'a'*32+'.bin')
        args = self.api.CreateFileW.call_args.args
        self.assertEqual(args[1:], (0xC0000000, 0, None, 1, 0x00200000, None))

    def test_non_disk_handle_is_rejected(self):
        self.api.GetFileType.return_value = 2
        with self.assertRaisesRegex(foundation.CaptureError, '^SOURCE_INVALID$'):
            self.io.info(7)
        self.api.GetFileInformationByHandle.assert_not_called()

    def test_create_error_is_fixed_and_file_exists_is_distinguished(self):
        self.api.CreateFileW.return_value = foundation.ctypes.c_void_p(-1).value
        for value, code in ((183, 'DESTINATION_EXISTS'), (5, 'DESTINATION_WRITE_FAILED')):
            with mock.patch.object(foundation.ctypes, 'get_last_error', return_value=value, create=True):
                with self.assertRaisesRegex(foundation.CaptureError, '^'+code+'$'):
                    self.io.create(DESTINATION, 'a'*32+'.bin')


@unittest.skipUnless(os.name == 'nt', 'Windows ordinary file mechanics only')
class WindowsOrdinaryFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / 'source'
        self.destination = Path(temporary.name) / 'copies'
        self.source.mkdir()
        self.destination.mkdir()
        (self.source / 'request.json').write_bytes(request_bytes())

    def test_native_capture_readback_and_no_overwrite(self):
        evidence = foundation.capture_file(str(self.source), 'request.json', str(self.destination))
        self.assertEqual((self.destination/evidence.filename).read_bytes(), request_bytes())
        with mock.patch.object(foundation.uuid, 'uuid4', return_value=mock.Mock(hex=evidence.capture_id)):
            with self.assertRaisesRegex(foundation.CaptureError, '^DESTINATION_EXISTS$'):
                foundation.capture_file(str(self.source), 'request.json', str(self.destination))

    def test_native_directory_and_hardlink_rejection(self):
        (self.source / 'directory').mkdir()
        os.link(self.source / 'request.json', self.source / 'linked.json')
        for name in ('directory', 'linked.json'):
            with self.subTest(name=name), self.assertRaises(foundation.CaptureError):
                foundation.capture_file(str(self.source), name, str(self.destination))

    def test_native_writer_sharing_conflict(self):
        with (self.source / 'request.json').open('r+b'):
            with self.assertRaises(foundation.CaptureError):
                foundation.capture_file(str(self.source), 'request.json', str(self.destination))


class RuntimeObservationTests(unittest.TestCase):
    def setUp(self):
        self.layout = foundation.RuntimeLayout(r'C:\installed\python.exe', r'C:\installed\code', r'C:\authority\work',
                                               (r'C:\installed\code', r'C:\installed\Lib'), (r'C:\checkout',), (r'C:\project-venv',))
        self.observation = foundation.RuntimeObservation(self.layout.interpreter, self.layout.code_root, self.layout.cwd,
                                                         self.layout.module_roots, False, True, True, False, ())

    def test_consistency_is_not_authority(self):
        self.assertEqual(foundation.validate_runtime_observation(self.observation, self.layout), 'CONSISTENT')
        self.assertEqual(foundation.validate_runtime_observation({'trusted': True}, self.layout), 'REJECTED')

    def test_checkout_project_venv_relative_and_prefix_trick_rejected(self):
        for path in (r'C:\checkout', r'C:\checkout\src', r'C:\project-venv\Lib', '.', '', 'relative',
                     r'C:\installed\code-evil', r'C:\installed\code\..\other', 'C:\\'):
            with self.subTest(path=path):
                self.assertEqual(foundation.validate_runtime_observation(replace(self.observation, sys_path=(path,)), self.layout), 'REJECTED')

    def test_user_site_pythonpath_and_isolation_observations_rejected(self):
        for change in ({'user_site_enabled': True}, {'isolated': False}, {'ignore_environment': False},
                       {'pythonpath_present': True}, {'editable_paths': (r'C:\editable',)}, {'isolated': 1},
                       {'interpreter': 'python.exe'}, {'cwd': r'C:\checkout'}):
            with self.subTest(change=change):
                self.assertEqual(foundation.validate_runtime_observation(replace(self.observation, **change), self.layout), 'REJECTED')


if __name__ == '__main__':
    unittest.main()
