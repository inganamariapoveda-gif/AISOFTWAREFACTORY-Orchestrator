import ast
from dataclasses import asdict, FrozenInstanceError
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from orchestrator import director_issuance as ledger
from orchestrator import trusted_request as request
from tests.test_director_issuance import make_bindings


def request_values(**changes):
    bindings = make_bindings()
    values = {key: getattr(bindings, key) for key in ledger.OPERATION_FIELDS}
    values["request_id"] = "request-1"
    return dict(values, **changes)


def request_bytes(**changes):
    return ledger.canonical_bytes(request_values(**changes))


class TrustedRequestTests(unittest.TestCase):
    def rejected(self, raw):
        with self.assertRaises(request.RequestError) as caught:
            request.parse_captured_request(raw)
        self.assertIn(str(caught.exception), {"INVALID_JSON", "INVALID_SCHEMA", "INVALID_ENCODING", "INVALID_SIZE"})
        self.assertTrue(caught.exception.__cause__ is None)
        return caught.exception

    def test_valid_exact_request_immutable_data_and_independent_digest(self):
        raw = request_bytes()
        value = request.parse_captured_request(raw)
        self.assertEqual(asdict(value), request_values())
        with self.assertRaises(FrozenInstanceError):
            value.request_id = "changed"
        expected = json.dumps(dict(domain="trusted-publication-request-v1",
                                   captured_sha256=hashlib.sha256(raw).hexdigest(), request=request_values()),
                              sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        self.assertEqual(request.request_digest(raw), hashlib.sha256(expected).hexdigest())

    def test_unknown_and_authority_execution_keys_rejected(self):
        for key in ("extra", "approved", "decision", "director_response", "credential", "executable", "command",
                    "argv", "environment", "config_path", "db_path", "module", "plugin", "script", "trusted", "protected"):
            with self.subTest(key=key):
                self.rejected(json.dumps(dict(request_values(), **{key: "secret sentinel"})).encode())

    def test_every_missing_key_rejected(self):
        for key in request.REQUEST_FIELDS:
            values = request_values()
            del values[key]
            with self.subTest(key=key):
                self.rejected(json.dumps(values).encode())

    def test_duplicate_keys_never_reserve_observed_id(self):
        for suffix in (b',"request_id":"other"}', b',"action":"other"}'):
            error = self.rejected(request_bytes()[:-1] + suffix)
            self.assertIsNone(error.request_id)

    def test_wrong_types_bool_as_int_and_top_level(self):
        for key in request.REQUEST_FIELDS:
            for value in (None, True, [], {}, 1.0):
                with self.subTest(key=key, value=value):
                    self.rejected(json.dumps(request_values(**{key: value})).encode())
        for raw in (b'[]', b'null', b'1', b'"object"', b'', b'false'):
            self.rejected(raw)

    def test_bom_and_invalid_utf8(self):
        self.rejected(b'\xef\xbb\xbf' + request_bytes())
        self.rejected(b'\xff' + request_bytes())
        self.rejected(request_bytes().decode().encode('utf-16'))

    def test_nan_infinity_float_and_large_integer(self):
        for number in (b'NaN', b'Infinity', b'-Infinity', b'1.0', b'1e0', b'1' * 8000):
            self.rejected(request_bytes().replace(b'"schema_version":1', b'"schema_version":' + number))

    def test_size_and_pathological_depth_bound_before_decode(self):
        self.rejected(b' ' * (request.MAX_REQUEST_BYTES + 1))
        self.rejected(b'[' * 4000 + b']' * 4000)
        self.rejected(bytearray(request_bytes()))
        self.assertEqual(request.parse_captured_request(request_bytes() + b' ' * (16384-len(request_bytes()))).request_id, 'request-1')

    def test_invalid_hashes_branch_ref_url_and_identifiers(self):
        cases = ({"branch": "task/../x"}, {"target_ref": "refs/heads/main"}, {"candidate_head_sha": "A" * 40},
                 {"task_packet_sha256": "0" * 64}, {"policies_sha256": "bad"},
                 {"effective_push_url": "https://secret@github.com/o/r.git"},
                 {"request_id": "../x"}, {"repository_identity": "C:\\repo"}, {"task_id": "x:ads"},
                 {"builder_id": "\u00e9"}, {"remote_name": "a" * 65}, {"action": "git_push"},
                 {"schema_version": "1"}, {"schema_version": 2})
        for values in cases:
            with self.subTest(values=values):
                self.rejected(request_bytes(**values))

    def test_byte_differences_remain_distinct_without_normalization(self):
        first, other = request_bytes(), json.dumps(request_values()).encode()
        self.assertEqual(request.parse_captured_request(first), request.parse_captured_request(other))
        self.assertNotEqual(request.request_digest(first), request.request_digest(other))
        for value in (' request-1', 'request-1 ', 'request\n1'):
            self.rejected(request_bytes(request_id=value))

    def test_material_helper_compatible_without_fake_approval(self):
        bindings = make_bindings()
        payload = {key: getattr(bindings, key) for key in ledger.OPERATION_FIELDS}
        expected = hashlib.sha256(json.dumps({"domain": "publication-operation-v1", "bindings": payload},
                                            sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(ledger.operation_key(bindings), expected)
        self.assertEqual(ledger.material_operation_key(payload), expected)
        self.assertEqual(request.parse_captured_request(request_bytes()).operation_key, expected)
        self.assertEqual(request.parse_captured_request(request_bytes(request_id='other')).operation_key, expected)
        with self.assertRaises(ledger.LedgerValidationError):
            ledger.material_operation_key(dict(payload, approved=True))

    def test_invalid_schema_preserves_only_unambiguous_valid_request_id(self):
        self.assertEqual(self.rejected(request_bytes(action='wrong')).request_id, 'request-1')
        self.assertIsNone(self.rejected(request_bytes(request_id='../invalid')).request_id)

    def test_pure_request_module_no_transport_or_approval_construction(self):
        source = inspect.getsource(request)
        tree = ast.parse(source)
        imports = {n.module if isinstance(n, ast.ImportFrom) else a.name
                   for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        self.assertEqual(imports, {'dataclasses', 'hashlib', 'json', 'director_issuance'})
        self.assertNotIn('ApprovalBindings(', source)
        self.assertNotIn('ApprovalIntent(', source)


if __name__ == '__main__':
    unittest.main()
