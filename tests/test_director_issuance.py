"""Data contracts only. No real Director, Git, credentials or publication."""

import ast
from dataclasses import asdict, FrozenInstanceError, replace
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from orchestrator import director_issuance as ledger


def make_bindings(**changes):
    values = dict(schema_version=1, approval_id="approval-1", director_request_id="request-1",
                  project_id="SAMPLE", repository_identity="repo-1", task_id="T-1",
                  task_packet_sha256="a" * 64, builder_id="builder-1", action="git_publish_task_branch",
                  branch="task/test", candidate_head_sha="b" * 40, remote_name="origin",
                  effective_push_url="https://github.com/example/project.git", target_ref="refs/heads/task/test",
                  permissions_sha256="c" * 64, policies_sha256="d" * 64, gates_sha256="e" * 64,
                  director_profile_id="director-1", director_profile_version="v1")
    return ledger.ApprovalBindings(**dict(values, **changes))


class DirectorIssuanceModelTests(unittest.TestCase):
    def test_canonical_decision_and_operation_are_deterministic_data(self):
        bindings = make_bindings()
        intent = ledger.ApprovalIntent.from_bindings(bindings)
        self.assertEqual(intent, ledger.ApprovalIntent.from_bindings(make_bindings()))
        document = {"domain": "publication-decision-v1", "decision": "APPROVE", "bindings": asdict(bindings)}
        expected = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(ledger.canonical_bytes(document), expected)
        self.assertEqual(intent.decision_digest, hashlib.sha256(expected).hexdigest())
        self.assertNotEqual(intent.operation_key, intent.decision_digest)
        with self.assertRaises(FrozenInstanceError):
            bindings.approval_id = "changed"

    def test_invalid_identifiers_and_schema_version(self):
        for name in ("approval_id", "director_request_id", "project_id", "repository_identity", "task_id",
                     "builder_id", "director_profile_id", "director_profile_version"):
            for value in (None, 1, "", "x" * 65, "a/b", "a\n", "director@example.invalid"):
                with self.subTest(name=name, value=value), self.assertRaises(ledger.LedgerValidationError):
                    make_bindings(**{name: value})
        for value in (True, 0, 2, "1", None):
            with self.subTest(version=value), self.assertRaises(ledger.LedgerValidationError):
                make_bindings(schema_version=value)

    def test_invalid_hashes_and_internally_inconsistent_digests(self):
        for name, length in (("task_packet_sha256", 64), ("permissions_sha256", 64),
                             ("policies_sha256", 64), ("gates_sha256", 64), ("candidate_head_sha", 40)):
            for value in (None, "", "A" * length, "g" * length, "0" * length, "a" * (length - 1)):
                with self.subTest(name=name, value=value), self.assertRaises(ledger.LedgerValidationError):
                    make_bindings(**{name: value})
        intent = ledger.ApprovalIntent.from_bindings(make_bindings())
        for name in ("operation_key", "decision_digest"):
            for value in (None, "bad", "A" * 64, "0" * 64, "f" * 64):
                with self.subTest(name=name, value=value), self.assertRaises(ledger.LedgerValidationError):
                    replace(intent, **{name: value})

    def test_branch_ref_and_unknown_action_fail_closed(self):
        for branch in ("main", "master", "task/", "task//x", "task/.hidden", "task/a..b",
                       "task/x.lock", "task/x.", "task/a b", "task/a@{b", "task/x\\y", None):
            with self.subTest(branch=branch), self.assertRaises(ledger.LedgerValidationError):
                make_bindings(branch=branch)
        for changes in ({"target_ref": "refs/heads/task/other"}, {"action": "git_push"},
                        {"action": "git_install_candidate_authority"}, {"remote_name": "-origin"}):
            with self.subTest(changes=changes), self.assertRaises(ledger.LedgerValidationError):
                make_bindings(**changes)

    def test_invalid_urls_never_normalized_or_exposed(self):
        urls = ("http://github.com/o/r.git", "ssh://github.com/o/r.git", "https://secret@github.com/o/r.git",
                "https://github.com:443/o/r.git", "https://github.com/o/r.git?q=secret",
                "https://github.com/o/r.git#x", "https://github.com/o/../r.git", "https://github.com/o/r.git\n",
                None, "", "https://github.com/o/r")
        for url in urls:
            with self.subTest(url=url), self.assertRaisesRegex(ledger.LedgerValidationError, "^invalid ledger URL$"):
                make_bindings(effective_push_url=url)

    def test_new_approval_request_or_profile_cannot_change_operation_identity(self):
        original = make_bindings()
        for changes in ({"approval_id": "approval-2"}, {"director_request_id": "request-2"},
                        {"director_profile_id": "director-2"}, {"director_profile_version": "v2"}):
            other = make_bindings(**changes)
            self.assertEqual(ledger.operation_key(original), ledger.operation_key(other))
            self.assertNotEqual(ledger.decision_digest(original), ledger.decision_digest(other))

    def test_every_material_binding_changes_operation_identity(self):
        original = make_bindings()
        changes = ({"project_id": "OTHER"}, {"repository_identity": "repo-2"}, {"task_id": "T-2"},
                   {"task_packet_sha256": "f" * 64}, {"builder_id": "builder-2"},
                   {"branch": "task/other", "target_ref": "refs/heads/task/other"},
                   {"candidate_head_sha": "f" * 40}, {"remote_name": "other"},
                   {"effective_push_url": "https://github.com/example/other.git"},
                   {"permissions_sha256": "f" * 64}, {"policies_sha256": "f" * 64}, {"gates_sha256": "f" * 64})
        for change in changes:
            with self.subTest(change=change):
                other = make_bindings(**change)
                self.assertNotEqual(ledger.operation_key(original), ledger.operation_key(other))
                self.assertNotEqual(ledger.decision_digest(original), ledger.decision_digest(other))

    def test_fabricated_provenance_status_and_record_are_not_execution_approval(self):
        from orchestrator import app
        intent = ledger.ApprovalIntent.from_bindings(make_bindings())
        for fabricated in (intent, asdict(intent), "EXTERNAL_TRUSTED_DIRECTOR", "TECH_APPROVED", {"actor": "director"}):
            with self.subTest(value=type(fabricated).__name__), self.assertRaises(app.ControlledPublicationApprovalError):
                app.validate_controlled_publication_approval(fabricated, None, None, "a" * 64,
                                                            "builder-1", "b" * 40, "origin", "")
        for decision in ("DENY", "TECH_APPROVED", True, {"actor": "director"}):
            with self.assertRaises(ledger.LedgerValidationError):
                ledger.decision_digest(make_bindings(), decision)
        with self.assertRaises(TypeError):
            make_bindings(issuer_identity="director")
        with self.assertRaises(TypeError):
            make_bindings(issued_at="2020-01-01T00:00:00+00:00")

    def test_no_transport_credentials_or_app_wiring(self):
        tree = ast.parse(inspect.getsource(ledger))
        imports = {node.module if isinstance(node, ast.ImportFrom) else alias.name
                   for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                   for alias in node.names}
        self.assertEqual(imports, {"dataclasses", "hashlib", "json", "re"})
        app_source = (ROOT / "src/orchestrator/app.py").read_text(encoding="utf-8")
        self.assertNotIn("director_issuance", app_source)
        self.assertNotIn("issue_controlled_publication_approval", app_source)
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                mock.patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
            ledger.ApprovalIntent.from_bindings(make_bindings()).validate()


if __name__ == "__main__":
    unittest.main()
