"""Offline contract checks; no credentials or real dispatch."""

import ast
import copy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")) if str(ROOT / "src") not in sys.path else None

from orchestrator import github_actions_backend as backend
from orchestrator.config_loader import ConfigError


class GitHubBackendContractTests(unittest.TestCase):
    def setUp(self):
        self.policies = yaml.safe_load((ROOT / "config/POLICIES.yaml").read_text(encoding="utf-8"))

    def test_valid_disabled_configuration(self):
        config = backend.GitHubBackendConfig.from_policies(self.policies)
        self.assertEqual(config.activation, "disabled")
        self.assertEqual(config.mvp, "fine_grained_pat_dpapi")
        self.assertEqual(config.production_required, "github_app_installation_token")
        self.assertEqual(config.github_app_required_before,
                         ("production", "multi_client", "commercial_external_customer"))
        self.assertFalse(hasattr(config, "execute"))
        with self.assertRaises(FrozenInstanceError):
            config.activation = "enabled"

    def test_every_fixed_value_rejects_changes(self):
        config = backend.GitHubBackendConfig.from_policies(self.policies)
        for name, value in (
            ("provider", "other"), ("activation", "enabled"),
            ("repository", "other/repo"), ("workflow_id", "other.yml"),
            ("workflow_ref", "task/example"), ("api_version", "2022-11-28"),
            ("return_run_details", False), ("return_run_details", 1),
            ("mvp", "plain_pat"), ("production_required", "fine_grained_pat_dpapi"),
            ("github_app_required_before", ("production",)),
        ):
            with self.subTest(name=name, value=value), self.assertRaises(ConfigError):
                replace(config, **{name: value})

    def test_missing_config_is_unavailable(self):
        with self.assertRaises(ConfigError):
            backend.GitHubBackendConfig.from_policies({})

    def test_unknown_or_secret_config_fields_rejected(self):
        for location in ((), ("github",), ("credential_strategy",)):
            policies = copy.deepcopy(self.policies)
            node = policies["safe_test_backend"]
            for key in location:
                node = node[key]
            node["token"] = "SENTINEL"
            with self.subTest(location=location), self.assertRaises(ConfigError) as error:
                backend.GitHubBackendConfig.from_policies(policies)
            self.assertNotIn("SENTINEL", str(error.exception))

    def test_digest_stable_compact_utf8_json(self):
        argv = ("python", "\u00f1", "a b", ";literal")
        expected = hashlib.sha256(json.dumps(list(argv), ensure_ascii=False,
                                            separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(backend.argv_sha256(argv), expected)
        self.assertEqual(backend.argv_sha256(argv), backend.argv_sha256(tuple(argv)))

    def test_digest_distinguishes_order_quantity_content_and_boundaries(self):
        cases = [("a", "b"), ("b", "a"), ("a", "b", "c"), ("a", "c"),
                 ("a b", "c"), ("a", "b c"), ("a b c",)]
        self.assertEqual(len({backend.argv_sha256(argv) for argv in cases}), len(cases))

    def test_digest_rejects_flattened_or_malformed_argv(self):
        for argv in ("python test.py", [], (), (1,), (None,)):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                backend.argv_sha256(argv)

    def test_dispatch_has_only_fixed_control_and_three_identity_inputs(self):
        request = backend.DispatchRequest("a" * 40, "unit", "b" * 64)
        self.assertEqual(request.to_payload(), {
            "ref": "main", "return_run_details": True,
            "inputs": {"candidate_sha": "a" * 40, "logical_test_id": "unit", "argv_sha256": "b" * 64},
        })
        with self.assertRaises(FrozenInstanceError):
            request.workflow_ref = "other"
        for key in ("argv", "token", "stdout", "stderr", "secret"):
            with self.subTest(key=key), self.assertRaises(TypeError):
                backend.DispatchRequest("a" * 40, "unit", "b" * 64, **{key: "SENTINEL"})

    def test_dispatch_identity_and_control_validation(self):
        request = backend.DispatchRequest("a" * 40, "unit", "b" * 64)
        for key, value in (("candidate_sha", "A" * 40), ("candidate_sha", "main"),
                           ("logical_test_id", "unit;evil"), ("argv_sha256", "x" * 64),
                           ("workflow_ref", "other"), ("return_run_details", 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(request, **{key: value})

    def test_response_and_snapshot_are_immutable_without_approval_or_credentials(self):
        response = backend.DispatchResponse(1, "run", "html")
        snapshot = backend.WorkflowRunSnapshot(1, "workflow_dispatch", "completed", "success",
                                               "a" * 40, 1)
        for value in (response, snapshot):
            names = {field.name for field in fields(value)}
            self.assertFalse(names & {"token", "secret", "credential", "technical_review", "security_review"})
            with self.assertRaises(FrozenInstanceError):
                setattr(value, next(iter(names)), None)

    def test_no_transport_or_execution_implementation(self):
        source = Path(backend.__file__).read_text(encoding="utf-8")
        module = ast.parse(source)
        imports = {alias.name.split(".")[0] for node in ast.walk(module)
                   if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module.split(".")[0] for node in ast.walk(module)
                    if isinstance(node, ast.ImportFrom) and node.module}
        self.assertEqual(imports, {"dataclasses", "hashlib", "json", "re", "typing", "config_loader"})
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            config = backend.GitHubBackendConfig.from_policies(self.policies)
            backend.DispatchRequest("a" * 40, "unit", backend.argv_sha256(("python",))).to_payload()
        self.assertEqual(config.activation, "disabled")
        self.assertNotRegex(source, r"gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9]+")


if __name__ == "__main__":
    unittest.main()
