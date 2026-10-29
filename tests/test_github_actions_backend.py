"""Offline contract checks; no credentials or real dispatch."""

import ast
import copy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
from pathlib import Path
import sys
import traceback
import warnings
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

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
        self.assertEqual(config.workflow_ref, "safe-test-runner-v1")
        self.assertEqual(config.workflow_source_sha, "db38ef6e6cbc73d8e54b591d4f0eb747073d500b")
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
            ("workflow_ref", "task/example"), ("workflow_source_sha", "a" * 40), ("api_version", "2022-11-28"),
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

    def test_dispatch_contains_only_candidate_and_test_identity(self):
        request = backend.DispatchRequest("a" * 40, "unit", "b" * 64)
        self.assertEqual({f.name for f in fields(request)},
                         {"candidate_sha", "logical_test_id", "argv_sha256"})
        with self.assertRaises(FrozenInstanceError):
            request.candidate_sha = "c" * 40
        for key in ("workflow_ref", "workflow_source_sha", "return_run_details",
                    "argv", "token", "stdout", "stderr", "secret"):
            with self.subTest(key=key), self.assertRaises(TypeError):
                backend.DispatchRequest("a" * 40, "unit", "b" * 64, **{key: "SENTINEL"})

    def test_dispatch_identity_and_control_validation(self):
        request = backend.DispatchRequest("a" * 40, "unit", "b" * 64)
        for key, value in (("candidate_sha", "A" * 40), ("candidate_sha", "main"),
                           ("logical_test_id", "unit;evil"), ("argv_sha256", "x" * 64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(request, **{key: value})

    def test_response_and_snapshot_are_immutable_without_approval_or_credentials(self):
        response = backend.DispatchResponse(1, backend._run_url(1),
                                            f"https://github.com/{backend.REPOSITORY}/actions/runs/1")
        snapshot = backend.WorkflowRunSnapshot(1, "workflow_dispatch", "completed", "success",
                                               "db38ef6e6cbc73d8e54b591d4f0eb747073d500b", 1, 7, backend.REPOSITORY)
        for value in (response, snapshot):
            names = {field.name for field in fields(value)}
            self.assertFalse(names & {"token", "secret", "credential", "technical_review", "security_review"})
            with self.assertRaises(FrozenInstanceError):
                setattr(value, next(iter(names)), None)

    def test_disconnected_stdlib_transport_has_no_credential_storage_or_shell(self):
        source = Path(backend.__file__).read_text(encoding="utf-8")
        module = ast.parse(source)
        imports = {alias.name.split(".")[0] for node in ast.walk(module)
                   if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module.split(".")[0] for node in ast.walk(module)
                    if isinstance(node, ast.ImportFrom) and node.module}
        self.assertEqual(imports, {"dataclasses", "hashlib", "json", "re", "typing", "config_loader",
                                  "math", "time", "urllib"})
        self.assertNotRegex(source, r"getenv|environ\b|subprocess|requests|httpx|aiohttp|DPAPI|gh CLI")
        self.assertNotRegex(source, r"/runs[\"']|/runs\?|/runs/latest")
        self.assertFalse(hasattr(backend.GitHubActionsTransport, "execute"))
        self.assertEqual(backend.GitHubActionsTransport.__bases__, (object,))
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            config = backend.GitHubBackendConfig.from_policies(self.policies)
            backend.DispatchRequest("a" * 40, "unit", backend.argv_sha256(("python",)))
        self.assertEqual(config.activation, "disabled")
        self.assertNotRegex(source, r"gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9]+")


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        self.sleeps.append(duration)
        self.now += duration


class FakeResponse:
    def __init__(self, payload, *, status=200, url=None, raw=None):
        self.body = json.dumps(payload).encode("utf-8") if raw is None else raw
        self.status = status
        self.url = url
        self.read_sizes = []
        self.closed = False
        self.cursor = 0

    def geturl(self):
        return self.url

    def read(self, size):
        self.read_sizes.append(size)
        chunk = self.body[self.cursor:self.cursor + size]
        self.cursor += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class FakeOpener:
    def __init__(self, responses, clock, duration=0):
        self.responses = list(responses)
        self.clock = clock
        self.duration = duration
        self.calls = []

    def open(self, request, *, timeout):
        self.calls.append((request, timeout, self.clock.now))
        self.clock.now += self.duration
        if not self.responses:
            raise AssertionError("Unexpected HTTP call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if response.url is None:
            response.url = request.full_url
        return response


class GitHubActionsTransportTests(unittest.TestCase):
    def setUp(self):
        # Every test denies sockets even if an injection is accidentally omitted.
        for target in ("socket.socket", "socket.create_connection"):
            patcher = mock.patch(target, side_effect=AssertionError("Real network forbidden"))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.config = backend.GitHubBackendConfig.from_policies(yaml.safe_load(
            (ROOT / "config/POLICIES.yaml").read_text(encoding="utf-8")))
        self.request = backend.DispatchRequest("a" * 40, "safe_runner_smoke_v1",
                                             "07e2764d9cb675f8894363f08ae9a52e7e6ebdbef8092a60a2ec403dc6fdd601")
        self.workflow_url = f"{backend.API_BASE}/repos/{backend.REPOSITORY}/actions/workflows/safe-test-runner.yml"
        self.workflow_sha = "db38ef6e6cbc73d8e54b591d4f0eb747073d500b"
        self.ref_url = f"{backend.API_BASE}/repos/{backend.REPOSITORY}/git/ref/tags/safe-test-runner-v1"
        self.run_id = 431
        self.run_url = f"{backend.API_BASE}/repos/{backend.REPOSITORY}/actions/runs/{self.run_id}"
        self.html_url = f"https://github.com/{backend.REPOSITORY}/actions/runs/{self.run_id}"
        self.token = "OFFLINE_SENTINEL_CREDENTIAL_029B2"
        self.provider = mock.Mock(return_value=self.token)
        self.clock = FakeClock()

    def metadata(self, **changes):
        return dict({"id": 17, "path": backend.WORKFLOW_PATH, "state": "active"}, **changes)

    def source_ref(self):
        return {"ref": "refs/tags/safe-test-runner-v1", "object": {"type": "commit", "sha": self.workflow_sha}}

    def test_distinct_workflow_and_candidate_identity(self):
        result, _, opener = self.invoke(self.valid_responses())
        self.assertEqual(result.head_sha, self.workflow_sha)
        self.assertEqual(json.loads(opener.calls[2][0].data)["inputs"]["candidate_sha"], "a" * 40)
        self.assertNotEqual(result.head_sha, self.request.candidate_sha)

    def test_call_cannot_override_configured_workflow_source(self):
        for key in ("expected_workflow_sha", "workflow_source_sha", "workflow_ref", "return_run_details"):
            transport, opener = self.transport([])
            with self.subTest(key=key), self.assertRaises(TypeError):
                transport.dispatch_and_wait(self.request, **{key: "SENTINEL"},
                    request_timeout_seconds=5, overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertFalse(opener.calls)
        self.assertEqual(self.provider.call_count, 0)

    def test_invalid_source_ref_blocks_before_post(self):
        bad = [None, [], {}, {"ref": "refs/tags/safe-test-runner-v1"}]
        for ref in ("main", "refs/heads/main", "refs/heads/other", "refs/tags/other", None):
            value = self.source_ref()
            value["ref"] = ref
            bad.append(value)
        for obj in (None, [], {}, {"type": "tree", "sha": self.workflow_sha}, {"type": "tag", "sha": self.workflow_sha},
                    *({"type": "commit", "sha": sha} for sha in
                      (True, None, "B" * 40, "b" * 39, "a" * 40))):
            bad.append({"ref": "refs/tags/safe-test-runner-v1", "object": obj})
        for value in bad:
            transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(value)])
            with self.subTest(value=value), self.assertRaises(backend.GitHubTransportError):
                transport.dispatch_and_wait(self.request,
                    request_timeout_seconds=5, overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertEqual([c[0].full_url for c in opener.calls], [self.workflow_url, self.ref_url])
            self.assertEqual([c[0].method for c in opener.calls], ["GET", "GET"])

    def dispatch(self, **changes):
        return dict({"workflow_run_id": self.run_id, "run_url": self.run_url,
                     "html_url": self.html_url}, **changes)

    def run_data(self, **changes):
        return dict({"id": self.run_id, "event": "workflow_dispatch", "status": "completed",
                     "conclusion": "success", "head_sha": self.workflow_sha, "run_attempt": 1,
                     "workflow_id": 17,
                     "repository": {"full_name": backend.REPOSITORY}}, **changes)

    def transport(self, responses, *, duration=0):
        opener = FakeOpener(responses, self.clock, duration)
        transport = backend.GitHubActionsTransport(self.config, self.provider, opener=opener,
                                                   monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        return transport, opener

    def invoke(self, responses, **timeouts):
        transport, opener = self.transport(responses)
        result = transport.dispatch_and_wait(self.request, **dict({"request_timeout_seconds": 5,
            "overall_timeout_seconds": 20, "poll_interval_seconds": 1}, **timeouts))
        return result, transport, opener

    def expected_payload(self):
        return {"ref": "safe-test-runner-v1", "return_run_details": True,
                "inputs": {"candidate_sha": self.request.candidate_sha,
                           "logical_test_id": self.request.logical_test_id,
                           "argv_sha256": self.request.argv_sha256,
                           "workflow_source_sha": self.workflow_sha}}

    def valid_responses(self, *runs):
        return [FakeResponse(self.metadata()), FakeResponse(self.source_ref()), FakeResponse(self.dispatch()),
                *(FakeResponse(value) for value in (runs or (self.run_data(),)))]

    def test_exact_request_headers_body_and_returned_id_endpoints(self):
        result, transport, opener = self.invoke(self.valid_responses())
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.config.activation, "disabled")
        self.assertFalse(hasattr(transport, "execute"))
        self.assertEqual([call[0].full_url for call in opener.calls],
                         [self.workflow_url, self.ref_url, self.workflow_url + "/dispatches", self.run_url])
        self.assertEqual([call[0].method for call in opener.calls], ["GET", "GET", "POST", "GET"])
        for req, timeout, started in opener.calls:
            headers = {key.lower(): value for key, value in req.header_items()}
            expected = {"accept": "application/vnd.github+json", "authorization": "Bearer " + self.token,
                        "x-github-api-version": "2026-03-10", "user-agent": "AISOFTWAREFACTORY-Orchestrator"}
            if req.method == "POST":
                expected["content-type"] = "application/json"
            self.assertEqual(headers, expected)
            self.assertGreater(timeout, 0)
        self.assertEqual(opener.calls[2][0].data, json.dumps(
            self.expected_payload(), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        self.assertEqual(self.provider.call_count, 4)

    def test_http_helper_rejects_destinations_before_credential(self):
        bad_urls = [
            self.workflow_url.replace("api.github.com", "evil.invalid"),
            self.workflow_url.replace("https://", "http://"),
            self.workflow_url.replace("api.github.com", "api.github.com.evil.invalid"),
            self.workflow_url.replace("api.github.com", "user@api.github.com"),
            self.workflow_url.replace("api.github.com", "api.github.com:443"),
            self.workflow_url + "?x=1", self.workflow_url + "#fragment",
            self.workflow_url + "/", "https://evil.invalid/arbitrary",
            self.workflow_url.replace("safe-test-runner.yml", "other.yml"),
            self.ref_url.replace("/git/ref/", "/git/refs/"),
            self.ref_url.replace("tags/safe-test-runner-v1", "heads/main"),
            self.ref_url.replace("safe-test-runner-v1", "other"),
            self.ref_url + "?x=1", self.ref_url + "#fragment", self.ref_url + "/",
            self.ref_url.replace("api.github.com", "api.github.com:443"),
            self.ref_url.replace("api.github.com", "user@api.github.com"),
            self.ref_url.replace("api.github.com", "evil.invalid"),
            self.ref_url.replace("https://", "http://"),
            self.run_url.rsplit("/", 1)[0], None, True, 1,
        ]
        run_prefix = self.run_url.rsplit("/", 1)[0] + "/"
        bad_urls += [run_prefix + value for value in
                     ("0", "-1", "abc", "1.0", "+1", "01", "١", "1/", "1?x=1", "1#x", "1\n")]
        for url in bad_urls:
            for payload in (None, {}):
                provider = mock.Mock(return_value=self.token)
                transport, opener = self.transport([])
                transport._credential_provider = provider
                with self.subTest(url=url, payload=payload), self.assertRaises(backend.GitHubTransportError) as error:
                    transport._request(url, payload, 20, 5)
                self.assertEqual(str(error.exception), "HTTP destination or operation rejected")
                self.assertEqual(provider.call_count, 0)
                self.assertEqual(opener.calls, [])

    def test_http_helper_binds_method_to_endpoint_before_credential(self):
        for url, payload in ((self.workflow_url + "/dispatches", None),
                             (self.workflow_url, {}), (self.ref_url, {}), (self.run_url, {})):
            transport, opener = self.transport([])
            with self.subTest(url=url), self.assertRaises(backend.GitHubTransportError) as error:
                transport._request(url, payload, 20, 5)
            self.assertEqual(str(error.exception), "HTTP destination or operation rejected")
            self.assertEqual(self.provider.call_count, 0)
            self.assertEqual(opener.calls, [])

    def test_http_helper_accepts_only_four_approved_operations(self):
        for url, payload, method in ((self.workflow_url, None, "GET"),
                                     (self.ref_url, None, "GET"),
                                     (self.workflow_url + "/dispatches", {}, "POST"),
                                     (self.run_url, None, "GET")):
            transport, opener = self.transport([FakeResponse({})])
            before = self.provider.call_count
            with self.subTest(url=url):
                self.assertEqual(transport._request(url, payload, 20, 5), {})
                self.assertEqual(self.provider.call_count, before + 1)
                self.assertEqual(len(opener.calls), 1)
                self.assertEqual(opener.calls[0][0].full_url, url)
                self.assertEqual(opener.calls[0][0].method, method)

    def test_workflow_metadata_rejected_before_dispatch(self):
        for key, value in (("id", True), ("id", 0), ("id", -1), ("id", "17"), ("id", 1.0),
                           ("path", "other.yml"), ("state", "disabled_manually"), ("state", None)):
            transport, opener = self.transport([FakeResponse(self.metadata(**{key: value}))])
            with self.subTest(key=key, value=value), self.assertRaises(backend.GitHubTransportError):
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertEqual(len(opener.calls), 1)

    def test_dispatch_response_invalid_identity_rejected(self):
        for key, value in (("workflow_run_id", True), ("workflow_run_id", 0), ("workflow_run_id", -1),
                           ("workflow_run_id", "431"), ("workflow_run_id", 431.0),
                           ("run_url", self.run_url + "/"), ("run_url", "https://evil.invalid"),
                           ("html_url", self.html_url + "?x=1")):
            transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(self.source_ref()),
                                                FakeResponse(self.dispatch(**{key: value}))])
            with self.subTest(key=key, value=value), self.assertRaises(backend.GitHubTransportError):
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertEqual(len(opener.calls), 3)
            with self.assertRaises(backend.GitHubTransportError):
                backend.DispatchResponse(**self.dispatch(**{key: value}))

    def test_wrong_run_identity_is_rejected_immediately_even_when_queued(self):
        for key, value in (("id", 432), ("id", True), ("event", "push"), ("head_sha", "a" * 40),
                           ("workflow_id", 18), ("workflow_id", True),
                           ("repository", {"full_name": "other/repo"}), ("repository", None),
                           ("run_attempt", 2), ("run_attempt", True), ("run_attempt", 1.0)):
            responses = self.valid_responses(self.run_data(status="queued", conclusion=None, **{key: value}))
            transport, opener = self.transport(responses)
            with self.subTest(key=key, value=value), self.assertRaises(backend.GitHubTransportError):
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertEqual(len(opener.calls), 4)
            self.assertFalse(self.clock.sleeps)

    def test_missing_each_required_run_field_fails_closed(self):
        for field in self.run_data():
            run = self.run_data()
            del run[field]
            with self.subTest(field=field), self.assertRaises(backend.GitHubTransportError):
                self.invoke(self.valid_responses(run))

    def test_run_path_and_head_branch_are_not_source_authority(self):
        for extra in ({}, {"path": None, "head_branch": None},
                      {"path": "undocumented-tag-format", "head_branch": "anything"}):
            result, _, _ = self.invoke(self.valid_responses(self.run_data(**extra)))
            self.assertEqual(result.head_sha, self.workflow_sha)
            self.assertFalse({f.name for f in fields(result)} & {"path", "head_branch"})

    def test_all_known_nonterminal_states_poll_same_run(self):
        runs = [self.run_data(status=status, conclusion=None)
                for status in ("queued", "in_progress", "requested", "waiting", "pending")]
        result, _, opener = self.invoke(self.valid_responses(*runs, self.run_data()))
        self.assertEqual(result.conclusion, "success")
        self.assertEqual([call[0].full_url for call in opener.calls[3:]], [self.run_url] * 6)
        self.assertEqual(self.clock.sleeps, [1] * 5)

    def test_terminal_failure_and_other_conclusions_are_metadata_not_approval(self):
        for conclusion in backend.CONCLUSIONS:
            result, _, _ = self.invoke(self.valid_responses(self.run_data(conclusion=conclusion)))
            self.assertEqual(result.conclusion, conclusion)
            self.assertFalse({f.name for f in fields(result)} & {"approval", "technical_approval", "security_approval"})

    def test_unknown_status_and_invalid_conclusion_semantics(self):
        for status, conclusion in (("unknown", None), (True, None), ("completed", None),
                                   ("completed", "unknown"), ("completed", True),
                                   ("queued", "success"), ("in_progress", "failure")):
            with self.subTest(status=status, conclusion=conclusion), self.assertRaises(backend.GitHubTransportError):
                self.invoke(self.valid_responses(self.run_data(status=status, conclusion=conclusion)))

    def test_http_status_errors_in_each_phase_do_not_retry(self):
        for phase in range(4):
            for status in (204, 301, 302, 307, 308, 401, 403, 429, 500):
                responses = self.valid_responses()
                responses[phase].status = status
                transport, opener = self.transport(responses)
                with self.subTest(phase=phase, status=status), self.assertRaises(backend.GitHubTransportError):
                    transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                                overall_timeout_seconds=20, poll_interval_seconds=1)
                self.assertEqual(len(opener.calls), phase + 1)

    def test_malformed_nonobject_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b"not JSON", b"\xff", b"[]", b"null", b'"text"', b'{"id":1,"id":2}', b'{"id":NaN}'):
            for phase in range(4):
                responses = self.valid_responses()
                responses[phase].body = raw
                with self.subTest(raw=raw, phase=phase), self.assertRaises(backend.GitHubTransportError):
                    self.invoke(responses)

    def test_bounded_reads_and_exact_limit(self):
        responses = self.valid_responses()
        responses[0].body += b" " * (backend.MAX_RESPONSE_BYTES - len(responses[0].body))
        self.invoke(responses)
        for response in responses:
            self.assertTrue(all(0 < size <= 65_536 for size in response.read_sizes))
            self.assertLessEqual(response.cursor, backend.MAX_RESPONSE_BYTES + 1)
            self.assertTrue(response.closed)
        for phase in range(4):
            responses = self.valid_responses()
            responses[phase].body = b" " * (backend.MAX_RESPONSE_BYTES + 1)
            with self.subTest(phase=phase), self.assertRaises(backend.GitHubTransportError):
                self.invoke(responses)
            self.assertTrue(responses[phase].closed)
            self.assertEqual(responses[phase].cursor, backend.MAX_RESPONSE_BYTES + 1)

    def test_partial_chunks_until_eof_succeed(self):
        responses = self.valid_responses()
        for response in responses:
            original = response.read
            response.read = mock.Mock(side_effect=lambda size, read=original: read(min(size, 3)))
        result, _, _ = self.invoke(responses)
        self.assertEqual(result.conclusion, "success")
        for response in responses:
            self.assertGreater(response.read.call_count, 2)
            self.assertEqual(response.cursor, len(response.body))
            for call in response.read.call_args_list:
                self.assertEqual(len(call.args), 1)
                self.assertGreater(call.args[0], 0)
                self.assertLessEqual(call.args[0], 65_536)

    def test_nonbytes_chunk_rejected_without_exposing_body(self):
        for chunk in (None, "REMOTE_NON_SECRET_SENTINEL", bytearray(b"{}")):
            responses = self.valid_responses()
            responses[0].read = mock.Mock(side_effect=[b"{", chunk])
            with self.subTest(chunk=chunk), self.assertRaises(backend.GitHubTransportError) as error:
                self.invoke(responses)
            self.assertEqual(str(error.exception), "HTTP response rejected")
            self.assertEqual(responses[0].read.call_count, 2)

    def test_response_url_mismatch_never_followed(self):
        for phase in range(4):
            responses = self.valid_responses()
            responses[phase].url = "https://evil.invalid/" + self.token
            transport, opener = self.transport(responses)
            with self.subTest(phase=phase), self.assertRaises(backend.GitHubTransportError) as error:
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertNotIn(self.token, str(error.exception))
            self.assertEqual(len(opener.calls), phase + 1)

    def test_production_opener_disables_redirects_and_environment_proxies(self):
        captured = []
        fake = FakeOpener([], self.clock)
        with mock.patch.object(backend.http, "build_opener", side_effect=lambda *handlers: captured.extend(handlers) or fake):
            backend.GitHubActionsTransport(self.config, self.provider)
        redirect = next(handler for handler in captured if isinstance(handler, backend._NoRedirect))
        proxy = next(handler for handler in captured if isinstance(handler, backend.http.ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        with self.assertRaises(backend.GitHubTransportError):
            redirect.redirect_request(None, None, 302, self.token, {}, "https://evil.invalid")

    def test_http_and_provider_exception_chains_do_not_expose_sentinel(self):
        for exception in (HTTPError(self.token, 500, self.token, {}, None), URLError(self.token), RuntimeError(self.token)):
            with self.subTest(exception=type(exception).__name__):
                transport, opener = self.transport([exception])
                with self.assertRaises(backend.GitHubTransportError) as error:
                    transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                                overall_timeout_seconds=20, poll_interval_seconds=1)
                self.assertEqual(len(opener.calls), 1)
                self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
                self.assertIsNone(error.exception.__context__)
        self.provider.side_effect = RuntimeError(self.token)
        transport, opener = self.transport([])
        with self.assertRaises(backend.GitHubTransportError) as error:
            transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                        overall_timeout_seconds=20, poll_interval_seconds=1)
        self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
        self.assertFalse(opener.calls)

    def test_invalid_tokens_fail_before_http_and_are_sanitized(self):
        for token in (None, True, 1, b"token", "", "sentinel\r", "sentinel\n"):
            self.provider.return_value = token
            transport, opener = self.transport([])
            with self.subTest(token=repr(token)), self.assertRaises(backend.GitHubTransportError) as error:
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertEqual(str(error.exception), "Credential unavailable")
            self.assertFalse(opener.calls)

    def test_http_error_resource_closed_without_secret_warning(self):
        error = HTTPError(self.token, 500, self.token, {}, None)
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            with self.assertRaises(backend.GitHubTransportError):
                self.invoke([error])
            self.assertTrue(error.closed)
        self.assertFalse(captured)

    def test_no_token_attribute_repr_or_dataclass_persistence(self):
        result, transport, _ = self.invoke(self.valid_responses())
        self.assertNotIn(self.token, repr(transport))
        self.assertNotIn(self.token, repr(result))
        self.assertNotIn(self.token, [value for value in vars(transport).values() if type(value) is str])
        for cls in (backend.WorkflowIdentity, backend.DispatchResponse, backend.WorkflowRunSnapshot):
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertTrue(hasattr(cls, "__slots__"))
            self.assertFalse({f.name for f in fields(cls)} & {"token", "secret", "raw_response", "stdout", "stderr"})

    def test_timeout_validation_including_bool_nan_and_infinity(self):
        for name, values in (("request_timeout_seconds", [False, True, 0, -1, 31, float("nan"), float("inf"), "1"]),
                             ("overall_timeout_seconds", [True, 0, -1, 601, float("nan"), float("inf")]),
                             ("poll_interval_seconds", [False, True, 0, 0.5, -1, 31, float("nan"), float("inf")])):
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaises(backend.GitHubTransportError):
                    self.invoke([], **{name: value})
        self.assertEqual(self.provider.call_count, 0)

    def test_absolute_deadline_caps_sleep_and_stops_polling(self):
        transport, opener = self.transport(self.valid_responses(self.run_data(status="queued", conclusion=None)))
        with self.assertRaises(backend.GitHubTransportError):
            transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                        overall_timeout_seconds=2, poll_interval_seconds=30)
        self.assertEqual(self.clock.sleeps, [2])
        self.assertEqual(len(opener.calls), 4)

    def test_each_request_timeout_is_capped_by_remaining_overall_time(self):
        transport, opener = self.transport(self.valid_responses(), duration=1)
        transport.dispatch_and_wait(self.request, request_timeout_seconds=30,
                                    overall_timeout_seconds=5, poll_interval_seconds=1)
        self.assertEqual([call[1] for call in opener.calls], [5, 4, 3, 2])

    def test_late_response_cannot_succeed_after_deadline(self):
        transport, opener = self.transport(self.valid_responses(), duration=3)
        with self.assertRaises(backend.GitHubTransportError):
            transport.dispatch_and_wait(self.request, request_timeout_seconds=1,
                                        overall_timeout_seconds=2, poll_interval_seconds=1)
        self.assertEqual(len(opener.calls), 1)

    def test_credential_acquisition_time_counts_against_deadline(self):
        def delayed():
            self.clock.now += 5
            return self.token
        self.provider.side_effect = delayed
        transport, opener = self.transport([])
        with self.assertRaises(backend.GitHubTransportError):
            transport.dispatch_and_wait(self.request, request_timeout_seconds=1,
                                        overall_timeout_seconds=2, poll_interval_seconds=1)
        self.assertFalse(opener.calls)

    def test_extra_remote_fields_ignored_without_retaining_raw_response(self):
        responses = [FakeResponse(self.metadata(extra=self.token)), FakeResponse(self.source_ref()), FakeResponse(self.dispatch(extra=self.token)),
                     FakeResponse(self.run_data(extra=self.token))]
        result, _, _ = self.invoke(responses)
        self.assertNotIn(self.token, repr(result))

    def test_pre_dispatch_failure_has_no_run_identity(self):
        for responses in ([RuntimeError(self.token)],
                          [FakeResponse(self.metadata()), FakeResponse({})]):
            with self.subTest(responses=len(responses)), self.assertRaises(backend.GitHubTransportError) as error:
                self.invoke(responses)
            self.assertIsNone(error.exception.workflow_run_id)

    def test_post_dispatch_failures_keep_id_without_secret_or_exception_chain(self):
        for failure in (RuntimeError(self.token), URLError(self.token),
                        FakeResponse({}, raw=self.token.encode()),
                        FakeResponse(self.run_data(id=999)),
                        FakeResponse(self.run_data(), status=500)):
            transport, opener = self.transport(self.valid_responses()[:3] + [failure])
            with self.subTest(failure=type(failure).__name__), self.assertRaises(backend.GitHubTransportError) as error:
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertEqual(error.exception.workflow_run_id, self.run_id)
            self.assertEqual(vars(error.exception), {"workflow_run_id": self.run_id})
            self.assertIsNone(error.exception.__context__)
            self.assertIsNone(error.exception.__cause__)
            self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
            self.assertEqual(sum(c[0].method == "POST" for c in opener.calls), 1)
            self.assertEqual(opener.calls[-1][0].full_url, self.run_url)

    def test_post_dispatch_timeout_and_sleep_failure_keep_id(self):
        for broken_sleep in (False, True):
            transport, opener = self.transport(self.valid_responses(self.run_data(status="queued", conclusion=None)))
            if broken_sleep:
                transport._sleep = mock.Mock(side_effect=RuntimeError(self.token))
            with self.subTest(broken_sleep=broken_sleep), self.assertRaises(backend.GitHubTransportError) as error:
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=2, poll_interval_seconds=30)
            self.assertEqual(error.exception.workflow_run_id, self.run_id)
            self.assertIsNone(error.exception.__context__)
            self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
            self.assertEqual(sum(c[0].method == "POST" for c in opener.calls), 1)

    def test_successful_dispatch_id_survives_subsequent_response_identity_failure(self):
        responses = self.valid_responses()
        responses[2] = FakeResponse(self.dispatch(run_url="https://evil.invalid/" + self.token))
        transport, opener = self.transport(responses)
        with self.assertRaises(backend.GitHubTransportError) as error:
            transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                        overall_timeout_seconds=20, poll_interval_seconds=1)
        self.assertEqual(error.exception.workflow_run_id, self.run_id)
        self.assertIsNone(error.exception.__context__)
        self.assertNotIn(self.token, repr(error.exception))
        self.assertEqual(len(opener.calls), 3)

    def test_invalid_dispatch_id_is_never_failure_metadata(self):
        for value in (None, True, 0, -1, "431", 431.0):
            responses = self.valid_responses()
            responses[2] = FakeResponse(self.dispatch(workflow_run_id=value))
            with self.subTest(value=value), self.assertRaises(backend.GitHubTransportError) as error:
                self.invoke(responses)
            self.assertIsNone(error.exception.workflow_run_id)

    def test_decoded_dispatch_id_survives_response_close_failure(self):
        token = self.token
        class BrokenClose(FakeResponse):
            def __exit__(self, *args):
                super().__exit__(*args)
                raise RuntimeError(token)
        responses = self.valid_responses()
        responses[2] = BrokenClose(self.dispatch())
        transport, opener = self.transport(responses)
        with self.assertRaises(backend.GitHubTransportError) as error:
            transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                        overall_timeout_seconds=20, poll_interval_seconds=1)
        self.assertEqual(error.exception.workflow_run_id, self.run_id)
        self.assertIsNone(error.exception.__context__)
        self.assertNotIn(token, "".join(traceback.format_exception(error.exception)))
        self.assertEqual(len(opener.calls), 3)

    def test_deadline_after_dispatch_decode_keeps_id_and_does_not_poll(self):
        decode = json.loads
        def delayed_decode(body, **kwargs):
            value = decode(body, **kwargs)
            if type(value) is dict and "workflow_run_id" in value:
                self.clock.now += 21
            return value
        transport, opener = self.transport(self.valid_responses())
        with mock.patch.object(backend.json, "loads", side_effect=delayed_decode):
            with self.assertRaises(backend.GitHubTransportError) as error:
                transport.dispatch_and_wait(self.request, request_timeout_seconds=5,
                                            overall_timeout_seconds=20, poll_interval_seconds=1)
        self.assertEqual(error.exception.workflow_run_id, self.run_id)
        self.assertIsNone(error.exception.__context__)
        self.assertEqual(len(opener.calls), 3)
        self.assertEqual(sum(c[0].method == "POST" for c in opener.calls), 1)

    def test_positive_poll_bounds_accepted(self):
        for interval in (1, 30):
            with self.subTest(interval=interval):
                result, _, _ = self.invoke(self.valid_responses(), poll_interval_seconds=interval)
                self.assertEqual(result.conclusion, "success")

    def test_success_grants_no_approval_or_mutation_authority(self):
        result, _, _ = self.invoke(self.valid_responses())
        self.assertFalse({f.name for f in fields(result)} & {
            "approval", "technical_approval", "security_approval", "human_approval",
            "merge_authority", "production_authority"})
        self.assertEqual(self.config.activation, "disabled")


    def observe_existing(self, transport, **timeouts):
        return transport.observe(self.run_id, **dict(
            {"request_timeout_seconds": 5, "overall_timeout_seconds": 20,
             "poll_interval_seconds": 1}, **timeouts))

    def test_separate_dispatch_performs_one_post_without_polling(self):
        transport, opener = self.transport(self.valid_responses()[:3])
        result = transport.dispatch(self.request, request_timeout_seconds=5, overall_timeout_seconds=20)
        self.assertEqual(result.workflow_run_id, self.run_id)
        self.assertEqual([call[0].method for call in opener.calls], ["GET", "GET", "POST"])
        self.assertFalse(self.clock.sleeps)

    def test_observer_get_only_continues_known_run_to_terminal(self):
        responses = [FakeResponse(self.metadata()), FakeResponse(self.source_ref()),
                     FakeResponse(self.run_data(status="queued", conclusion=None)), FakeResponse(self.run_data())]
        transport, opener = self.transport(responses)
        with mock.patch.object(transport, "dispatch", side_effect=AssertionError("dispatch forbidden")), \
             mock.patch.object(transport, "_dispatch_once", side_effect=AssertionError("POST forbidden")):
            result = self.observe_existing(transport)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(result.conclusion, "success")
        self.assertEqual(self.clock.sleeps, [1])
        self.assertEqual([call[0].full_url for call in opener.calls],
                         [self.workflow_url, self.ref_url, self.run_url, self.run_url])
        self.assertTrue(all(call[0].method == "GET" and call[0].data is None for call in opener.calls))
        self.assertFalse({f.name for f in fields(result)} & {
            "approval", "technical_approval", "security_approval", "human_approval",
            "merge_authority", "production_authority"})

    def test_observer_rejects_each_wrong_or_missing_run_identity(self):
        changes = [("id", 432), ("workflow_id", 18), ("repository", {"full_name": "other/repo"}),
                   ("event", "push"), ("run_attempt", 2), ("head_sha", "a" * 40)]
        runs = [self.run_data(**{key: value}) for key, value in changes]
        for field in self.run_data():
            run = self.run_data()
            del run[field]
            runs.append(run)
        for run in runs:
            with self.subTest(run=run):
                transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(self.source_ref()), FakeResponse(run)])
                with self.assertRaises(backend.GitHubTransportError) as error:
                    self.observe_existing(transport)
                self.assertEqual(error.exception.workflow_run_id, self.run_id)
                self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_observer_rejects_invalid_input_id_without_http(self):
        for value in (None, True, 0, -1, "431", 431.0, "https://evil.invalid"):
            transport, opener = self.transport([])
            with self.subTest(value=value), self.assertRaises(backend.GitHubTransportError):
                transport.observe(value, request_timeout_seconds=5, overall_timeout_seconds=20, poll_interval_seconds=1)
            self.assertFalse(opener.calls)

    def test_observer_timeout_keeps_id_and_never_dispatches(self):
        transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(self.source_ref()),
                                           FakeResponse(self.run_data(status="in_progress", conclusion=None))])
        with self.assertRaises(backend.GitHubTransportError) as error:
            transport.observe(self.run_id, request_timeout_seconds=5, overall_timeout_seconds=2, poll_interval_seconds=30)
        self.assertEqual(error.exception.workflow_run_id, self.run_id)
        self.assertEqual(self.clock.sleeps, [2])
        self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_observer_errors_sanitize_secrets_and_chains_at_every_get(self):
        for phase in range(3):
            responses = [FakeResponse(self.metadata()), FakeResponse(self.source_ref()), FakeResponse(self.run_data())]
            responses[phase] = RuntimeError(self.token)
            transport, opener = self.transport(responses)
            with self.subTest(phase=phase), self.assertRaises(backend.GitHubTransportError) as error:
                self.observe_existing(transport)
            self.assertEqual(error.exception.workflow_run_id, self.run_id)
            self.assertIsNone(error.exception.__context__)
            self.assertIsNone(error.exception.__cause__)
            self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
            self.assertTrue(all(c[0].method == "GET" for c in opener.calls))

    def test_dispatch_uncertain_response_does_not_retry_or_infer_absence(self):
        transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(self.source_ref()), RuntimeError(self.token)])
        with self.assertRaises(backend.GitHubTransportError) as error:
            transport.dispatch(self.request, request_timeout_seconds=5, overall_timeout_seconds=20)
        self.assertIsNone(error.exception.workflow_run_id)
        self.assertIsNone(error.exception.__context__)
        self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
        self.assertEqual(sum(call[0].method == "POST" for call in opener.calls), 1)
        self.assertEqual(len(opener.calls), 3)

    def test_observer_terminal_failure_is_evidence_without_mutation(self):
        transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(self.source_ref()),
                                           FakeResponse(self.run_data(conclusion="failure"))])
        result = self.observe_existing(transport)
        self.assertEqual(result.conclusion, "failure")
        self.assertTrue(all(c[0].method == "GET" for c in opener.calls))


    def test_observer_rejects_workflow_and_source_before_run_get(self):
        for responses in ([FakeResponse(self.metadata(id=True))],
                          [FakeResponse(self.metadata(state="disabled_manually"))],
                          [FakeResponse(self.metadata(path="other.yml"))],
                          [FakeResponse(self.metadata()), FakeResponse({})]):
            transport, opener = self.transport(responses)
            with self.subTest(count=len(responses)), self.assertRaises(backend.GitHubTransportError):
                self.observe_existing(transport)
            self.assertTrue(all(c[0].method == "GET" for c in opener.calls))
            self.assertNotIn(self.run_url, [c[0].full_url for c in opener.calls])

    def test_observer_invalid_limits_never_contact_provider(self):
        for key, value in (("request_timeout_seconds", 0), ("overall_timeout_seconds", 601),
                           ("poll_interval_seconds", 0), ("poll_interval_seconds", True),
                           ("overall_timeout_seconds", float("nan"))):
            transport, opener = self.transport([])
            with self.subTest(key=key), self.assertRaises(backend.GitHubTransportError):
                self.observe_existing(transport, **{key: value})
            self.assertFalse(opener.calls)

    def test_observer_http_failures_never_dispatch_and_are_sanitized(self):
        import io
        remote_url = "https://evil.invalid/REMOTE_URL_SENTINEL"
        body = "REMOTE_BODY_SENTINEL " + self.token
        for failure_kind in ("http_error", "rejected_response"):
            with self.subTest(failure_kind=failure_kind):
                stream = io.BytesIO(body.encode())
                failure = (HTTPError(remote_url, 503, self.token, {"X-Secret": self.token}, stream)
                           if failure_kind == "http_error" else
                           FakeResponse({}, status=503, raw=body.encode()))
                responses = [FakeResponse(self.metadata()), FakeResponse(self.source_ref()), failure]
                transport, opener = self.transport(responses)
                with mock.patch.object(transport, "dispatch") as dispatch, \
                     mock.patch.object(transport, "_dispatch_once") as dispatch_once, \
                     mock.patch.object(transport, "_request", wraps=transport._request) as request:
                    with self.assertRaises(backend.GitHubTransportError) as caught:
                        self.observe_existing(transport)
                    dispatch.assert_not_called()
                    dispatch_once.assert_not_called()
                    self.assertEqual(request.call_count, 3)
                    self.assertTrue(all(call.args[1] is None for call in request.call_args_list))
                error = caught.exception
                self.assertEqual(error.workflow_run_id, self.run_id)
                self.assertEqual(str(error), "Dispatch or run observation failed")
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertEqual(vars(error), {"workflow_run_id": self.run_id})
                rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
                for secret in (self.token, body, "REMOTE_BODY_SENTINEL", remote_url):
                    self.assertNotIn(secret, rendered)
                self.assertEqual([call[0].method for call in opener.calls], ["GET", "GET", "GET"])
                self.assertEqual([call[0].full_url for call in opener.calls],
                                 [self.workflow_url, self.ref_url, self.run_url])
                self.assertFalse(self.clock.sleeps)
                if failure_kind == "http_error":
                    self.assertTrue(stream.closed)
                else:
                    self.assertTrue(failure.closed)
                    stream.close()

    def test_separate_dispatch_retains_known_id_after_invalid_response(self):
        transport, opener = self.transport([FakeResponse(self.metadata()), FakeResponse(self.source_ref()),
                                           FakeResponse(self.dispatch(run_url="https://evil.invalid/" + self.token))])
        with self.assertRaises(backend.GitHubTransportError) as error:
            transport.dispatch(self.request, request_timeout_seconds=5, overall_timeout_seconds=20)
        self.assertEqual(error.exception.workflow_run_id, self.run_id)
        self.assertIsNone(error.exception.__context__)
        self.assertNotIn(self.token, "".join(traceback.format_exception(error.exception)))
        self.assertEqual(sum(c[0].method == "POST" for c in opener.calls), 1)


if __name__ == "__main__":
    unittest.main()
