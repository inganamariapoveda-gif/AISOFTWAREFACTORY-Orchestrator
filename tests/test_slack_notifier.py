"""HUMAN-GATE-NOTIFY-001: adapter de Slack Incoming Webhook. TODO con opener /
capa HTTP falsos: ninguna prueba abre una conexión ni llama a hooks.slack.com."""

import io
import json
import os
import socket
import sys
import unittest
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.adapters import slack_notifier as slack  # noqa: E402
from orchestrator.adapters.slack_notifier import (  # noqa: E402
    SlackWebhookNotifier,
    build_message_text,
    escape_slack,
    is_valid_webhook_url,
)
from orchestrator.notifications import NotificationEvent, NotificationResult, NotifierPort  # noqa: E402

ENV_VAR = "AISOFTWAREFACTORY_SLACK_WEBHOOK_URL"
WEBHOOK = "https://hooks.slack.com/services/TSENTINEL9/BSENTINEL9/SENTINELSECRET9x"
ACTION = "prueba funcionalmente -> APROBADO o describe el problema"
GATE_ACTIONS = {"HUMAN_FUNCTIONAL_TEST": ACTION}
EVENT = NotificationEvent(
    event_type="human_gate",
    project_id="PROJ-1",
    task_id="TASK-1",
    gate_type="HUMAN_FUNCTIONAL_TEST",
    dedupe_key="human_gate:TASK-1:7",
)


class FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status
        self.closed = False

    def read(self, *args, **kwargs):  # el adapter NUNCA debe leer el cuerpo
        raise AssertionError("the response body must never be read")

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    """Registra cada petición y el timeout; devuelve/lanza lo configurado."""

    def __init__(self, outcome=None) -> None:
        self.outcome = FakeResponse(200) if outcome is None else outcome
        self.calls: list[tuple[urllib.request.Request, object]] = []

    def open(self, request, timeout=None):
        self.calls.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(WEBHOOK, code, "msg", {}, io.BytesIO(b"raw slack body"))  # type: ignore[arg-type]


def notifier(opener=None, environ=None, actions=GATE_ACTIONS) -> tuple[SlackWebhookNotifier, FakeOpener]:
    opener = opener if opener is not None else FakeOpener()
    env = {ENV_VAR: WEBHOOK} if environ is None else environ
    return (
        SlackWebhookNotifier(
            webhook_env_var=ENV_VAR, gate_actions=actions, opener=opener, environ=env
        ),
        opener,
    )


class ResultTests(unittest.TestCase):
    def test_2xx_is_sent(self) -> None:
        for status in (200, 201, 204, 299):
            with self.subTest(status):
                n, opener = notifier(FakeOpener(FakeResponse(status)))
                self.assertEqual(n.notify(EVENT), NotificationResult("SENT", None))
                self.assertEqual(len(opener.calls), 1)
                self.assertTrue(opener.outcome.closed)

    def test_http_4xx(self) -> None:
        for code in (400, 403, 404, 410, 429, 499):
            with self.subTest(code):
                n, _ = notifier(FakeOpener(http_error(code)))
                self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", "HTTP_4XX"))

    def test_http_5xx(self) -> None:
        for code in (500, 502, 503, 599):
            with self.subTest(code):
                n, _ = notifier(FakeOpener(http_error(code)))
                self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", "HTTP_5XX"))

    def test_timeout(self) -> None:
        for error in (
            TimeoutError("timed out"),
            socket.timeout("timed out"),
            urllib.error.URLError(TimeoutError("timed out")),
            urllib.error.URLError(socket.timeout("timed out")),
        ):
            with self.subTest(type(error).__name__):
                n, _ = notifier(FakeOpener(error))
                self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", "TIMEOUT"))

    def test_dns_and_network_errors(self) -> None:
        for error in (
            urllib.error.URLError("dns failure"),
            urllib.error.URLError(socket.gaierror(11001, "getaddrinfo failed")),
            ConnectionResetError("reset"),
            OSError("network down"),
        ):
            with self.subTest(type(error).__name__):
                n, _ = notifier(FakeOpener(error))
                self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", "NETWORK"))

    def test_an_unexpected_exception_never_escapes_notify(self) -> None:
        n, _ = notifier(FakeOpener(RuntimeError("boom " + WEBHOOK)))
        result = n.notify(EVENT)
        self.assertEqual(result, NotificationResult("FAILED", "NETWORK"))

    def test_unexpected_status_codes_are_failures_not_success(self) -> None:
        for status in (100, 199, 300, 302):
            with self.subTest(status):
                n, _ = notifier(FakeOpener(FakeResponse(status)))
                self.assertEqual(n.notify(EVENT).status, "FAILED")

    def test_the_response_body_is_never_read_nor_returned(self) -> None:
        n, opener = notifier(FakeOpener(http_error(500)))
        result = n.notify(EVENT)  # FakeResponse.read() haría fallar; HTTPError no se lee
        self.assertNotIn("raw slack body", repr(result))


class SecretTests(unittest.TestCase):
    def test_missing_or_empty_secret(self) -> None:
        for env in ({}, {ENV_VAR: ""}, {ENV_VAR: "   "}):
            with self.subTest(env):
                n, opener = notifier(environ=env)
                self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", "MISSING_SECRET"))
                self.assertEqual(opener.calls, [])  # sin red

    def test_the_secret_is_read_from_the_configured_environment_variable_only(self) -> None:
        opener = FakeOpener()
        n = SlackWebhookNotifier(webhook_env_var="MY_OTHER_VAR", gate_actions=GATE_ACTIONS, opener=opener)
        with mock.patch.dict(os.environ, {ENV_VAR: WEBHOOK, "MY_OTHER_VAR": ""}, clear=False):
            self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", "MISSING_SECRET"))
        with mock.patch.dict(os.environ, {"MY_OTHER_VAR": WEBHOOK}, clear=False):
            self.assertEqual(n.notify(EVENT).status, "SENT")
        (request, _timeout), = opener.calls
        self.assertEqual(request.full_url, WEBHOOK)

    def test_the_webhook_never_appears_in_results_or_errors(self) -> None:
        errors = [
            urllib.error.URLError(WEBHOOK),
            OSError(WEBHOOK),
            RuntimeError(WEBHOOK),
            http_error(500),
            http_error(400),
        ]
        for error in errors:
            n, _ = notifier(FakeOpener(error))
            result = n.notify(EVENT)
            self.assertNotIn("SENTINEL", repr(result))
            self.assertNotIn("hooks.slack.com", repr(result))
        n, _ = notifier()
        self.assertNotIn("SENTINEL", repr(n.notify(EVENT)))
        self.assertNotIn("SENTINEL", repr(n))
        self.assertNotIn("SENTINEL", str(vars(n).get("_gate_actions")))

    def test_the_env_var_name_is_validated(self) -> None:
        for bad in ("", "lower", "1ABC", "A B", "https://hooks.slack.com/services/T/B/X", None):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    SlackWebhookNotifier(webhook_env_var=bad)  # type: ignore[arg-type]


class WebhookValidationTests(unittest.TestCase):
    def test_a_valid_slack_webhook_is_accepted(self) -> None:
        self.assertTrue(is_valid_webhook_url(WEBHOOK))
        self.assertTrue(is_valid_webhook_url("https://HOOKS.SLACK.COM/services/T1/B2/abc"))

    def test_every_other_shape_is_invalid_and_never_opens_the_network(self) -> None:
        bad = {
            "http": "http://hooks.slack.com/services/T/B/X",
            "other scheme": "ftp://hooks.slack.com/services/T/B/X",
            "no scheme": "hooks.slack.com/services/T/B/X",
            "wrong host": "https://example.com/services/T/B/X",
            "suffix host": "https://hooks.slack.com.evil.com/services/T/B/X",
            "prefix host": "https://evilhooks.slack.com/services/T/B/X",
            "subdomain host": "https://a.hooks.slack.com/services/T/B/X",
            "userinfo": "https://user:pw@hooks.slack.com/services/T/B/X",
            "userinfo trick": "https://hooks.slack.com@evil.com/services/T/B/X",
            "user only": "https://user@hooks.slack.com/services/T/B/X",
            "port": "https://hooks.slack.com:8443/services/T/B/X",
            "wrong path": "https://hooks.slack.com/api/T/B/X",
            "path prefix only": "https://hooks.slack.com/services/",
            "no path": "https://hooks.slack.com",
            "fragment": "https://hooks.slack.com/services/T/B/X#frag",
            "query": "https://hooks.slack.com/services/T/B/X?a=b",
            "whitespace": "https://hooks.slack.com/services/T/B/ X",
            "leading space": " https://hooks.slack.com/services/T/B/X",
            "newline": "https://hooks.slack.com/services/T/B/X\n",
            "control char": "https://hooks.slack.com/services/T/B/X\x00",
            "malformed ipv6": "https://[hooks.slack.com/services/T/B/X",
            "empty": "",
        }
        for label, url in bad.items():
            with self.subTest(label):
                self.assertFalse(is_valid_webhook_url(url))
                n, opener = notifier(environ={ENV_VAR: url})
                expected = "MISSING_SECRET" if not url.strip() else "INVALID_WEBHOOK"
                self.assertEqual(n.notify(EVENT), NotificationResult("FAILED", expected))
                self.assertEqual(opener.calls, [])  # no se abre la red

    def test_non_strings_are_invalid(self) -> None:
        for value in (None, 1, b"https://hooks.slack.com/services/T/B/X", ["x"]):
            self.assertFalse(is_valid_webhook_url(value))


class RequestTests(unittest.TestCase):
    def sent(self):
        n, opener = notifier()
        n.notify(EVENT)
        (request, timeout), = opener.calls
        return request, timeout

    def test_timeout_is_explicit_and_five_seconds(self) -> None:
        request, timeout = self.sent()
        self.assertEqual(slack.HTTP_TIMEOUT_SECONDS, 5)
        self.assertEqual(timeout, 5)

    def test_single_attempt_no_retry(self) -> None:
        n, opener = notifier(FakeOpener(http_error(500)))
        n.notify(EVENT)
        self.assertEqual(len(opener.calls), 1)

    def test_post_json_with_fixed_user_agent(self) -> None:
        request, _ = self.sent()
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, WEBHOOK)
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(request.get_header("User-agent"), "AISOFTWAREFACTORY-Orchestrator/notify")
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(set(body), {"text"})  # sin `channel` (el webhook fija el destino)
        self.assertNotIn("channel", body)

    def test_redirects_are_not_followed(self) -> None:
        handler = slack._NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                urllib.request.Request(WEBHOOK), None, 302, "Found", {}, "https://evil.example/x"
            )
        )
        seen: list[str] = []

        class FakeHttpsHandler(urllib.request.BaseHandler):
            def https_open(self, req):
                seen.append(req.full_url)
                headers = {"Location": "https://evil.example/steal"}
                return urllib.response.addinfourl(io.BytesIO(b""), headers, req.full_url, 302)  # type: ignore[arg-type]

        director = urllib.request.OpenerDirector()
        for h in (slack._NoRedirectHandler(), urllib.request.HTTPErrorProcessor(), FakeHttpsHandler()):
            director.add_handler(h)
        n, _ = notifier(director)
        with warnings.catch_warnings():
            # El addinfourl simulado de la prueba no es el objeto que cierra el adapter.
            warnings.simplefilter("ignore", ResourceWarning)
            result = n.notify(EVENT)
        self.assertEqual(seen, [WEBHOOK])  # UNA sola petición: no se siguió el redirect
        self.assertEqual(result.status, "FAILED")
        self.assertNotIn("evil", repr(result))

    def test_the_default_opener_uses_the_no_redirect_handler(self) -> None:
        director = slack.build_no_redirect_opener()
        redirect_handlers = [
            h for h in director.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
        ]
        self.assertEqual(len(redirect_handlers), 1)
        self.assertIsInstance(redirect_handlers[0], slack._NoRedirectHandler)

    def test_default_opener_is_used_when_none_is_injected(self) -> None:
        n = SlackWebhookNotifier(webhook_env_var=ENV_VAR, gate_actions=GATE_ACTIONS, environ={ENV_VAR: WEBHOOK})
        fake = FakeOpener()
        with mock.patch.object(slack, "build_no_redirect_opener", return_value=fake):
            self.assertEqual(n.notify(EVENT).status, "SENT")
        self.assertEqual(len(fake.calls), 1)


class MessageTests(unittest.TestCase):
    def test_the_message_has_only_the_approved_fields(self) -> None:
        text = build_message_text(EVENT, ACTION)
        self.assertEqual(
            text.split("\n"),
            [
                "🚦 AISOFTWAREFACTORY — Acción requerida",
                "",
                "Proyecto: PROJ-1",
                "Tarea: TASK-1",
                "Gate: HUMAN_FUNCTIONAL_TEST",
                "Acción: prueba funcionalmente -&gt; APROBADO o describe el problema",
                "Estado: listo para revisión humana",
            ],
        )

    def test_dynamic_values_are_escaped_and_mentions_are_impossible(self) -> None:
        self.assertEqual(escape_slack("a & b < c > d"), "a &amp; b &lt; c &gt; d")
        self.assertEqual(escape_slack("@channel @here @everyone <!channel>"), "channel here everyone &lt;!channel&gt;")
        event = NotificationEvent("human_gate", "P<script>", "T&1", "HUMAN_FUNCTIONAL_TEST", "k")
        text = build_message_text(event, "<!channel> @here <https://evil.example|click>")
        for forbidden in ("@", "<!", "<http", "<script"):
            self.assertNotIn(forbidden, text)
        self.assertIn("&amp;", text)

    def test_an_unknown_gate_or_missing_action_falls_back_to_fixed_text(self) -> None:
        text = build_message_text(NotificationEvent("human_gate", "P", "T", "weird gate!", "k"), None)
        self.assertIn("Gate: HUMAN_GATE", text)
        self.assertIn("Acción: revisión humana requerida", text)

    def test_the_action_comes_only_from_the_static_gate_actions(self) -> None:
        n, opener = notifier(actions={"HUMAN_FUNCTIONAL_TEST": "accion estatica"})
        n.notify(EVENT)
        body = json.loads(opener.calls[0][0].data.decode("utf-8"))
        self.assertIn("Acción: accion estatica", body["text"])

    def test_the_payload_carries_nothing_beyond_the_event_and_static_text(self) -> None:
        n, opener = notifier()
        n.notify(EVENT)
        payload = opener.calls[0][0].data.decode("utf-8")
        for forbidden in (
            "need_text", "persisted execution", "objective", "acceptance", "hash", "sha256",
            "stdout", "stderr", "diff", "\\\\", "/", "@channel", "@here", ".py", ".txt",
        ):
            self.assertNotIn(forbidden, payload.replace("\\u2014", "-").replace("->", ""))
        self.assertNotIn(WEBHOOK, payload)
        self.assertNotIn("SENTINEL", payload)

    def test_the_action_is_bounded(self) -> None:
        text = build_message_text(EVENT, "x" * 5000)
        self.assertLess(len(text), 600)


class ArchitectureTests(unittest.TestCase):
    def test_the_adapter_satisfies_the_port(self) -> None:
        n, _ = notifier()
        self.assertIsInstance(n, NotifierPort)
        self.assertEqual(n.provider, "slack")

    def test_only_the_standard_library_is_used(self) -> None:
        source = (SRC_DIR / "orchestrator" / "adapters" / "slack_notifier.py").read_text(encoding="utf-8")
        for needle in ("import requests", "import httpx", "import aiohttp", "import urllib3", "shell=True"):
            self.assertNotIn(needle, source)
        for needle in ("time.sleep", "threading", "asyncio", "os.environ[", "putenv", "setdefault("):
            self.assertNotIn(needle, source)


if __name__ == "__main__":
    unittest.main()
