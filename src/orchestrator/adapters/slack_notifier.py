"""Adapter de Slack Incoming Webhook (HUMAN-GATE-NOTIFY-001). SOLO salida.

Implementa `NotifierPort`. Solo biblioteca estándar (urllib): sin
dependencias nuevas. Sin bot, sin OAuth, sin eventos entrantes, sin botones.

Seguridad:
- El webhook es SECRETO: se lee únicamente del entorno del proceso, en la
  variable cuyo NOMBRE está configurado, en el momento de enviar; nunca se
  imprime, registra, persiste ni aparece en resultados o errores.
- Solo https://hooks.slack.com/services/... (sin userinfo, puerto, query ni
  fragment); si no cumple no se abre ninguna conexión.
- Los redirects NO se siguen (una redirección no provoca otra petición).
- Timeout explícito de 5 s por intento; un solo intento, sin reintentos.
- El cuerpo de la respuesta nunca se lee ni se devuelve.
- El payload NO lleva `channel` (el webhook fija el destino) ni menciones,
  enlaces dinámicos, paths, hashes, contenido de archivos ni datos de Claude.
"""

from __future__ import annotations

import json
import os
import re
import socket
import urllib.error
import urllib.request
from typing import Any, Mapping
from urllib.parse import urlsplit

from ..notifications import (
    ERROR_HTTP_4XX,
    ERROR_HTTP_5XX,
    ERROR_INVALID_WEBHOOK,
    ERROR_MISSING_SECRET,
    ERROR_NETWORK,
    ERROR_TIMEOUT,
    STATUS_FAILED,
    STATUS_SENT,
    NotificationEvent,
    NotificationResult,
)

PROVIDER = "slack"
WEBHOOK_HOST = "hooks.slack.com"
WEBHOOK_PATH_PREFIX = "/services/"
HTTP_TIMEOUT_SECONDS = 5
USER_AGENT = "AISOFTWAREFACTORY-Orchestrator/notify"
CONTENT_TYPE = "application/json"

_FIXED_TITLE = "🚦 AISOFTWAREFACTORY — Acción requerida"
_FIXED_STATE = "listo para revisión humana"
_FALLBACK_ACTION = "revisión humana requerida"
_ENV_VAR_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_GATE_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_MAX_ACTION_CHARS = 200


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """No sigue redirects: `redirect_request` devuelve None, así que urllib
    lanza HTTPError (3xx) en lugar de hacer una segunda petición."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def build_no_redirect_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirectHandler)


def is_valid_webhook_url(url: object) -> bool:
    """https + host EXACTO hooks.slack.com + ruta /services/...; sin
    userinfo, puerto, query ni fragment. Cualquier duda -> False."""
    if not isinstance(url, str) or not url or url != url.strip():
        return False
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.netloc.lower() == WEBHOOK_HOST
        and parts.username is None
        and parts.password is None
        and port is None
        and not parts.query
        and not parts.fragment
        and parts.path.startswith(WEBHOOK_PATH_PREFIX)
        and len(parts.path) > len(WEBHOOK_PATH_PREFIX)
    )


def escape_slack(text: str) -> str:
    """Escapa &, < y > (Slack) y elimina '@' para que ningún valor variable
    pueda producir menciones (@channel, @here, @everyone)."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("@", "")
    )


def _one_line(text: str) -> str:
    return " ".join(text.split())


def build_message_text(event: NotificationEvent, action: str | None) -> str:
    """Texto mínimo y seguro: proyecto, tarea, gate, acción ESTÁTICA de
    GATES.yaml y estado fijo. Nada más."""
    gate = event.gate_type if _GATE_RE.fullmatch(event.gate_type) else "HUMAN_GATE"
    action_text = _one_line(action) if isinstance(action, str) and action.strip() else ""
    action_text = escape_slack(action_text[:_MAX_ACTION_CHARS]) or _FALLBACK_ACTION
    lines = (
        _FIXED_TITLE,
        "",
        f"Proyecto: {escape_slack(event.project_id)}",
        f"Tarea: {escape_slack(event.task_id)}",
        f"Gate: {escape_slack(gate)}",
        f"Acción: {action_text}",
        f"Estado: {_FIXED_STATE}",
    )
    return "\n".join(lines)


def build_payload(event: NotificationEvent, action: str | None) -> bytes:
    return json.dumps({"text": build_message_text(event, action)}).encode("utf-8")


class SlackWebhookNotifier:
    """NotifierPort sobre un Incoming Webhook de Slack."""

    provider = PROVIDER

    def __init__(
        self,
        *,
        webhook_env_var: str,
        gate_actions: Mapping[str, str] | None = None,
        opener: Any | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(webhook_env_var, str) or not _ENV_VAR_RE.fullmatch(webhook_env_var):
            raise ValueError("invalid webhook environment variable name")
        self._env_var = webhook_env_var
        self._gate_actions = dict(gate_actions or {})
        self._opener = opener
        self._environ = environ if environ is not None else os.environ

    def notify(self, event: NotificationEvent) -> NotificationResult:
        try:
            return self._notify(event)
        except Exception:  # noqa: BLE001 - notify() nunca lanza; sin detalles
            return NotificationResult(STATUS_FAILED, ERROR_NETWORK)

    def _notify(self, event: NotificationEvent) -> NotificationResult:
        url = self._environ.get(self._env_var)
        if not isinstance(url, str) or not url.strip():
            return NotificationResult(STATUS_FAILED, ERROR_MISSING_SECRET)
        if not is_valid_webhook_url(url):
            return NotificationResult(STATUS_FAILED, ERROR_INVALID_WEBHOOK)

        payload = build_payload(event, self._gate_actions.get(event.gate_type))
        request = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": CONTENT_TYPE, "User-Agent": USER_AGENT},
        )
        opener = self._opener if self._opener is not None else build_no_redirect_opener()
        try:
            response = opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            return _classify_status(code)
        except (TimeoutError, socket.timeout):
            return NotificationResult(STATUS_FAILED, ERROR_TIMEOUT)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                return NotificationResult(STATUS_FAILED, ERROR_TIMEOUT)
            return NotificationResult(STATUS_FAILED, ERROR_NETWORK)
        except OSError:
            return NotificationResult(STATUS_FAILED, ERROR_NETWORK)

        try:
            code = getattr(response, "status", None)
            if code is None:
                code = response.getcode()
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        return _classify_status(code)


def _classify_status(code: object) -> NotificationResult:
    """2xx -> SENT; 4xx -> HTTP_4XX; 5xx -> HTTP_5XX. Cualquier otra cosa
    (p. ej. un 3xx no seguido) -> NETWORK: la entrega no se confirmó."""
    if isinstance(code, int) and not isinstance(code, bool):
        if 200 <= code <= 299:
            return NotificationResult(STATUS_SENT)
        if 400 <= code <= 499:
            return NotificationResult(STATUS_FAILED, ERROR_HTTP_4XX)
        if 500 <= code <= 599:
            return NotificationResult(STATUS_FAILED, ERROR_HTTP_5XX)
    return NotificationResult(STATUS_FAILED, ERROR_NETWORK)
