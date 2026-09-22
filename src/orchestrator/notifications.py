"""Notificaciones salientes de Human Gate (HUMAN-GATE-NOTIFY-001).

MOTOR != CANAL: este módulo solo conoce un puerto (`NotifierPort`) y no
importa ningún proveedor. Los adapters (paquete adapters/, p. ej. el de
Slack) implementan el puerto; la composición ocurre en app.py.

Reglas:
- SQLite sigue siendo la fuente de verdad; el aviso es solo un canal.
- Semántica AT-MOST-ONCE: primero se reclama una fila ATTEMPTING (única por
  status_event + tipo + proveedor); solo quien la reclama envía, UNA vez, sin
  reintentos. Si el proceso muere con ATTEMPTING, no se reenvía.
- Ningún fallo de notificación cambia el estado de la tarea ni lo propaga.
- Vocabulario FIJO: nunca texto de excepción, cuerpo HTTP, URL ni mensaje.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .store import (
    NOTIFICATION_ERROR_CATEGORIES,
    NOTIFICATION_STATUS_FAILED,
    NOTIFICATION_STATUS_SENT,
    Store,
)

EVENT_TYPE_HUMAN_GATE = "human_gate"

# Estado de un intento (persistido en notification_event).
STATUS_SENT = NOTIFICATION_STATUS_SENT
STATUS_FAILED = NOTIFICATION_STATUS_FAILED

# Categorías de error permitidas (vocabulario fijo).
ERROR_HTTP_4XX = "HTTP_4XX"
ERROR_HTTP_5XX = "HTTP_5XX"
ERROR_TIMEOUT = "TIMEOUT"
ERROR_NETWORK = "NETWORK"
ERROR_MISSING_SECRET = "MISSING_SECRET"
ERROR_INVALID_WEBHOOK = "INVALID_WEBHOOK"
ERROR_CONFIG_INVALID = "CONFIG_INVALID"

# Valores públicos (campo aditivo `notification_status` en la salida de la CLI).
PUBLIC_SENT = "sent"
PUBLIC_FAILED = "failed"
PUBLIC_ALREADY_ATTEMPTED = "already_attempted"
PUBLIC_CONFIG_INVALID = "config_invalid"


@dataclass(frozen=True)
class NotificationEvent:
    """Único contenido que cruza el puerto: identificadores y tipo de gate.
    Ningún texto libre de Claude, del Task Packet ni de archivos."""

    event_type: str
    project_id: str
    task_id: str
    gate_type: str
    dedupe_key: str


@dataclass(frozen=True)
class NotificationResult:
    """SENT (error_category None) o FAILED + categoría fija."""

    status: str
    error_category: str | None = None

    def __post_init__(self) -> None:
        if self.status == STATUS_SENT:
            valid = self.error_category is None
        elif self.status == STATUS_FAILED:
            valid = self.error_category in NOTIFICATION_ERROR_CATEGORIES
        else:
            valid = False
        if not valid:
            raise ValueError("invalid notification result")


@runtime_checkable
class NotifierPort(Protocol):
    """Contrato mínimo de un canal de aviso. `provider` identifica al canal
    en notification_event; `notify` NUNCA debe lanzar (devuelve FAILED)."""

    provider: str

    def notify(self, event: NotificationEvent) -> NotificationResult: ...


@dataclass(frozen=True)
class NotificationOutcome:
    """Resultado público seguro de un intento de aviso."""

    status: str  # sent | failed | already_attempted
    error_category: str | None = None


def human_gate_dedupe_key(task_id: str, status_event_id: int) -> str:
    """Identidad del gate: la ENTRADA concreta (status_event) a HUMAN_GATE, no
    solo (task, estado): un nuevo ingreso posterior sí puede notificar."""
    return f"{EVENT_TYPE_HUMAN_GATE}:{task_id}:{status_event_id}"


def dispatch_human_gate_notification(
    store: Store,
    notifier: NotifierPort,
    *,
    project_id: str,
    task_id: str,
    gate_type: str,
    status_event_id: int,
) -> NotificationOutcome:
    """Reclama -> envía UNA vez -> registra. Se invoca SOLO después de que la
    transición a HUMAN_GATE ya esté committed.

    Los errores del Store al reclamar se propagan (el llamador los atrapa: la
    tarea nunca se ve afectada). Si el envío falla o el notifier lanza algo
    inesperado, se registra FAILED/NETWORK con vocabulario fijo. Si registrar
    el resultado falla, la fila queda ATTEMPTING (evidencia visible) y NO se
    reenvía."""
    notification_id = store.claim_human_gate_notification(
        task_id,
        status_event_id,
        event_type=EVENT_TYPE_HUMAN_GATE,
        provider=notifier.provider,
        gate_type=gate_type,
    )
    if notification_id is None:
        return NotificationOutcome(PUBLIC_ALREADY_ATTEMPTED)

    event = NotificationEvent(
        event_type=EVENT_TYPE_HUMAN_GATE,
        project_id=project_id,
        task_id=task_id,
        gate_type=gate_type,
        dedupe_key=human_gate_dedupe_key(task_id, status_event_id),
    )
    try:
        result = notifier.notify(event)
        if not isinstance(result, NotificationResult):
            raise TypeError("notifier returned an invalid result")
    except Exception:  # noqa: BLE001 - un canal roto jamás afecta a la tarea
        result = NotificationResult(STATUS_FAILED, ERROR_NETWORK)

    try:
        store.complete_notification(
            notification_id, status=result.status, error_category=result.error_category
        )
    except Exception:  # noqa: BLE001 - queda ATTEMPTING como evidencia; sin reenvío
        pass
    if result.status == STATUS_SENT:
        return NotificationOutcome(PUBLIC_SENT)
    return NotificationOutcome(PUBLIC_FAILED, result.error_category)
