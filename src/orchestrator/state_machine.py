"""Máquina de estados — estados y transiciones exactos de 01_MASTER_SPEC.md §5.

Las transiciones permitidas están centralizadas en ALLOWED_TRANSITIONS y deben
verificarse antes de persistir cualquier cambio de estado (§5.2, invariante).
Una transición inválida o un estado desconocido nunca mutan estado: solo
levantan una excepción controlada.
"""

from __future__ import annotations

STATES: frozenset[str] = frozenset(
    {
        "BACKLOG",
        "SPECIFICATION",
        "DEVELOPING",
        "WAITING_FOR_CLAUDE_CAPACITY",
        "AUTOMATED_TEST",
        "TECHNICAL_REVIEW",
        "SECURITY_REVIEW",
        "CHANGES_REQUESTED",
        "TECH_APPROVED",
        "HUMAN_GATE",
        "HUMAN_APPROVED",
        "READY_FOR_COMMIT",
        "COMPLETED",
        "BLOCKED",
    }
)

INITIAL_STATE: str = "BACKLOG"

TERMINAL_STATES: frozenset[str] = frozenset({"COMPLETED"})

# Tabla de transiciones permitidas (01_MASTER_SPEC.md §5.2).
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "BACKLOG": frozenset({"SPECIFICATION"}),
    "SPECIFICATION": frozenset({"DEVELOPING", "BLOCKED"}),
    # CAPACITY-RESUME-FOUNDATION-001: espera automática temporal tras una
    # señal ESTRUCTURADA de capacidad de Claude (ver 01_MASTER_SPEC.md §5).
    "DEVELOPING": frozenset({"AUTOMATED_TEST", "BLOCKED", "WAITING_FOR_CLAUDE_CAPACITY"}),
    "WAITING_FOR_CLAUDE_CAPACITY": frozenset({"DEVELOPING", "BLOCKED"}),
    "AUTOMATED_TEST": frozenset({"TECHNICAL_REVIEW", "CHANGES_REQUESTED"}),
    "TECHNICAL_REVIEW": frozenset({"SECURITY_REVIEW", "CHANGES_REQUESTED", "BLOCKED"}),
    "SECURITY_REVIEW": frozenset(
        {"TECH_APPROVED", "CHANGES_REQUESTED", "BLOCKED", "HUMAN_GATE"}
    ),
    "CHANGES_REQUESTED": frozenset({"DEVELOPING", "BLOCKED"}),
    "TECH_APPROVED": frozenset({"HUMAN_GATE"}),
    "HUMAN_GATE": frozenset({"HUMAN_APPROVED", "CHANGES_REQUESTED", "BLOCKED"}),
    "HUMAN_APPROVED": frozenset({"READY_FOR_COMMIT"}),
    "READY_FOR_COMMIT": frozenset({"COMPLETED"}),
    "COMPLETED": frozenset(),
    # BLOCKED: el cierre manual (sin destino) no es una transición de estado;
    # los tres destinos automatizables quedan representados aquí (§5.2).
    "BLOCKED": frozenset({"HUMAN_GATE", "SPECIFICATION", "CHANGES_REQUESTED"}),
}

assert set(ALLOWED_TRANSITIONS) == STATES


class StateMachineError(Exception):
    """Base para errores controlados de la máquina de estados."""


class UnknownStateError(StateMachineError):
    """Un estado no pertenece al conjunto definido en la Master Spec."""


class InvalidTransitionError(StateMachineError):
    """Una transición no está permitida desde el estado de origen."""


def validate_state(state: str) -> str:
    if state not in STATES:
        raise UnknownStateError(f"unknown state: {state!r}")
    return state


def allowed_targets(from_state: str) -> frozenset[str]:
    validate_state(from_state)
    return ALLOWED_TRANSITIONS[from_state]


def validate_transition(from_state: str, to_state: str) -> None:
    """Verifica que from_state -> to_state esté permitido.

    No muta nada; solo lanza UnknownStateError o InvalidTransitionError si la
    transición no es válida. El llamador debe verificar antes de persistir.
    """
    validate_state(from_state)
    validate_state(to_state)
    allowed = ALLOWED_TRANSITIONS[from_state]
    if to_state not in allowed:
        raise InvalidTransitionError(
            f"transition {from_state} -> {to_state} is not allowed; "
            f"allowed targets from {from_state}: {sorted(allowed) if allowed else 'none (terminal state)'}"
        )
