import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator.state_machine import (  # noqa: E402
    ALLOWED_TRANSITIONS,
    INITIAL_STATE,
    STATES,
    TERMINAL_STATES,
    InvalidTransitionError,
    UnknownStateError,
    validate_state,
    validate_transition,
)


class StateSetTests(unittest.TestCase):
    def test_exact_state_set(self) -> None:
        expected = {
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
        self.assertEqual(STATES, expected)

    def test_initial_state_is_backlog(self) -> None:
        self.assertEqual(INITIAL_STATE, "BACKLOG")


class ValidTransitionTests(unittest.TestCase):
    def test_valid_transition_does_not_raise(self) -> None:
        validate_transition("BACKLOG", "SPECIFICATION")
        validate_transition("SECURITY_REVIEW", "HUMAN_GATE")
        validate_transition("TECH_APPROVED", "HUMAN_GATE")


# CAPACITY-RESUME-FOUNDATION-001: WAITING_FOR_CLAUDE_CAPACITY. Espera
# automática temporal tras una señal estructurada de capacidad de Claude.
WAITING = "WAITING_FOR_CLAUDE_CAPACITY"

# Tabla COMPLETA esperada (01_MASTER_SPEC.md §5.2). Es una afirmación exacta:
# si alguien añade o quita cualquier transición, este test lo detecta.
EXPECTED_TRANSITIONS = {
    "BACKLOG": {"SPECIFICATION"},
    "SPECIFICATION": {"DEVELOPING", "BLOCKED"},
    "DEVELOPING": {"AUTOMATED_TEST", "BLOCKED", WAITING},
    WAITING: {"DEVELOPING", "BLOCKED"},
    "AUTOMATED_TEST": {"TECHNICAL_REVIEW", "CHANGES_REQUESTED"},
    "TECHNICAL_REVIEW": {"SECURITY_REVIEW", "CHANGES_REQUESTED", "BLOCKED"},
    "SECURITY_REVIEW": {"TECH_APPROVED", "CHANGES_REQUESTED", "BLOCKED", "HUMAN_GATE"},
    "CHANGES_REQUESTED": {"DEVELOPING", "BLOCKED"},
    "TECH_APPROVED": {"HUMAN_GATE"},
    "HUMAN_GATE": {"HUMAN_APPROVED", "CHANGES_REQUESTED", "BLOCKED"},
    "HUMAN_APPROVED": {"READY_FOR_COMMIT"},
    "READY_FOR_COMMIT": {"COMPLETED"},
    "COMPLETED": set(),
    "BLOCKED": {"HUMAN_GATE", "SPECIFICATION", "CHANGES_REQUESTED"},
}


class WaitingForClaudeCapacityTests(unittest.TestCase):
    def test_waiting_state_is_in_the_state_set(self) -> None:
        self.assertIn(WAITING, STATES)

    def test_transition_table_covers_exactly_the_state_set(self) -> None:
        self.assertEqual(set(ALLOWED_TRANSITIONS), STATES)

    def test_developing_to_waiting_is_allowed(self) -> None:
        validate_transition("DEVELOPING", WAITING)

    def test_waiting_to_developing_is_allowed(self) -> None:
        validate_transition(WAITING, "DEVELOPING")

    def test_waiting_to_blocked_is_allowed(self) -> None:
        validate_transition(WAITING, "BLOCKED")

    def test_waiting_has_exactly_two_exits(self) -> None:
        self.assertEqual(ALLOWED_TRANSITIONS[WAITING], frozenset({"DEVELOPING", "BLOCKED"}))

    def test_waiting_is_only_reachable_from_developing(self) -> None:
        sources = {state for state, targets in ALLOWED_TRANSITIONS.items() if WAITING in targets}
        self.assertEqual(sources, {"DEVELOPING"})

    def test_every_other_transition_into_or_out_of_waiting_is_rejected(self) -> None:
        for state in STATES - {"DEVELOPING", WAITING}:
            with self.subTest(source=state):
                with self.assertRaises(InvalidTransitionError):
                    validate_transition(state, WAITING)
        for target in STATES - {"DEVELOPING", "BLOCKED"}:
            with self.subTest(target=target):
                with self.assertRaises(InvalidTransitionError):
                    validate_transition(WAITING, target)

    def test_full_transition_table_is_exactly_the_approved_one(self) -> None:
        # Solo se añadieron las tres transiciones nuevas; el resto no cambió.
        actual = {state: set(targets) for state, targets in ALLOWED_TRANSITIONS.items()}
        self.assertEqual(actual, EXPECTED_TRANSITIONS)

    def test_waiting_is_not_terminal(self) -> None:
        self.assertNotIn(WAITING, TERMINAL_STATES)


class InvalidTransitionTests(unittest.TestCase):
    def test_invalid_transition_is_rejected(self) -> None:
        with self.assertRaises(InvalidTransitionError):
            validate_transition("BACKLOG", "COMPLETED")

    def test_terminal_state_has_no_outgoing_transitions(self) -> None:
        with self.assertRaises(InvalidTransitionError):
            validate_transition("COMPLETED", "BACKLOG")

    def test_allowed_transitions_table_is_deterministic_after_failure(self) -> None:
        snapshot = {state: frozenset(targets) for state, targets in ALLOWED_TRANSITIONS.items()}
        with self.assertRaises(InvalidTransitionError):
            validate_transition("BACKLOG", "COMPLETED")
        self.assertEqual(ALLOWED_TRANSITIONS, snapshot)


class UnknownStateTests(unittest.TestCase):
    def test_unknown_source_state_is_rejected(self) -> None:
        with self.assertRaises(UnknownStateError):
            validate_transition("NOT_A_STATE", "BACKLOG")

    def test_unknown_target_state_is_rejected(self) -> None:
        with self.assertRaises(UnknownStateError):
            validate_transition("BACKLOG", "NOT_A_STATE")

    def test_validate_state_rejects_arbitrary_state(self) -> None:
        with self.assertRaises(UnknownStateError):
            validate_state("ARBITRARY")


if __name__ == "__main__":
    unittest.main()
