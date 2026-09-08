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
