"""Reconciliación fail-closed de precondiciones (STATE-RECONCILIATION-001).

Responsabilidad única: comparar las precondiciones declaradas en un Task
Packet (`task_packet.Preconditions`) contra hechos observados en la
realidad técnica actual, y clasificar cada comprobación. Este módulo NUNCA
corrige nada, nunca ejecuta una operación mutante (ni Git ni de Windows),
y nunca decide POR SU CUENTA continuar ante una discrepancia material: solo
detecta y clasifica (MOTOR != REGLAS -- el Task Packet declara hechos
esperados, este módulo decide el resultado de la comparación, y quien lo
invoca decide qué hacer con ese resultado).

Git: reutiliza EXCLUSIVAMENTE las primitivas de solo lectura ya existentes
en `evidence.py` (capture_snapshot, con su propio confinamiento vía
`_validate_repo_root` y su allowlist de subcomandos git de solo lectura).
No se crea un segundo motor Git.

Windows Scheduled Task: única consulta permitida, `schtasks.exe /Query
/TN <name> /HRESULT`, con argv separado (shell=False), timeout explícito, y sin
`/Create`, `/Delete`, `/Change`, `/Run` ni `/End`. Nunca invoca PowerShell
ni cmd.exe. Un resultado ambiguo (código de salida no documentado, timeout,
ejecutable no encontrado) se clasifica UNKNOWN, nunca se interpreta como
ausencia/presencia confirmada.

Clasificaciones (deliberadamente solo tres en este incremento; las
precondiciones de un Task Packet son invariantes exactas de ejecución, no
admiten un intermedio "drift no material"):
  - MATCH: lo esperado coincide con lo observado.
  - DRIFT_MATERIAL: difieren -- bloquea, nunca se autocorrige.
  - UNKNOWN: no se pudo verificar -- fail closed, se trata igual que
    DRIFT_MATERIAL a efectos de bloqueo.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from . import evidence as evidence_mod
from .task_packet import (
    EXTERNAL_RESOURCE_TYPE_WINDOWS_SCHEDULED_TASK,
    ExternalResourcePrecondition,
    GitPreconditions,
    Preconditions,
)

CLASSIFICATION_MATCH = "MATCH"
CLASSIFICATION_DRIFT_MATERIAL = "DRIFT_MATERIAL"
CLASSIFICATION_UNKNOWN = "UNKNOWN"

_SCHEDULED_TASK_QUERY_TIMEOUT_SECONDS = 15
# /HRESULT conserva el error estructurado: solo ERROR_FILE_NOT_FOUND
# confirma ausencia. El código genérico 1 también indica sintaxis inválida
# y NUNCA prueba ausencia. No se interpretan mensajes localizados.
_SCHTASKS_EXIT_CODE_PRESENT = 0
_SCHTASKS_HRESULT_FILE_NOT_FOUND = 0x80070002


@dataclass(frozen=True)
class ReconciliationCheck:
    """Un único hecho comparado. `expected`/`observed` son siempre JSON-
    serializables (str, bool, dict de esos tipos, o None) -- nunca stdout,
    stderr ni ningún detalle crudo del sistema operativo."""

    check_type: str
    expected: Any
    observed: Any
    classification: str
    evidence_code: str


@dataclass(frozen=True)
class ReconciliationReport:
    classification: str
    checks: tuple[ReconciliationCheck, ...]


def _reconcile_git(
    project_root: Path, git_preconditions: GitPreconditions
) -> list[ReconciliationCheck]:
    """Repository válido + working tree + branch + HEAD, en una sola
    captura de solo lectura (`evidence.capture_snapshot`). Si el repo no
    se puede consultar de forma segura, TODO el bloque Git se reporta como
    un único check UNKNOWN -- nunca se asume limpio/coincidente ante la
    duda, y nunca se interpreta ancestry para permitir continuar: un HEAD
    distinto es SIEMPRE DRIFT_MATERIAL en este incremento."""
    try:
        snapshot = evidence_mod.capture_snapshot(project_root, authorized_root=project_root)
    except evidence_mod.EvidenceError:
        return [
            ReconciliationCheck(
                check_type="git",
                expected={
                    "expected_branch": git_preconditions.expected_branch,
                    "expected_head": git_preconditions.expected_head,
                    "require_clean": git_preconditions.require_clean,
                },
                observed=None,
                classification=CLASSIFICATION_UNKNOWN,
                evidence_code="git_unavailable",
            )
        ]

    checks: list[ReconciliationCheck] = []

    clean_match = snapshot.is_clean
    checks.append(
        ReconciliationCheck(
            check_type="git_working_tree_clean",
            expected=True,
            observed=snapshot.is_clean,
            classification=(
                CLASSIFICATION_MATCH if clean_match else CLASSIFICATION_DRIFT_MATERIAL
            ),
            evidence_code="working_tree_clean" if clean_match else "working_tree_dirty",
        )
    )

    branch_match = snapshot.branch == git_preconditions.expected_branch
    checks.append(
        ReconciliationCheck(
            check_type="git_branch",
            expected=git_preconditions.expected_branch,
            observed=snapshot.branch,
            classification=(
                CLASSIFICATION_MATCH if branch_match else CLASSIFICATION_DRIFT_MATERIAL
            ),
            evidence_code="branch_match" if branch_match else "branch_mismatch",
        )
    )

    head_match = snapshot.head_sha == git_preconditions.expected_head
    checks.append(
        ReconciliationCheck(
            check_type="git_head",
            expected=git_preconditions.expected_head,
            observed=snapshot.head_sha,
            classification=(
                CLASSIFICATION_MATCH if head_match else CLASSIFICATION_DRIFT_MATERIAL
            ),
            evidence_code="head_match" if head_match else "head_mismatch",
        )
    )
    return checks


def _query_windows_scheduled_task_presence(name: str) -> bool | None:
    """Solo lectura: `schtasks.exe /Query /TN <name> /HRESULT`, argv separado
    (shell=False), timeout explícito. Devuelve True (existe), False
    (confirmado ausente) o None (indeterminado: ejecutable no encontrado,
    timeout, o código de salida fuera de los dos documentados). Nunca
    ejecuta /Create, /Delete, /Change, /Run ni /End; nunca invoca
    PowerShell ni cmd.exe."""
    executable = shutil.which("schtasks.exe") or shutil.which("schtasks")
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, "/Query", "/TN", name, "/HRESULT"],
            capture_output=True,
            timeout=_SCHEDULED_TASK_QUERY_TIMEOUT_SECONDS,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    returncode = completed.returncode & 0xFFFFFFFF
    if returncode == _SCHTASKS_EXIT_CODE_PRESENT:
        return True
    if returncode == _SCHTASKS_HRESULT_FILE_NOT_FOUND:
        return False
    return None


def _reconcile_external_resource(
    resource: ExternalResourcePrecondition,
) -> ReconciliationCheck:
    expected = {
        "resource_type": resource.type,
        "resource_name": resource.name,
        "expected_present": resource.expected_present,
    }

    if resource.type == EXTERNAL_RESOURCE_TYPE_WINDOWS_SCHEDULED_TASK:
        observed_present = _query_windows_scheduled_task_presence(resource.name)
    else:  # pragma: no cover - task_packet ya restringe `type` a valores conocidos
        observed_present = None

    if observed_present is None:
        return ReconciliationCheck(
            check_type="external_resource",
            expected=expected,
            observed={"observed_present": None},
            classification=CLASSIFICATION_UNKNOWN,
            evidence_code="resource_check_unavailable",
        )

    match = observed_present == resource.expected_present
    return ReconciliationCheck(
        check_type="external_resource",
        expected=expected,
        observed={"observed_present": observed_present},
        classification=CLASSIFICATION_MATCH if match else CLASSIFICATION_DRIFT_MATERIAL,
        evidence_code="resource_present" if observed_present else "resource_absent",
    )


def _global_classification(checks: Sequence[ReconciliationCheck]) -> str:
    classifications = {check.classification for check in checks}
    if CLASSIFICATION_UNKNOWN in classifications:
        return CLASSIFICATION_UNKNOWN
    if CLASSIFICATION_DRIFT_MATERIAL in classifications:
        return CLASSIFICATION_DRIFT_MATERIAL
    return CLASSIFICATION_MATCH


def reconcile_preconditions(
    project_root: Path, preconditions: Preconditions
) -> ReconciliationReport:
    """Único punto de entrada del motor de reconciliación: Git primero,
    luego cada external_resource declarado, en el orden en que aparecen en
    el Task Packet. Nunca corrige nada; solo detecta y clasifica."""
    checks: list[ReconciliationCheck] = list(
        _reconcile_git(project_root, preconditions.git)
    )
    for resource in preconditions.external_resources:
        checks.append(_reconcile_external_resource(resource))
    return ReconciliationReport(
        classification=_global_classification(checks), checks=tuple(checks)
    )


def report_to_public_dict(report: ReconciliationReport) -> dict[str, Any]:
    """Forma JSON-segura del reporte: nunca incluye stdout/stderr crudo,
    solo los campos ya sanitizados de cada `ReconciliationCheck`."""
    return {
        "classification": report.classification,
        "checks": [
            {
                "check_type": check.check_type,
                "expected": check.expected,
                "observed": check.observed,
                "classification": check.classification,
                "evidence_code": check.evidence_code,
            }
            for check in report.checks
        ],
    }
