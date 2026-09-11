"""Recolector reutilizable de evidencia Git (EVIDENCE-001).

Responsabilidad única: capturar el estado real de un repositorio Git local
(BEFORE/AFTER) y calcular qué cambió, de forma que Claude (o cualquier
agente) NUNCA pueda declarar qué archivos modificó y que eso se considere
evidencia. Todo se calcula aquí, a partir de `git` real.

Principio rector (Master Spec §11): la evidencia ejecutable tiene
prioridad sobre la narrativa del agente.

Este módulo es principalmente READ-ONLY: internamente solo puede invocar
un conjunto muy reducido de subcomandos de git de solo lectura
(`rev-parse`, `branch`, `status`, `diff`). Nunca ejecuta `push`, `pull`,
`fetch`, `merge`, `rebase`, `reset`, `clean`, `checkout`, `switch`,
`remote`, `tag`, `add` ni `commit`. La creación/eliminación de un
repositorio Git de prueba (setup) es responsabilidad de quien invoca este
módulo (CLI de demostración o pruebas), no de este recolector.

CORRECTION-001 (parseo robusto de paths, sección de renombres): todo el
parseo de `git status`/`git diff` usa los formatos NUL-terminated de git
(`-z`), nunca líneas/tabs ni el quoting humano de git. `renamed_paths`
contiene EXCLUSIVAMENTE renombres que Git reporta explícitamente
(R###/C### en `git diff --name-status -z`); no existe ninguna inferencia
heurística por contenido/hash. Un rename realizado solo por filesystem
(sin stage) y cuyo destino sea untracked se reporta CONSERVADORAMENTE
como delete + untracked, nunca como rename inventado — ante ambigüedad,
DELETE + CREATE/UNTRACKED es preferible a inventar una correspondencia.

CORRECTION-002 (parseo -z estricto, fail-closed): los parsers NUL-
terminated (`_split_nul_terminated`, `_parse_diff_name_status_z`,
`_iter_status_records_z`) nunca aceptan/truncan silenciosamente un
formato incompleto o inesperado. Formato inesperado = EvidenceError,
siempre — nunca `continue` silencioso ni `break` devolviendo evidencia
parcial. Un registro corto, un rename/copy sin sus dos paths, un path
vacío o una salida `-z` que no termina en NUL hacen fallar la captura por
completo en vez de reportar una evidencia incompleta.

CORRECTION-002 (revalidación BEFORE -> AFTER): `capture_change_evidence()`
nunca asume que el `repo_root` capturado en `before` sigue siendo el mismo
repositorio confinado y seguro que cuando se capturó `capture_snapshot()`.
Entre BEFORE y AFTER puede haber ocurrido actividad arbitraria (del
Developer o de cualquier otro proceso); por eso `GitEvidenceSnapshot`
conserva también el `authorized_root` canónico usado en BEFORE, y
`capture_change_evidence()` vuelve a ejecutar la validación completa de
`_validate_repo_root()` ANTES de invocar cualquier comando git sobre el
AFTER. Si la identidad/frontera del repositorio dejó de ser válida
(symlink/junction, `.git` sustituido, `show-toplevel` distinto, etc.), se
falla cerrado (EvidenceError) sin ejecutar diff/status sobre un destino
inseguro y sin intentar reparar nada.

No conecta AIP ni FOA. No conoce nada sobre Claude Code ni sobre el
sandbox de escritura (adapters/claude_code.py): ese acoplamiento se evita
deliberadamente; sí reutiliza `_is_link_like` de sandbox.py para aplicar
la misma filosofía de detección de enlaces sin duplicar esa lógica.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Sequence

from .sandbox import _is_link_like

# Subcomandos de git permitidos desde este recolector. Cualquier otro
# (incluidos push/pull/fetch/merge/rebase/reset/clean/checkout/switch/
# remote/tag/add/commit/show) se rechaza incondicionalmente por
# construcción (allowlist, no blacklist). "show" NO está aquí: se usaba
# únicamente para la inferencia heurística de renombres por contenido,
# eliminada en CORRECTION-001 (hallazgo 2).
_ALLOWED_GIT_SUBCOMMANDS = frozenset({"rev-parse", "branch", "status", "diff"})

_DEFAULT_TIMEOUT_SECONDS = 15

# Prefijo del repositorio Git ficticio y desechable usado por
# evidence-probe (CLI de demostración, app.py). El setup del repositorio
# (git init/config/add/commit) NO vive en este módulo (ver docstring del
# módulo); solo el prefijo se expone aquí para que create_sandbox()/
# cleanup_sandbox() (sandbox.py) puedan reutilizarse de forma segura.
GIT_EVIDENCE_PROBE_PREFIX = ".git_evidence_probe_"


class EvidenceError(Exception):
    """Error controlado del recolector de evidencia. Falla cerrado."""


@dataclass(frozen=True)
class GitEvidenceSnapshot:
    repo_root: Path
    authorized_root: Path
    head_sha: str
    branch: str
    is_clean: bool
    status_entries: tuple[str, ...]


@dataclass(frozen=True)
class GitChangeEvidence:
    base_sha: str
    current_head_sha: str
    head_changed: bool
    changed_paths: tuple[str, ...]
    created_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    renamed_paths: tuple[tuple[str, str], ...]
    untracked_paths: tuple[str, ...]
    out_of_scope_paths: tuple[str, ...]
    has_out_of_scope_changes: bool
    working_tree_clean: bool
    diff_available: bool
    diff_stat: str | None = None


@dataclass(frozen=True)
class EvidenceEvaluation:
    success: bool
    base_sha: str
    current_head_sha: str
    changed_paths: tuple[str, ...]
    created_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    renamed_paths: tuple[tuple[str, str], ...]
    untracked_paths: tuple[str, ...]
    out_of_scope_paths: tuple[str, ...]
    head_changed: bool
    reason: str


def _resolve_git_executable() -> str:
    resolved = shutil.which("git")
    if resolved is None:
        raise EvidenceError("git executable not found on PATH")
    return resolved


def _run_git(
    git_executable: str, args: list[str], *, cwd: Path, timeout: int = _DEFAULT_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess:
    """Ejecuta un subcomando git de solo lectura. `args` nunca proviene de
    Claude; siempre lo construye este módulo. shell=False, lista de
    argumentos, cwd explícito, timeout acotado.

    `encoding="utf-8"` se especifica EXPLÍCITAMENTE (en vez de solo
    `text=True`, que decodificaría con la codificación preferida de la
    localización del sistema): git emite paths codificados en UTF-8
    incluso en Windows, especialmente con `-z`; dejar la decodificación a
    la localización del sistema puede corromper silenciosamente cualquier
    carácter no ASCII (verificado empíricamente: bytes UTF-8 de 'é'
    decodificados como dos caracteres Latin-1 separados en este
    entorno). `errors="surrogateescape"` evita que un byte inesperado
    haga fallar la decodificación por completo (fail closed en el
    parseo, no en la propia lectura del proceso)."""
    if not args or args[0] not in _ALLOWED_GIT_SUBCOMMANDS:
        raise EvidenceError(
            f"git subcommand not allowed for evidence collection: {args[0] if args else '<empty>'!r}"
        )
    full_args = [git_executable, *args]
    try:
        completed = subprocess.run(
            full_args,
            cwd=str(cwd),
            capture_output=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise EvidenceError(f"git executable could not be launched: {type(exc).__name__}") from exc
    except subprocess.TimeoutExpired as exc:
        raise EvidenceError(f"git command timed out after {timeout}s") from exc

    if completed.returncode != 0:
        # Sanitizado: nunca se incluye stdout/stderr completos en el error.
        raise EvidenceError(f"git command failed: exit_code={completed.returncode}")
    return completed


def _validate_repo_root(repo_root: Path | str, authorized_root: Path | str) -> Path:
    """Falla cerrado si repo_root no existe, no es directorio, sale de
    authorized_root, es un symlink/junction (misma filosofía que
    sandbox.cleanup_sandbox(): se verifica la IDENTIDAD del candidato
    ANTES de resolver su último componente, para no seguir un enlace que
    apunte fuera), o no es un repositorio git CONFINADO (CORRECTION-001,
    hallazgo 6): .git debe ser un directorio ordinario dentro de
    repo_root (no symlink/junction, no archivo "gitdir:" de
    redirección/worktree — sin soporte de worktrees externos en este
    MVP), y `git rev-parse --show-toplevel` debe coincidir EXACTAMENTE
    con repo_root."""
    authorized_root_resolved = Path(authorized_root).resolve()
    candidate = Path(repo_root)

    parent_resolved = candidate.parent.resolve()
    target = parent_resolved / candidate.name

    if _is_link_like(target):
        raise EvidenceError("refusing to operate on a symlink/junction repo_root")

    resolved = target.resolve()
    if not resolved.exists():
        raise EvidenceError(f"repo_root does not exist: {resolved}")
    if not resolved.is_dir():
        raise EvidenceError(f"repo_root is not a directory: {resolved}")
    if authorized_root_resolved not in (resolved, *resolved.parents):
        raise EvidenceError("repo_root is outside the authorized root")

    # .git debe ser un directorio ORDINARIO dentro de repo_root. Un repo_root
    # sustituido por un enlace ya falló arriba, ANTES de tocar Git; aquí se
    # aplica la misma regla al propio ".git".
    git_dir_candidate = resolved / ".git"
    if _is_link_like(git_dir_candidate):
        raise EvidenceError("repo_root's .git must not be a symlink/junction")
    if not git_dir_candidate.exists():
        raise EvidenceError(f"repo_root is not a git repository: {resolved}")
    if not git_dir_candidate.is_dir():
        raise EvidenceError(
            "repo_root's .git must be an ordinary directory "
            "(gitdir redirection / worktrees are not supported in this MVP)"
        )

    # Confirmación final vía Git real: el top-level del repositorio debe
    # ser EXACTAMENTE repo_root (rechaza cualquier redirección/anidamiento
    # que las comprobaciones de filesystem anteriores no hubieran cubierto).
    git_exe = _resolve_git_executable()
    toplevel = _run_git(
        git_exe, ["rev-parse", "--show-toplevel"], cwd=resolved
    ).stdout.strip()
    if not toplevel:
        raise EvidenceError("git rev-parse --show-toplevel returned empty output")
    if Path(toplevel).resolve() != resolved:
        raise EvidenceError(
            "repo_root does not match its own git top-level directory "
            "(worktree/redirection not supported in this MVP)"
        )

    return resolved


def _normalize_allowed_paths(allowed_paths: Sequence[str]) -> frozenset[str]:
    """Valida y normaliza allowed_paths: únicamente rutas relativas en
    formato POSIX. Rechaza explícitamente (CORRECTION-001, hallazgo 3):
    absolute path POSIX (/...), cualquier forma de path Windows (drive
    C:\\..., C:/..., UNC \\\\server\\share o //server/share, o un drive
    sin separador como "C:relativo"), backslash como separador, '..'/
    traversal, string vacío y bytes NUL. Los paths se normalizan SIEMPRE
    a formato POSIX internamente, igual que la salida real de git
    (incluso en Windows, git informa paths con '/')."""
    normalized: set[str] = set()
    for raw in allowed_paths:
        if not isinstance(raw, str) or not raw:
            raise EvidenceError(f"allowed_paths entry must be a non-empty string: {raw!r}")
        if "\x00" in raw:
            raise EvidenceError(f"allowed_paths entry must not contain NUL characters: {raw!r}")
        if "\\" in raw:
            raise EvidenceError(
                f"allowed_paths entry must use POSIX separators ('/'), not backslash: {raw!r}"
            )

        # PureWindowsPath detecta ademas 'C:/...' y '//server/share/...'
        # (drive/UNC con separadores '/'), que PurePosixPath NO reconoce
        # como absolutos por sí solo (ese fue exactamente el hallazgo
        # reproducido por el Director). `.drive` también cubre un drive
        # sin separador ("C:relativo.txt"), que la tarea exige rechazar
        # como "cualquier drive Windows".
        windows_view = PureWindowsPath(raw)
        if windows_view.drive or windows_view.root:
            raise EvidenceError(f"allowed_paths entry must not be a Windows-style path: {raw!r}")

        candidate = PurePosixPath(raw)
        if candidate.is_absolute():
            raise EvidenceError(f"allowed_paths entry must be relative, got absolute: {raw!r}")
        if not candidate.parts:
            raise EvidenceError(f"allowed_paths entry must not be empty: {raw!r}")
        if ".." in candidate.parts:
            raise EvidenceError(f"allowed_paths entry must not contain '..': {raw!r}")

        normalized.add(candidate.as_posix())
    return frozenset(normalized)


def _split_nul_terminated(output: str) -> list[str]:
    """Divide una salida de git NUL-terminated (`-z`) en sus campos, sin
    usar splitlines() (un path puede contener un salto de línea o un tab
    real, que deben preservarse intactos) y sin aplicar strip() a ningún
    campo (preservaría espacios/caracteres iniciales o finales reales del
    nombre de archivo).

    CORRECTION-002: falla cerrado ante formato incompleto. Una salida
    `-z` no vacía SIEMPRE termina en un byte NUL estructural (el
    delimitador final del último campo); si no termina en NUL, la salida
    está truncada/incompleta y NUNCA se debe interpretar parcialmente. Se
    elimina EXCLUSIVAMENTE ese único campo vacío estructural final —
    nunca ningún otro campo — preservando el resto exactamente."""
    if output == "":
        return []
    if not output.endswith("\x00"):
        raise EvidenceError(
            "git -z output did not end with the expected NUL terminator "
            "(truncated/incomplete output)"
        )
    fields = output.split("\x00")
    fields.pop()  # el campo vacío estructural posterior al último NUL.
    return fields


def _parse_diff_name_status_z(
    output: str,
) -> tuple[list[str], list[str], list[str], list[tuple[str, str]]]:
    """Parsea `git diff --name-status -z <base>`: secuencia PLANA de
    campos NUL-terminados, con los bytes reales del path (sin quoting ni
    escapes humanos de git). Un código R###/C### consume los DOS campos
    siguientes (old_path, new_path); cualquier otro código consume el
    campo siguiente (path). Formato verificado empíricamente contra git
    real (incluye rutas con espacios y con caracteres no ASCII).

    CORRECTION-002: nunca devuelve evidencia parcial. Un registro
    truncado (rename/copy sin sus dos paths, o código ordinario sin su
    path), un código de estado vacío, o un path vacío hacen fallar la
    captura por completo (EvidenceError) en vez de `break`/`continue`
    silencioso. Un código no reconocido (p. ej. "T" cambio de tipo) se
    trata conservadoramente como "changed" -- consume exactamente el
    mismo número de campos (1) que M/A/D, por lo que nunca desincroniza
    el stream de campos."""
    fields = _split_nul_terminated(output)

    changed: list[str] = []
    created: list[str] = []
    deleted: list[str] = []
    renamed: list[tuple[str, str]] = []

    i = 0
    while i < len(fields):
        code = fields[i]
        if not code:
            raise EvidenceError(
                "git diff --name-status -z produced an empty status code "
                "(malformed/truncated output)"
            )
        if code[0] in ("R", "C"):
            if i + 2 >= len(fields):
                raise EvidenceError(
                    "git diff --name-status -z rename/copy record is truncated "
                    "(missing old/new path)"
                )
            old_path = fields[i + 1]
            new_path = fields[i + 2]
            if not old_path or not new_path:
                raise EvidenceError(
                    "git diff --name-status -z rename/copy record has an empty path"
                )
            renamed.append((old_path, new_path))
            i += 3
            continue
        if i + 1 >= len(fields):
            raise EvidenceError(
                "git diff --name-status -z record is truncated (missing path)"
            )
        path = fields[i + 1]
        if not path:
            raise EvidenceError("git diff --name-status -z record has an empty path")
        if code == "M":
            changed.append(path)
        elif code == "A":
            created.append(path)
        elif code == "D":
            deleted.append(path)
        else:
            # Código no reconocido: tratamiento conservador explícito que
            # consume el mismo número de campos que M/A/D, sin desincronizar
            # el parser.
            changed.append(path)
        i += 2

    return changed, created, deleted, renamed


def _iter_status_records_z(output: str) -> list[tuple[str, str, str | None]]:
    """Parsea `git status --porcelain=v1 -z --untracked-files=all`:
    secuencia PLANA de campos NUL-terminados. Un registro ordinario es un
    único campo "XY path"; un registro de rename/copy ocupa DOS campos
    consecutivos: "XY new_path" seguido de "old_path" (sin prefijo XY).
    Formato verificado empíricamente contra git real. Devuelve tuplas
    (xy, path, old_path_or_None).

    CORRECTION-002: nunca devuelve evidencia parcial. Se exige la
    estructura completa "XY<espacio>path" (mínimo 3 caracteres, con el
    separador exactamente en la posición esperada); un registro más
    corto o sin ese separador es EvidenceError, nunca un registro
    descartado en silencio. Un path vacío es EvidenceError. Se considera
    rename/copy si 'R'/'C' aparece en CUALQUIERA de las dos posiciones de
    XY (no solo X), para no desincronizar el stream ante cualquier forma
    que porcelain v1 pueda producir; si el segundo campo (old_path) falta
    o está vacío, EvidenceError -- nunca se reinterpreta como un registro
    ordinario (eso dejaría el old_path real como si fuera el próximo
    registro, corrompiendo todo el resto del parseo)."""
    fields = _split_nul_terminated(output)

    records: list[tuple[str, str, str | None]] = []
    i = 0
    while i < len(fields):
        record = fields[i]
        if len(record) < 3 or record[2] != " ":
            raise EvidenceError(
                "git status --porcelain=v1 -z record is malformed/truncated "
                "(expected 'XY path' structure)"
            )
        xy = record[:2]
        path = record[3:]
        if not path:
            raise EvidenceError(
                "git status --porcelain=v1 -z record has an empty path"
            )
        is_rename_or_copy = xy[0] in ("R", "C") or xy[1] in ("R", "C")
        if is_rename_or_copy:
            if i + 1 >= len(fields):
                raise EvidenceError(
                    "git status --porcelain=v1 -z rename/copy record is "
                    "missing its old path"
                )
            old_path = fields[i + 1]
            if not old_path:
                raise EvidenceError(
                    "git status --porcelain=v1 -z rename/copy record has an "
                    "empty old path"
                )
            records.append((xy, path, old_path))
            i += 2
        else:
            records.append((xy, path, None))
            i += 1
    return records


def capture_snapshot(repo_root: Path | str, *, authorized_root: Path | str) -> GitEvidenceSnapshot:
    """Captura BEFORE: HEAD, branch y estado de limpieza reales, mediante
    git real. No acepta repo_root fuera de authorized_root.

    CORRECTION-002: `authorized_root` se canonicaliza (resolve()) y se
    conserva en el snapshot resultante, para que `capture_change_evidence()`
    pueda volver a aplicar exactamente la misma frontera de autorización
    al revalidar el repositorio en el momento del AFTER."""
    authorized_root_resolved = Path(authorized_root).resolve()
    resolved_root = _validate_repo_root(repo_root, authorized_root_resolved)
    git_exe = _resolve_git_executable()

    head_sha = _run_git(git_exe, ["rev-parse", "HEAD"], cwd=resolved_root).stdout.strip()
    if not head_sha:
        raise EvidenceError("git rev-parse HEAD returned empty output")

    branch = _run_git(git_exe, ["branch", "--show-current"], cwd=resolved_root).stdout.strip()

    status_output = _run_git(
        git_exe,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=resolved_root,
    ).stdout
    records = _iter_status_records_z(status_output)
    status_entries = tuple(
        f"{xy} {old} -> {path}" if old is not None else f"{xy} {path}"
        for xy, path, old in records
    )

    return GitEvidenceSnapshot(
        repo_root=resolved_root,
        authorized_root=authorized_root_resolved,
        head_sha=head_sha,
        branch=branch,
        is_clean=len(records) == 0,
        status_entries=status_entries,
    )


def capture_change_evidence(
    before: GitEvidenceSnapshot,
    allowed_paths: Sequence[str],
    *,
    include_diff_stat: bool = True,
) -> GitChangeEvidence:
    """Captura AFTER y calcula el diff contra el HEAD/base capturado en
    `before`, usando git real (nunca la narrativa de Claude). Calcula
    también el alcance no autorizado a partir de `allowed_paths`.

    renamed_paths contiene EXCLUSIVAMENTE lo que `git diff --name-status
    -z` reporta explícitamente como R###/C### (CORRECTION-001, hallazgo
    2): no existe ninguna inferencia heurística por contenido/hash. Un
    rename hecho solo por filesystem (sin stage) se reporta
    conservadoramente como delete + untracked, nunca como rename
    inventado; la evaluación de alcance sigue cubriendo ambos paths por
    separado, por lo que la seguridad no disminuye.

    CORRECTION-002 (hallazgo 2): ANTES de ejecutar cualquier comando git
    sobre el AFTER (`rev-parse HEAD`, `diff`, `status`), se vuelve a
    aplicar la validación COMPLETA de `_validate_repo_root()` sobre
    `before.repo_root`/`before.authorized_root` -- exactamente la misma
    frontera de autorización usada en BEFORE. Entre BEFORE y AFTER puede
    haber ocurrido actividad arbitraria (Developer u otro proceso); si el
    repositorio ya no es el mismo directorio confinado y seguro (symlink/
    junction, `.git` sustituido/convertido en archivo de redirección,
    `show-toplevel` ya no coincide, etc.), esta revalidación falla cerrado
    (EvidenceError) y NINGÚN comando git posterior se ejecuta sobre ese
    destino inseguro. No se intenta reparar el repositorio."""
    normalized_allowed = _normalize_allowed_paths(allowed_paths)
    git_exe = _resolve_git_executable()
    resolved_root = _validate_repo_root(before.repo_root, before.authorized_root)

    current_head_sha = _run_git(git_exe, ["rev-parse", "HEAD"], cwd=resolved_root).stdout.strip()
    head_changed = current_head_sha != before.head_sha

    diff_output = _run_git(
        git_exe, ["diff", "--name-status", "-z", before.head_sha], cwd=resolved_root
    ).stdout
    changed, created, deleted, renamed = _parse_diff_name_status_z(diff_output)

    status_output = _run_git(
        git_exe,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=resolved_root,
    ).stdout
    status_records = _iter_status_records_z(status_output)
    untracked = [path for xy, path, _old in status_records if xy == "??"]
    working_tree_clean = len(status_records) == 0

    diff_available = True
    diff_stat: str | None = None
    if include_diff_stat:
        try:
            diff_stat = (
                _run_git(git_exe, ["diff", "--stat", before.head_sha], cwd=resolved_root).stdout.strip()
                or None
            )
        except EvidenceError:
            diff_available = False

    # Alcance: TODO path tocado (modificado/creado/eliminado/renombrado en
    # cualquiera de sus dos extremos/o simplemente untracked) que no esté
    # en allowed_paths es fuera de alcance. Se incluyen deliberadamente
    # los untracked aquí (más allá de la redacción literal de la sección
    # 8 original): un archivo nunca "git add"eado sigue siendo una
    # modificación real del árbol de trabajo y excluirlo del cómputo de
    # alcance abriría un hueco de seguridad evidente.
    scope_candidates: set[str] = set(changed) | set(created) | set(deleted) | set(untracked)
    for old_path, new_path in renamed:
        scope_candidates.add(old_path)
        scope_candidates.add(new_path)

    out_of_scope = tuple(sorted(p for p in scope_candidates if p not in normalized_allowed))

    return GitChangeEvidence(
        base_sha=before.head_sha,
        current_head_sha=current_head_sha,
        head_changed=head_changed,
        changed_paths=tuple(sorted(changed)),
        created_paths=tuple(sorted(created)),
        deleted_paths=tuple(sorted(deleted)),
        renamed_paths=tuple(sorted(renamed)),
        untracked_paths=tuple(sorted(untracked)),
        out_of_scope_paths=out_of_scope,
        has_out_of_scope_changes=len(out_of_scope) > 0,
        working_tree_clean=working_tree_clean,
        diff_available=diff_available,
        diff_stat=diff_stat,
    )


def evaluate(
    evidence: GitChangeEvidence,
    *,
    expected_head_unchanged: bool = True,
) -> EvidenceEvaluation:
    """Aplica la política de evaluación sobre la evidencia ya calculada.

    success solo puede ser True si:
    - no hay cambios fuera de alcance (evidence.has_out_of_scope_changes es False);
    - Y, si expected_head_unchanged es True, HEAD no cambió.

    Un HEAD cambiado NUNCA se resetea/revierte aquí: solo se registra y,
    según la política, puede hacer fallar la evaluación (fail closed)."""
    reasons: list[str] = []

    if expected_head_unchanged and evidence.head_changed:
        reasons.append("HEAD changed unexpectedly")
    if evidence.has_out_of_scope_changes:
        reasons.append("changes outside authorized scope")

    success = not reasons
    reason = "; ".join(reasons) if reasons else "all checks passed"

    return EvidenceEvaluation(
        success=success,
        base_sha=evidence.base_sha,
        current_head_sha=evidence.current_head_sha,
        changed_paths=evidence.changed_paths,
        created_paths=evidence.created_paths,
        deleted_paths=evidence.deleted_paths,
        renamed_paths=evidence.renamed_paths,
        untracked_paths=evidence.untracked_paths,
        out_of_scope_paths=evidence.out_of_scope_paths,
        head_changed=evidence.head_changed,
        reason=reason,
    )
