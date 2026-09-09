"""Sandbox efímero confinado a REPO_ROOT (CLAUDE-EXECUTION-002).

Responsabilidad única: crear/eliminar un directorio temporal dentro de la
raíz del orquestador y producir una instantánea determinista de su
contenido (paths, tipo de entrada, tamaño, sha256) usando exclusivamente
APIs de Python — nunca comandos de shell ni la narrativa de ningún agente.

Este módulo no conoce nada sobre Claude Code ni sobre el contrato del
write-probe (TARGET.txt/DO_NOT_TOUCH.txt): esa lógica vive en
adapters/claude_code.py. Aquí solo se gestiona el ciclo de vida seguro del
directorio y su instantánea.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Prefijo fijo del sandbox: cleanup_sandbox() lo usa para reverificar,
# antes de eliminar nada, que la ruta corresponde a un sandbox creado por
# create_sandbox() y no a un directorio arbitrario.
SANDBOX_PREFIX = ".claude_write_probe_"


class SandboxError(Exception):
    """Error controlado de gestión del sandbox. Falla cerrado."""


@dataclass(frozen=True)
class EntrySnapshot:
    kind: str  # "file" | "dir" | "symlink" | "other"
    size: int | None
    sha256: str | None


def _is_link_like(path: Path) -> bool:
    """True si `path` es un symlink o (en Windows) un junction/reparse
    directory, SIN seguirlo nunca. `Path.is_symlink()` no sigue el enlace
    para determinarlo; `Path.is_junction()` (Python 3.12+) tampoco. En
    versiones sin `is_junction()` se degrada a solo detectar symlinks, para
    seguir siendo portable (CORRECTION-001: no asumir que is_symlink()
    cubre junctions de Windows)."""
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            return bool(is_junction())
        except OSError:
            return False
    return False


def create_sandbox(repo_root: Path | str) -> Path:
    """Crea un directorio temporal DENTRO de repo_root, con un nombre no
    predecible (tempfile.mkdtemp). No crea symlinks ni copia archivos del
    orquestador; el directorio se crea vacío."""
    repo_root_resolved = Path(repo_root).resolve()
    if not repo_root_resolved.is_dir():
        raise SandboxError(f"repo_root does not exist or is not a directory: {repo_root_resolved}")

    raw = tempfile.mkdtemp(prefix=SANDBOX_PREFIX, dir=str(repo_root_resolved))
    sandbox = Path(raw).resolve()

    # Defensivo: no debería poder ocurrir con mkdtemp(dir=...), pero se
    # reverifica antes de devolver la ruta (fail closed, no confiar).
    if repo_root_resolved not in (sandbox, *sandbox.parents):
        raise SandboxError("sandbox path escaped the repository root")

    return sandbox


def snapshot(sandbox: Path | str) -> dict[str, EntrySnapshot]:
    """Instantánea determinista del sandbox, producida directamente por
    Python (sin invocar comandos de shell ni depender implícitamente de
    rglob()). Recorrido EXPLÍCITO: por cada entrada se detecta primero si
    es un enlace (symlink o junction) ANTES de is_dir()/is_file(); una
    entrada de tipo enlace se registra como "symlink" y NUNCA se recursa
    en ella ni se lee nada a través de ella (ni su propio contenido, ni el
    de lo que apunte). Solo se recursa en directorios ordinarios.

    Las claves son rutas relativas al sandbox, en formato POSIX, para que
    la comparación entre instantáneas sea estable."""
    sandbox_resolved = Path(sandbox).resolve()
    entries: dict[str, EntrySnapshot] = {}
    _snapshot_directory(sandbox_resolved, sandbox_resolved, entries)
    return entries


def _snapshot_directory(
    directory: Path, sandbox_root: Path, entries: dict[str, EntrySnapshot]
) -> None:
    for child in sorted(directory.iterdir(), key=lambda p: p.name):
        relative = child.relative_to(sandbox_root).as_posix()

        if _is_link_like(child):
            # Nunca se recursa ni se lee a través de un enlace: ni su
            # contenido propio (si fuera un symlink a un archivo) ni el de
            # lo que apunte (si fuera un symlink/junction a un directorio).
            entries[relative] = EntrySnapshot(kind="symlink", size=None, sha256=None)
            continue

        if child.is_dir():
            entries[relative] = EntrySnapshot(kind="dir", size=None, sha256=None)
            _snapshot_directory(child, sandbox_root, entries)
        elif child.is_file():
            data = child.read_bytes()
            entries[relative] = EntrySnapshot(
                kind="file", size=len(data), sha256=hashlib.sha256(data).hexdigest()
            )
        else:
            entries[relative] = EntrySnapshot(kind="other", size=None, sha256=None)


def cleanup_sandbox(sandbox: Path | str, *, repo_root: Path | str) -> None:
    """Elimina el sandbox usando APIs de Python (shutil.rmtree), verificando
    la IDENTIDAD del path ORIGINAL antes de seguir ningún enlace.

    CORRECTION-001 (link/junction cleanup escape): a diferencia de la
    versión anterior, NUNCA se hace `Path(sandbox).resolve()` como primer
    paso sobre el candidato a eliminar — eso seguiría un symlink/junction
    que hubiera sustituido al sandbox original antes de validar su
    identidad, permitiendo eliminar un directorio hermano distinto que
    también cumpliera las comprobaciones de nombre/ubicación. En su lugar:
    se resuelve únicamente el directorio PADRE (donde no se espera ningún
    enlace legítimo) y se reconstruye el candidato uniendo ese padre
    resuelto con el nombre final LITERAL, sin resolverlo. Solo entonces se
    comprueba si ese candidato exacto es un symlink/junction (rechazando
    sin más) antes de decidir si existe, si es un directorio ordinario, y
    finalmente eliminarlo.

    `sandbox` debe provenir siempre del propio orquestador (nunca de texto
    suministrado por Claude)."""
    repo_root_resolved = Path(repo_root).resolve()
    candidate = Path(sandbox)

    # Se resuelve el PADRE, nunca el componente final del propio
    # candidato: así el nombre final se compara literalmente, sin haber
    # seguido un posible enlace que ocupe esa posición.
    parent_resolved = candidate.parent.resolve()
    target = parent_resolved / candidate.name

    if parent_resolved != repo_root_resolved:
        raise SandboxError("refusing to clean up a path that is not a direct child of repo_root")
    if target == repo_root_resolved:
        raise SandboxError("refusing to clean up the repository root itself")
    if not target.name.startswith(SANDBOX_PREFIX):
        raise SandboxError("refusing to clean up a path that is not a recognized sandbox")

    # A partir de aquí `target` es exactamente la ruta original (padre
    # resuelto + nombre literal). is_symlink()/is_junction() se evalúan
    # SOBRE ESE PATH, sin seguirlo: si el sandbox original fue sustituido
    # por un enlace hacia otro directorio, se rechaza aquí, ANTES de
    # cualquier chequeo de existencia/tipo que pudiera seguirlo.
    if _is_link_like(target):
        raise SandboxError("refusing to clean up a symlink/junction sandbox path")

    if not target.exists():
        return  # ya no existe: la limpieza se considera completada.

    if not target.is_dir():
        raise SandboxError(
            "refusing to clean up a sandbox path that is not an ordinary directory"
        )

    shutil.rmtree(target)
