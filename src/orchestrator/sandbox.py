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
import os
import shutil
import stat
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


def _validate_prefix(prefix: str) -> str:
    """CORRECTION-001: valida `prefix` ANTES de usarlo en tempfile.mkdtemp()
    o en la comprobación de nombre de cleanup_sandbox(). Falla cerrado
    ante cualquier valor que pudiera introducir un componente de ruta
    adicional o anular el control de identidad por nombre (p. ej.
    prefix="" hace que "cualquier_nombre".startswith("") sea siempre
    True, anulando por completo ese control)."""
    if not isinstance(prefix, str):
        raise SandboxError("sandbox prefix must be a string")
    if not prefix:
        raise SandboxError("sandbox prefix must not be empty")
    if prefix in (".", ".."):
        raise SandboxError("sandbox prefix must not be '.' or '..'")
    if "\x00" in prefix:
        raise SandboxError("sandbox prefix must not contain NUL characters")
    # Se rechazan AMBOS separadores explícitamente (no solo os.sep/altsep
    # del sistema actual), para que la validación sea la misma sin
    # importar en qué plataforma se ejecute.
    if "/" in prefix or "\\" in prefix:
        raise SandboxError("sandbox prefix must not contain path separators")
    if ".." in prefix:
        raise SandboxError("sandbox prefix must not contain '..'")
    return prefix


def create_sandbox(repo_root: Path | str, *, prefix: str = SANDBOX_PREFIX) -> Path:
    """Crea un directorio temporal DENTRO de repo_root, con un nombre no
    predecible (tempfile.mkdtemp), garantizando que sea HIJO DIRECTO de
    repo_root (nunca un descendiente más profundo). No crea symlinks ni
    copia archivos del orquestador; el directorio se crea vacío.

    `prefix` por defecto es SANDBOX_PREFIX (uso del write-probe de Claude);
    otros llamadores seguros del propio orquestador (p. ej. EVIDENCE-001)
    pueden pasar un prefijo distinto para su propio tipo de sandbox
    desechable, reutilizando esta misma lógica de creación confinada.
    `prefix` se valida (_validate_prefix) ANTES de invocar mkdtemp."""
    validated_prefix = _validate_prefix(prefix)
    repo_root_resolved = Path(repo_root).resolve()
    if not repo_root_resolved.is_dir():
        raise SandboxError(f"repo_root does not exist or is not a directory: {repo_root_resolved}")

    raw = tempfile.mkdtemp(prefix=validated_prefix, dir=str(repo_root_resolved))
    sandbox = Path(raw).resolve()

    # Defensivo: no debería poder ocurrir con mkdtemp(dir=...) + un prefix
    # ya validado sin separadores, pero se reverifica antes de devolver la
    # ruta (fail closed, no confiar). Exige HIJO DIRECTO, no solo
    # descendiente, simétrico con la exigencia de cleanup_sandbox().
    if sandbox.parent != repo_root_resolved:
        raise SandboxError("sandbox path is not a direct child of the repository root")

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


def cleanup_sandbox(
    sandbox: Path | str, *, repo_root: Path | str, prefix: str = SANDBOX_PREFIX
) -> None:
    """Elimina el sandbox usando APIs de Python (shutil.rmtree), verificando
    la IDENTIDAD del path ORIGINAL antes de seguir ningún enlace.

    `prefix` debe coincidir con el usado en create_sandbox() para este
    sandbox (por defecto SANDBOX_PREFIX); se valida (_validate_prefix)
    ANTES de cualquier otra comprobación (CORRECTION-001: un prefix
    inválido, p. ej. "", nunca debe poder anular el control de nombre).

    CORRECTION-001 (link/junction cleanup escape): NUNCA se hace
    `Path(sandbox).resolve()` como primer paso sobre el candidato a
    eliminar — eso seguiría un symlink/junction que hubiera sustituido al
    sandbox original antes de validar su identidad, permitiendo eliminar
    un directorio hermano distinto que también cumpliera las
    comprobaciones de nombre/ubicación. En su lugar: se resuelve
    únicamente el directorio PADRE (donde no se espera ningún enlace
    legítimo) y se reconstruye el candidato uniendo ese padre resuelto
    con el nombre final LITERAL, sin resolverlo. Solo entonces se
    comprueba si ese candidato exacto es un symlink/junction (rechazando
    sin más) antes de decidir si existe, si es un directorio ordinario, y
    finalmente eliminarlo. Antes de invocar shutil.rmtree() se verifica
    además que ningún descendiente ANIDADO sea symlink/junction
    (_ensure_no_nested_links), para que rmtree nunca pueda recorrer un
    enlace interno.

    `sandbox` debe provenir siempre del propio orquestador (nunca de texto
    suministrado por Claude)."""
    validated_prefix = _validate_prefix(prefix)
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
    if not target.name.startswith(validated_prefix):
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

    # Ningún descendiente anidado puede ser symlink/junction: elimina por
    # completo el riesgo de que shutil.rmtree recurra a través de un
    # enlace interno que no fue el candidato validado arriba.
    _ensure_no_nested_links(target)

    shutil.rmtree(target, onexc=_make_safe_cleanup_handler(target))


def _ensure_no_nested_links(root: Path) -> None:
    """Recorre `root` (ya confirmado que NO es, en sí mismo, un enlace)
    buscando cualquier descendiente que sea symlink/junction. Si
    encuentra alguno, falla cerrado (SandboxError): no se invoca
    shutil.rmtree() sobre un árbol que contenga enlaces internos, para
    que jamás pueda recorrerse/seguirse uno durante la eliminación
    (CORRECTION-001, hallazgo 5). No sigue ningún enlace para
    inspeccionarlo: is_link_like() se comprueba antes de is_dir()."""
    for entry in root.iterdir():
        if _is_link_like(entry):
            raise SandboxError(
                "refusing to clean up a tree containing a nested symlink/junction"
            )
        if entry.is_dir():
            _ensure_no_nested_links(entry)


def _make_safe_cleanup_handler(cleanup_root: Path):
    """Construye el handler onexc de shutil.rmtree() para la eliminación
    de `cleanup_root` (ya validado por cleanup_sandbox() antes de esta
    llamada). El handler FALLA CERRADO (CORRECTION-001, hallazgo 5):

    1. solo procesa PermissionError (cualquier otro tipo -> SandboxError,
       sin chmod);
    2. solo reintenta la operación si es una de las compatibles con este
       tratamiento (os.unlink/os.remove/os.rmdir) -- cualquier otra
       (p. ej. os.scandir/os.lstat, fallos de lectura, no de escritura)
       -> SandboxError, sin chmod;
    3. reconstruye el candidato resolviendo su PADRE (nunca su propio
       último componente, mismo patrón que cleanup_sandbox) y exige que
       siga dentro de cleanup_root -- si no, SandboxError;
    4. rechaza (SandboxError, sin chmod) si el candidato es symlink/
       junction;
    5. solo entonces aplica el cambio mínimo de atributo
       (os.chmod(..., stat.S_IWRITE, follow_symlinks=False)) y reintenta
       ÚNICAMENTE la función que falló;
    6. cualquier fallo en la propia resolución, chmod o reintento se
       traduce en SandboxError, nunca se propaga una excepción de bajo
       nivel sin controlar."""
    _retryable_functions = (os.unlink, os.remove, os.rmdir)

    def _handler(func, path, exc_info) -> None:  # noqa: ANN001
        exc = exc_info if isinstance(exc_info, BaseException) else None

        # 1. Solo PermissionError se trata; cualquier otro tipo falla cerrado.
        if not isinstance(exc, PermissionError):
            raise SandboxError(
                "unexpected error while cleaning up sandbox path: "
                f"{type(exc).__name__ if exc is not None else 'unknown'}"
            )

        # 2. Solo se reintenta una operación de eliminación conocida.
        if func not in _retryable_functions:
            raise SandboxError(
                f"refusing to retry an unexpected operation during cleanup: {func!r}"
            )

        path_obj = Path(path)
        try:
            parent_resolved = path_obj.parent.resolve()
        except OSError as resolve_exc:
            raise SandboxError(
                "could not resolve the parent of a path during cleanup"
            ) from resolve_exc
        candidate = parent_resolved / path_obj.name

        # 3. El candidato debe seguir dentro de cleanup_root.
        if cleanup_root not in (candidate, *candidate.parents):
            raise SandboxError("refusing to modify a path outside the sandbox during cleanup")

        # 4. Nunca chmod sobre un symlink/junction.
        if _is_link_like(candidate):
            raise SandboxError("refusing to chmod a symlink/junction during cleanup")

        if not candidate.exists():
            return  # ya no existe: nada que reintentar.

        # 5. Cambio mínimo de atributo y reintento único de la misma función.
        try:
            os.chmod(candidate, stat.S_IWRITE, follow_symlinks=False)
        except (OSError, NotImplementedError) as chmod_exc:
            raise SandboxError(
                "failed to clear the read-only attribute during cleanup"
            ) from chmod_exc

        try:
            func(path)
        except OSError as retry_exc:
            raise SandboxError(
                "retry failed while cleaning up sandbox path"
            ) from retry_exc

    return _handler
