"""Offline deterministic generator. Git blob material is normative, not checkout bytes.

Inputs are explicit data objects. No application execution, Git command, network,
package resolution or implicit filesystem enumeration is performed.
The caller must independently verify commit/tree membership before installation.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

# Tool import only; this module is never installed as a runtime entrypoint.
if str(Path(__file__).resolve().parents[2] / 'src') not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from orchestrator.trusted_runtime_windows import (
    APPLICATION_FILES, ROOTS, REPOSITORY, WORK_LIMITS, AdmissionError,
    canonical, closed, digest, relative_path, require, validate_manifest, validate_provenance,
)


@dataclass(frozen=True)
class Material:
    relative_path: str
    content: bytes
    role: str
    origin: str
    git_blob_sha: str | None = None
    links: int = 1
    reparse: bool = False
    alternate_streams: tuple = ()
    short_name: str | None = None


def generate(source, provenance, materials, expected_inventory):
    """Return bytes only; all physical observations remain untrusted inputs.

Independent acquisition/verification is mandatory. This function cannot prove
that a caller-labelled Git object belongs to an authoritative tree.
"""
    closed(source, ('repository', 'commit', 'tree', 'independently_verified'))
    require(source['repository'] == REPOSITORY)
    digest(source['commit'], 40); digest(source['tree'], 40)
    require(source['independently_verified'] is True, 'INDEPENDENT_PROVENANCE_REQUIRED')
    validate_provenance(provenance)
    require(type(expected_inventory) is dict and bool(expected_inventory))
    inventory = {}
    for name, role in expected_inventory.items():
        key = relative_path(name)
        require(key not in inventory, 'DUPLICATE_PATH'); inventory[key] = (name, role)
    files = []
    seen = set()
    for item in materials:
        require(type(item) is Material and type(item.content) is bytes)
        key = relative_path(item.relative_path)
        require(key not in seen, 'DUPLICATE_PATH'); seen.add(key)
        require(key in inventory and inventory[key] == (item.relative_path, item.role), 'UNEXPECTED_FILE')
        require(type(item.links) is int and item.links == 1 and item.reparse is False
                and item.alternate_streams == () and item.short_name is None, 'UNSAFE_FILE_OBJECT')
        if item.relative_path in APPLICATION_FILES:
            require(item.origin == 'git_blob', 'GIT_BLOB_BYTES_REQUIRED')
            digest(item.git_blob_sha, 40)
            header = b'blob ' + str(len(item.content)).encode('ascii') + b'\0'
            require(hashlib.sha1(header + item.content).hexdigest() == item.git_blob_sha, 'GIT_BLOB_MISMATCH')
        else:
            require(item.origin in ('python_artifact', 'reviewed_import_config'), 'INVALID_ORIGIN')
        files.append(dict(relative_path=item.relative_path, role=item.role,
                          size=len(item.content), sha256=hashlib.sha256(item.content).hexdigest()))
    require(seen == set(inventory), 'MISSING_REQUIRED_FILE')
    result = dict(schema_version='trusted-runtime-install-manifest-v1', installable=True,
        runtime_version='001B', source_repository=source['repository'], source_commit_sha=source['commit'],
        source_tree_sha=source['tree'], manifest_generator_version='1', python_version='3.14.10',
        architecture='amd64', python_provenance=provenance, **ROOTS,
        entrypoint_relative_path='app/orchestrator/trusted_runtime_entrypoint.py',
        python_relative_path='python/python.exe', python_arguments=['-I', '-B'],
        allowed_import_roots=['python', 'python/python314.zip', 'app'], work_limits=WORK_LIMITS,
        files=sorted(files, key=lambda f: f['relative_path'].casefold()))
    validate_manifest(result)
    return canonical(result)


if __name__ == '__main__':
    # No implicit checkout acquisition or installable output from unverified CLI inputs.
    print('EXPLICIT_VERIFIED_GIT_OBJECT_MATERIAL_REQUIRED')
    raise SystemExit(2)
