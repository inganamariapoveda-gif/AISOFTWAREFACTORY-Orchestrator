"""Local durable sealing only. Objects are data, never branch or execution authority.

Endpoint continuity detects drift; it is not exclusion of concurrent writers.
No caller installs this primitive into the engine in this slice.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata

from .task_packet import TaskPacket


class MaterializationError(Exception):
    """Fixed public failure codes, without subprocess or file payloads."""


def require(condition, code="BLOCKED_MATERIALIZATION_IDENTITY"):
    if not condition:
        raise MaterializationError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git_oid(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def hex_id(value, size):
    require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None
            and value != "0" * size)


def safe_path(value):
    require(type(value) is str and value and not any(
        unicodedata.category(c).startswith("C") for c in value), "BLOCKED_UNSAFE_PATH")
    require(not any(c in value for c in "\\:*?[]<>|\"") and not value.startswith("/"), "BLOCKED_UNSAFE_PATH")
    for part in value.split("/"):
        require(part not in ("", ".", "..") and part == part.rstrip(" .") and "~" not in part,
                "BLOCKED_UNSAFE_PATH")
        require(not part.startswith(" ") and part.casefold() != ".git" and not re.fullmatch(
            r"(?i)(con|prn|aux|nul|conin\$|conout\$|clock\$|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?", part), "BLOCKED_UNSAFE_PATH")
    return value


def ordinary(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "BLOCKED_UNSAFE_PATH")
    for component in reversed((path, *path.parents)):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
        if component != path or directory:
            require(stat.S_ISDIR(info.st_mode), "BLOCKED_UNSAFE_PATH")
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
    return info


def read_regular(path):
    before = ordinary(path)
    with open(path, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns))
        require(opened.st_nlink == 1)
        data = stream.read()
        after = os.fstat(stream.fileno())
    final = ordinary(path)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) ==
            (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns))
    return data


@dataclass(frozen=True, slots=True)
class CommitMetadata:
    message: str
    author_name: str
    author_email: str
    author_timestamp: int
    author_timezone: str
    committer_name: str
    committer_email: str
    committer_timestamp: int
    committer_timezone: str

    def __post_init__(self):
        require(type(self.message) is str and self.message.endswith("\n") and self.message.strip())
        require(not any(unicodedata.category(c).startswith("C") and c != "\n" for c in self.message))
        for who in ("author", "committer"):
            for field in ("name", "email"):
                value = getattr(self, who + "_" + field)
                require(type(value) is str and value and value == value.strip()
                        and not any(unicodedata.category(c).startswith("C") or c in "<>" for c in value))
                if field == "email":
                    require(re.fullmatch(r"[^\s@]+@[^\s@]+", value) is not None)
            stamp = getattr(self, who + "_timestamp")
            zone = getattr(self, who + "_timezone")
            require(type(stamp) is int and 0 <= stamp <= 253402300799)
            require(type(zone) is str and re.fullmatch(r"[+-](?:0[0-9]|1[0-4])[0-5][0-9]", zone) is not None)

    def commit_bytes(self, tree, parent):
        headers = ["tree " + tree, "parent " + parent]
        for who in ("author", "committer"):
            headers.append(f"{who} {getattr(self, who + '_name')} <{getattr(self, who + '_email')}> "
                           f"{getattr(self, who + '_timestamp')} {getattr(self, who + '_timezone')}")
        return ("\n".join(headers) + "\n\n" + self.message).encode("utf-8")


def materialization_key(task_id, repo_root, branch, base_head_sha):
    # Manifest, packet digest and commit metadata are conflict bindings, not
    # a means to silently obtain a fresh identity after restart/drift.
    return digest(canonical(dict(task_id=task_id, repo_root=repo_root, branch=branch,
                                 base_head_sha=base_head_sha)).encode())


def validate_intent(task_id, intent):
    require(type(task_id) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", task_id))
    require(set(intent) == {"materialization_key", "task_packet_sha256", "repo_root", "branch", "base_head_sha",
                            "base_tree_sha", "manifest_sha256", "manifest_json", "commit_metadata_json"})
    for name in ("materialization_key", "task_packet_sha256", "manifest_sha256"):
        hex_id(intent[name], 64)
    for name in ("base_head_sha", "base_tree_sha"):
        hex_id(intent[name], 40)
    require(type(intent["repo_root"]) is str and Path(intent["repo_root"]).is_absolute())
    safe_path(intent["branch"])
    require(intent["branch"].startswith("task/"))
    require(intent["materialization_key"] == materialization_key(
        task_id, intent["repo_root"], intent["branch"], intent["base_head_sha"]))
    manifest = json.loads(intent["manifest_json"])
    require(type(manifest) is list and canonical(manifest) == intent["manifest_json"])
    require(digest(intent["manifest_json"].encode()) == intent["manifest_sha256"])
    paths = []
    for entry in manifest:
        require(type(entry) is dict and set(entry) == {"path", "operation", "mode", "size", "sha256", "blob_oid"})
        paths.append(safe_path(entry["path"]))
        require(entry["operation"] in ("ADD", "MODIFY"))
        require(entry["mode"] in ("100644", "100755") and (entry["operation"] != "ADD" or entry["mode"] == "100644"))
        require(type(entry["size"]) is int and entry["size"] >= 0)
        hex_id(entry["sha256"], 64)
        hex_id(entry["blob_oid"], 40)
    require(paths == sorted(paths) and len({p.casefold() for p in paths}) == len(paths))
    metadata = CommitMetadata(**json.loads(intent["commit_metadata_json"]))
    require(canonical(asdict(metadata)) == intent["commit_metadata_json"])


@dataclass(frozen=True, slots=True)
class MaterializationResult:
    materialization_id: int
    phase: str
    base_head_sha: str
    base_tree_sha: str
    manifest_sha256: str
    candidate_tree_sha: str
    candidate_commit_sha: str

    def __post_init__(self):
        require(type(self.materialization_id) is int and self.materialization_id > 0 and self.phase == "SEALED")
        for name in ("base_head_sha", "base_tree_sha", "candidate_tree_sha", "candidate_commit_sha"):
            hex_id(getattr(self, name), 40)
        hex_id(self.manifest_sha256, 64)


class _Git:
    def __init__(self, repo, empty_global, scratch):
        self.repo = Path(repo)
        ordinary(self.repo, True)
        ordinary(self.repo / ".git", True)
        self.empty = Path(empty_global)
        require(read_regular(self.empty) == b"")
        require(not self.empty.is_relative_to(self.repo))
        self.hooks = scratch / "hooks"
        self.hooks.mkdir()
        self.executable = shutil.which("git")
        require(self.executable is not None)
        self.env = {key: value for key, value in os.environ.items()
                    if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR"}}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.empty), GIT_ATTR_NOSYSTEM="1",
                        GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1",
                        GIT_NO_LAZY_FETCH="1", LC_ALL="C")

    def run(self, *args, data=None, index=None, source=None, metadata=None):
        # Only module-owned command forms; no shell, remote commands or porcelain mutations.
        require(args[0] in {"config", "rev-parse", "symbolic-ref", "ls-tree", "ls-files", "diff",
                            "check-attr", "cat-file", "hash-object", "read-tree", "update-index", "write-tree", "commit-tree"})
        ordinary(self.hooks, True)
        require(read_regular(self.empty) == b"" and not list(self.hooks.iterdir()))
        env = dict(self.env)
        if index is not None:
            env["GIT_INDEX_FILE"] = str(index)
        if source is not None:
            env["GIT_ATTR_SOURCE"] = source
        if metadata is not None:
            for who in ("author", "committer"):
                prefix = "GIT_" + who.upper()
                env[prefix + "_NAME"] = getattr(metadata, who + "_name")
                env[prefix + "_EMAIL"] = getattr(metadata, who + "_email")
                env[prefix + "_DATE"] = f"@{getattr(metadata, who + '_timestamp')} {getattr(metadata, who + '_timezone')}"
        command = [self.executable, "--no-lazy-fetch", "-c", "core.hooksPath=" + str(self.hooks),
                   "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                   "-c", "core.attributesFile=" + str(self.empty), "-c", "commit.gpgSign=false",
                   "-c", "i18n.commitEncoding=UTF-8", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
        result = subprocess.run(command, cwd=self.repo, env=env, input=data, capture_output=True,
                                timeout=30, shell=False)
        require(result.returncode == 0, "BLOCKED_GIT_OBSERVATION")
        return result.stdout

    def oid(self, *args, **kwargs):
        value = self.run(*args, **kwargs).decode("ascii").strip()
        hex_id(value, 40)
        return value

    def tree(self, oid):
        rows = self.run("ls-tree", "-r", "-z", "--full-tree", oid)
        result = {}
        for row in records(rows):
            info, name = row.split(b"\t", 1)
            mode, kind, object_id = info.decode("ascii").split(" ")
            path = safe_path(name.decode("utf-8"))
            require(mode in ("100644", "100755") and kind == "blob", "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
            hex_id(object_id, 40)
            require(path not in result)
            result[path] = (mode, kind, object_id)
        require(len({p.casefold() for p in result}) == len(result), "BLOCKED_UNSAFE_PATH")
        return result

    def admit_metadata(self):
        gitdir = self.repo / ".git"
        for name in ("commondir", "config.worktree", "shallow", "info/grafts", "info/attributes",
                     "objects/info/alternates", "objects/info/http-alternates", "info/sparse-checkout",
                     "index.lock", "HEAD.lock", "packed-refs.lock"):
            require(not os.path.lexists(gitdir / name), "BLOCKED_GIT_CONTEXT")
        # Metadata path redirection could otherwise redirect an object write.
        for directory, dirs, files in os.walk(gitdir, followlinks=False):
            ordinary(Path(directory), True)
            for name in dirs:
                ordinary(Path(directory) / name, True)
            for name in files:
                ordinary(Path(directory) / name)
                require(not name.startswith("sharedindex.") and not name.endswith(".promisor"), "BLOCKED_GIT_CONTEXT")
        require(not (gitdir / "refs/replace").exists(), "BLOCKED_GIT_CONTEXT")
        packed = read_regular(gitdir / "packed-refs") if (gitdir / "packed-refs").exists() else b""
        require(b" refs/replace/" not in packed, "BLOCKED_GIT_CONTEXT")
        raw = read_regular(gitdir / "config")
        parsed = self.run("config", "--no-includes", "--file", "-", "--null", "--list", data=raw)
        for record in records(parsed):
            key, _, value = record.partition(b"\n")
            key = key.decode("utf-8").lower()
            require(key.split(".")[0] not in {"include", "includeif", "filter", "alias", "extensions"}, "BLOCKED_GIT_CONTEXT")
            require(key not in {"core.worktree", "core.sparsecheckout", "core.sparsecheckoutcone", "core.splitindex", "index.sparse"}, "BLOCKED_GIT_CONTEXT")
            require(not key.endswith((".promisor", ".partialclonefilter")), "BLOCKED_GIT_CONTEXT")
            if key == "core.bare":
                require(value.lower() == b"false", "BLOCKED_GIT_CONTEXT")
        return raw, read_regular(gitdir / "index"), read_regular(gitdir / "HEAD"), packed

    def attributes(self, paths, *, index=None, source=None):
        data = b"".join(p.encode() + b"\0" for p in paths)
        args = ["check-attr"]
        if source is not None:
            args.append("--source=" + source)
        output = records(self.run(*args, "--stdin", "-z", "filter", "working-tree-encoding", "ident", data=data, index=index))
        expected = []
        for path in paths:
            for attribute in ("filter", "working-tree-encoding", "ident"):
                expected.extend([path.encode(), attribute.encode(), b"unspecified"])
        require(output == expected, "BLOCKED_GIT_ATTRIBUTES")


def records(raw):
    require(not raw or raw.endswith(b"\0"))
    return raw.split(b"\0")[:-1]


def _observe(git, packet):
    metadata = git.admit_metadata()
    head = git.oid("rev-parse", "HEAD")
    require(head == packet.preconditions.git.expected_head, "BLOCKED_BASE_IDENTITY_CHANGED")
    branch = git.run("symbolic-ref", "--quiet", "--short", "HEAD").decode().strip()
    require(branch == packet.preconditions.git.expected_branch and branch.startswith("task/"))
    require(Path(git.run("rev-parse", "--show-toplevel").decode().strip()).resolve() == git.repo)
    base_tree = git.oid("rev-parse", head + "^{tree}")
    base = git.tree(base_tree)
    index = {}
    for row in records(git.run("ls-files", "--stage", "-z")):
        info, path = row.split(b"\t", 1)
        mode, oid, stage = info.decode().split()
        require(stage == "0" and mode in ("100644", "100755"), "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
        index[safe_path(path.decode())] = (mode, "blob", oid)
    require(index == base, "BLOCKED_REAL_INDEX_DIVERGENCE")
    require(all(row.startswith(b"H ") for row in records(git.run("ls-files", "-v", "-z"))),
            "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
    untracked = [safe_path(p.decode()) for p in records(git.run("ls-files", "--others", "--exclude-standard", "-z"))]
    paths = sorted(set(base) | set(untracked))
    require(len({p.casefold() for p in paths}) == len(paths), "BLOCKED_UNSAFE_PATH")
    contents = {}
    for path in paths:
        require(os.path.lexists(git.repo / path), "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
        contents[path] = read_regular(git.repo / path)
        if os.name != "nt":
            mode = "100755" if (git.repo / path).stat().st_mode & 0o111 else "100644"
            require(mode == (base[path][0] if path in base else "100644"), "BLOCKED_UNSUPPORTED_MUTATION_TYPE")
    git.attributes(paths)
    git.attributes(paths, source=base_tree)
    # Mutation authority is RAW blob identity, independent of attributes,
    # EOL conversion and index stat hints. Git diff is only used later for
    # candidate/worktree compatibility, never to select the manifest.
    modified = [path for path in base if git_oid("blob", contents[path]) != base[path][2]]
    touched = sorted(set(modified) | set(untracked))
    allowed = {safe_path(p) for p in packet.authorized_files}
    forbidden = {safe_path(p) for p in packet.forbidden_files}
    require(set(touched) <= allowed and not set(touched) & forbidden, "BLOCKED_MUTATION_BOUNDARY")
    manifest = []
    for path in touched:
        data = contents[path]
        manifest.append(dict(path=path, operation="MODIFY" if path in base else "ADD",
                             mode=base[path][0] if path in base else "100644", size=len(data),
                             sha256=digest(data), blob_oid=git_oid("blob", data)))
    # Attributes/ignored state and untouched tracked bytes participate in drift
    # detection even when they do not belong in the mutation manifest.
    evidence = (metadata, head, branch, base_tree, base, manifest,
                {p: digest(data) for p, data in contents.items()})
    return evidence, contents


def materialize_candidate(store, task_packet: TaskPacket, task_packet_sha256: str, repo_root: Path,
                          commit_metadata: CommitMetadata, *, empty_global_config: Path) -> MaterializationResult:
    """Seal an unreferenced local object. Caller supplies admitted packet/digest.

    AUTHORITY_INSTALLATION_PENDING. No ref, real-index, worktree or remote write.
    """
    try:
        return _materialize(store, task_packet, task_packet_sha256, repo_root, commit_metadata, empty_global_config)
    except MaterializationError:
        raise
    except Exception:
        pass
    raise MaterializationError("BLOCKED_MATERIALIZATION")


def _materialize(store, packet, packet_sha, repo_root, metadata, empty_global):
    require(type(packet) is TaskPacket and packet.preconditions.git.require_clean is True)
    hex_id(packet_sha, 64)
    hex_id(packet.preconditions.git.expected_head, 40)
    safe_path(packet.preconditions.git.expected_branch)
    require(type(metadata) is CommitMetadata)
    metadata.__post_init__()
    repo = Path(repo_root)
    ordinary(repo, True)
    repo = repo.resolve()
    empty = Path(empty_global)
    require(read_regular(empty) == b"" and not empty.is_relative_to(repo))
    with tempfile.TemporaryDirectory(prefix="candidate-seal-", dir=empty.parent) as temporary:
        git = _Git(repo, empty, Path(temporary))
        before, contents = _observe(git, packet)
        _, head, branch, base_tree, base, manifest, _ = before
        manifest_json = canonical(manifest)
        row = store.prepare_candidate_materialization(packet.task_id,
            materialization_key=materialization_key(packet.task_id, str(repo), branch, head),
            task_packet_sha256=packet_sha, repo_root=str(repo), branch=branch, base_head_sha=head,
            base_tree_sha=base_tree, manifest_sha256=digest(manifest_json.encode()), manifest_json=manifest_json,
            commit_metadata_json=canonical(asdict(metadata)))
        expected = dict(base)
        for entry in manifest:
            expected[entry["path"]] = (entry["mode"], "blob", entry["blob_oid"])
        temp_index = Path(temporary) / "index"
        if row["phase"] == "PREPARED":
            for entry in manifest:
                oid = git.oid("hash-object", "--no-filters", "-w", "--stdin", data=contents[entry["path"]])
                require(oid == entry["blob_oid"])
                require(git.run("cat-file", "blob", oid) == contents[entry["path"]])
            git.run("read-tree", head, index=temp_index)
            entries = b"".join((e["mode"] + " " + e["blob_oid"] + "\t" + e["path"] + "\0").encode() for e in manifest)
            if entries:
                git.run("update-index", "-z", "--index-info", index=temp_index, data=entries)
            tree = git.oid("write-tree", index=temp_index)
            require(git.tree(tree) == expected, "BLOCKED_TREE_EXACTNESS")
            commit = git.oid("commit-tree", tree, "-p", head, "--no-gpg-sign", data=metadata.message.encode(), metadata=metadata)
        else:
            tree, commit = row["candidate_tree_sha"], row["candidate_commit_sha"]
            require(git.tree(tree) == expected, "BLOCKED_TREE_EXACTNESS")
            git.run("read-tree", tree, index=temp_index)
        raw_commit = metadata.commit_bytes(tree, head)
        require(git_oid("commit", raw_commit) == commit and git.run("cat-file", "commit", commit) == raw_commit)
        for entry in manifest:
            require(git.run("cat-file", "blob", entry["blob_oid"]) == contents[entry["path"]])
        git.attributes(sorted(expected), index=temp_index, source=tree)
        require(git.run("diff", "--name-status", "--no-renames", "--no-ext-diff", "--no-textconv", "-z",
                        index=temp_index, source=tree) == b"", "BLOCKED_WORKTREE_COMPATIBILITY")
        after, _ = _observe(git, packet)
        require(after == before, "BLOCKED_MATERIALIZATION_DRIFT")
        sealed = store.seal_candidate_materialization(row["id"], candidate_tree_sha=tree, candidate_commit_sha=commit)
        return MaterializationResult(sealed["id"], sealed["phase"], head, base_tree,
                                     sealed["manifest_sha256"], tree, commit)
