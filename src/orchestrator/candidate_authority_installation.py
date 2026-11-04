"""Local authority installation only. No engine wiring, publication or execution.

Structural approval must be supplied by the trusted Director admission boundary.
NO_EXACTLY_ATOMIC_SQLITE_REF_INDEX_GUARANTEE. Locks exclude cooperative Git
writers, not arbitrary filesystem writers or power-loss/ABA scenarios.
"""
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading

from . import candidate_materialization as cm
from .config_loader import (OrchestratorConfig, require_candidate_installation_authority,
    load_permissions_from_yaml_bytes, load_policies_from_yaml_bytes, load_gates_from_yaml_bytes)
from .task_packet import TaskPacket

ACTION = "git_install_candidate_authority"


class InstallationError(Exception):
    """Fixed codes; no Git stderr, credentials or provider payload."""
    def __init__(self, code, observed_state=None):
        super().__init__(code)
        self.observed_state = observed_state


def require(value, code="BLOCKED_INSTALLATION_BINDING"):
    if not value:
        raise InstallationError(code)


@dataclass(frozen=True, slots=True)
class InstallationAuthority:
    permissions: bytes
    policies: bytes
    gates: bytes

    def admit(self):
        require(all(type(v) is bytes for v in (self.permissions, self.policies, self.gates)))
        p = load_permissions_from_yaml_bytes(self.permissions, "PERMISSIONS.yaml")
        o = load_policies_from_yaml_bytes(self.policies, "POLICIES.yaml")
        g = load_gates_from_yaml_bytes(self.gates, "GATES.yaml")
        require_candidate_installation_authority(OrchestratorConfig(o, {}, g, p))
        return tuple(cm.digest(v) for v in (self.permissions, self.policies, self.gates))


@dataclass(frozen=True, slots=True)
class InstallationApproval:
    task_id: str
    task_packet_sha256: str
    materialization_id: int
    repo_root: str
    branch: str
    base_head_sha: str
    candidate_tree_sha: str
    candidate_commit_sha: str
    manifest_sha256: str
    permissions_sha256: str
    policies_sha256: str
    gates_sha256: str
    director_source: str
    director_approval_id: str
    director_approval_sha256: str

    def validate(self):
        require(type(self.materialization_id) is int and self.materialization_id > 0)
        for name in ("task_packet_sha256", "manifest_sha256", "permissions_sha256", "policies_sha256",
                     "gates_sha256", "director_approval_sha256"):
            cm.hex_id(getattr(self, name), 64)
        for name in ("base_head_sha", "candidate_tree_sha", "candidate_commit_sha"):
            cm.hex_id(getattr(self, name), 40)
        for value in (self.task_id, self.director_source, self.director_approval_id):
            require(type(value) is str and 0 < len(value) <= 128 and
                    all(c.isascii() and (c.isalnum() or c in "-_.") for c in value))
        cm.safe_path(self.branch)
        require(self.branch.startswith("task/") and Path(self.repo_root).is_absolute())


@dataclass(frozen=True, slots=True)
class InstallationResult:
    installation_id: int
    materialization_id: int
    phase: str
    candidate_commit_sha: str
    candidate_tree_sha: str
    status: str = "AUTHORITY_INSTALLED"


def installation_key(materialization_id, repo, branch):
    return cm.digest(cm.canonical(dict(materialization_id=materialization_id, repo_root=repo, branch=branch)).encode())


def validate_bindings(materialization_id, key, raw):
    b = json.loads(raw)
    require(cm.canonical(b) == raw and set(b) == {"approval", "materialization_sha256",
        "packet_model_sha256", "worktree", "context", "other_refs"})
    approval = InstallationApproval(**b["approval"])
    approval.validate()
    require(approval.materialization_id == materialization_id)
    require(key == installation_key(materialization_id, approval.repo_root, approval.branch))
    for name in ("materialization_sha256", "packet_model_sha256"):
        cm.hex_id(b[name], 64)
    require(type(b["context"]) is list and len(b["context"]) == 2)
    for value in b["context"]:
        cm.hex_id(value, 64)
    require(type(b["worktree"]) is dict and type(b["other_refs"]) is list)
    for path, entry in b["worktree"].items():
        cm.safe_path(path)
        require(set(entry) == {"sha256", "size", "mode", "oid"})
        cm.hex_id(entry["sha256"], 64)
        cm.hex_id(entry["oid"], 40)
        require(type(entry["size"]) is int and entry["size"] >= 0 and entry["mode"] in ("100644", "100755"))


def validate_verification(bindings_json, raw):
    b = json.loads(bindings_json)
    expected = dict(head=b["approval"]["candidate_commit_sha"], tree=b["approval"]["candidate_tree_sha"],
                    worktree_sha256=cm.digest(cm.canonical(b["worktree"]).encode()),
                    bindings_sha256=cm.digest(bindings_json.encode()), clean=True)
    require(cm.canonical(expected) == raw)


class _Git(cm._Git):
    """Only additional module-owned observation forms and a separate CAS protocol."""
    def run(self, *args, data=None, index=None, source=None, metadata=None):
        if args[0] not in {"status", "for-each-ref"}:
            return super().run(*args, data=data, index=index, source=source, metadata=metadata)
        command, env = self.execution_context(args, index=index, source=source, metadata=metadata)
        p = subprocess.run(command, cwd=self.repo, env=env, input=data, capture_output=True, timeout=30, shell=False)
        require(p.returncode == 0, "BLOCKED_GIT_OBSERVATION")
        return p.stdout


def file_identity(path):
    info = cm.ordinary(path)
    return info.st_dev, info.st_ino


class _IndexLock:
    def __init__(self, repo):
        self.path = repo / ".git/index.lock"
        self.fd = None
        self.identity = None
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            raise InstallationError("BLOCKED_INDEX_LOCK_OWNERSHIP") from None
        info = os.fstat(self.fd)
        self.identity = (info.st_dev, info.st_ino)
        self.assert_owned()

    def assert_owned(self):
        require(self.identity is not None and file_identity(self.path) == self.identity, "BLOCKED_INDEX_LOCK_OWNERSHIP")
        if self.fd is not None:
            info = os.fstat(self.fd)
            require((info.st_dev, info.st_ino) == self.identity, "BLOCKED_INDEX_LOCK_OWNERSHIP")

    def install(self, contents, destination):
        self.assert_owned()
        with os.fdopen(self.fd, "wb", closefd=False) as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        self.assert_owned()
        os.close(self.fd)
        self.fd = None
        self.assert_owned()
        os.replace(self.path, destination)
        self.identity = None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.identity is not None:
            self.assert_owned()
            self.path.unlink()  # Only this live operation's demonstrated lock.
            self.identity = None


class _RefTransaction:
    TIMEOUT = 10

    def __init__(self, git, row):
        self.git = git
        self.row = row
        self.events = queue.Queue()
        self.process = None
        self.owned = {}

    def __enter__(self):
        command, env = self.git.execution_context(("update-ref", "--no-deref", "--stdin"),
            metadata=cm.CommitMetadata(**json.loads(self.row["commit_metadata_json"])))
        self.process = subprocess.Popen(command, cwd=self.git.repo, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
        def reader():
            try:
                while True:
                    line = self.process.stdout.readline(4096)
                    self.events.put(line)
                    if not line:
                        break
            except (OSError, ValueError):
                self.events.put(b"")
        self.reader = threading.Thread(target=reader, daemon=True)
        self.reader.start()
        return self

    def exchange(self, text, expected):
        try:
            self.process.stdin.write(text.encode("ascii"))
            self.process.stdin.flush()
            answer = self.events.get(timeout=self.TIMEOUT)
        except (OSError, ValueError, queue.Empty):
            raise InstallationError("BLOCKED_REF_TRANSACTION") from None
        require(answer == expected.encode("ascii") + b"\n", "BLOCKED_REF_TRANSACTION")

    def prepare(self):
        self.exchange("start\n", "start: ok")
        self.exchange("update refs/heads/" + self.row["branch"] + " " + self.row["candidate_commit_sha"] +
                      " " + self.row["base_head_sha"] + "\nprepare\n", "prepare: ok")
        # Initial context rejected every existing lock. These are held by this
        # still-live prepared process; verify both identity and exact ref state.
        require(self.process.poll() is None, "BLOCKED_REF_TRANSACTION")
        for name in ("HEAD.lock", "refs/heads/" + self.row["branch"] + ".lock"):
            path = self.git.repo / ".git" / name
            self.owned[path] = file_identity(path)

    def commit(self):
        require(self.process.poll() is None, "BLOCKED_REF_TRANSACTION")
        for path, identity in self.owned.items():
            require(file_identity(path) == identity, "BLOCKED_REF_LOCK_OWNERSHIP")
        self.exchange("commit\n", "commit: ok")
        self.process.stdin.close()
        require(self.process.wait(timeout=self.TIMEOUT) == 0, "BLOCKED_REF_TRANSACTION")
        self.owned.clear()

    def __exit__(self, *exc):
        # EOF aborts an uncommitted transaction. Never unlink Git's lockfiles.
        try:
            if not self.process.stdin.closed:
                self.process.stdin.close()
            self.process.wait(timeout=self.TIMEOUT)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait(timeout=self.TIMEOUT)
        self.reader.join(timeout=self.TIMEOUT)
        self.process.stdout.close()


def index_map(git, index=None):
    result = {}
    for row in cm.records(git.run("ls-files", "--stage", "-z", index=index)):
        info, path = row.split(b"\t", 1)
        mode, oid, stage = info.decode().split()
        path = cm.safe_path(path.decode())
        require(stage == "0" and mode in ("100644", "100755") and path not in result, "BLOCKED_REAL_INDEX_DIVERGENCE")
        result[path] = (mode, "blob", oid)
    require(all(row.startswith(b"H ") for row in cm.records(git.run("ls-files", "-v", "-z", index=index))),
            "BLOCKED_REAL_INDEX_DIVERGENCE")
    return result


def observe(git, row, *, owned=None):
    owned = {} if owned is None else owned
    for path in (git.repo / ".git").rglob("*.lock"):
        require(path in owned and file_identity(path) == owned[path],
                "BLOCKED_INDEX_LOCK_OWNERSHIP" if path.name == "index.lock" else "BLOCKED_REF_LOCK_OWNERSHIP")
    raw_config, _, _, packed = git.admit_metadata(owned_locks=owned)
    require(Path(git.run("rev-parse", "--show-toplevel").decode().strip()).resolve() == git.repo)
    target = "refs/heads/" + row["branch"]
    require(git.run("symbolic-ref", "--quiet", "HEAD").decode().strip() == target, "BLOCKED_HEAD_IDENTITY")
    refs = git.run("for-each-ref", "--format=%(refname) %(objectname) %(symref)").decode().splitlines()
    target_rows = [x.split(" ", 2) for x in refs if x.startswith(target + " ")]
    require(len(target_rows) == 1 and target_rows[0][2] == "", "BLOCKED_TASK_REF_IDENTITY")
    head = git.oid("rev-parse", "HEAD")
    require(head == target_rows[0][1] and head in (row["base_head_sha"], row["candidate_commit_sha"]), "BLOCKED_REF_DIVERGENCE")
    base = git.tree(row["base_tree_sha"])
    require(git.oid("rev-parse", row["base_head_sha"] + "^{tree}") == row["base_tree_sha"])
    manifest = json.loads(row["manifest_json"])
    expected = dict(base)
    for e in manifest:
        require((e["operation"] == "MODIFY" and e["path"] in base and e["mode"] == base[e["path"]][0])
                or (e["operation"] == "ADD" and e["path"] not in base and e["mode"] == "100644"))
        expected[e["path"]] = (e["mode"], "blob", e["blob_oid"])
    require(git.tree(row["candidate_tree_sha"]) == expected, "BLOCKED_CANDIDATE_TREE")
    metadata = cm.CommitMetadata(**json.loads(row["commit_metadata_json"]))
    commit = metadata.commit_bytes(row["candidate_tree_sha"], row["base_head_sha"])
    require(cm.git_oid("commit", commit) == row["candidate_commit_sha"] and
            git.run("cat-file", "commit", row["candidate_commit_sha"]) == commit, "BLOCKED_CANDIDATE_COMMIT")
    real = index_map(git)
    if real == expected:
        index_state = "C"  # For equal trees B/C is resolved by ref identity below.
    elif real == base:
        index_state = "B"
    else:
        raise InstallationError("BLOCKED_REAL_INDEX_DIVERGENCE")
    ref_state = "B" if head == row["base_head_sha"] else "C"
    if real == base and ref_state == "B":
        index_state = "B"
    require((ref_state, index_state) != ("B", "C"), "BLOCKED_REF_INDEX_STATE")
    untracked = {cm.safe_path(x.decode()) for x in cm.records(git.run("ls-files", "--others", "--exclude-standard", "-z"))}
    require(untracked <= set(expected), "BLOCKED_UNEXPECTED_UNTRACKED")
    worktree = {}
    for path, (mode, _, oid) in expected.items():
        data = cm.read_regular(git.repo / path)
        require(cm.git_oid("blob", data) == oid, "BLOCKED_RAW_WORKTREE_DRIFT")
        require(git.run("cat-file", "blob", oid) == data, "BLOCKED_CANDIDATE_BLOB")
        if os.name != "nt":
            require(("100755" if (git.repo / path).stat().st_mode & 0o111 else "100644") == mode)
        worktree[path] = dict(sha256=cm.digest(data), size=len(data), mode=mode, oid=oid)
    for e in manifest:
        w = worktree[e["path"]]
        require((w["size"], w["sha256"], w["oid"]) == (e["size"], e["sha256"], e["blob_oid"]))
    git.attributes(sorted(expected))
    git.attributes(sorted(expected), source=row["candidate_tree_sha"])
    return dict(ref=ref_state, index=index_state, worktree=worktree,
                context=[cm.digest(raw_config), cm.digest(packed)],
                other_refs=[x for x in refs if not x.startswith(target + " ")],
                expected=expected)


def _admit(store, packet, packet_sha, approval, authority, repo):
    require(type(packet) is TaskPacket and packet.authorizes_action(ACTION), "BLOCKED_INSTALLATION_AUTHORITY")
    require(type(approval) is InstallationApproval and type(authority) is InstallationAuthority)
    approval.validate()
    require(authority.admit() == (approval.permissions_sha256, approval.policies_sha256, approval.gates_sha256),
            "BLOCKED_INSTALLATION_AUTHORITY")
    row = store.get_candidate_materialization(approval.materialization_id)
    require(row is not None and row["phase"] == "SEALED", "BLOCKED_MATERIALIZATION_NOT_SEALED")
    keys = {"materialization_key", "task_packet_sha256", "repo_root", "branch", "base_head_sha",
            "base_tree_sha", "manifest_sha256", "manifest_json", "commit_metadata_json"}
    cm.validate_intent(row["task_id"], {k: row[k] for k in keys})
    require(row["task_id"] == packet.task_id == approval.task_id and row["task_packet_sha256"] == packet_sha == approval.task_packet_sha256)
    require(str(repo) == row["repo_root"] == approval.repo_root)
    for name in ("branch", "base_head_sha", "candidate_tree_sha", "candidate_commit_sha", "manifest_sha256"):
        require(row[name] == getattr(approval, name))
    require(packet.preconditions.git.expected_branch == row["branch"] and packet.preconditions.git.expected_head == row["base_head_sha"]
            and packet.preconditions.git.require_clean is True)
    changed = {e["path"] for e in json.loads(row["manifest_json"])}
    require(changed <= set(packet.authorized_files) and not changed & set(packet.forbidden_files))
    task = store.get_task(packet.task_id)
    require(task is not None and task["project_id"] == packet.project_id)
    return row


def install_candidate_authority(store, task_packet, task_packet_sha256, approval, authority, repo_root, *, empty_global_config):
    """Trusted caller supplies a specifically admitted Director record; no issuer/wiring."""
    try:
        return _install(store, task_packet, task_packet_sha256, approval, authority, repo_root, empty_global_config)
    except InstallationError:
        raise
    except Exception:
        pass
    raise InstallationError("BLOCKED_INSTALLATION")


def _install(store, packet, packet_sha, approval, authority, repo_root, empty_global):
    repo = Path(repo_root)
    cm.ordinary(repo, True)
    repo = repo.resolve()
    row = _admit(store, packet, packet_sha, approval, authority, repo)
    with tempfile.TemporaryDirectory(prefix="authority-install-", dir=Path(empty_global).parent) as temporary:
        git = _Git(repo, empty_global, Path(temporary))
        observed = observe(git, row)
        bindings = cm.canonical(dict(approval=asdict(approval), materialization_sha256=cm.digest(cm.canonical(row).encode()),
            packet_model_sha256=cm.digest(cm.canonical(asdict(packet)).encode()),
            worktree=observed["worktree"], context=observed["context"], other_refs=observed["other_refs"]))
        key = installation_key(row["id"], str(repo), row["branch"])
        existing = store.get_candidate_authority_installation(row["id"])
        require(existing is not None or (observed["ref"], observed["index"]) == ("B", "B"), "BLOCKED_MISSING_INSTALLATION_INTENT")
        intent = store.prepare_candidate_authority_installation(row["id"], key, bindings)

        def readmit(owned=None):
            require(_admit(store, packet, packet_sha, approval, authority, repo) == row)
            current = store.get_candidate_authority_installation(row["id"])
            require(current == intent, "BLOCKED_INSTALLATION_INTENT_DRIFT")
            now = observe(git, row, owned=owned)
            for field in ("worktree", "context", "other_refs"):
                require(now[field] == observed[field], "BLOCKED_INSTALLATION_DRIFT")
            return now

        state = observed
        if (state["ref"], state["index"]) != ("C", "C"):
            require(intent["phase"] == "PREPARED", "BLOCKED_VERIFIED_STATE_DRIFT")
            candidate_index = Path(temporary) / "candidate-index"
            git.run("read-tree", row["candidate_tree_sha"], index=candidate_index)
            require(index_map(git, candidate_index) == state["expected"], "BLOCKED_CANDIDATE_INDEX")
            require(git.run("diff", "--name-status", "--no-renames", "--no-ext-diff", "--no-textconv", "-z",
                index=candidate_index, source=row["candidate_tree_sha"]) == b"", "BLOCKED_WORKTREE_COMPATIBILITY")
            index_bytes = cm.read_regular(candidate_index)
            lock = _IndexLock(repo)
            try:
                lock.assert_owned()
                owned = {lock.path: lock.identity}
                state = readmit(owned)
                if state["ref"] == "B":
                    with _RefTransaction(git, row) as transaction:
                        transaction.prepare()
                        lock.assert_owned()
                        before_commit = readmit({**owned, **transaction.owned})
                        require((before_commit["ref"], before_commit["index"]) == ("B", "B"))
                        transaction.commit()
                lock.assert_owned()
                state = readmit(owned)
                require(state["ref"] == "C")
                if state["index"] == "B":
                    lock.install(index_bytes, repo / ".git/index")
            except Exception as exc:
                # Outcome is observational, never inferred from an incomplete ACK.
                try:
                    current = observe(git, row, owned={lock.path: lock.identity} if lock.identity is not None else {})
                    outcome = (current["ref"], current["index"])
                except Exception:
                    outcome = ("UNKNOWN", "UNKNOWN")
                code = str(exc) if isinstance(exc, InstallationError) else "BLOCKED_INSTALLATION_INTERRUPTED"
                raise InstallationError(code, outcome) from None
            finally:
                lock.close()
        final = readmit()
        require((final["ref"], final["index"]) == ("C", "C"), "BLOCKED_FINAL_GIT_STATE")
        require(git.run("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none",
                       source=row["candidate_tree_sha"]) == b"", "BLOCKED_FINAL_GIT_STATE")
        verification = cm.canonical(dict(head=row["candidate_commit_sha"], tree=row["candidate_tree_sha"],
            worktree_sha256=cm.digest(cm.canonical(final["worktree"]).encode()), bindings_sha256=cm.digest(bindings.encode()), clean=True))
        sealed = store.verify_candidate_authority_installation(row["id"], key, bindings, verification)
        return InstallationResult(sealed["id"], row["id"], sealed["phase"], row["candidate_commit_sha"], row["candidate_tree_sha"])
