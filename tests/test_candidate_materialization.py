"""Synthetic Git only. Never materialize the development repository."""

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
from orchestrator import candidate_materialization as cm
from orchestrator.store import Store
from orchestrator.task_packet import TaskPacket, Preconditions, GitPreconditions


class Crash(BaseException):
    pass


class CandidateMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="materialization-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.assertFalse(self.repo.is_relative_to(ROOT))
        self.empty = self.root / "global"
        self.empty.write_bytes(b"")
        self.env = {k: v for k, v in os.environ.items() if k.upper() in
                    {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR"}}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.empty), GIT_TERMINAL_PROMPT="0",
                        GIT_AUTHOR_NAME="Synthetic", GIT_AUTHOR_EMAIL="test@example.invalid",
                        GIT_COMMITTER_NAME="Synthetic", GIT_COMMITTER_EMAIL="test@example.invalid",
                        GIT_AUTHOR_DATE="@1700000000 +0000", GIT_COMMITTER_DATE="@1700000000 +0000")
        self.git("init", "--quiet", "--initial-branch=task/synthetic", "--template=")
        self.git("config", "core.autocrlf", "false")
        (self.repo / "a.txt").write_bytes(b"base\n")
        (self.repo / "untouched.txt").write_bytes(b"keep\n")
        self.git("add", "--", "a.txt", "untouched.txt")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", "synthetic base")
        self.base = self.git("rev-parse", "HEAD").decode().strip()
        self.packet = TaskPacket(task_id="T-1", project_id="SAMPLE", objective="test", scope=("test",),
            out_of_scope=("other",), authorized_files=("a.txt", "new.bin", "untouched.txt", ".gitattributes"),
            forbidden_files=("forbidden.txt",), constraints=("test",), acceptance_criteria=("test",),
            security_criteria=("test",), mandatory_tests=(), stop_rules=("test",), required_evidence=("test",),
            preconditions=Preconditions(GitPreconditions("task/synthetic", self.base, True), ()), resource_profile="standard")
        self.metadata = cm.CommitMetadata("sealed synthetic\n", "Synthetic", "test@example.invalid", 1700000000,
                                          "+0000", "Synthetic", "test@example.invalid", 1700000000, "+0000")
        self.store = Store(self.root / "db")
        self.addCleanup(self.store.close)
        self.store.register_project("SAMPLE", "Synthetic", str(self.repo), "ref")
        self.store.create_task("T-1", "SAMPLE", "Title", "Need")
        self.initial = self.authority()
        for target in ("socket.socket", "socket.create_connection"):
            patcher = mock.patch(target, side_effect=AssertionError("network forbidden"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def git(self, *args, data=None):
        proc = subprocess.run([shutil.which("git"), *args], cwd=self.repo, env=self.env,
                              input=data, capture_output=True, timeout=15, shell=False)
        if proc.returncode:
            raise AssertionError(proc.stderr.decode(errors="replace"))
        return proc.stdout

    def authority(self):
        return ((self.repo / ".git/index").read_bytes(), (self.repo / ".git/HEAD").read_bytes(),
                self.git("rev-parse", "HEAD"), self.git("for-each-ref", "--format=%(refname) %(objectname)"))

    def change(self):
        (self.repo / "a.txt").write_bytes(b"changed\n")

    def seal(self, **kwargs):
        return cm.materialize_candidate(self.store, self.packet, "a" * 64, self.repo,
                                        kwargs.get("metadata", self.metadata), empty_global_config=self.empty)

    def row(self):
        rows = self.store._conn.execute("SELECT id FROM candidate_materialization").fetchall()
        self.assertEqual(len(rows), 1)
        return self.store.get_candidate_materialization(rows[0][0])

    def blocked(self):
        with self.assertRaises(cm.MaterializationError):
            self.seal()
        self.assertEqual(self.store._conn.execute("SELECT count(*) FROM candidate_materialization WHERE phase='SEALED'").fetchone()[0], 0)

    def test_modify_add_binary_full_tree_and_authority_unchanged(self):
        self.change()
        (self.repo / "new.bin").write_bytes(b"\x00\xff\r\nRAW\x00")
        before_other = self.store.get_task("T-1"), self.store.get_history("T-1"), self.store.list_agent_runs("T-1")
        result = self.seal()
        self.assertEqual(result.phase, "SEALED")
        self.assertEqual(self.authority(), self.initial)
        manifest = json.loads(self.row()["manifest_json"])
        self.assertEqual([e["path"] for e in manifest], ["a.txt", "new.bin"])
        self.assertEqual([e["operation"] for e in manifest], ["MODIFY", "ADD"])
        for entry in manifest:
            self.assertEqual(self.git("cat-file", "blob", entry["blob_oid"]), (self.repo / entry["path"]).read_bytes())
        tree = self.git("ls-tree", "-r", result.candidate_tree_sha)
        self.assertEqual(len(tree.splitlines()), 3)
        self.assertIn(self.git("rev-parse", self.base + ":untouched.txt").strip(), tree)
        raw = self.git("cat-file", "commit", result.candidate_commit_sha)
        self.assertEqual(raw, self.metadata.commit_bytes(result.candidate_tree_sha, self.base))
        self.assertEqual(before_other, (self.store.get_task("T-1"), self.store.get_history("T-1"), self.store.list_agent_runs("T-1")))

    def test_raw_crlf_without_conversion_is_preserved(self):
        (self.repo / "a.txt").write_bytes(b"changed\r\n")
        result = self.seal()
        self.assertEqual(self.git("cat-file", "blob", result.candidate_commit_sha + ":a.txt"), b"changed\r\n")

    def test_raw_crlf_with_text_eol_lf_blocks_before_sealed(self):
        (self.repo / "a.txt").write_bytes(b"changed\r\n")
        (self.repo / ".gitattributes").write_bytes(b"*.txt text eol=lf\n")
        self.blocked()
        self.assertEqual(self.row()["phase"], "PREPARED")
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"changed\r\n")
        self.assertEqual(self.authority(), self.initial)
        self.assertEqual(self.git("config", "core.autocrlf").strip(), b"false")

    def prepare_eol_base(self):
        (self.repo / ".gitattributes").write_bytes(b"*.txt text eol=lf\n")
        for name in ("allowed.txt", "unauthorized.txt"):
            (self.repo / name).write_bytes(b"keep\n")
        self.git("add", "--", ".gitattributes", "allowed.txt", "unauthorized.txt")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", "EOL base")
        self.base = self.git("rev-parse", "HEAD").decode().strip()
        self.packet = replace(self.packet, authorized_files=("allowed.txt",),
            preconditions=Preconditions(GitPreconditions("task/synthetic", self.base, True), ()))
        self.initial = self.authority()

    def test_authorized_eol_only_raw_change_enters_manifest_and_blocks_compatibility(self):
        self.prepare_eol_base()
        raw = b"keep\r\n"
        (self.repo / "allowed.txt").write_bytes(raw)
        self.assertEqual(self.git("diff", "--name-only"), b"")
        with self.assertRaisesRegex(cm.MaterializationError, "^BLOCKED_WORKTREE_COMPATIBILITY$"):
            self.seal()
        row = self.row()
        self.assertEqual(row["phase"], "PREPARED")
        self.assertIsNone(row["candidate_commit_sha"])
        self.assertEqual(json.loads(row["manifest_json"]), [dict(path="allowed.txt", operation="MODIFY",
            mode="100644", size=len(raw), sha256=cm.digest(raw), blob_oid=cm.git_oid("blob", raw))])
        self.assertEqual(self.git("cat-file", "blob", cm.git_oid("blob", raw)), raw)
        self.assertEqual((self.repo / "allowed.txt").read_bytes(), raw)
        self.assertEqual(self.authority(), self.initial)

    def test_unauthorized_eol_only_raw_change_blocks_boundary(self):
        self.prepare_eol_base()
        (self.repo / "unauthorized.txt").write_bytes(b"keep\r\n")
        self.assertEqual(self.git("diff", "--name-only"), b"")
        with self.assertRaisesRegex(cm.MaterializationError, "^BLOCKED_MUTATION_BOUNDARY$"):
            self.seal()
        self.assertEqual(self.store._conn.execute("SELECT count(*) FROM candidate_materialization").fetchone()[0], 0)
        self.assertEqual((self.repo / "unauthorized.txt").read_bytes(), b"keep\r\n")
        self.assertEqual(self.authority(), self.initial)

    def test_mixed_authorized_change_and_unauthorized_eol_only_change_blocks(self):
        self.prepare_eol_base()
        (self.repo / "allowed.txt").write_bytes(b"legitimate change\n")
        (self.repo / "unauthorized.txt").write_bytes(b"keep\r\n")
        self.assertEqual(self.git("diff", "--name-only"), b"allowed.txt\n")
        with self.assertRaisesRegex(cm.MaterializationError, "^BLOCKED_MUTATION_BOUNDARY$"):
            self.seal()
        self.assertEqual(self.store._conn.execute("SELECT count(*) FROM candidate_materialization").fetchone()[0], 0)
        self.assertEqual((self.repo / "allowed.txt").read_bytes(), b"legitimate change\n")
        self.assertEqual((self.repo / "unauthorized.txt").read_bytes(), b"keep\r\n")
        self.assertEqual(self.authority(), self.initial)

    def test_unchanged_raw_content_is_omitted_from_manifest(self):
        self.prepare_eol_base()
        result = self.seal()
        self.assertEqual(result.phase, "SEALED")
        self.assertEqual(json.loads(self.row()["manifest_json"]), [])
        self.assertEqual(self.git("cat-file", "blob", result.candidate_commit_sha + ":allowed.txt"), b"keep\n")
        self.assertEqual((self.repo / "allowed.txt").read_bytes(), b"keep\n")
        self.assertEqual(self.authority(), self.initial)

    def test_sealed_replay_same_identity_and_no_object_writes(self):
        self.change()
        first = self.seal()
        original = cm._Git.run
        commands = []
        def record(git, *args, **kwargs):
            commands.append(args[0])
            return original(git, *args, **kwargs)
        with mock.patch.object(cm._Git, "run", record):
            self.assertEqual(self.seal(), first)
        self.assertFalse(set(commands) & {"hash-object", "write-tree", "commit-tree"})
        self.assertEqual(self.authority(), self.initial)

    def test_sealed_missing_commit_is_not_recreated(self):
        self.change()
        result = self.seal()
        path = self.repo / ".git/objects" / result.candidate_commit_sha[:2] / result.candidate_commit_sha[2:]
        path.chmod(0o600)
        path.unlink()
        with self.assertRaises(cm.MaterializationError):
            self.seal()
        self.assertFalse(path.exists())

    def test_unauthorized_modified_and_untracked_paths_block(self):
        self.packet = replace(self.packet, authorized_files=("a.txt",))
        (self.repo / "untouched.txt").write_bytes(b"changed\n")
        self.blocked()
        (self.repo / "untouched.txt").write_bytes(b"keep\n")
        (self.repo / "unexpected.txt").write_bytes(b"new")
        self.blocked()

    def test_forbidden_path_blocks_even_if_also_authorized(self):
        self.packet = replace(self.packet, forbidden_files=("a.txt",))
        self.change()
        self.blocked()

    def test_staged_contamination_intent_to_add_and_unmerged_block(self):
        self.change()
        self.git("add", "a.txt")
        self.blocked()
        self.git("read-tree", self.base)
        (self.repo / "new.bin").write_bytes(b"new")
        self.git("add", "-N", "new.bin")
        self.blocked()
        self.git("read-tree", self.base)
        oid = self.git("rev-parse", self.base + ":a.txt").decode().strip()
        self.git("update-index", "--index-info", data=("0 " + "0" * 40 + "\ta.txt\n100644 " + oid + " 1\ta.txt\n").encode())
        self.blocked()

    def test_delete_and_rename_block(self):
        (self.repo / "a.txt").rename(self.repo / "new.bin")
        self.blocked()
        (self.repo / "new.bin").unlink()
        self.blocked()

    def test_index_mode_change_and_gitlink_block(self):
        self.git("update-index", "--chmod=+x", "a.txt")
        self.blocked()
        self.git("read-tree", self.base)
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.base + ",submodule")
        self.blocked()

    def test_hardlink_blocks(self):
        os.link(self.repo / "a.txt", self.root / "alias")
        self.blocked()

    def test_symlink_or_reparse_blocks_when_platform_permits(self):
        (self.repo / "a.txt").unlink()
        try:
            (self.repo / "a.txt").symlink_to(self.repo / "untouched.txt")
        except OSError:
            self.skipTest("symlink privilege unavailable")
        self.blocked()

    def test_hidden_index_flags_and_split_index_block(self):
        for flag in ("assume-unchanged", "skip-worktree"):
            self.git("update-index", "--" + flag, "a.txt")
            self.blocked()
            self.git("update-index", "--no-" + flag, "a.txt")
        self.git("update-index", "--split-index")
        self.blocked()

    def test_sparse_config_blocks(self):
        self.git("config", "core.sparseCheckout", "true")
        self.blocked()

    def test_filter_and_process_markers_never_execute(self):
        marker = self.root / "filter-ran"
        for driver in ("clean", "process"):
            self.git("config", "filter.evil." + driver, "echo ran > " + marker.as_posix())
        (self.repo / ".gitattributes").write_bytes(b"* filter=evil\n")
        self.change()
        self.blocked()
        self.assertFalse(marker.exists())

    def test_hooks_never_execute(self):
        marker = self.root / "hook-ran"
        hooks = self.repo / ".git/hooks"
        hooks.mkdir(exist_ok=True)
        for name in ("pre-commit", "commit-msg", "post-commit", "reference-transaction"):
            path = hooks / name
            path.write_text("#!/bin/sh\necho ran > '" + marker.as_posix() + "'\n")
            path.chmod(0o755)
        self.git("config", "core.hooksPath", str(hooks))
        self.change()
        self.seal()
        self.assertFalse(marker.exists())

    def test_inherited_git_environment_cannot_redirect_authority(self):
        self.change()
        injected = {name: str(self.root / "nonexistent") for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG",
            "GIT_ATTR_SOURCE", "GIT_REPLACE_REF_BASE")}
        injected.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.worktree", GIT_CONFIG_VALUE_0="/invalid")
        with mock.patch.dict(os.environ, injected):
            self.seal()
        self.assertEqual(self.authority(), self.initial)

    def test_includes_alternates_info_attributes_and_replace_refs_block(self):
        self.git("config", "include.path", str(self.root / "missing"))
        self.blocked()
        self.git("config", "--unset", "include.path")
        for relative in ("info/attributes", "objects/info/alternates", "info/grafts"):
            path = self.repo / ".git" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"")
            self.blocked()
            path.unlink()
        path = self.repo / ".git/refs/replace"
        path.mkdir()
        (path / self.base).write_text(self.base + "\n")
        self.blocked()

    def test_path_validation_and_case_collisions(self):
        for path in ("../x", "/x", "C:/x", "a\\b", "a:b", "a//b", "a/./b", ".git/x", ".GiT/x",
                     "NUL.txt", "COM1", "CONIN$", "CONOUT$", "CLOCK$", " leading", "a.", "a ",
                     "git~1/x", "a\nb", "a\rb", "a\0b", "a\tb"):
            with self.subTest(path=repr(path)), self.assertRaises(cm.MaterializationError):
                cm.safe_path(path)
        (self.repo / "A.TXT").write_bytes(b"case alias")
        if os.name != "nt":
            self.blocked()
        else:
            # Windows resolves this to the original; a logical tree collision
            # is independently rejected by the tree reader.
            fake = b"100644 blob " + b"a" * 40 + b"\ta.txt\0" + b"100644 blob " + b"b" * 40 + b"\tA.TXT\0"
            with mock.patch.object(cm._Git, "run", return_value=fake), self.assertRaises(cm.MaterializationError):
                cm._Git.tree(cm._Git.__new__(cm._Git), "a" * 40)

    def test_commit_metadata_injection_and_frozen_result(self):
        for field, value in (("author_name", "evil\nparent x"), ("author_email", "a>b"),
                             ("committer_timestamp", True), ("author_timezone", "+0000\n")):
            with self.assertRaises(cm.MaterializationError):
                replace(self.metadata, **{field: value})
        self.change()
        result = self.seal()
        with self.assertRaises(AttributeError):
            result.phase = "APPROVED"

    def test_crash_replay_after_prepared_blobs_tree_and_commit(self):
        self.change()
        (self.repo / "new.bin").write_bytes(b"second")
        original = cm._Git.run
        for command in ("hash-object", "write-tree", "commit-tree"):
            hit = []
            def interrupt(git, *args, **kwargs):
                result = original(git, *args, **kwargs)
                if args[0] == command and not hit:
                    hit.append(result)
                    raise Crash()
                return result
            with mock.patch.object(cm._Git, "run", interrupt), self.assertRaises(Crash):
                self.seal()
            self.assertEqual(self.row()["phase"], "PREPARED")
            self.assertEqual(self.authority(), self.initial)
        orphan = hit[0].decode().strip()
        self.assertNotEqual(self.base, orphan)
        result = self.seal()
        self.assertEqual(result.candidate_commit_sha, orphan)
        self.assertEqual(self.authority(), self.initial)

    def test_crash_immediately_after_prepared_and_drift_blocks(self):
        self.change()
        original = self.store.prepare_candidate_materialization
        def stop(*args, **kwargs):
            original(*args, **kwargs)
            raise Crash()
        with mock.patch.object(self.store, "prepare_candidate_materialization", side_effect=stop), self.assertRaises(Crash):
            self.seal()
        old = self.row()
        (self.repo / "a.txt").write_bytes(b"drift\n")
        self.blocked()
        self.assertEqual(self.row(), old)

    def test_drift_during_build_blocks_and_preserves_authority(self):
        self.change()
        original = cm._Git.run
        def drift(git, *args, **kwargs):
            result = original(git, *args, **kwargs)
            if args[0] == "commit-tree":
                (self.repo / "a.txt").write_bytes(b"drift\n")
            return result
        with mock.patch.object(cm._Git, "run", drift):
            self.blocked()
        self.assertEqual(self.authority(), self.initial)

    def test_unexpected_tree_entry_blocks(self):
        self.change()
        original = cm._Git.tree
        count = []
        def wrong_tree(git, oid):
            result = original(git, oid)
            count.append(oid)
            if len(count) == 2:
                result["extra"] = ("100644", "blob", "f" * 40)
            return result
        with mock.patch.object(cm._Git, "tree", wrong_tree):
            self.blocked()

    def test_base_branch_and_packet_drift_block(self):
        self.change()
        original_packet = self.packet
        for precondition in (GitPreconditions("task/wrong", self.base, True),
                             GitPreconditions("task/synthetic", "b" * 40, True)):
            self.packet = replace(original_packet, preconditions=Preconditions(precondition, ()))
            self.blocked()
        self.packet = original_packet
        result = self.seal()
        with self.assertRaises(cm.MaterializationError):
            cm.materialize_candidate(self.store, self.packet, "b" * 64, self.repo,
                                     self.metadata, empty_global_config=self.empty)
        self.assertEqual(self.row()["candidate_commit_sha"], result.candidate_commit_sha)

    def test_unrelated_orphan_is_never_adopted(self):
        self.change()
        orphan = self.git("commit-tree", self.base + "^{tree}", "-p", self.base, data=b"unrelated orphan\n").decode().strip()
        result = self.seal()
        self.assertNotEqual(result.candidate_commit_sha, orphan)
        self.assertEqual(self.authority(), self.initial)

    def test_drift_of_commit_metadata_never_silently_creates_another_intent(self):
        self.change()
        result = self.seal()
        with self.assertRaises(cm.MaterializationError):
            self.seal(metadata=replace(self.metadata, author_timestamp=1700000001))
        self.assertEqual(self.row()["candidate_commit_sha"], result.candidate_commit_sha)

    def test_stat_cache_cannot_hide_same_size_mtime_change(self):
        previous = (self.repo / "a.txt").stat()
        (self.repo / "a.txt").write_bytes(b"evil\n")
        os.utime(self.repo / "a.txt", ns=(previous.st_atime_ns, previous.st_mtime_ns))
        result = self.seal()
        self.assertEqual(self.git("cat-file", "blob", result.candidate_commit_sha + ":a.txt"), b"evil\n")
        self.assertEqual([entry["path"] for entry in json.loads(self.row()["manifest_json"])], ["a.txt"])

    def test_candidate_filter_attribute_without_driver_blocks(self):
        self.change()
        (self.repo / ".gitattributes").write_bytes(b"*.txt filter=not_configured\n")
        self.blocked()

    def test_linked_worktree_partial_clone_and_external_index_are_rejected(self):
        self.git("config", "remote.origin.promisor", "true")
        self.blocked()
        self.git("config", "--unset", "remote.origin.promisor")
        (self.repo / ".git/commondir").write_text("../other\n")
        self.blocked()
        (self.repo / ".git/commondir").unlink()
        os.link(self.repo / ".git/index", self.root / "index-alias")
        self.blocked()


if __name__ == "__main__":
    unittest.main()
