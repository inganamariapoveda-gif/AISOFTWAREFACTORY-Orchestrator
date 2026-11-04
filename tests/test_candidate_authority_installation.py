"""Authority installation: synthetic repositories only, no candidate execution."""
from dataclasses import asdict, replace
import ctypes
import json
import os
from pathlib import Path
import queue
import unittest
from unittest import mock

import yaml
from tests import test_candidate_materialization as fixtures
from orchestrator import candidate_materialization as cm
from orchestrator import candidate_authority_installation as ai


class Crash(BaseException):
    pass


class AuthorityInstallationTests(unittest.TestCase):
    git = fixtures.CandidateMaterializationTests.git
    authority = fixtures.CandidateMaterializationTests.authority
    change = fixtures.CandidateMaterializationTests.change

    def setUp(self):
        fixtures.CandidateMaterializationTests.setUp(self)
        self.packet = replace(self.packet, authorized_actions=(ai.ACTION,),
                              authorized_files=(*self.packet.authorized_files, "empty.bin"))
        (self.repo / "a.txt").write_bytes(b"candidate\r\nwithout-final-newline")
        (self.repo / "new.bin").write_bytes(b"\x00\xff\r\nbinary\n")
        (self.repo / "empty.bin").write_bytes(b"")
        self.sealed = cm.materialize_candidate(self.store, self.packet, "a"*64, self.repo, self.metadata,
                                              empty_global_config=self.empty)
        self.mat = self.store.get_candidate_materialization(self.sealed.materialization_id)
        self.raw = {p.name:p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        self.governance = ai.InstallationAuthority(*((fixtures.ROOT/"config"/name).read_bytes()
                                                   for name in ("PERMISSIONS.yaml","POLICIES.yaml","GATES.yaml")))
        p,o,g = self.governance.admit()
        self.approval = ai.InstallationApproval(self.packet.task_id, "a"*64, self.mat["id"], str(self.repo),
            self.mat["branch"], self.mat["base_head_sha"], self.mat["candidate_tree_sha"],
            self.mat["candidate_commit_sha"], self.mat["manifest_sha256"], p,o,g,
            "synthetic-director", "installation-001", "d"*64)

    def install(self, **kwargs):
        return ai.install_candidate_authority(self.store, kwargs.get("packet",self.packet), kwargs.get("packet_sha","a"*64),
            kwargs.get("approval",self.approval), kwargs.get("authority",self.governance),
            kwargs.get("repo",self.repo), empty_global_config=self.empty)

    def prepared(self):
        with mock.patch.object(ai, "_IndexLock", side_effect=Crash), self.assertRaises(Crash):
            self.install()
        row=self.store.get_candidate_authority_installation(self.mat["id"])
        self.assertEqual(row["phase"], "PREPARED")
        return row

    def assert_preserved(self):
        self.assertEqual({p.name:p.read_bytes() for p in self.repo.iterdir() if p.is_file()}, self.raw)
        self.assertEqual(self.store.get_candidate_materialization(self.mat["id"]), self.mat)

    def assert_blocked(self, **kwargs):
        with self.assertRaises(ai.InstallationError):
            self.install(**kwargs)

    def move_ref(self):
        self.git("update-ref","refs/heads/task/synthetic",self.sealed.candidate_commit_sha,self.base)

    def test_installation_and_preflight_git_conditions(self):
        before=self.store.get_task("T-1"),self.store.get_history("T-1"),self.store.list_agent_runs("T-1")
        result=self.install()
        self.assertEqual((result.phase,result.status),("VERIFIED","AUTHORITY_INSTALLED"))
        self.assertEqual(self.git("rev-parse","HEAD").decode().strip(),self.sealed.candidate_commit_sha)
        self.assertEqual(self.git("symbolic-ref","HEAD").strip(),b"refs/heads/task/synthetic")
        self.assertEqual(self.git("write-tree").decode().strip(),self.sealed.candidate_tree_sha)
        self.assertEqual(self.git("status","--porcelain=v1","--untracked-files=all"),b"")
        self.assertEqual(self.git("ls-files","--unmerged"),b"")
        self.assertEqual(before,(self.store.get_task("T-1"),self.store.get_history("T-1"),self.store.list_agent_runs("T-1")))
        self.assert_preserved()
        self.assertEqual(self.git("for-each-ref","--format=%(refname)").strip(),b"refs/heads/task/synthetic")

    def test_governance_absent_disabled_and_capability_fail_closed(self):
        for section,path,value in (
            ("permissions",("git_install_candidate_authority",),None),
            ("permissions",("git_install_candidate_authority","enabled"),False),
            ("permissions",("role_capabilities","builder"),["implement_authorized_changes","publish_authorized_task_branch"]),
            ("policies",("controlled_actions","git_install_candidate_authority"),None),
            ("policies",("controlled_actions","git_install_candidate_authority","enabled"),False),
            ("gates",("director_internal_gate","git_install_candidate_authority"),None),
            ("gates",("director_internal_gate","git_install_candidate_authority"),False)):
            with self.subTest(section=section,path=path,value=value):
                data=yaml.safe_load(getattr(self.governance,section))
                node=data
                for part in path[:-1]:node=node[part]
                if value is None:node.pop(path[-1])
                else:node[path[-1]]=value
                authority=replace(self.governance,**{section:yaml.safe_dump(data).encode()})
                self.assert_blocked(authority=authority)
        self.assertEqual(self.authority(),self.initial)

    def test_publication_absent_unknown_actions_never_authorize_installation(self):
        for actions in ((),("git_publish_task_branch",),("unknown",)):
            self.assert_blocked(packet=replace(self.packet,authorized_actions=actions))
        self.assertFalse(self.packet.authorizes_action("git_publish_task_branch"))
        self.assertEqual(self.authority(),self.initial)

    def test_each_approval_binding_mismatch(self):
        for field,value in (("task_id","OTHER"),("task_packet_sha256","e"*64),("materialization_id",999),
            ("repo_root",str(self.root)),("branch","task/other"),("base_head_sha","e"*40),
            ("candidate_tree_sha","e"*40),("candidate_commit_sha","e"*40),("manifest_sha256","e"*64),
            ("permissions_sha256","e"*64),("policies_sha256","e"*64),("gates_sha256","e"*64)):
            with self.subTest(field=field):
                self.assert_blocked(approval=replace(self.approval,**{field:value}))
        self.assert_blocked(packet_sha="f"*64)
        self.assert_blocked(repo=self.root)
        self.assertEqual(self.authority(),self.initial)

    def test_specific_director_identity_required_and_frozen(self):
        self.assert_blocked(approval=replace(self.approval,director_source=""))
        self.assert_blocked(approval=replace(self.approval,director_approval_sha256=""))
        with self.assertRaises(AttributeError):self.approval.branch="task/evil"
        self.prepared()
        self.assert_blocked(approval=replace(self.approval,director_approval_id="different"))

    def test_missing_commit_tree_blob_fail_without_recreation(self):
        blob=json.loads(self.mat["manifest_json"])[0]["blob_oid"]
        for oid in (self.sealed.candidate_commit_sha,self.sealed.candidate_tree_sha,blob):
            with self.subTest(oid=oid):
                path=self.repo/".git/objects"/oid[:2]/oid[2:]
                data=path.read_bytes();path.chmod(0o600);path.unlink()
                self.assert_blocked()
                self.assertFalse(path.exists())
                path.write_bytes(data)
        self.assertEqual(self.authority(),self.initial)

    def test_wrong_parent_and_tree_cannot_replace_sealed_identity(self):
        for tree,parent in ((self.mat["base_tree_sha"],self.base),(self.sealed.candidate_tree_sha,None)):
            args=["commit-tree",tree]
            if parent:args.extend(["-p",parent])
            wrong=self.git(*args,data=b"wrong\n").decode().strip()
            self.store._conn.execute("UPDATE candidate_materialization SET candidate_commit_sha=? WHERE id=?",(wrong,self.mat["id"]))
            self.store._conn.commit()
            self.assert_blocked(approval=replace(self.approval,candidate_commit_sha=wrong))
        self.assertEqual(self.authority(),self.initial)

    def test_raw_drift_and_unexpected_untracked(self):
        (self.repo/"a.txt").write_bytes(b"other")
        self.assert_blocked()
        (self.repo/"a.txt").write_bytes(self.raw["a.txt"])
        (self.repo/"extra").write_bytes(b"extra")
        self.assert_blocked()
        self.assertEqual(self.authority(),self.initial)

    def test_symbolic_task_wrong_branch_detached_and_stale_base(self):
        self.git("update-ref","refs/heads/task/other",self.base)
        self.git("symbolic-ref","refs/heads/task/synthetic","refs/heads/task/other")
        self.assert_blocked()
        self.git("update-ref","--no-deref","refs/heads/task/synthetic",self.base)
        self.git("symbolic-ref","HEAD","refs/heads/task/other")
        self.assert_blocked()
        (self.repo/".git/HEAD").write_text(self.base+"\n")
        self.assert_blocked()
        self.git("symbolic-ref","HEAD","refs/heads/task/synthetic")
        third=self.git("commit-tree",self.mat["base_tree_sha"],"-p",self.base,data=b"third\n").decode().strip()
        self.git("update-ref","refs/heads/task/synthetic",third,self.base)
        self.assert_blocked()

    def test_no_intent_cannot_adopt_candidate_ref(self):
        self.move_ref()
        self.assert_blocked()

    def test_crash_after_prepared_and_resume_base_base(self):
        self.prepared()
        self.assertEqual(self.authority(),self.initial)
        self.assertEqual(self.install().phase,"VERIFIED")
        self.assert_preserved()

    def test_recover_candidate_base_without_second_cas(self):
        self.prepared();self.move_ref()
        with mock.patch.object(ai,"_RefTransaction",side_effect=AssertionError("CAS forbidden")):
            self.assertEqual(self.install().phase,"VERIFIED")
        self.assert_preserved()

    def test_recover_candidate_candidate_verify_only(self):
        self.prepared();self.move_ref();self.git("read-tree",self.sealed.candidate_tree_sha)
        with mock.patch.object(ai,"_IndexLock",side_effect=AssertionError("index mutation forbidden")), \
             mock.patch.object(ai,"_RefTransaction",side_effect=AssertionError("ref mutation forbidden")):
            self.assertEqual(self.install().phase,"VERIFIED")

    def test_base_candidate_blocks(self):
        self.prepared();self.git("read-tree",self.sealed.candidate_tree_sha)
        before=self.authority()
        self.assert_blocked()
        self.assertEqual(before,self.authority())

    def test_third_index_staging_preserved(self):
        self.prepared()
        oid=self.git("hash-object","-w","--stdin",data=b"foreign").decode().strip()
        self.git("update-index","--cacheinfo","100644,"+oid+",a.txt")
        before=self.authority()
        self.assert_blocked()
        self.assertEqual(before,self.authority())

    def test_unmerged_intent_to_add_and_flags_rejected(self):
        self.git("update-index","--index-info",data=("0 "+"0"*40+"\ta.txt\n100644 "+
            self.git("rev-parse",self.base+":a.txt").decode().strip()+" 1\ta.txt\n").encode())
        self.assert_blocked();self.git("read-tree",self.base)
        self.git("add","-N","new.bin");self.assert_blocked();self.git("read-tree",self.base)
        for flag in ("assume-unchanged","skip-worktree"):
            self.git("update-index","--"+flag,"a.txt");self.assert_blocked()
            self.git("update-index","--no-"+flag,"a.txt")

    def test_ambiguous_locks_are_not_deleted(self):
        for name in ("index.lock","HEAD.lock","refs/heads/task/synthetic.lock"):
            p=self.repo/".git"/name;p.write_bytes(b"foreign")
            self.assert_blocked()
            self.assertEqual(p.read_bytes(),b"foreign")
            p.unlink()

    def test_concurrent_index_writer_blocked_and_no_direct_read_tree(self):
        original=ai._IndexLock.__init__
        seen=[]
        def acquire(lock,repo):
            original(lock,repo)
            p=__import__("subprocess").run([__import__("shutil").which("git"),"read-tree",self.sealed.candidate_tree_sha],
                cwd=self.repo,env=self.env,capture_output=True,timeout=15)
            seen.append(p.returncode)
        run=ai._Git.run
        def guarded(git,*args,**kw):
            if args[0]=="read-tree":self.assertIsNotNone(kw.get("index"))
            return run(git,*args,**kw)
        with mock.patch.object(ai._IndexLock,"__init__",acquire),mock.patch.object(ai._Git,"run",guarded):
            self.install()
        self.assertEqual(seen,[128])
        self.assert_preserved()

    def test_third_index_written_before_lock_is_preserved(self):
        original=ai._IndexLock.__init__
        foreign=[]
        def acquire(lock,repo):
            oid=self.git("hash-object","-w","--stdin",data=b"foreign").decode().strip()
            self.git("update-index","--cacheinfo","100644,"+oid+",a.txt")
            foreign.append((self.repo/".git/index").read_bytes())
            original(lock,repo)
        with mock.patch.object(ai._IndexLock,"__init__",acquire):
            self.assert_blocked()
        self.assertEqual((self.repo/".git/index").read_bytes(),foreign[0])
        self.assertEqual(self.git("rev-parse","HEAD").decode().strip(),self.base)

    def test_hooks_neutralized(self):
        marker=self.root/"hook-marker"
        hooks=self.repo/".git/hooks";hooks.mkdir(exist_ok=True)
        (hooks/"reference-transaction").write_text('#!/bin/sh\necho ran > "'+marker.as_posix()+'"\nexit 1\n',newline="\n")
        self.install()
        self.assertFalse(marker.exists())

    def test_inherited_environment_cannot_redirect_git(self):
        env={k:str(self.root/"missing") for k in ("GIT_DIR","GIT_INDEX_FILE","GIT_OBJECT_DIRECTORY",
            "GIT_WORK_TREE","GIT_COMMON_DIR","GIT_ALTERNATE_OBJECT_DIRECTORIES","GIT_CONFIG","GIT_ATTR_SOURCE")}
        env.update(GIT_CONFIG_COUNT="1",GIT_CONFIG_KEY_0="core.worktree",GIT_CONFIG_VALUE_0="evil")
        with mock.patch.dict(os.environ,env):self.install()
        self.assert_preserved()

    def test_config_includes_filters_and_metadata_redirection_block(self):
        for key in ("include.path","filter.evil.clean","alias.status","extensions.worktreeConfig"):
            self.git("config",key,"true" if key=="extensions.worktreeConfig" else "invalid")
            self.assert_blocked()
            self.git("config","--unset",key)
        for name in ("info/attributes","objects/info/alternates","commondir"):
            p=self.repo/".git"/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b"")
            self.assert_blocked();p.unlink()

    def test_transaction_prepare_rejection_and_eof_leave_base(self):
        original=ai._RefTransaction.exchange
        def reject(tx,text,expected):
            if expected=="prepare: ok":
                tx.process.stdin.write(b"update refs/heads/task/synthetic "+b"0"*40+b" "+b"0"*40+b"\nprepare\n")
                tx.process.stdin.flush()
                answer=tx.events.get(timeout=10)
                ai.require(answer==b"prepare: ok\n","BLOCKED_REF_TRANSACTION")
            else:original(tx,text,expected)
        with mock.patch.object(ai._RefTransaction,"exchange",reject):self.assert_blocked()
        self.assertEqual(self.authority(),self.initial)

    def test_transaction_timeout_and_abort_leave_base(self):
        original=ai._RefTransaction.prepare
        def stop(tx):
            original(tx)
            raise ai.InstallationError("BLOCKED_REF_TRANSACTION_TIMEOUT")
        with mock.patch.object(ai._RefTransaction,"prepare",stop):self.assert_blocked()
        self.assertEqual(self.authority(),self.initial)
        self.assertFalse(list((self.repo/".git").rglob("*.lock")))

    def test_transaction_ack_timeout_and_eof_fail_closed(self):
        for failure in (queue.Empty(), b""):
            with self.subTest(failure=type(failure).__name__):
                kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with mock.patch.object(ai.queue.Queue, "get", **kwargs):
                    self.assert_blocked()
                self.assertEqual(self.authority(), self.initial)
                self.assertFalse(list((self.repo/".git").rglob("*.lock")))

    def test_cas_stale_after_readmission_does_not_install_index(self):
        original = ai._RefTransaction.prepare
        third = self.git("commit-tree", self.mat["base_tree_sha"], "-p", self.base, data=b"third\n").decode().strip()
        def competing(tx):
            self.git("update-ref", "refs/heads/task/synthetic", third, self.base)
            original(tx)
        with mock.patch.object(ai._RefTransaction, "prepare", competing):
            self.assert_blocked()
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), third)
        self.assertEqual((self.repo/".git/index").read_bytes(), self.initial[0])

    def test_prepared_transaction_context_drift_aborts(self):
        original = ai._RefTransaction.prepare
        def drift(tx):
            original(tx)
            self.git("config", "core.autocrlf", "true")
        with mock.patch.object(ai._RefTransaction, "prepare", drift):
            self.assert_blocked()
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), self.base)
        self.assertEqual((self.repo/".git/index").read_bytes(), self.initial[0])

    def test_materialization_not_sealed_and_manifest_digest_mismatch_block(self):
        self.store._conn.execute("UPDATE candidate_materialization SET manifest_sha256=? WHERE id=?", ("f"*64,self.mat["id"]))
        self.store._conn.commit()
        self.assert_blocked(approval=replace(self.approval,manifest_sha256="f"*64))
        self.store._conn.execute("UPDATE candidate_materialization SET phase='PREPARED', candidate_commit_sha=NULL, candidate_tree_sha=NULL WHERE id=?", (self.mat["id"],))
        self.store._conn.commit()
        self.assert_blocked()
        self.assertEqual(self.authority(),self.initial)

    def test_crash_after_ref_commit_reconciles(self):
        original=ai._RefTransaction.commit
        def crash(tx):original(tx);raise Crash()
        with mock.patch.object(ai._RefTransaction,"commit",crash),self.assertRaises(Crash):self.install()
        self.assertEqual(self.git("rev-parse","HEAD").decode().strip(),self.sealed.candidate_commit_sha)
        self.assertEqual(self.git("write-tree").decode().strip(),self.mat["base_tree_sha"])
        self.assertEqual(self.install().phase,"VERIFIED")

    def test_crash_after_index_install_and_before_verified(self):
        original=ai._IndexLock.install
        def crash(lock,*a):original(lock,*a);raise Crash()
        with mock.patch.object(ai._IndexLock,"install",crash),self.assertRaises(Crash):self.install()
        with mock.patch.object(self.store,"verify_candidate_authority_installation",side_effect=Crash),self.assertRaises(Crash):self.install()
        self.assertEqual(self.store.get_candidate_authority_installation(self.mat["id"])["phase"],"PREPARED")
        self.assertEqual(self.install().phase,"VERIFIED")
        self.assert_preserved()

    def test_verified_replay_no_git_mutation(self):
        result=self.install();authority=self.authority()
        with mock.patch.object(ai,"_IndexLock",side_effect=AssertionError("lock forbidden")), \
             mock.patch.object(ai,"_RefTransaction",side_effect=AssertionError("CAS forbidden")):
            self.assertEqual(self.install(),result)
        self.assertEqual(self.authority(),authority)

    @unittest.skipUnless(os.name=="nt","Windows sharing semantics")
    def test_windows_open_destination_replace_failure_preserves_index(self):
        original=ai._IndexLock.install
        base_index=(self.repo/".git/index").read_bytes()
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,
                                    ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
        kernel.CreateFileW.restype=ctypes.c_void_p
        kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        def held(lock,contents,destination):
            handle=kernel.CreateFileW(str(destination),0x80000000,1,None,3,0x80,None)
            self.assertNotEqual(handle,ctypes.c_void_p(-1).value)
            try:original(lock,contents,destination)
            finally:kernel.CloseHandle(handle)
        with mock.patch.object(ai._IndexLock,"install",held):self.assert_blocked()
        self.assertEqual((self.repo/".git/index").read_bytes(),base_index)
        self.assertEqual(self.git("rev-parse","HEAD").decode().strip(),self.sealed.candidate_commit_sha)
        self.assertEqual(self.install().phase,"VERIFIED")
        self.assert_preserved()


if __name__=="__main__":
    unittest.main()
