#!/usr/bin/env python3
"""Unprivileged filesystem fixtures with an explicit synthetic owner transport."""
import importlib.util
import errno
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).with_name("supported_local_execution_roots.py")
SPEC = importlib.util.spec_from_file_location("supported_local_execution_roots", SOURCE)
roots = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(roots)


class StatView:
    def __init__(self, original, **overrides):
        self.original = original
        self.overrides = overrides

    def __getattr__(self, name):
        return self.overrides.get(name, getattr(self.original, name))


class SyntheticRootOps:
    """Real fixture creates/chmods; only privileged ownership is synthetic."""

    def __init__(self):
        self.owners = {}
        self.fail_mkdir = None
        self.mode_override = None
        self.visible_inode_override = None
        self.owner_override = None
        self.device_override = None
        self.link_override = None
        self.created = []
        self.mutations = []
        self.before_visible_stat = None
        self.after_fchmod = None

    def mkdir(self, name, mode, *, dir_fd):
        if name == self.fail_mkdir:
            raise OSError("injected mkdir refusal")
        os.mkdir(name, mode, dir_fd=dir_fd)
        self.created.append(name)

    def open(self, name, flags, *, dir_fd):
        return os.open(name, flags, dir_fd=dir_fd)

    def fchown(self, fd, uid, gid):
        s = os.fstat(fd)
        self.mutations.append(("fchown", s.st_dev, s.st_ino))
        self.owners[(s.st_dev, s.st_ino)] = (uid, gid)

    def fchmod(self, fd, mode):
        s = os.fstat(fd)
        self.mutations.append(("fchmod", s.st_dev, s.st_ino))
        os.fchmod(fd, mode)
        if self.after_fchmod is not None:
            self.after_fchmod(self.created[-1])

    def view(self, s, *, visible=False):
        uid, gid = self.owners.get((s.st_dev, s.st_ino), (s.st_uid, s.st_gid))
        overrides = {"st_uid": uid, "st_gid": gid}
        if self.owner_override is not None:
            overrides["st_uid"], overrides["st_gid"] = self.owner_override
        if self.mode_override is not None:
            overrides["st_mode"] = stat.S_IFDIR | self.mode_override
        if visible and self.visible_inode_override is not None:
            overrides["st_ino"] = self.visible_inode_override
        if self.device_override is not None:
            overrides["st_dev"] = self.device_override
        if self.link_override is not None:
            overrides["st_nlink"] = self.link_override
        return StatView(s, **overrides)

    def fstat(self, fd):
        return self.view(os.fstat(fd))

    def stat(self, name, *, dir_fd, follow_symlinks):
        if self.before_visible_stat is not None:
            callback = self.before_visible_stat
            self.before_visible_stat = None
            callback(name)
        return self.view(os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks), visible=True)


class SyntheticRootProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proof = pathlib.Path(self.temp.name).resolve() / "proof"
        self.proof.mkdir()
        self.proof_id = "fixture-proof"
        self.ops = SyntheticRootOps()

    def bind(self):
        return roots.bind_fresh_proof(str(self.proof), self.proof_id)

    def config(self):
        path = self.proof / "es.json"
        path.write_text(json.dumps({"execution": {
            "staging_root_dir": str(self.proof / "es-staging"),
            "results_root_dir": str(self.proof / "es-results"),
        }}), encoding="utf-8")
        return str(path)

    def replacement(self):
        spare = self.proof / "valid-synthetic-replacement"
        spare.mkdir(mode=0o755)
        s = os.lstat(spare)
        self.ops.owners[(s.st_dev, s.st_ino)] = (0, 0)
        return spare, (s.st_dev, s.st_ino)

    def substitute(self, spare, name):
        original = self.proof / name
        detached = self.proof / (name + "-detached-original")
        original.rename(detached)
        spare.rename(original)
        return detached

    def assert_closed_after(self, action):
        opened = []
        actual_open = os.open

        def recorded_open(*args, **kwargs):
            fd = actual_open(*args, **kwargs)
            opened.append(fd)
            return fd

        with mock.patch.object(os, "open", side_effect=recorded_open):
            action()
        self.assertTrue(opened)
        for fd in opened:
            with self.assertRaises(OSError) as raised:
                os.fstat(fd)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_fresh_pair_and_static_consumer_with_synthetic_owner(self):
        binding = self.bind()
        roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
        self.assertEqual(self.ops.created, ["es-staging", "es-results"])
        for name in ("es-staging", "es-results"):
            s = os.lstat(self.proof / name)
            self.assertTrue(stat.S_ISDIR(s.st_mode))
            self.assertEqual(stat.S_IMODE(s.st_mode), 0o755)
            self.assertEqual(s.st_uid, os.geteuid())  # No real chown in this fixture.
        roots.check_profile(str(self.proof), self.proof_id, self.config(), self.ops)
        self.assertEqual({p.name for p in self.proof.iterdir()},
                         {".supported-local-es-root-binding-v1", "es-staging", "es-results", "es.json"})

    def test_preexisting_children_refuse_without_adoption(self):
        for name in ("es-staging", "es-results"):
            for kind in ("empty-directory", "nonempty-directory", "file", "symlink"):
                with self.subTest(name=name, kind=kind):
                    with tempfile.TemporaryDirectory() as temp:
                        proof = pathlib.Path(temp).resolve() / "proof"
                        proof.mkdir()
                        binding = roots.bind_fresh_proof(str(proof), self.proof_id)
                        child = proof / name
                        if kind in ("empty-directory", "nonempty-directory"):
                            child.mkdir()
                            if kind == "nonempty-directory":
                                (child / "sentinel").write_text("retain", encoding="utf-8")
                        elif kind == "file":
                            child.write_text("retain", encoding="utf-8")
                        else:
                            child.symlink_to("other-target")
                        with self.assertRaises(roots.Refusal):
                            roots.provision_pair(str(proof), self.proof_id, binding, SyntheticRootOps())
                        self.assertFalse((proof / ("es-results" if name == "es-staging" else "es-staging")).exists())
                        self.assertTrue(child.is_symlink() or child.exists())

    def test_bad_paths_and_parent_symlink_refuse(self):
        with self.assertRaises(roots.Refusal):
            roots.preflight_path(str(self.proof), self.proof_id)
        for value in ("/", "relative/path", str(self.proof / ".." / "proof"), str(self.proof) + "/"):
            with self.subTest(value=value), self.assertRaises(roots.Refusal):
                roots.preflight_path(value, self.proof_id)
        alias = pathlib.Path(self.temp.name).resolve() / "alias"
        alias.symlink_to(self.proof)
        with self.assertRaises(roots.Refusal):
            roots.preflight_path(str(alias), self.proof_id)
        with self.assertRaises(roots.Refusal):
            roots.preflight_path(str(alias / "child"), self.proof_id)
        source_root = SOURCE.parents[2]
        with self.assertRaises(roots.Refusal):
            roots.preflight_path(str(source_root / "fixtures"), self.proof_id)
        with self.assertRaises(roots.Refusal):
            roots.preflight_path(str(source_root.parent), self.proof_id)

    def test_partial_second_create_failure_retains_first_exact_child(self):
        binding = self.bind()
        self.ops.fail_mkdir = "es-results"
        with self.assertRaises(roots.Refusal):
            roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
        self.assertTrue((self.proof / "es-staging").is_dir())
        self.assertFalse((self.proof / "es-results").exists())
        self.assertEqual(self.ops.created, ["es-staging"])

    def test_metadata_valid_replacement_after_initialization_refuses(self):
        binding = self.bind()
        spare, replacement_id = self.replacement()
        original_id = []

        def replace(name):
            if name == "es-staging":
                original_id.append((os.lstat(self.proof / name).st_dev,
                                    os.lstat(self.proof / name).st_ino))
                self.substitute(spare, name)

        self.ops.after_fchmod = replace
        with self.assertRaises(roots.Refusal):
            roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
        self.assertEqual(self.ops.created, ["es-staging"])
        self.assertTrue((self.proof / "es-staging-detached-original").is_dir())
        self.assertEqual((os.lstat(self.proof / "es-staging").st_dev,
                          os.lstat(self.proof / "es-staging").st_ino), replacement_id)
        self.assertFalse((self.proof / "es-results").exists())
        self.assertEqual({entry[1:] for entry in self.ops.mutations}, set(original_id))
        self.assertNotIn(replacement_id, {entry[1:] for entry in self.ops.mutations})

    def test_first_child_replaced_during_second_refuses_final_pair_check(self):
        binding = self.bind()
        spare, replacement_id = self.replacement()
        first_id = []

        def replace(name):
            if name == "es-results":
                original = os.lstat(self.proof / "es-staging")
                first_id.append((original.st_dev, original.st_ino))
                self.substitute(spare, "es-staging")

        self.ops.after_fchmod = replace
        with self.assertRaises(roots.Refusal):
            roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
        self.assertEqual(self.ops.created, ["es-staging", "es-results"])
        self.assertTrue((self.proof / "es-staging-detached-original").is_dir())
        self.assertTrue((self.proof / "es-results").is_dir())
        self.assertEqual((os.lstat(self.proof / "es-staging").st_dev,
                          os.lstat(self.proof / "es-staging").st_ino), replacement_id)
        self.assertIn(first_id[0], {entry[1:] for entry in self.ops.mutations})
        self.assertNotIn(replacement_id, {entry[1:] for entry in self.ops.mutations})

    def test_pre_mutation_substitution_never_targets_replacement(self):
        binding = self.bind()
        spare, replacement_id = self.replacement()

        def replace(name):
            if name == "es-staging":
                self.substitute(spare, name)

        self.ops.before_visible_stat = replace
        with self.assertRaises(roots.Refusal):
            roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
        self.assertEqual(self.ops.mutations, [])
        self.assertEqual((os.lstat(self.proof / "es-staging").st_dev,
                          os.lstat(self.proof / "es-staging").st_ino), replacement_id)
        self.assertTrue((self.proof / "es-staging-detached-original").is_dir())
        self.assertFalse((self.proof / "es-results").exists())

    def test_descriptors_close_on_success_and_injected_failures(self):
        for fault in ("success", "pre-mutation-replacement", "post-mutation-replacement",
                      "first-child-during-second", "missing-visible", "symlink-visible",
                      "second-child-mkdir", "wrong-full-mode", "wrong-device",
                      "parent-drift", "marker-drift-initial", "marker-drift-final"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                proof = pathlib.Path(temp).resolve() / "proof"
                proof.mkdir()
                binding = roots.bind_fresh_proof(str(proof), self.proof_id)
                ops = SyntheticRootOps()
                spare = proof / "valid-synthetic-replacement"
                if fault in ("pre-mutation-replacement", "post-mutation-replacement",
                             "first-child-during-second"):
                    spare.mkdir(mode=0o755)
                    s = os.lstat(spare)
                    ops.owners[(s.st_dev, s.st_ino)] = (0, 0)

                    def replace(name):
                        target = "es-staging"
                        if (fault == "first-child-during-second" and name == "es-results"
                                or fault != "first-child-during-second" and name == target):
                            (proof / target).rename(proof / "detached-original")
                            spare.rename(proof / target)

                    if fault == "pre-mutation-replacement":
                        ops.before_visible_stat = replace
                    else:
                        ops.after_fchmod = replace
                elif fault in ("missing-visible", "symlink-visible"):
                    def replace(name):
                        if name == "es-staging":
                            (proof / name).rename(proof / "detached-original")
                            if fault == "symlink-visible":
                                (proof / name).symlink_to("detached-original")

                    ops.after_fchmod = replace
                elif fault == "second-child-mkdir":
                    ops.fail_mkdir = "es-results"
                elif fault == "wrong-full-mode":
                    ops.mode_override = 0o2755
                elif fault == "wrong-device":
                    ops.device_override = 1
                elif fault == "parent-drift":
                    def replace(name):
                        if name == "es-staging":
                            proof.rename(proof.parent / "moved")
                            proof.mkdir()

                    ops.after_fchmod = replace
                elif fault == "marker-drift-initial":
                    (proof / roots.MARKER).write_bytes(b"drift\n")
                elif fault == "marker-drift-final":
                    def replace(name):
                        if name == "es-results":
                            (proof / roots.MARKER).write_bytes(b"drift\n")

                    ops.after_fchmod = replace

                def invoke():
                    if fault == "success":
                        roots.provision_pair(str(proof), self.proof_id, binding, ops)
                    else:
                        with self.assertRaises(roots.Refusal):
                            roots.provision_pair(str(proof), self.proof_id, binding, ops)

                self.assert_closed_after(invoke)
                if fault == "success":
                    config = proof / "es.json"
                    config.write_text(json.dumps({"execution": {
                        "staging_root_dir": str(proof / "es-staging"),
                        "results_root_dir": str(proof / "es-results"),
                    }}), encoding="utf-8")
                    self.assert_closed_after(lambda: roots.check_profile(str(proof), self.proof_id,
                                                                           str(config), ops))
                    ops.mode_override = 0o2755

                    def invalid_static_check():
                        with self.assertRaises(roots.Refusal):
                            roots.check_profile(str(proof), self.proof_id, str(config), ops)

                    self.assert_closed_after(invalid_static_check)

    def test_full_mode_owner_and_visible_identity_fail_closed(self):
        for fault in ("special-mode", "wrong-uid", "wrong-gid", "wrong-device", "zero-links", "visible-inode"):
            with self.subTest(fault=fault):
                with tempfile.TemporaryDirectory() as temp:
                    proof = pathlib.Path(temp).resolve() / "proof"
                    proof.mkdir()
                    binding = roots.bind_fresh_proof(str(proof), self.proof_id)
                    ops = SyntheticRootOps()
                    if fault == "special-mode": ops.mode_override = 0o2755
                    elif fault == "wrong-uid": ops.owner_override = (501, 0)
                    elif fault == "wrong-gid": ops.owner_override = (0, 1000)
                    elif fault == "wrong-device": ops.device_override = 1
                    elif fault == "zero-links": ops.link_override = 0
                    else: ops.visible_inode_override = 1
                    with self.assertRaises(roots.Refusal):
                        roots.provision_pair(str(proof), self.proof_id, binding, ops)
                    self.assertTrue((proof / "es-staging").is_dir())
                    self.assertFalse((proof / "es-results").exists())

    def test_binding_and_parent_identity_drift_refuse(self):
        binding = self.bind()
        with self.assertRaises(roots.Refusal):
            roots.provision_pair(str(self.proof), self.proof_id, "0:0:0", self.ops)
        self.assertFalse((self.proof / "es-staging").exists())
        marker = self.proof / roots.MARKER
        original_marker = marker.read_bytes()
        marker.write_bytes(b"changed\n")
        try:
            with self.assertRaises(roots.Refusal):
                roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
            self.assertFalse((self.proof / "es-staging").exists())
        finally:
            marker.write_bytes(original_marker)
        chain = roots.open_chain(str(self.proof))
        moved = pathlib.Path(self.temp.name).resolve() / "moved"
        self.proof.rename(moved)
        self.proof.mkdir()
        try:
            with self.assertRaises(roots.Refusal):
                roots.assert_chain_stable(chain)
        finally:
            self.proof.rmdir()
            moved.rename(self.proof)
            roots.close_chain(chain)

    def test_static_consumer_rejects_mismatch_and_missing(self):
        binding = self.bind()
        roots.provision_pair(str(self.proof), self.proof_id, binding, self.ops)
        config = self.config()
        for fault in ("wrong-uid", "wrong-gid", "wrong-mode", "wrong-device", "zero-links", "wrong-visible-inode"):
            with self.subTest(fault=fault):
                ops = SyntheticRootOps()
                ops.owners = self.ops.owners.copy()
                if fault == "wrong-uid": ops.owner_override = (7, 0)
                elif fault == "wrong-gid": ops.owner_override = (0, 9)
                elif fault == "wrong-mode": ops.mode_override = 0o775
                elif fault == "wrong-device": ops.device_override = 1
                elif fault == "zero-links": ops.link_override = 0
                else: ops.visible_inode_override = 1
                with self.assertRaises(roots.Refusal):
                    roots.check_profile(str(self.proof), self.proof_id, config, ops)
        bad_config = self.proof / "other.json"
        bad_config.write_text('{}', encoding="utf-8")
        with self.assertRaises(roots.Refusal):
            roots.check_profile(str(self.proof), self.proof_id, str(bad_config), self.ops)
        (self.proof / "es-results").rmdir()
        with self.assertRaises(roots.Refusal):
            roots.check_profile(str(self.proof), self.proof_id, config, self.ops)
        (self.proof / "es-results").symlink_to("es-staging")
        with self.assertRaises(roots.Refusal):
            roots.check_profile(str(self.proof), self.proof_id, config, self.ops)


if __name__ == "__main__":
    unittest.main()
