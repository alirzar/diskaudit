"""Tests for diskaudit. Run from the repository root:

    python3 -m unittest discover -s tests -v

They build small folder trees in a temporary directory, so they are quick and
never touch your real files.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "diskaudit.py")


def load():
    spec = importlib.util.spec_from_file_location("diskaudit", SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    # Shrink the size thresholds so a few kilobytes count as "large".
    m.LARGE_BYTES = 1000
    m.MIN_REPORT_KB = 1
    m.MIN_DUP_DIR_KB = 1
    m.GIB_KB = 1
    return m


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class DiskAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        env = mock.patch.dict(os.environ, {"HOME": self.home})
        env.start()
        self.addCleanup(env.stop)
        self.da = load()
        self.tree = os.path.join(self.tmp, "tree")
        os.makedirs(self.tree)

    def scan(self):
        rd, ext, nfiles, errors, secs = self.da.scan(self.tree, 2, False)
        return rd

    def test_hard_links_counted_once(self):
        a = os.path.join(self.tree, "a", "data.bin")
        write(a, os.urandom(50000))
        os.makedirs(os.path.join(self.tree, "b"))
        os.link(a, os.path.join(self.tree, "b", "data.bin"))
        rd = self.scan()
        blocks = os.stat(a).st_blocks // 2
        self.assertEqual(rd.full_kb - rd.kb, blocks)

    def test_duplicate_files_grouped_by_folder_pair(self):
        for run in ("run_a", "run_b"):
            for s in ("s1", "s2"):
                write(os.path.join(self.tree, "proj", run, s, "big.dat"), b"x" * 50000 + s.encode())
        rd = self.scan()
        fs = self.da.resolve(rd, self.da.dupfile_findings(rd, [], False, False))
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual(f["tier"], 2)  # many matching files: likely pipeline outputs, so "check first"
        self.assertEqual(f["cmd"].count("ln -f "), 2)
        self.assertIn("Identical files in", f["title"])

    def test_single_duplicate_file_is_safe(self):
        write(os.path.join(self.tree, "x", "image.sif"), b"y" * 40000)
        write(os.path.join(self.tree, "y", "image.sif"), b"y" * 40000)
        rd = self.scan()
        fs = self.da.resolve(rd, self.da.dupfile_findings(rd, [], False, False))
        self.assertEqual([f["tier"] for f in fs], [1])
        self.assertTrue(fs[0]["title"].startswith("Identical copy of"))

    def test_installed_software_is_skipped(self):
        for sw in ("tool_a", "tool_b"):
            os.makedirs(os.path.join(self.tree, sw, "bin"))
            write(os.path.join(self.tree, sw, "lib", "libx.so"), b"z" * 40000)
        rd = self.scan()
        skip = sorted(self.da.install_roots(rd))
        self.assertEqual(len(skip), 2)
        self.assertEqual(self.da.dupfile_findings(rd, skip, False, False), [])
        self.assertEqual(self.da.dupdir_findings(rd, skip), [])

    def test_duplicate_folder(self):
        for d in ("original", "copy_of_original"):
            write(os.path.join(self.tree, d, "f1.nii.gz"), b"a" * 30000)
            write(os.path.join(self.tree, d, "sub", "f2.nii.gz"), b"b" * 30000)
        rd = self.scan()
        fs = self.da.resolve(rd, self.da.dupdir_findings(rd, []))
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["tier"], 2)
        self.assertTrue(fs[0]["paths"][0].endswith("copy_of_original"))  # "copy" in the name: suggest that one

    def test_archive_already_unpacked(self):
        data = os.path.join(self.tree, "dataset")
        write(os.path.join(data, "scan.nii.gz"), os.urandom(5000))
        with tarfile.open(os.path.join(self.tree, "dataset_v1.tar.gz"), "w:gz") as t:
            t.add(data, arcname="dataset")
        rd = self.scan()
        fs = self.da.archive_findings(rd, [])
        self.assertEqual([f["kind"] for f in fs], ["archive"])

    def test_trash_from_outside_home_needs_a_check(self):
        trash = os.path.join(self.tree, ".local", "share", "Trash")
        write(os.path.join(trash, "files", "mine", "a.dat"), os.urandom(5000))
        write(os.path.join(trash, "files", "shared", "b.dat"), os.urandom(5000))
        write(os.path.join(trash, "info", "mine.trashinfo"),
              f"[Trash Info]\nPath={self.tree}/projects/mine\nDeletionDate=2026-01-02T10:00:00\n".encode())
        write(os.path.join(trash, "info", "shared.trashinfo"),
              b"[Trash Info]\nPath=/data/raw/shared\nDeletionDate=2026-03-04T10:00:00\n")
        rd = self.scan()
        fs = self.da.trash_findings(rd, self.da.find_trash(rd))
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["tier"], 2)
        self.assertIn("outside your home folder", fs[0]["note"])

    def test_older_container_image(self):
        write(os.path.join(self.tree, "img", "tool-1.0.0.sif"), b"1" * 3000)
        write(os.path.join(self.tree, "img", "tool-2.1.0.sif"), b"2" * 3000)
        rd = self.scan()
        fs = self.da.old_image_findings(self.da.image_list(rd, []))
        self.assertEqual(len(fs), 1)
        self.assertIn("(1.0.0)", fs[0]["title"])

    def test_pipeline_working_directory(self):
        for i in range(25):
            write(os.path.join(self.tree, "proj", "work", "sub_01_wf", f"node{i}", "result.pklz"),
                  os.urandom(200))
        rd = self.scan()
        fs = self.da.scratch_findings(rd, [], __import__("time").time())
        self.assertEqual([os.path.basename(f["paths"][0]) for f in fs], ["work"])

    def test_end_to_end_report_and_history(self):
        write(os.path.join(self.tree, "a", "file.bin"), os.urandom(20000))
        out = os.path.join(self.tmp, "reports")
        env = dict(os.environ, HOME=self.home)
        cmd = [sys.executable, SRC, self.tree, "--no-open", "-o", out]
        r1 = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        r2 = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("since the scan on", r2.stdout)
        reports = [f for f in os.listdir(out) if f.endswith(".html")]
        self.assertTrue(reports)
        with open(os.path.join(out, reports[0])) as f:
            page = f.read()
        self.assertIn("<title>Disk audit", page)
        self.assertNotIn("__DATA__", page)
        hist = os.path.join(self.home, ".local", "share", "diskaudit", "history.jsonl")
        with open(hist) as f:
            self.assertEqual(len(f.readlines()), 2)


if __name__ == "__main__":
    unittest.main()
