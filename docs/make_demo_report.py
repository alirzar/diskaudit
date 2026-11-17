#!/usr/bin/env python3
"""Render a diskaudit report from made-up demo data (for the README screenshot).

    python3 docs/make_demo_report.py [OUT.html]

The data describe a fictional user on a fictional lab server. They go through
the same report template as a real scan, so the page looks exactly like the
real thing without showing anyone's files.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("diskaudit", os.path.join(HERE, "..", "src", "diskaudit.py"))
da = importlib.util.module_from_spec(spec)
spec.loader.exec_module(da)

GB = 1048576  # KiB
TB = 1024 ** 4
HOME = "/data/home/jdoe"


def kb(gb):
    return int(gb * GB)


def node(name, gb=None, kids=None, v=None, t=None, f=False, other=0.0):
    """A treemap node. A folder's size is its children plus `other` GB of small items."""
    n = {"n": name}
    if kids:
        n["c"] = kids
        if other:
            kids.append({"n": "smaller items", "s": kb(other), "o": 1})
        n["s"] = sum(k["s"] for k in kids)
    else:
        n["s"] = kb(gb)
    if v:
        n["v"], n["t"] = v, t
    if f:
        n["f"] = 1
    return n


# (tier, title, paths, GB, note, command)
FINDINGS = [
    (1, "Desktop Trash", ["~/.local/share/Trash/files", "~/.local/share/Trash/info"], 180.4,
     "1,204 items you deleted in the file manager between 3 Feb 2025 and 2 Nov 2026. Files in Trash still "
     "take up disk space until it is emptied.",
     f"rm -rf {HOME}/.local/share/Trash/files {HOME}/.local/share/Trash/info {HOME}/.local/share/Trash/expunged "
     f"&& mkdir -p {HOME}/.local/share/Trash/files {HOME}/.local/share/Trash/info"),
    (1, "Apptainer cache", ["~/.apptainer/cache"], 61.8,
     "Downloaded files kept to speed things up; they are fetched again when needed.",
     "apptainer cache clean --force"),
    (1, "Conda package cache", ["~/miniconda3/pkgs"], 6.8,
     "Downloaded package tarballs and packages that no environment uses. Packages your environments use are "
     "left alone.", f"{HOME}/miniconda3/bin/conda clean --all -y"),
    (1, "Identical copy of fmriprep-24.1.1.sif", ["~/projects/study_rest/fmriprep-24.1.1.sif"], 5.1,
     "Same contents as ~/containers/fmriprep-24.1.1.sif. Replacing the copies with hard links keeps every "
     "path working and stores the data once. Do this only for finished files: a program that later rewrites "
     "one copy in place (for example a pipeline rerun with overwrite) would change both.",
     f"ln -f {HOME}/containers/fmriprep-24.1.1.sif {HOME}/projects/study_rest/fmriprep-24.1.1.sif"),
    (1, "pip download cache", ["~/.cache/pip"], 2.1,
     "Downloaded files kept to speed things up; they are fetched again when needed.", "pip cache purge"),
    (2, "Mostly a copy of another folder", ["~/Downloads/shared_sourcedata"], 48.0,
     "46.2 GB of its 48.0 GB has the same file names and sizes as ~/projects/study_rest/sourcedata. Delete "
     "whichever copy you don't use; contents were not compared byte for byte.",
     f"rm -rf {HOME}/Downloads/shared_sourcedata"),
    (2, "Identical files in xcp_d_gsr and xcp_d", ["~/projects/study_rest/derivatives/xcp_d_gsr/  (212 files)"],
     21.4,
     "Files under ~/projects/study_rest/derivatives/xcp_d_gsr have exactly the same contents as files under "
     "~/projects/study_rest/derivatives/xcp_d. Replacing the copies with hard links keeps every path working "
     "and stores the data once. Do this only for finished files: a program that later rewrites one copy in "
     "place (for example a pipeline rerun with overwrite) would change both.",
     "\n".join(f"ln -f {HOME}/projects/study_rest/derivatives/xcp_d/sub-{i:02d}/func/sub-{i:02d}_task-rest_"
               f"desc-denoised_bold.nii.gz {HOME}/projects/study_rest/derivatives/xcp_d_gsr/sub-{i:02d}/func/"
               f"sub-{i:02d}_task-rest_desc-denoised_bold.nii.gz" for i in range(1, 7))),
    (3, "Pipeline working directory", ["~/projects/study_rest/work"], 120.3,
     "Pipeline (Nipype) working directory, last written 14 Aug 2026. Final outputs live in the pipeline's "
     "output folder; this is only needed to resume or rerun a run.", f"rm -rf {HOME}/projects/study_rest/work"),
    (3, "Pipeline working directory", ["~/projects/dwi_pilot/work"], 44.7,
     "Pipeline (Nipype) working directory, last written 2 Jun 2026. Final outputs live in the pipeline's "
     "output folder; this is only needed to resume or rerun a run.", f"rm -rf {HOME}/projects/dwi_pilot/work"),
    (3, "Archive already unpacked", ["~/datasets/ds000228.tar.gz"], 12.4,
     "Its contents are already unpacked next to it in ds000228/ (14.1 GB), as of the archive's date "
     "(9 Mar 2026). Keep it only as a frozen backup.", f"rm -rf {HOME}/datasets/ds000228.tar.gz"),
    (3, "Installer in Downloads", ["~/Downloads/freesurfer_ubuntu22-7.4.1_amd64.deb"], 8.9,
     "Downloaded 11 Jan 2026. Delete it if the software is already installed.",
     f"rm -rf {HOME}/Downloads/freesurfer_ubuntu22-7.4.1_amd64.deb"),
    (3, "Older qsiprep image (0.21.4)", ["~/containers/qsiprep-0.21.4.sif"], 8.2,
     "You also have qsiprep 1.0.1 at ~/containers/qsiprep-1.0.1.sif. Keep the old one only if you need to "
     "reproduce results made with it.", f"rm -rf {HOME}/containers/qsiprep-0.21.4.sif"),
    (3, "Older fmriprep image (23.2.0)", ["~/containers/fmriprep-23.2.0.sif"], 4.9,
     "You also have fmriprep 24.1.1 at ~/containers/fmriprep-24.1.1.sif. Keep the old one only if you need "
     "to reproduce results made with it.", f"rm -rf {HOME}/containers/fmriprep-23.2.0.sif"),
]
NOTE = {p.split("  (")[0].rstrip("/"): (t, f"{title}. {note}") for t, title, ps, g, note, c in FINDINGS for p in ps}


def flag(path):
    return NOTE.get(path, (None, None))


def leaf(name, gb, path, f=False):
    v, t = flag(path)
    return node(name, gb, v=v, t=t, f=f)


tree = node("jdoe", kids=[
    node("projects", kids=[
        node("study_rest", kids=[
            node("derivatives", kids=[
                leaf("fmriprep", 152.6, "~/projects/study_rest/derivatives/fmriprep"),
                leaf("xcp_d", 38.2, "~/projects/study_rest/derivatives/xcp_d"),
                leaf("xcp_d_gsr", 24.8, "~/projects/study_rest/derivatives/xcp_d_gsr"),
                leaf("freesurfer", 49.5, "~/projects/study_rest/derivatives/freesurfer"),
                leaf("mriqc", 6.3, "~/projects/study_rest/derivatives/mriqc"),
            ], other=1.4),
            leaf("work", 120.3, "~/projects/study_rest/work"),
            leaf("sourcedata", 50.1, "~/projects/study_rest/sourcedata"),
            node("rawdata", kids=[leaf(f"sub-{i:02d}", 2.1 + 0.07 * i, "") for i in range(1, 15)], other=0.6),
            leaf("fmriprep-24.1.1.sif", 5.1, "~/projects/study_rest/fmriprep-24.1.1.sif", f=True),
        ], other=2.2),
        node("dwi_pilot", kids=[
            leaf("qsiprep", 91.4, "~/projects/dwi_pilot/qsiprep"),
            leaf("qsirecon", 58.7, "~/projects/dwi_pilot/qsirecon"),
            leaf("work", 44.7, "~/projects/dwi_pilot/work"),
            leaf("rawdata", 21.9, "~/projects/dwi_pilot/rawdata"),
        ], other=1.1),
        node("task_learning", kids=[
            leaf("derivatives", 64.2, ""),
            leaf("rawdata", 27.5, ""),
            leaf("analysis", 18.4, ""),
        ], other=0.9),
        node("surface_atlas", kids=[leaf("templates", 21.7, ""), leaf("outputs", 13.2, "")], other=0.4),
    ], other=3.8),
    node(".local", kids=[node("share", kids=[node("Trash", kids=[
        leaf("files", 180.3, "~/.local/share/Trash/files"),
        leaf("info", 0.1, "~/.local/share/Trash/info"),
    ])], other=0.6)]),
    node("Downloads", kids=[
        leaf("shared_sourcedata", 48.0, "~/Downloads/shared_sourcedata"),
        leaf("freesurfer_ubuntu22-7.4.1_amd64.deb", 8.9, "~/Downloads/freesurfer_ubuntu22-7.4.1_amd64.deb", f=True),
    ], other=3.4),
    node("containers", kids=[
        leaf("qsiprep-1.0.1.sif", 8.6, "", f=True),
        leaf("qsiprep-0.21.4.sif", 8.2, "~/containers/qsiprep-0.21.4.sif", f=True),
        leaf("fmriprep-24.1.1.sif", 5.1, "", f=True),
        leaf("fmriprep-23.2.0.sif", 4.9, "~/containers/fmriprep-23.2.0.sif", f=True),
        leaf("mriqc-24.0.2.sif", 4.3, "", f=True),
        leaf("xcp_d-0.10.6.sif", 3.9, "", f=True),
    ]),
    node(".apptainer", kids=[leaf("cache", 61.8, "~/.apptainer/cache")], other=0.2),
    node("datasets", kids=[
        leaf("ds000228", 14.1, "~/datasets/ds000228"),
        leaf("ds000228.tar.gz", 12.4, "~/datasets/ds000228.tar.gz", f=True),
    ], other=0.3),
    node("miniconda3", kids=[leaf("envs", 14.9, ""), leaf("pkgs", 6.8, "~/miniconda3/pkgs")], other=1.6),
    node(".cache", kids=[leaf("pip", 2.1, "~/.cache/pip")], other=1.9),
], other=6.2)

total = tree["s"]
tiers = {1: 0, 2: 0, 3: 0}
for t, title, ps, g, note, c in FINDINGS:
    tiers[t] += kb(g)

images = [("~/containers/qsiprep-1.0.1.sif", 8.6, "4 Sep 2026", False),
          ("~/containers/qsiprep-0.21.4.sif", 8.2, "19 Feb 2025", True),
          ("~/projects/study_rest/fmriprep-24.1.1.sif", 5.1, "2 Jul 2026", False),
          ("~/containers/fmriprep-24.1.1.sif", 5.1, "2 Jul 2026", False),
          ("~/containers/fmriprep-23.2.0.sif", 4.9, "12 Mar 2025", True),
          ("~/containers/mriqc-24.0.2.sif", 4.3, "8 Apr 2026", False),
          ("~/containers/xcp_d-0.10.6.sif", 3.9, "21 Jun 2026", False)]

data = {
    "root": HOME, "rootDisplay": "~", "version": da.__version__,
    "generated": "17 Nov 2026, 14:20", "date": "2026-11-17",
    "total": total, "files": 2214903, "errors": 0, "seconds": 96, "quick": False,
    "volume": {"mount": "/data", "fstype": "ext4", "device": "/dev/md0", "total": int(87.3 * TB),
               "used": int(82.5 * TB), "avail": int(0.42 * TB), "reserved": int(4.38 * TB)},
    "tiers": tiers,
    "findings": [{"tier": t, "title": title, "paths": ps, "kb": kb(g), "note": note, "cmd": c}
                 for t, title, ps, g, note, c in FINDINGS],
    "tree": tree,
    "ext": [{"e": e, "s": kb(g), "c": c} for e, g, c in [
        (".nii.gz", 742.0, 61872), (".h5", 88.4, 1310), (".sif", 63.9, 9), (".gii", 41.2, 30544),
        (".tar.gz", 35.7, 41), ("(none)", 34.8, 402115), (".pklz", 19.6, 512330), (".tsv", 12.1, 88410),
        (".deb", 8.9, 3), (".json", 3.4, 210388)]],
    "images": [{"p": p, "kb": kb(g), "m": m, "old": o} for p, g, m, o in images],
    "largest": [{"p": p, "kb": kb(g), "m": m} for p, g, m in [
        ("~/datasets/ds000228.tar.gz", 12.4, "9 Mar 2026"),
        ("~/Downloads/freesurfer_ubuntu22-7.4.1_amd64.deb", 8.9, "11 Jan 2026"),
        ("~/containers/qsiprep-1.0.1.sif", 8.6, "4 Sep 2026"),
        ("~/containers/qsiprep-0.21.4.sif", 8.2, "19 Feb 2025"),
        ("~/projects/dwi_pilot/qsiprep/sub-03/dwi/sub-03_space-T1w_desc-preproc_dwi.nii.gz", 6.1, "3 Jun 2026"),
        ("~/projects/study_rest/fmriprep-24.1.1.sif", 5.1, "2 Jul 2026"),
        ("~/containers/fmriprep-24.1.1.sif", 5.1, "2 Jul 2026")]],
    "history": [{"t": "2026-09-01T09:12", "kb": kb(1611.8), "avail": int(0.88 * TB)},
                {"t": "2026-10-06T16:40", "kb": kb(1538.2), "avail": int(0.61 * TB)},
                {"t": "2026-11-17T14:20", "kb": total, "avail": int(0.42 * TB)}],
}

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "demo-report.html")
da.write_report(out, data)
print(out)
