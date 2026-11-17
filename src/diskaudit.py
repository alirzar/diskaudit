#!/usr/bin/env python3
"""diskaudit - see where your disk space goes and what you can safely delete.

    diskaudit                 scan your home folder
    diskaudit /some/path      scan another folder
    diskaudit --quick         skip the byte-for-byte check of duplicate files
    diskaudit --no-open       don't open the report in a browser

Writes a self-contained HTML report (treemap + cleanup plan) to ~/disk-audit/,
prints a summary, and remembers each scan in ~/.local/share/diskaudit/ so the
next report shows what changed. It never deletes anything: the report lists the
commands, and you decide what to run.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import unquote

__version__ = "1.0.0"
GIB_KB = 1024 * 1024                 # KiB in one GiB
LARGE_BYTES = 100 * 1024 ** 2        # files at least this big are remembered individually
TILE_FILE_KB = GIB_KB                # files this big get their own treemap tile
MIN_TILE_KB = GIB_KB // 2            # smaller folders fold into one "smaller items" tile
MAX_TILES = 40                       # tiles per folder before folding
MIN_DUP_DIR_KB = GIB_KB // 4         # folders smaller than this are not compared
MIN_REPORT_KB = 100 * 1024           # suggestions under 100 MB are not worth listing
EDGE = 1024 * 1024                   # bytes read from each end for the quick hash
CHUNK = 8 * 1024 * 1024

ARCHIVE_EXT = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tar", ".zip")
INSTALLER_EXT = (".deb", ".rpm", ".appimage", ".run", ".exe", ".msi", ".dmg", ".pkg", ".iso")
INSTALLER_SH = re.compile(r"(?i)^(miniconda|anaconda|miniforge|mambaforge|micromamba).*\.sh$")
IMAGE_EXT = (".sif", ".simg")
SCRATCH_NAME = re.compile(r"(?i)((^|[._-])(work|scratch|tmp|temp)([._-]|$)|_wf$)")
PLAIN_SCRATCH = {"work", "scratch", "tmp", "temp"}
EXT_RE = re.compile(r"(\.[a-z0-9]{1,10})(\.(?:gz|bz2|xz|zst))?$")
VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")
ORG_PREFIX = re.compile(r"^(nipreps|pennlinc|poldracklab|bids|neurodesk)[-_]", re.I)
DELETE_HINT = re.compile(r"(?i)/(downloads|tmp|temp)/|copy|backup|\bbak\b|\bold\b|shared")
CONDA_ROOTS = ("miniconda3", "anaconda3", "miniforge3", "mambaforge", "micromamba", ".conda")

# (path inside a home folder, tier, title, command). {p} is the quoted path.
CACHE_RULES = [
    (".apptainer/cache", 1, "Apptainer cache", "apptainer cache clean --force"),
    (".singularity/cache", 1, "Singularity cache", "singularity cache clean --force"),
    (".cache/pip", 1, "pip download cache", "pip cache purge"),
    (".npm/_cacache", 1, "npm download cache", "npm cache clean --force"),
    (".cache/go-build", 1, "Go build cache", "go clean -cache"),
    (".cache/yarn", 1, "Yarn cache", "yarn cache clean"),
    (".cache/thumbnails", 1, "Thumbnail cache", "rm -rf {p}"),
    (".cache/google-chrome", 1, "Chrome cache", "rm -rf {p}"),
    (".cache/mozilla", 1, "Firefox cache", "rm -rf {p}"),
    (".cache/tracker", 1, "Desktop search index", "rm -rf {p}"),
    (".cache/tracker3", 1, "Desktop search index", "rm -rf {p}"),
    (".cache/huggingface", 3, "Hugging Face downloads", "rm -rf {p}"),
    (".cache/torch", 3, "PyTorch downloads", "rm -rf {p}"),
    (".cache/templateflow", 3, "TemplateFlow templates", "rm -rf {p}"),
]
TIER_NAMES = {1: "Safe to remove", 2: "Check first", 3: "Worth reviewing"}


# ----------------------------------------------------------------------------- scanning

class Dir:
    __slots__ = ("name", "path", "parent", "kids", "kb", "nohl_kb", "hl_kb", "files",
                 "mtime", "pklz", "sig", "big", "parts")

    def __init__(self, name, path, parent):
        self.name, self.path, self.parent = name, path, parent
        self.kids = []
        self.kb = 0        # disk usage, each hard-linked inode counted once (like du)
        self.nohl_kb = 0   # usage of entries with a single link
        self.hl_kb = 0     # usage of multi-link files, counted at every link
        self.files = 0
        self.mtime = 0.0
        self.pklz = 0
        self.sig = b""
        self.big = []      # (name, kb, size, mtime, ino, nlink) for files >= LARGE_BYTES
        self.parts = []

    @property
    def full_kb(self):
        return self.nohl_kb + self.hl_kb


class Acc:
    def __init__(self):
        self.ext = {}
        self.files = 0
        self.errors = 0


class Ctx:
    def __init__(self, dev, par_depth):
        self.dev = dev
        self.par_depth = par_depth
        self.lock = threading.Lock()
        self.inodes = set()
        self.accs = []
        self.stop = False


def ext_of(name):
    m = EXT_RE.search(name.lower())
    return m.group(0) if m else "(none)"


def scan_entries(d, ctx, acc):
    """Read one directory: count its files into d and create child Dir objects."""
    if ctx.stop:
        return
    try:
        it = os.scandir(d.path)
    except OSError:
        acc.errors += 1
        return
    with it:
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                acc.errors += 1
                continue
            mode = st.st_mode
            name = e.name
            if stat.S_ISDIR(mode):
                if st.st_dev != ctx.dev:
                    continue  # another filesystem (like du -x)
                k = Dir(name, e.path, d)
                k.kb = k.nohl_kb = st.st_blocks // 2
                d.kids.append(k)
            elif stat.S_ISREG(mode):
                kb = st.st_blocks // 2
                acc.files += 1
                d.files += 1
                if st.st_nlink > 1:
                    d.hl_kb += kb
                    key = (st.st_dev, st.st_ino)
                    with ctx.lock:
                        first = key not in ctx.inodes
                        if first:
                            ctx.inodes.add(key)
                    if first:
                        d.kb += kb
                else:
                    d.kb += kb
                    d.nohl_kb += kb
                if st.st_mtime > d.mtime:
                    d.mtime = st.st_mtime
                x = ext_of(name)
                t = acc.ext.get(x)
                if t is None:
                    acc.ext[x] = [st.st_size, 1]
                else:
                    t[0] += st.st_size
                    t[1] += 1
                if name.endswith(".pklz"):
                    d.pklz += 1
                if st.st_size >= LARGE_BYTES:
                    d.big.append((name, kb, st.st_size, st.st_mtime, st.st_ino, st.st_nlink))
                d.parts.append(b"F" + os.fsencode(name) + b"\0" + str(st.st_size).encode())
            else:
                kb = st.st_blocks // 2
                d.kb += kb
                d.nohl_kb += kb
                if stat.S_ISLNK(mode):
                    d.parts.append(b"L" + os.fsencode(name))


def finalize(d):
    for k in d.kids:
        d.kb += k.kb
        d.nohl_kb += k.nohl_kb
        d.hl_kb += k.hl_kb
        d.files += k.files
        d.pklz += k.pklz
        if k.mtime > d.mtime:
            d.mtime = k.mtime
        d.parts.append(b"D" + os.fsencode(k.name) + b"\0" + k.sig)
    d.parts.sort()
    d.sig = hashlib.blake2b(b"\n".join(d.parts), digest_size=16).digest()
    d.parts = None


def scan_tree(d, ctx, acc):
    scan_entries(d, ctx, acc)
    for k in d.kids:
        scan_tree(k, ctx, acc)
    finalize(d)


def build_shell(d, ctx, acc, depth, tasks):
    scan_entries(d, ctx, acc)
    for k in d.kids:
        if depth + 1 < ctx.par_depth:
            build_shell(k, ctx, acc, depth + 1, tasks)
        else:
            tasks.append(k)


def finalize_shell(d, ctx, depth):
    for k in d.kids:
        if depth + 1 < ctx.par_depth:
            finalize_shell(k, ctx, depth + 1)
    finalize(d)


def scan(root, threads, tty):
    st = os.lstat(root)
    ctx = Ctx(st.st_dev, par_depth=3)
    rd = Dir(os.path.basename(root.rstrip("/")) or root, root, None)
    rd.kb = rd.nohl_kb = st.st_blocks // 2
    main = Acc()
    ctx.accs.append(main)
    tasks = []
    t0 = time.time()
    build_shell(rd, ctx, main, 0, tasks)

    def work(d):
        acc = Acc()
        ctx.accs.append(acc)
        scan_tree(d, ctx, acc)

    ex = ThreadPoolExecutor(max_workers=threads)
    try:
        pending = {ex.submit(work, d) for d in tasks}
        while pending:
            done, pending = wait(pending, timeout=1.0)
            for f in done:
                f.result()
            if tty:
                n = sum(a.files for a in ctx.accs)
                print(f"\r  scanning {root} ... {n:,} files, {time.time() - t0:.0f}s ",
                      end="", file=sys.stderr, flush=True)
    except BaseException:
        ctx.stop = True
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    ex.shutdown()
    if tty:
        print("\r" + " " * 90 + "\r", end="", file=sys.stderr)
    finalize_shell(rd, ctx, 0)
    ext = defaultdict(lambda: [0, 0])
    for a in ctx.accs:
        for k, (s, c) in a.ext.items():
            ext[k][0] += s
            ext[k][1] += c
    return rd, dict(ext), sum(a.files for a in ctx.accs), sum(a.errors for a in ctx.accs), time.time() - t0


# ----------------------------------------------------------------------------- helpers

def walk_dirs(rd, max_depth=None, skip=None):
    """All folders under rd with their depth; folders whose path is in `skip` are pruned."""
    stack = [(rd, 0)]
    while stack:
        d, depth = stack.pop()
        if skip and d.path in skip:
            continue
        yield d, depth
        if max_depth is None or depth < max_depth:
            stack.extend((k, depth + 1) for k in d.kids)


INSTALL_MARKERS = {"lib", "lib64", "share", "libexec", "include", "toolbox", "runtime", "sys", "extern"}


def install_roots(rd):
    """Folders that look like installed software: bin/ next to lib/, share/, or MATLAB's toolbox/, sys/ ..."""
    out = set()
    for d, depth in walk_dirs(rd):
        if depth == 0:
            continue
        names = {k.name for k in d.kids}
        if "bin" in names and names & INSTALL_MARKERS:
            out.add(d.path)
    return out


def node_at(rd, path):
    base = rd.path.rstrip("/")
    if path == rd.path or path == base:
        return rd
    if not path.startswith(base + "/"):
        return None
    d = rd
    for part in path[len(base) + 1:].split("/"):
        d = next((k for k in d.kids if k.name == part), None)
        if d is None:
            return None
    return d


def within(p, q):
    """True if path p is q or inside q."""
    return p == q or p.startswith(q.rstrip("/") + "/")


def walk_exclusive(paths):
    """Disk usage that deleting all of `paths` would free, respecting hard links."""
    seen = {}
    free = 0

    def add(full, st):
        nonlocal free
        if stat.S_ISDIR(st.st_mode) or st.st_nlink <= 1:
            free += st.st_blocks // 2
            return
        key = (st.st_dev, st.st_ino)
        rec = seen.get(key)
        if rec is None:
            seen[key] = [st.st_nlink, 1, st.st_blocks // 2]
        else:
            rec[1] += 1

    for p in paths:
        try:
            st = os.lstat(p)
        except OSError:
            continue
        add(p, st)
        if stat.S_ISDIR(st.st_mode):
            for dp, dn, fn in os.walk(p):
                for name in dn + fn:
                    q = os.path.join(dp, name)
                    try:
                        add(q, os.lstat(q))
                    except OSError:
                        pass
    free += sum(b for n, c, b in seen.values() if c >= n)
    return free


def exclusive_kb(rd, paths):
    total, slow = 0, []
    for p in paths:
        d = node_at(rd, p)
        if d is not None:
            if d.hl_kb == 0:
                total += d.nohl_kb
            else:
                slow.append(p)
            continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode) and st.st_nlink <= 1:
            total += st.st_blocks // 2
        else:
            slow.append(p)
    return total + (walk_exclusive(slow) if slow else 0)


def big_files(rd, skip):
    for d, _ in walk_dirs(rd, skip=set(skip)):
        for name, kb, size, mtime, ino, nlink in d.big:
            yield d, d.path + "/" + name, name, kb, size, mtime, ino, nlink


def day(ts):
    return dt.datetime.fromtimestamp(ts).strftime("%-d %b %Y") if ts else "unknown"


def fmt_kb(kb):
    g = kb / GIB_KB
    if g >= 10000:
        return f"{g / 1024:.1f} TB"
    if g >= 100:
        return f"{g:,.0f} GB"
    if g >= 1:
        return f"{g:.1f} GB"
    return f"{kb / 1024:,.0f} MB"


def q(p):
    return shlex.quote(p)


def pick_keep(paths_mtimes):
    """Choose which copy to keep: fewest Downloads/copy/backup-looking hints in the path, then newest, then shortest."""
    return sorted(paths_mtimes, key=lambda pm: (len(DELETE_HINT.findall(pm[0])), -pm[1], len(pm[0])))[0][0]


def quick_hash(path, size):
    h = hashlib.blake2b(digest_size=16)
    h.update(str(size).encode())
    with open(path, "rb") as f:
        h.update(f.read(EDGE))
        if size > 2 * EDGE:
            f.seek(size - EDGE)
            h.update(f.read(EDGE))
    return h.digest()


def full_hash(path, progress):
    h = hashlib.blake2b(digest_size=20)
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
            progress(len(b))
    return h.digest()


def archive_top(path):
    """Top-level folder named by an archive's first entry, read without extracting."""
    try:
        if path.lower().endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                for n in z.namelist()[:50]:
                    top = n.lstrip("/").removeprefix("./").split("/")[0]
                    if top:
                        return top
        else:
            with tarfile.open(path, "r:*") as t:
                m = t.next()
                if m is not None:
                    return m.name.lstrip("/").removeprefix("./").split("/")[0] or None
    except Exception:
        return None
    return None


def archive_stem(name):
    low = name.lower()
    for e in ARCHIVE_EXT:
        if low.endswith(e):
            return name[: -len(e)]
    return name


def is_singularity_img(path):
    try:
        with open(path, "rb") as f:
            return f.read(64).startswith(b"#!/usr/bin/env run-singularity")
    except OSError:
        return False


def image_tool_version(name):
    stem = name
    for e in IMAGE_EXT + (".img",):
        if stem.lower().endswith(e):
            stem = stem[: -len(e)]
    m = VERSION_RE.search(stem)
    if not m:
        return None, None
    prefix = stem[: m.start()].rstrip("-_.vV")
    tool = ORG_PREFIX.sub("", prefix).lower()
    if not tool:
        return None, None
    return tool, tuple(int(x) for x in m.group(1).split("."))


def volume_info(path):
    s = os.statvfs(path)
    total = s.f_blocks * s.f_frsize
    free_root = s.f_bfree * s.f_frsize
    avail = s.f_bavail * s.f_frsize
    mount, fstype, device = "/", "", ""
    real = os.path.realpath(path)
    try:
        with open("/proc/mounts") as f:
            for line in f:
                dev, mnt, fs = line.split()[:3]
                mnt = mnt.replace("\\040", " ")
                if within(real, mnt) and len(mnt) >= len(mount):
                    mount, fstype, device = mnt, fs, dev
    except OSError:
        pass
    return {"mount": mount, "fstype": fstype, "device": device, "total": total,
            "used": total - free_root, "avail": avail, "reserved": free_root - avail}


# ----------------------------------------------------------------------------- findings

def finding(kind, tier, title, paths, note, cmd=None, keep=None, nominal=None):
    return {"kind": kind, "tier": tier, "title": title, "paths": list(paths), "note": note,
            "cmd": cmd, "keep": keep, "nominal": nominal}


def find_homes(rd):
    homes = []
    for d, depth in walk_dirs(rd, max_depth=1):
        names = {k.name for k in d.kids}
        if names & {".local", ".cache", ".config"}:
            homes.append(d)
    return homes


def find_trash(rd):
    out = []
    for d, _ in walk_dirs(rd):
        p = d.parent
        if d.name == "Trash" and p and p.name == "share" and p.parent and p.parent.name == ".local":
            out.append(d)
        elif d.name == ".Trash" or d.name.startswith(".Trash-"):
            out.append(d)
    return out


def trash_findings(rd, trashes):
    res = []
    for t in trashes:
        if t.kb < MIN_REPORT_KB:
            continue
        files_dir, info_dir = t.path + "/files", t.path + "/info"
        fnode = node_at(rd, files_dir)
        owner_home = t.path[: -len("/.local/share/Trash")] if t.path.endswith("/.local/share/Trash") else None
        items, dates, outside_kb, outside_n, origins = 0, [], 0, 0, defaultdict(int)
        try:
            names = os.listdir(files_dir)
        except OSError:
            names = []
        items = len(names)
        for name in names:
            info = os.path.join(info_dir, name + ".trashinfo")
            orig, when = None, None
            try:
                with open(info, errors="replace") as f:
                    for line in f:
                        if line.startswith("Path="):
                            orig = unquote(line[5:].strip())
                        elif line.startswith("DeletionDate="):
                            when = line[13:].strip()[:10]
            except OSError:
                pass
            if when:
                dates.append(when)
            if owner_home and orig and orig.startswith("/") and not within(orig, owner_home):
                k = next((c for c in (fnode.kids if fnode else []) if c.name == name), None)
                if k is not None:
                    kb = k.full_kb
                else:
                    try:
                        kb = os.lstat(os.path.join(files_dir, name)).st_blocks // 2
                    except OSError:
                        kb = 0
                outside_kb += kb
                outside_n += 1
                origins["/".join(orig.split("/")[:4])] += kb
        span = f" between {day_iso(min(dates))} and {day_iso(max(dates))}" if dates else ""
        note = (f"{items:,} items you deleted in the file manager{span}. "
                "Files in Trash still take up disk space until it is emptied.")
        tier = 1
        if outside_kb >= GIB_KB:
            tier = 2
            top = sorted(origins.items(), key=lambda kv: -kv[1])[:3]
            note += (f" {outside_n} items ({fmt_kb(outside_kb)}) were deleted from outside your home folder, "
                     f"mostly from {', '.join(o for o, _ in top)}. Make sure that data still exists elsewhere "
                     "before emptying.")
        cmd = (f"rm -rf {q(files_dir)} {q(info_dir)} {q(t.path + '/expunged')} && "
               f"mkdir -p {q(files_dir)} {q(info_dir)}")
        res.append(finding("trash", tier, "Desktop Trash", [files_dir, info_dir], note, cmd=cmd))
    return res


def day_iso(s):
    try:
        return dt.date.fromisoformat(s).strftime("%-d %b %Y")
    except ValueError:
        return s


def cache_findings(rd, homes):
    res = []
    for h in homes:
        for rel, tier, title, cmd in CACHE_RULES:
            p = h.path.rstrip("/") + "/" + rel
            d = node_at(rd, p)
            if d is None or d.kb < MIN_REPORT_KB:
                continue
            note = ("Downloaded files kept to speed things up; they are fetched again when needed."
                    if tier == 1 else "Downloads that are fetched again on next use, which can take a while.")
            res.append(finding("cache", tier, title, [p], note, cmd=cmd.format(p=q(p))))
        cache = node_at(rd, h.path.rstrip("/") + "/.cache")
        known = {h.path.rstrip("/") + "/" + r for r, *_ in CACHE_RULES}
        if cache:
            for k in cache.kids:
                if k.path not in known and k.kb >= GIB_KB:
                    res.append(finding("cache", 3, f"Application cache ({k.name})", [k.path],
                                       "Cache folder of an application. Usually safe to delete when that "
                                       "application is closed.", cmd=f"rm -rf {q(k.path)}"))
        for cr in CONDA_ROOTS:
            croot = h.path.rstrip("/") + "/" + cr
            pk = node_at(rd, croot + "/pkgs")
            if pk is None or pk.kb < MIN_REPORT_KB:
                continue
            conda = croot + "/bin/conda"
            exe = q(conda) if os.path.exists(conda) else "conda"
            est = conda_clean_estimate(conda) if os.path.exists(conda) else None
            res.append(finding("conda", 1, "Conda package cache", [croot + "/pkgs"],
                               "Downloaded package tarballs and packages that no environment uses. "
                               "Packages your environments use are left alone.",
                               cmd=f"{exe} clean --all -y", nominal=est))
    return res


def conda_clean_estimate(conda):
    """Bytes `conda clean --all` would free, in KiB, or None."""
    try:
        out = subprocess.run([conda, "clean", "--all", "--dry-run", "--json"], capture_output=True,
                             text=True, timeout=180).stdout
        data = json.loads(out)
    except Exception:
        return None
    total = 0

    def walk(x):
        nonlocal total
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "total_size" and isinstance(v, (int, float)):
                    total += v
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(data)
    return int(total // 1024)


def dupdir_findings(rd, skip):
    groups = defaultdict(list)
    for d, depth in walk_dirs(rd, skip=set(skip)):
        if depth == 0 or d.files == 0 or d.full_kb < MIN_DUP_DIR_KB:
            continue
        groups[d.sig].append(d)
    dups = {s: ms for s, ms in groups.items() if len(ms) > 1}
    member = {id(m) for ms in dups.values() for m in ms}
    res = []
    agg, agg_sigs = defaultdict(int), defaultdict(list)
    loose = []
    for sig, ms in dups.items():
        free = [m for m in ms if not (m.parent is not None and id(m.parent) in member)]
        if not free:
            continue
        if len(ms) == 2 and len(free) == 2:
            a, b = free
            pa, pb = a.parent, b.parent
            if pa is not None and pb is not None and pa is not pb and not within(pa.path, pb.path) \
                    and not within(pb.path, pa.path):
                key = tuple(sorted((pa.path, pb.path)))
                agg[key] += a.full_kb
                agg_sigs[key].append((sig, ms, free))
                continue
        loose.append((ms, free))
    for key, kb in agg.items():
        pa, pb = node_at(rd, key[0]), node_at(rd, key[1])
        small = min(pa.full_kb, pb.full_kb)
        if kb >= GIB_KB and kb >= 0.5 * small:
            keep = pick_keep([(pa.path, pa.mtime), (pb.path, pb.mtime)])
            drop = pb if keep == pa.path else pa
            note = (f"{fmt_kb(kb)} of its {fmt_kb(drop.full_kb)} has the same file names and sizes as "
                    f"{disp(keep)}. Delete whichever copy you don't use; contents were not compared "
                    "byte for byte.")
            res.append(finding("dupdir", 2, "Mostly a copy of another folder", [drop.path], note,
                               keep=keep, nominal=drop.full_kb))
        else:
            for sig, ms, free in agg_sigs[key]:
                loose.append((ms, free))
    for ms, free in loose:
        keep = pick_keep([(m.path, m.mtime) for m in ms])
        drops = [m for m in free if m.path != keep]
        if not drops or drops[0].full_kb < GIB_KB:
            continue
        note = (f"Same file names and sizes throughout as {disp(keep)}. Delete whichever copy you don't "
                "use; contents were not compared byte for byte.")
        res.append(finding("dupdir", 2, "Copy of another folder", [m.path for m in drops], note,
                           keep=keep, nominal=sum(m.full_kb for m in drops)))
    return res


def dupfile_findings(rd, skip, quick, tty):
    by_size = defaultdict(dict)
    for d, path, name, kb, size, mtime, ino, nlink in big_files(rd, skip):
        by_size[size].setdefault(ino, (path, mtime))
    cands = {s: list(v.values()) for s, v in by_size.items() if len(v) > 1}
    if not cands:
        return []
    groups = defaultdict(list)
    for size, items in cands.items():
        for path, mtime in items:
            try:
                groups[(size, quick_hash(path, size))].append((path, mtime))
            except OSError:
                pass
    groups = {k: v for k, v in groups.items() if len(v) > 1}
    if not quick:
        cache = load_hash_cache()
        used = {}
        todo = sum(k[0] * len(v) for k, v in groups.items())
        done = [0]

        def prog(n):
            done[0] += n
            if tty and time.time() - prog.last > 1:
                prog.last = time.time()
                print(f"\r  checking duplicate files byte for byte ... {done[0] / 2**30:,.1f} of "
                      f"{todo / 2**30:,.1f} GB ", end="", file=sys.stderr, flush=True)
        prog.last = 0
        full = defaultdict(list)
        for (size, _), items in groups.items():
            for path, mtime in items:
                try:
                    st = os.stat(path)
                    key = f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}"
                    hx = cache.get(key)
                    if hx is None:
                        hx = full_hash(path, prog).hex()
                    else:
                        prog(size)
                    used[key] = hx
                    full[(size, hx)].append((path, mtime))
                except OSError:
                    pass
        if tty:
            print("\r" + " " * 90 + "\r", end="", file=sys.stderr)
        save_hash_cache(used)
        groups = {k: v for k, v in full.items() if len(v) > 1}

    # Group copies by the pair of folders they sit in, so parallel pipeline outputs
    # (e.g. run_a/... and run_b/...) become one suggestion instead of hundreds.
    pairs = defaultdict(list)
    for (size, _), items in groups.items():
        keep = pick_keep(items)
        for p, m in items:
            if p == keep:
                continue
            common = os.path.commonpath([keep, p])
            ktop = keep[len(common) + 1:].split("/")[0]
            dtop = p[len(common) + 1:].split("/")[0]
            pairs[(common, ktop, dtop)].append((keep, p))
    res = []
    for (common, ktop, dtop), links in pairs.items():
        kdir, ddir = common + "/" + ktop, common + "/" + dtop
        single = len(links) == 1
        if single:
            keep, p = links[0]
            title = f"Identical copy of {os.path.basename(keep)}"
            where = f"Same contents as {disp(keep)}."
            show = [disp(p)]
        else:
            title = f"Identical files in {dtop} and {ktop}"
            where = f"Files under {disp(ddir)} have exactly the same contents as files under {disp(kdir)}."
            show = [disp(ddir) + "/"]
        if quick:
            note = where + " Matched by size and first and last megabyte only (--quick)."
            tier = 2
        else:
            note = (where + " Replacing the copies with hard links keeps every path working and stores the data "
                    "once. Do this only for finished files: a program that later rewrites one copy in place "
                    "(for example a pipeline rerun with overwrite) would change both.")
            # A lone duplicated file is a plain copy; many matching files are usually pipeline outputs.
            tier = 1 if single else 2
        f = finding("dupfile", tier, title, [p for k, p in links], note,
                    cmd="\n".join(f"ln -f {q(k)} {q(p)}" for k, p in links))
        f["show"] = show
        f["links"] = links
        res.append(f)
    return res


def hash_cache_path():
    return os.path.join(os.path.expanduser("~/.local/share/diskaudit"), "hashes.json")


def load_hash_cache():
    try:
        with open(hash_cache_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_hash_cache(used):
    p = hash_cache_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p + ".tmp", "w") as f:
            json.dump(used, f)
        os.replace(p + ".tmp", p)
    except OSError:
        pass


def scratch_findings(rd, skip, now):
    res, taken = [], []
    for d, depth in sorted(walk_dirs(rd, skip=set(skip)), key=lambda x: x[1]):
        if depth == 0 or d.kb < GIB_KB or not SCRATCH_NAME.search(d.name):
            continue
        if any(within(d.path, t) for t in taken):
            continue
        age = (now - d.mtime) / 86400 if d.mtime else 0
        if d.pklz >= 20:
            note = (f"Pipeline (Nipype) working directory, last written {day(d.mtime)}. Final outputs live in "
                    "the pipeline's output folder; this is only needed to resume or rerun a run.")
        elif d.name.lower() in PLAIN_SCRATCH and age >= 30:
            note = f"Scratch-style folder, untouched since {day(d.mtime)}."
        else:
            continue
        taken.append(d.path)
        res.append(finding("scratch", 3, "Pipeline working directory" if d.pklz >= 20 else "Old scratch folder",
                           [d.path], note))
    return res


def archive_findings(rd, skip):
    res = []
    for d, path, name, kb, size, mtime, ino, nlink in big_files(rd, skip):
        low = name.lower()
        if low.endswith(ARCHIVE_EXT):
            kids = {k.name: k for k in d.kids}
            hit = None
            for cand in (archive_top(path), archive_stem(name)):
                if cand and cand in kids and kids[cand].kb > 0:
                    hit = kids[cand]
                    break
            if hit:
                note = (f"Its contents are already unpacked next to it in {hit.name}/ ({fmt_kb(hit.full_kb)}), "
                        f"as of the archive's date ({day(mtime)}). Keep it only as a frozen backup.")
                res.append(finding("archive", 3, "Archive already unpacked", [path], note))
        elif "/Downloads/" in path + "/" and (low.endswith(INSTALLER_EXT) or INSTALLER_SH.match(name)):
            res.append(finding("installer", 3, "Installer in Downloads", [path],
                               f"Downloaded {day(mtime)}. Delete it if the software is already installed."))
    return res


def image_list(rd, skip):
    imgs = []
    for d, path, name, kb, size, mtime, ino, nlink in big_files(rd, skip):
        low = name.lower()
        if low.endswith(IMAGE_EXT) or (low.endswith(".img") and is_singularity_img(path)):
            tool, ver = image_tool_version(name)
            imgs.append({"path": path, "kb": kb, "mtime": mtime, "tool": tool, "ver": ver})
    return imgs


def old_image_findings(imgs):
    by_tool = defaultdict(list)
    for im in imgs:
        if im["tool"]:
            by_tool[im["tool"]].append(im)
    res = []
    for tool, ims in by_tool.items():
        newest = max(ims, key=lambda i: i["ver"])
        if all(i["ver"] == newest["ver"] for i in ims):
            continue
        nv = ".".join(map(str, newest["ver"]))
        for im in ims:
            if im["ver"] < newest["ver"]:
                v = ".".join(map(str, im["ver"]))
                res.append(finding("image", 3, f"Older {tool} image ({v})", [im["path"]],
                                   f"You also have {tool} {nv} at {disp(newest['path'])}. "
                                   "Keep the old one only if you need to reproduce results made with it."))
    return res


def resolve(rd, cands):
    """Drop paths covered by another suggestion, then measure what each frees."""
    entries = []
    for fi, f in enumerate(cands):
        for p in f["paths"]:
            entries.append((p.rstrip("/").count("/"), fi, p))
    entries.sort()
    claimed, kept = [], defaultdict(list)
    for _, fi, p in entries:
        if any(within(p, c) for c in claimed):
            continue
        claimed.append(p)
        kept[fi].append(p)
    out = []
    for fi, f in enumerate(cands):
        paths = [p for p in f["paths"] if p in kept[fi]]
        if not paths:
            continue
        f["paths"] = paths
        kb = exclusive_kb(rd, paths)
        if f["kind"] == "conda" and f["nominal"] is not None:
            kb = min(kb, f["nominal"])
        if f["kind"] == "dupdir" and f["nominal"] and kb < 0.25 * f["nominal"]:
            continue  # hard-linked twins: deleting one frees almost nothing
        if kb < MIN_REPORT_KB:
            continue
        f["kb"] = kb
        if f["kind"] == "dupfile":
            links = [(k, p) for k, p in f["links"] if p in kept[fi]]
            f["cmd"] = "\n".join(f"ln -f {q(k)} {q(p)}" for k, p in links)
            if len(links) > 1:
                f["show"] = [f["show"][0] + f"  ({len(links):,} files)"]
        if f["cmd"] is None:
            if f["kind"] == "dupfile":
                f["cmd"] = "\n".join(f"ln -sfn {q(f['keep'])} {q(p)}" for p in paths)
            else:
                f["cmd"] = "rm -rf " + " ".join(q(p) for p in paths)
        out.append(f)
    out.sort(key=lambda f: (f["tier"], -f["kb"]))
    return out


# ----------------------------------------------------------------------------- report

HOME = os.path.expanduser("~")


def disp(p):
    return "~" + p[len(HOME):] if within(p, HOME) else p


def emit_tree(rd, flags):
    def emit(d, depth):
        node = {"n": d.name, "s": d.kb}
        if d.path in flags:
            node["v"], node["t"] = flags[d.path]
        items = [(k.kb, False, k) for k in d.kids]
        for name, kb, size, mtime, ino, nlink in d.big:
            p = d.path + "/" + name
            if kb >= TILE_FILE_KB or p in flags:
                items.append((kb, True, (name, p)))
        items.sort(key=lambda x: -x[0])
        out, folded = [], 0
        for kb, isfile, obj in items:
            p = obj[1] if isfile else obj.path
            ok = kb >= MIN_TILE_KB or (p in flags and kb >= MIN_REPORT_KB)
            if depth < 14 and len(out) < MAX_TILES and ok:
                if isfile:
                    fn = {"n": obj[0], "s": kb, "f": 1}
                    if p in flags:
                        fn["v"], fn["t"] = flags[p]
                    out.append(fn)
                else:
                    out.append(emit(obj, depth + 1))
            else:
                folded += 1
        if out:
            rest = d.kb - sum(o["s"] for o in out)
            if rest > 0:
                out.append({"n": f"{folded:,} smaller items" if folded else "files in this folder",
                            "s": rest, "o": 1})
            node["c"] = out
        return node
    return emit(rd, 0)


def history_path():
    return os.path.join(os.path.expanduser("~/.local/share/diskaudit"), "history.jsonl")


def load_history(root):
    out = []
    try:
        with open(history_path()) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("root") == root:
                    out.append(e)
    except OSError:
        pass
    return out


def save_history(entry):
    p = history_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(entry) + "\n")


def write_report(path, data):
    blob = json.dumps(data, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")
    title = f"Disk audit {data['rootDisplay']} {data['date']}"
    page = TEMPLATE.replace("__TITLE__", title).replace("__DATA__", blob)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(page)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(prog="diskaudit", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Nothing is ever deleted: the report lists commands for you to run.")
    ap.add_argument("path", nargs="?", default=HOME, help="folder to scan (default: your home folder)")
    ap.add_argument("-o", "--out-dir", default=os.path.join(HOME, "disk-audit"),
                    help="where to write the HTML report (default: ~/disk-audit)")
    ap.add_argument("--quick", action="store_true", help="skip the byte-for-byte check of duplicate files")
    ap.add_argument("--no-open", action="store_true", help="don't open the report in a browser")
    ap.add_argument("-j", "--threads", type=int, default=8, help="parallel scan threads (default 8)")
    ap.add_argument("--version", action="version", version=f"diskaudit {__version__}")
    args = ap.parse_args()

    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        sys.exit(f"diskaudit: {root} is not a folder")
    tty = sys.stderr.isatty()
    sys.setrecursionlimit(20000)
    now = time.time()

    print(f"diskaudit: scanning {disp(root)} (Ctrl-C to stop)", file=sys.stderr)
    try:
        rd, ext, nfiles, errors, secs = scan(root, args.threads, tty)
    except KeyboardInterrupt:
        sys.exit("\ndiskaudit: stopped")

    vol = volume_info(root)
    trashes = find_trash(rd)
    homes = find_homes(rd)
    trash_paths = [t.path for t in trashes]
    # Never suggest deleting pieces of installed software (FreeSurfer, FSL, conda, ...).
    skip = trash_paths + sorted(install_roots(rd))
    try:
        cands = []
        cands += trash_findings(rd, trashes)
        cands += cache_findings(rd, homes)
        cands += dupdir_findings(rd, skip)
        cands += scratch_findings(rd, skip, now)
        cands += archive_findings(rd, skip)
        imgs = image_list(rd, trash_paths)
        cands += old_image_findings(imgs)
        # Files inside folders already suggested for deletion don't need hashing.
        covered = skip + [p for f in cands for p in f["paths"] if os.path.isdir(p)]
        cands += dupfile_findings(rd, covered, args.quick, tty)
        findings = resolve(rd, cands)
    except KeyboardInterrupt:
        sys.exit("\ndiskaudit: stopped")

    tiers = {1: 0, 2: 0, 3: 0}
    flags = {}
    for f in findings:
        tiers[f["tier"]] += f["kb"]
        for p in f["paths"]:
            flags[p] = (f["tier"], f"{f['title']}. {f['note']}")

    hist = load_history(root)
    prev = hist[-1] if hist else None
    entry = {"time": dt.datetime.fromtimestamp(now).isoformat(timespec="minutes"), "root": root,
             "kb": rd.kb, "files": nfiles, "avail": vol["avail"], "total": vol["total"],
             "flagged": [tiers[1], tiers[2], tiers[3]]}

    largest = sorted(((kb, path, mtime) for _, path, _, kb, _, mtime, _, _ in big_files(rd, [])),
                     reverse=True)[:25]
    old_img = {p for f in findings if f["kind"] == "image" for p in f["paths"]}
    data = {
        "root": root, "rootDisplay": disp(root), "version": __version__,
        "generated": dt.datetime.fromtimestamp(now).strftime("%-d %b %Y, %H:%M"),
        "date": dt.datetime.fromtimestamp(now).strftime("%Y-%m-%d"),
        "total": rd.kb, "files": nfiles, "errors": errors, "seconds": round(secs),
        "quick": args.quick, "volume": vol, "tiers": tiers,
        "findings": [{"tier": f["tier"], "title": f["title"],
                      "paths": f.get("show") or [disp(p) for p in f["paths"]],
                      "kb": f["kb"], "note": f["note"], "cmd": f["cmd"]} for f in findings],
        "tree": emit_tree(rd, flags),
        "ext": [{"e": k, "s": v[0] // 1024, "c": v[1]} for k, v in
                sorted(ext.items(), key=lambda kv: -kv[1][0])[:12]],
        "images": [{"p": disp(i["path"]), "kb": i["kb"], "m": day(i["mtime"]),
                    "old": i["path"] in old_img} for i in sorted(imgs, key=lambda i: -i["kb"])],
        "largest": [{"p": disp(p), "kb": kb, "m": day(m)} for kb, p, m in largest],
        "history": [{"t": e["time"], "kb": e["kb"], "avail": e.get("avail")} for e in hist + [entry]],
    }

    os.makedirs(args.out_dir, exist_ok=True)
    out = os.path.join(args.out_dir, f"diskaudit_{(os.path.basename(root) or 'root')}_"
                                     f"{dt.datetime.fromtimestamp(now).strftime('%Y-%m-%d_%H%M')}.html")
    write_report(out, data)
    save_history(entry)

    # ---- terminal summary
    tb = lambda b: f"{b / 1024 ** 4:.1f} TB"
    print(f"\n{disp(root)}  {fmt_kb(rd.kb)} in {nfiles:,} files  (scanned in {secs:.0f}s"
          + (f", {errors:,} unreadable entries skipped" if errors else "") + ")")
    if prev:
        delta = rd.kb - prev["kb"]
        when = day_iso(prev["time"][:10])
        print(f"  {'down' if delta < 0 else 'up'} {fmt_kb(abs(delta))} since the scan on {when}")
    denom = vol["used"] + vol["avail"]  # same formula as df's Use%
    pct_used = 100 * vol["used"] / denom if denom else 0
    print(f"Volume {vol['mount']}: {tb(vol['used'])} used of {tb(vol['total'])}, "
          f"{fmt_kb(vol['avail'] // 1024)} free ({pct_used:.0f}% full)")
    print("\nLargest folders")
    for k in sorted(rd.kids, key=lambda k: -k.kb)[:8]:
        print(f"  {fmt_kb(k.kb):>9}  {disp(k.path)}")
    print("\nCleanup suggestions (nothing has been deleted)")
    if not findings:
        print("  nothing obvious to clean up")
    for t in (1, 2, 3):
        fs = [f for f in findings if f["tier"] == t]
        if not fs:
            continue
        print(f"  {TIER_NAMES[t]:<20} {fmt_kb(tiers[t]):>9}")
        for f in fs[:8]:
            if f.get("show"):
                where = f["show"][0]
            else:
                where = disp(f["paths"][0]) + (f" (+{len(f['paths']) - 1} more)" if len(f["paths"]) > 1 else "")
            print(f"    {fmt_kb(f['kb']):>9}  {f['title']}: {where}")
        if len(fs) > 8:
            print(f"    ... and {len(fs) - 8} more in the report")
    print(f"\nReport: {out}")
    if not args.no_open and os.environ.get("DISPLAY"):
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.Popen([opener, out], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
/* One 1180px column: summary, a WinDirStat-style treemap with a synced folder table, then the tiered plan. */
:root {
  --bg: #f3f4f6; --panel: #fcfcfb; --ink: #111418; --ink-2: #4a5059; --muted: #747a83;
  --line: #dcdfe3; --frame: #e4e6ea; --focus: #1c5cab;
  --v1: #2a78d6; --v2: #eb6834; --v3: #1baf7a; --v0: #b9bec5; --tile-mix: 50%; --free: #d03b3b;
  --font-ui: system-ui, -apple-system, "Segoe UI", "Noto Sans", "DejaVu Sans", sans-serif;
  --font-mono: ui-monospace, "DejaVu Sans Mono", "Liberation Mono", Menlo, Consolas, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg: #0f1113; --panel: #17191c; --ink: #eef0f2; --ink-2: #b7bcc3; --muted: #8b9199;
  --line: #2b2f34; --frame: #22262b; --focus: #86b6ef;
  --v1: #3987e5; --v2: #d95926; --v3: #199e70; --v0: #4a5058; --tile-mix: 62%; --free: #e66767; color-scheme: dark; } }
:root[data-theme="dark"] {
  --bg: #0f1113; --panel: #17191c; --ink: #eef0f2; --ink-2: #b7bcc3; --muted: #8b9199;
  --line: #2b2f34; --frame: #22262b; --focus: #86b6ef;
  --v1: #3987e5; --v2: #d95926; --v3: #199e70; --v0: #4a5058; --tile-mix: 62%; --free: #e66767; color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--font-ui); font-size: 15px; line-height: 1.5;
  padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); padding-block: 28px 56px; }
[hidden] { display: none !important; }
.wrap { max-width: 1180px; margin: 0 auto; display: grid; gap: 36px; }
h1, h2, h3 { margin: 0; text-wrap: balance; font-weight: 600; letter-spacing: -0.01em; }
h1 { font-size: clamp(24px, 4vw, 32px); } h2 { font-size: 20px; } h3 { font-size: 16px; }
p { margin: 0; }
code, .mono { font-family: var(--font-mono); font-size: 0.86em; }
.muted { color: var(--muted); } .ink2 { color: var(--ink-2); }
section { display: grid; gap: 14px; min-width: 0; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
header { display: grid; gap: 18px; }
.title-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 16px; }
.headline { font-size: 17px; color: var(--ink-2); max-width: 75ch; }
.headline strong { color: var(--ink); font-weight: 600; }
.delta { font-size: 14px; color: var(--ink-2); }
.volume { padding: 16px 18px; display: grid; gap: 10px; }
.volume-top { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 16px; font-size: 14px; }
.volbar { display: flex; height: 14px; gap: 2px; border-radius: 4px; overflow: hidden; }
.volbar span { display: block; height: 100%; }
.vol-home { background: var(--ink); } .vol-other { background: var(--v0); }
.vol-res { background: repeating-linear-gradient(135deg, var(--v0) 0 3px, transparent 3px 6px); }
.vol-free { background: var(--free); min-width: 3px; }
.vol-legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 13px; color: var(--ink-2); }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; flex: none; }
.sw[data-v="1"] { background: var(--v1); } .sw[data-v="2"] { background: var(--v2); }
.sw[data-v="3"] { background: var(--v3); } .sw[data-v="0"] { background: var(--v0); }
.stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.stat { padding: 14px 16px; display: grid; gap: 4px; align-content: start; }
.stat .k { font-size: 13px; color: var(--ink-2); display: flex; align-items: center; }
.stat .val { font-size: 28px; font-weight: 600; letter-spacing: -0.02em; }
.stat .d { font-size: 13px; color: var(--muted); }
.stat.total { background: transparent; border-style: dashed; }
@media (max-width: 860px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 13px; color: var(--ink-2); }
.legend .sw { width: 12px; height: 12px; }
.crumbs { display: flex; flex-wrap: wrap; align-items: center; gap: 2px 4px; font-family: var(--font-mono); font-size: 13px; }
.crumbs button { font: inherit; color: var(--focus); background: none; border: 0; padding: 2px 4px; border-radius: 4px; cursor: pointer; }
.crumbs button:hover { background: var(--frame); }
.crumbs .here { color: var(--ink); padding: 2px 4px; font-weight: 500; }
.crumbs .sep { color: var(--muted); }
.tm-grid { display: grid; grid-template-columns: minmax(0, 1fr) 330px; gap: 14px; align-items: start; }
@media (max-width: 900px) { .tm-grid { grid-template-columns: minmax(0, 1fr); } }
.tm-box { position: relative; height: clamp(380px, 64vh, 640px); overflow: hidden; }
#tm { position: absolute; inset: 6px; }
.tm-el { position: absolute; overflow: hidden; border-radius: 3px; cursor: pointer; }
.tm-el:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; z-index: 5; }
.grp { background: var(--frame); }
.grp > .gl { position: absolute; left: 6px; right: 6px; top: 2px; height: 16px; font-size: 11.5px; font-weight: 600; color: var(--ink-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; line-height: 16px; }
.grp > .gl .gs { font-weight: 400; color: var(--muted); margin-left: 6px; }
.grp:hover { background: color-mix(in oklab, var(--frame) 80%, var(--ink)); }
.tile { padding: 4px 6px; font-size: 11.5px; line-height: 1.25; color: var(--ink); }
.tile[data-v="0"] { background: color-mix(in oklab, var(--v0) 45%, var(--panel)); }
.tile[data-v="1"] { background: color-mix(in oklab, var(--v1) var(--tile-mix), var(--panel)); }
.tile[data-v="2"] { background: color-mix(in oklab, var(--v2) var(--tile-mix), var(--panel)); }
.tile[data-v="3"] { background: color-mix(in oklab, var(--v3) var(--tile-mix), var(--panel)); }
.tile[data-o="1"] { background-image: repeating-linear-gradient(135deg, transparent 0 5px, color-mix(in oklab, var(--panel) 45%, transparent) 5px 7px); }
.tile:hover { filter: brightness(0.93); }
.tile .tn { display: block; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.tile .ts { display: block; color: var(--ink-2); white-space: nowrap; font-variant-numeric: tabular-nums; }
.tip { position: fixed; z-index: 50; pointer-events: none; max-width: min(380px, calc(100vw - 24px)); background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; box-shadow: 0 6px 24px rgba(0,0,0,0.18); font-size: 13px; display: grid; gap: 4px; }
.tip .tp { font-family: var(--font-mono); font-size: 12px; color: var(--ink-2); word-break: break-all; }
.tip .tz { font-size: 16px; font-weight: 600; }
.tip .tz span { font-weight: 400; color: var(--muted); font-size: 13px; margin-left: 6px; }
.chip { display: inline-flex; align-items: center; font-size: 12px; font-weight: 500; color: var(--ink-2); }
.hint { font-size: 13px; color: var(--muted); }
.ftable { overflow: hidden; }
.ftable .fh { padding: 10px 14px; border-bottom: 1px solid var(--line); font-size: 13px; color: var(--ink-2); display: flex; justify-content: space-between; gap: 8px; }
.ftable .scroll { max-height: clamp(320px, 58vh, 590px); overflow: auto; }
table { width: 100%; border-collapse: collapse; }
.ftable td { padding: 6px 14px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: middle; }
.ftable tr:last-child td { border-bottom: 0; }
.ftable td.n { font-family: var(--font-mono); font-size: 12.5px; word-break: break-all; }
.ftable td.s { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
.ftable td.p { width: 64px; padding-left: 0; }
.bar { height: 6px; border-radius: 3px; background: var(--ink-2); opacity: 0.55; }
.ftable tr.zoomable { cursor: pointer; }
.ftable tr.zoomable:hover td { background: var(--frame); }
.ftable tr.zoomable td.n { color: var(--focus); }
.tier { overflow: hidden; }
.tier-h { padding: 14px 16px; display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: baseline; gap: 4px 16px; border-bottom: 1px solid var(--line); }
.tier-h .tt { display: flex; align-items: center; gap: 8px; }
.tier-h .tt .sw { width: 12px; height: 12px; margin: 0; }
.tier-h .tsum { font-size: 22px; font-weight: 600; }
.tier-h .tdesc { grid-column: 1 / -1; font-size: 13.5px; color: var(--ink-2); max-width: 85ch; }
.row { display: grid; grid-template-columns: minmax(0, 1fr) 90px; gap: 6px 18px; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.row:last-child { border-bottom: 0; }
.row .main { display: grid; gap: 4px; min-width: 0; }
.row .rt { font-weight: 600; font-size: 14.5px; }
.row .rp { font-family: var(--font-mono); font-size: 12.5px; color: var(--ink-2); word-break: break-all; }
.row .rw { font-size: 13.5px; color: var(--ink-2); max-width: 85ch; }
.row .rs { text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; white-space: nowrap; }
.empty { padding: 14px 16px; color: var(--muted); font-size: 14px; }
.cmd { display: flex; align-items: stretch; margin-top: 6px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); min-width: 0; }
.cmd pre { margin: 0; padding: 8px 10px; font-family: var(--font-mono); font-size: 12px; line-height: 1.5; overflow: auto; max-height: 220px; flex: 1; min-width: 0; white-space: pre; }
.cmd button { font: 500 12px var(--font-ui); color: var(--ink-2); background: transparent; border: 0; border-left: 1px solid var(--line); padding: 0 12px; cursor: pointer; border-radius: 0 6px 6px 0; }
.cmd button:hover { background: var(--frame); color: var(--ink); }
button:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
.cols { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
@media (max-width: 860px) { .cols { grid-template-columns: minmax(0, 1fr); } }
.note { padding: 16px 18px; display: grid; gap: 10px; align-content: start; min-width: 0; }
.trow { display: grid; grid-template-columns: 82px minmax(0, 1fr) 70px; gap: 10px; align-items: center; font-size: 13px; }
.trow .te { font-family: var(--font-mono); font-size: 12.5px; }
.trow .tb { height: 8px; border-radius: 0 4px 4px 0; background: var(--ink-2); opacity: 0.6; }
.trow .tv { text-align: right; font-variant-numeric: tabular-nums; color: var(--ink-2); }
.list td { padding: 5px 0; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
.list tr:last-child td { border-bottom: 0; }
.list td.p { font-family: var(--font-mono); font-size: 12px; word-break: break-all; padding-right: 12px; }
.list td.s, .list td.d { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; padding-left: 10px; color: var(--ink-2); }
.list th { text-align: left; font-size: 12px; font-weight: 500; color: var(--muted); padding: 0 0 4px; }
.list th.r { text-align: right; }
footer { font-size: 13px; color: var(--muted); display: grid; gap: 6px; max-width: 95ch; }
@media (max-width: 520px) { .row { grid-template-columns: minmax(0, 1fr) auto; } .stat .val { font-size: 24px; } }
</style></head>
<body>
<div class="wrap">
  <header>
    <div class="title-row"><h1>Disk audit</h1><span class="mono muted" id="sub"></span></div>
    <p class="headline" id="headline"></p>
    <p class="delta" id="delta" hidden></p>
    <div class="panel volume" id="volume"></div>
    <div class="stats" id="stats"></div>
  </header>
  <section aria-labelledby="map-h">
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:6px 16px">
      <h2 id="map-h">Where the space goes</h2>
      <div class="legend"><span><span class="sw" data-v="1"></span>Safe to remove</span><span><span class="sw" data-v="2"></span>Check first</span><span><span class="sw" data-v="3"></span>Worth reviewing</span><span><span class="sw" data-v="0"></span>Not flagged</span></div>
    </div>
    <nav class="crumbs" id="crumbs" aria-label="Current folder"></nav>
    <div class="tm-grid">
      <div class="panel tm-box"><div id="tm" role="group" aria-label="Treemap of folder sizes"></div></div>
      <div class="panel ftable"><div class="fh"><span id="ft-title"></span><span id="ft-total" class="mono"></span></div>
        <div class="scroll"><table><tbody id="ft-body"></tbody></table></div></div>
    </div>
    <p class="hint">Area is disk usage. Click a folder to open it; click the path above or press Esc to go back. Folders under 0.5 GB are grouped into striped tiles.</p>
  </section>
  <section aria-labelledby="plan-h"><h2 id="plan-h">Cleanup plan</h2><div id="plan" style="display:grid;gap:14px"></div></section>
  <section aria-labelledby="ctx-h"><h2 id="ctx-h">Details</h2>
    <div class="cols">
      <div class="panel note"><h3>Disk usage by file type</h3><div id="types" style="display:grid;gap:7px"></div>
        <p class="muted" style="font-size:12.5px">Apparent size, Trash included.</p></div>
      <div class="panel note"><h3>History</h3><table class="list" id="hist"></table><p class="muted" style="font-size:12.5px" id="hist-note"></p></div>
      <div class="panel note"><h3>Container images</h3><table class="list" id="imgs"></table></div>
      <div class="panel note"><h3>Largest files</h3><table class="list" id="big"></table></div>
    </div>
    <div class="panel note" id="admin" hidden></div>
  </section>
  <footer id="foot"></footer>
</div>
<div class="tip" id="tip" hidden></div>
<script>
const D = __DATA__;
const GiB = 1048576;
const VL = { 0: "Not flagged", 1: "Safe to remove", 2: "Check first", 3: "Worth reviewing" };
const $ = id => document.getElementById(id);
function fmt(kb) {
  const g = kb / GiB;
  if (g >= 10000) return (g / 1024).toFixed(1) + " TB";
  if (g >= 100) return Math.round(g).toLocaleString("en-US") + " GB";
  if (g >= 1) return g.toFixed(1) + " GB";
  const m = kb / 1024; return (m >= 1 ? Math.round(m).toLocaleString("en-US") : "<1") + " MB";
}
const fmtB = b => fmt(b / 1024);
const tb = b => (b / 1024 ** 4).toFixed(1) + " TB";
function pct(a, b) { if (!b) return "0%"; const p = 100 * a / b; return p >= 10 ? Math.round(p) + "%" : p.toFixed(1) + "%"; }
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function dateOf(iso) { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }); }

/* ---- header ---- */
const T = D.tiers, ALL = T[1] + T[2] + T[3];
$("sub").textContent = D.rootDisplay + " · " + D.generated;
let h = `${esc(D.rootDisplay)} uses <strong>${fmt(D.total)}</strong> in ${D.files.toLocaleString("en-US")} files.`;
if (ALL === 0) h += " Nothing obvious to clean up.";
else {
  h += T[1] ? ` About <strong>${fmt(T[1])}</strong> can go right away` : " Nothing is safe to delete outright";
  h += ALL > T[1] ? `, and up to <strong>${fmt(ALL)}</strong> (${pct(ALL, D.total)}) if you sign off on the rest of the plan.` : ".";
}
$("headline").innerHTML = h;
if (D.history.length > 1) {
  const p = D.history[D.history.length - 2], dlt = D.total - p.kb;
  $("delta").hidden = false;
  $("delta").textContent = `${dlt < 0 ? "Down" : "Up"} ${fmt(Math.abs(dlt))} since the scan on ${dateOf(p.t)}.`;
}
(function volume() {
  const v = D.volume, mine = Math.min(D.total * 1024, v.used), other = Math.max(0, v.used - mine);
  const full = v.total ? Math.round(100 * v.used / (v.used + v.avail)) : 0;
  const seg = (cls, val) => `<span class="${cls}" style="flex:${Math.max(val / 2 ** 30, 0.0001)}"></span>`;
  $("volume").innerHTML = `
    <div class="volume-top"><span><strong>${esc(v.mount)} is ${full}% full.</strong> <span class="ink2">${tb(v.used)} used of ${tb(v.total)}, ${fmtB(v.avail)} free to users.</span></span>
      <span class="muted">${esc(v.fstype)} · ${esc(v.device)}</span></div>
    <div class="volbar" role="img" aria-label="Volume usage">${seg("vol-home", mine)}${seg("vol-other", other)}${v.reserved > 0 ? seg("vol-res", v.reserved) : ""}${seg("vol-free", v.avail)}</div>
    <div class="vol-legend"><span><span class="sw vol-home"></span>This scan ${fmtB(mine)} (${pct(mine, v.used)} of used space)</span>
      <span><span class="sw vol-other"></span>Everything else ${tb(other)}</span>
      ${v.reserved > 0 ? `<span><span class="sw vol-res"></span>Reserved for root ${tb(v.reserved)}</span>` : ""}
      <span><span class="sw vol-free"></span>Free ${fmtB(v.avail)}</span></div>`;
  if (v.fstype.startsWith("ext") && v.reserved > 0.01 * v.total) {
    $("admin").hidden = false;
    const gain = v.reserved - 0.01 * v.total;
    $("admin").innerHTML = `<h3>For whoever runs the server</h3><p class="ink2" style="font-size:14px">${esc(v.mount)} is ${esc(v.fstype)} with ${tb(v.reserved)} reserved for root. On a data-only volume, lowering the reserve with <code>tune2fs -m 1 ${esc(v.device)}</code> would make about ${tb(gain)} usable. That needs root and is a decision for the lab.</p>`;
  }
})();
$("stats").innerHTML = [
  [1, "Safe to remove now", "Trash, caches and byte-identical copies"],
  [2, "Check first", "Duplicated folders and pipeline outputs"],
  [3, "Worth reviewing", "Scratch, unpacked archives, installers, old images"],
].map(([k, n, d]) => `<div class="panel stat"><span class="k"><span class="sw" data-v="${k}"></span>${n}</span><span class="val">${fmt(T[k])}</span><span class="d">${d}</span></div>`).join("")
  + `<div class="panel stat total"><span class="k">All three together</span><span class="val">${fmt(ALL)}</span><span class="d">${pct(ALL, D.total)} of this folder</span></div>`;

/* ---- treemap ---- */
const root = D.tree;
(function link(n, parent) {
  n.p = parent || null;
  n.path = parent ? parent.path + "/" + n.n : D.rootDisplay;
  n.iv = n.v || (parent ? parent.iv : 0);
  if (n.c) n.c.forEach(k => link(k, n));
})(root, null);
function worst(row, side) {
  let s = 0, mx = 0, mn = Infinity;
  for (const r of row) { s += r.a; if (r.a > mx) mx = r.a; if (r.a < mn) mn = r.a; }
  return Math.max(side * side * mx / (s * s), (s * s) / (side * side * mn));
}
function squarify(nodes, rect) {
  const out = []; let { x, y, w, h } = rect;
  const items = nodes.filter(n => n.s > 0), total = items.reduce((a, n) => a + n.s, 0);
  if (!total || w <= 0 || h <= 0) return out;
  const scale = (w * h) / total, q = items.map(n => ({ n, a: n.s * scale }));
  let row = [];
  function place(row) {
    const s = row.reduce((a, r) => a + r.a, 0);
    if (w >= h) { const cw = s / h; let cy = y; for (const r of row) { const rh = r.a / cw; out.push({ n: r.n, x, y: cy, w: cw, h: rh }); cy += rh; } x += cw; w -= cw; }
    else { const rh = s / w; let cx = x; for (const r of row) { const rw = r.a / rh; out.push({ n: r.n, x: cx, y, w: rw, h: rh }); cx += rw; } y += rh; h -= rh; }
  }
  while (q.length) {
    const side = Math.min(w, h), c = q[0];
    if (!row.length || worst(row.concat([c]), side) <= worst(row, side)) { row.push(c); q.shift(); }
    else { place(row); row = []; }
  }
  if (row.length) place(row);
  return out;
}
const tm = $("tm"), tip = $("tip"), els = [];
let current = root;
function draw(n, r, depth) {
  const x = r.x + 1, y = r.y + 1, w = r.w - 2, h = r.h - 2;
  if (w < 1 || h < 1) return;
  const el = document.createElement("div");
  el.className = "tm-el"; el.style.cssText = `left:${x}px;top:${y}px;width:${w}px;height:${h}px`;
  el.dataset.i = els.length; els.push(n);
  if (depth === 1) { el.tabIndex = 0; el.setAttribute("role", "button"); el.setAttribute("aria-label", `${n.n}, ${fmt(n.s)}, ${VL[n.iv]}`); }
  if (n.c && depth <= 3 && w > 72 && h > 48) {
    el.classList.add("grp");
    el.innerHTML = `<div class="gl">${esc(n.n)}<span class="gs">${fmt(n.s)}</span></div>`;
    tm.appendChild(el);
    for (const k of squarify(n.c, { x: x + 2, y: y + 19, w: w - 4, h: h - 21 })) draw(k.n, k, depth + 1);
  } else {
    el.classList.add("tile"); el.dataset.v = n.iv; if (n.o) el.dataset.o = 1;
    if (w > 46 && h > 22) el.innerHTML = `<span class="tn">${esc(n.n)}</span>` + (h > 36 ? `<span class="ts">${fmt(n.s)}</span>` : "");
    tm.appendChild(el);
  }
}
function render() {
  tm.innerHTML = ""; els.length = 0; tip.hidden = true;
  for (const k of squarify(current.c || [current], { x: 0, y: 0, w: tm.clientWidth, h: tm.clientHeight })) draw(k.n, k, 1);
  const c = $("crumbs"), chain = []; for (let n = current; n; n = n.p) chain.unshift(n);
  c.innerHTML = "";
  chain.forEach((n, i) => {
    if (i) { const s = document.createElement("span"); s.className = "sep"; s.textContent = "/"; c.appendChild(s); }
    const label = i === 0 ? D.rootDisplay : n.n;
    if (n === current) { const s = document.createElement("span"); s.className = "here"; s.textContent = label + "  " + fmt(n.s); c.appendChild(s); }
    else { const b = document.createElement("button"); b.type = "button"; b.textContent = label; b.onclick = () => zoom(n); c.appendChild(b); }
  });
  $("ft-title").textContent = current === root ? D.rootDisplay : current.n;
  $("ft-total").textContent = fmt(current.s);
  const kids = (current.c || []).slice().sort((a, b) => b.s - a.s), mx = kids.length ? kids[0].s : 1, body = $("ft-body");
  body.innerHTML = kids.map((k, i) => `<tr class="${k.c ? "zoomable" : ""}" data-k="${i}" ${k.c ? 'tabindex="0"' : ""}>
    <td class="n"><span class="sw" data-v="${k.iv}" title="${VL[k.iv]}"></span>${esc(k.n)}${k.c ? "/" : ""}</td>
    <td class="p"><div class="bar" style="width:${Math.max(2, 100 * k.s / mx)}%"></div></td><td class="s">${fmt(k.s)}</td></tr>`).join("");
  body.querySelectorAll("tr").forEach(tr => {
    const k = kids[+tr.dataset.k]; if (!k.c) return;
    tr.onclick = () => zoom(k);
    tr.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); zoom(k); } };
  });
}
function zoom(n) { if (n && n.c) { current = n; render(); } }
const target = n => n.c ? n : (n.p && n.p !== current ? n.p : null);
function showTip(n, cx, cy) {
  const note = n.o ? "Loose files and folders under 0.5 GB, grouped." : (n.t || "");
  tip.innerHTML = `<div class="tp">${esc(n.o ? n.p.path + "/…" : n.path)}</div>
    <div class="tz">${fmt(n.s)}<span>${pct(n.s, root.s)} of this scan</span></div>
    <div class="chip"><span class="sw" data-v="${n.iv}"></span>${VL[n.iv]}</div>${note ? `<div class="ink2">${esc(note)}</div>` : ""}`;
  tip.hidden = false;
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  let x = cx + 14, y = cy + 14;
  if (x + tw > innerWidth - 8) x = Math.max(8, cx - tw - 14);
  if (y + th > innerHeight - 8) y = Math.max(8, cy - th - 14);
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const nodeOf = e => { const el = e.target.closest(".tm-el"); return el ? els[+el.dataset.i] : null; };
tm.addEventListener("mousemove", e => { const n = nodeOf(e); n ? showTip(n, e.clientX, e.clientY) : (tip.hidden = true); });
tm.addEventListener("mouseleave", () => tip.hidden = true);
tm.addEventListener("click", e => { const n = nodeOf(e); if (n) zoom(target(n)); });
tm.addEventListener("focusin", e => { const n = nodeOf(e); if (n) { const r = e.target.getBoundingClientRect(); showTip(n, r.left + 8, r.top + 8); } });
tm.addEventListener("focusout", () => tip.hidden = true);
tm.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { const n = nodeOf(e); if (n) { e.preventDefault(); zoom(target(n)); } } });
document.addEventListener("keydown", e => { if (e.key === "Escape" && current.p) zoom(current.p); });
let rt; new ResizeObserver(() => { clearTimeout(rt); rt = setTimeout(render, 80); }).observe(tm);
render();

/* ---- plan ---- */
const TIERS = [
  [1, "Safe to remove now", "Things you already deleted, caches that refill themselves, and byte-identical copies."],
  [2, "Check first", "Duplicates you can remove or hard-link once you've confirmed which copy you use: duplicated folders, identical files shared by pipeline outputs, or Trash holding items from outside your folder."],
  [3, "Worth reviewing", "Pipeline scratch, archives already unpacked, installers and older container images. Not guaranteed to exist elsewhere: copy off anything you want to keep."],
];
$("plan").innerHTML = TIERS.map(([k, name, desc]) => {
  const fs = D.findings.filter(f => f.tier === k);
  const rows = fs.map(f => {
    const shown = f.paths.slice(0, 6).map(esc).join("<br>") + (f.paths.length > 6 ? `<br>+${f.paths.length - 6} more` : "");
    return `<div class="row"><div class="main"><span class="rt">${esc(f.title)}</span><span class="rp">${shown}</span>
      <p class="rw">${esc(f.note)}</p><div class="cmd"><pre>${esc(f.cmd)}</pre><button type="button">Copy</button></div></div>
      <span class="rs">${fmt(f.kb)}</span></div>`;
  }).join("");
  return `<div class="panel tier"><div class="tier-h"><span class="tt"><span class="sw" data-v="${k}"></span><h3>${name}</h3></span>
    <span class="tsum">${fmt(T[k])}</span><p class="tdesc">${desc}</p></div>${rows || '<p class="empty">Nothing found.</p>'}</div>`;
}).join("");
document.querySelectorAll(".cmd button").forEach(b => b.addEventListener("click", () => {
  const pre = b.parentElement.querySelector("pre");
  const done = t => { b.textContent = t; setTimeout(() => b.textContent = "Copy", 1500); };
  const sel = () => { const r = document.createRange(); r.selectNodeContents(pre); const s = getSelection(); s.removeAllRanges(); s.addRange(r); done("Selected"); };
  try { navigator.clipboard.writeText(pre.textContent).then(() => done("Copied"), sel); } catch (e) { sel(); }
}));

/* ---- details ---- */
const mxe = D.ext.length ? D.ext[0].s : 1;
$("types").innerHTML = D.ext.slice(0, 10).map(e => `<div class="trow"><span class="te">${esc(e.e)}</span><div><div class="tb" style="width:${Math.max(1, 100 * e.s / mxe)}%"></div></div><span class="tv">${fmt(e.s)}</span></div>`).join("");
$("hist").innerHTML = `<tr><th>Scan</th><th class="r">Size</th><th class="r">Change</th><th class="r">Volume free</th></tr>` +
  D.history.slice(-12).map((e, i, a) => {
    const prev = i ? a[i - 1] : (D.history.length > a.length ? D.history[D.history.length - a.length - 1] : null);
    const ch = prev ? e.kb - prev.kb : null;
    return `<tr><td>${esc(dateOf(e.t))}</td><td class="s">${fmt(e.kb)}</td><td class="s">${ch === null ? "" : (ch < 0 ? "−" : "+") + fmt(Math.abs(ch))}</td><td class="s">${e.avail != null ? fmtB(e.avail) : ""}</td></tr>`;
  }).join("");
$("hist-note").textContent = D.history.length < 2 ? "Run diskaudit again later to see changes over time." : "";
$("imgs").innerHTML = D.images.length
  ? `<tr><th>Image</th><th class="r">Size</th><th class="r">Modified</th></tr>` + D.images.slice(0, 20).map(i => `<tr><td class="p">${i.old ? '<span class="sw" data-v="3" title="Older version"></span>' : ""}${esc(i.p)}</td><td class="s">${fmt(i.kb)}</td><td class="d">${esc(i.m)}</td></tr>`).join("")
  : `<tr><td class="muted">No Apptainer/Singularity images found.</td></tr>`;
$("big").innerHTML = `<tr><th>File</th><th class="r">Size</th><th class="r">Modified</th></tr>` + D.largest.map(f => `<tr><td class="p">${esc(f.p)}</td><td class="s">${fmt(f.kb)}</td><td class="d">${esc(f.m)}</td></tr>`).join("");
$("foot").innerHTML = `<p>diskaudit ${esc(D.version)} scanned ${esc(D.root)} in ${D.seconds}s, staying on one filesystem like <code>du -x</code>. Sizes are disk usage in binary units (1 GB = 1024³ bytes); hard-linked files count once, and each suggestion's size is what deleting it would actually free.${D.errors ? ` ${D.errors.toLocaleString("en-US")} entries could not be read (permissions).` : ""} Duplicate files were ${D.quick ? "matched by size and first/last megabyte only (--quick)" : "compared byte for byte"}; duplicate folders are matched by file names and sizes. Nothing was deleted.</p>`;
</script>
</body></html>
"""

if __name__ == "__main__":
    main()
