#!/usr/bin/env python3
"""
verify-recovered.py
===================
Integrity sweep for files recovered by lockbit-rescue.py (or any other tool).

For every file under the given roots, runs `file -b` (libmagic) and classifies
the result as:
  - GOOD     : libmagic recognized a sane file type matching its extension
  - MISMATCH : recognized a sane type but disagreeing with the extension
              (usually means the original file was user-renamed before encryption)
  - SUSPECT  : libmagic returned raw "data", "empty", or "corrupted"
              (this is the signal of a botched decryption)

Usage:
  python3 verify-recovered.py /path/to/recovered [/another/path ...]
"""

import argparse
import collections
import os
import subprocess
import sys
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: tqdm not installed. Run: pip install tqdm")
    sys.exit(1)

# libmagic family -> set of extensions that are "expected" for that family
FAMILY_EXT = {
    "JPEG":   {"jpg", "jpeg"},
    "PNG":    {"png"},
    "GIF":    {"gif"},
    "TIFF":   {"tif", "tiff", "arw", "cr2", "nef"},
    "BMP":    {"bmp"},
    "WebP":   {"webp"},
    "PDF":    {"pdf", "ai"},
    "PostScript": {"ps", "eps"},
    "Microsoft Word":       {"doc", "docx"},
    "Microsoft Excel":      {"xls", "xlsx"},
    "Microsoft PowerPoint": {"ppt", "pptx"},
    "OpenDocument":         {"odt", "ods", "odp"},
    "Composite Document File": {"doc", "xls", "ppt", "msi", "msg", "db"},
    "Rich Text Format":     {"rtf"},
    "Zip archive":          {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp",
                             "epub", "jar", "apk"},
    "RAR archive":          {"rar"},
    "7-zip archive":        {"7z"},
    "gzip compressed":      {"gz", "tgz"},
    "bzip2 compressed":     {"bz2"},
    "XZ compressed":        {"xz"},
    "POSIX tar":            {"tar"},
    "MP4":             {"mp4", "m4v", "mov"},
    "ISO Media":       {"mp4", "m4v", "mov", "heic", "m4a"},
    "Matroska":        {"mkv", "webm"},
    "AVI":             {"avi"},
    "RIFF":            {"avi", "wav", "webp"},
    "MPEG":            {"mp3", "mp2", "mpeg", "mpg"},
    "Audio file with ID3": {"mp3"},
    "FLAC audio":      {"flac"},
    "Ogg":             {"ogg", "oga"},
    "WAVE audio":      {"wav"},
    "MS Windows":      {"exe", "dll", "sys", "msi"},
    "HTML":            {"html", "htm"},
    "XML":             {"xml", "svg", "docx", "xlsx", "pptx"},
    "JSON":            {"json"},
    "ASCII text":      {"txt", "md", "csv", "log", "xml", "json", "htm", "html",
                         "rtf"},
    "UTF-8":           {"txt", "md", "csv", "xml", "json", "htm", "html"},
    "Unicode text":    {"txt", "md", "csv"},
    "Photoshop":       {"psd"},
    "SQLite":          {"db", "sqlite", "sqlite3"},
    "EPUB":            {"epub"},
    "Mobipocket":      {"mobi", "azw3"},
}


def classify(ftype: str, ext: str):
    f = (ftype or "").strip()
    if not f or f.lower() == "empty":
        return "SUSPECT", "empty"
    fl = f.lower()
    if fl == "data" or fl.startswith("data,") or "corrupted" in fl:
        return "SUSPECT", f
    # libmagic output reliably starts with the format name. Anchor the match
    # at the beginning so that, e.g., 'SQLite ... UTF-8 ...' isn't wrongly
    # attributed to the UTF-8 family.
    for fam, exts in FAMILY_EXT.items():
        if fl.startswith(fam.lower()):
            if ext in exts:
                return "GOOD", fam
            return "MISMATCH", f"{fam} but ext .{ext}"
    return "GOOD", f.split(",")[0]


def root_for(path: str, roots):
    """Return the root in `roots` that is an exact ancestor of `path`."""
    p = Path(path).resolve()
    best = None
    for r in roots:
        try:
            p.relative_to(r)
        except ValueError:
            continue
        if best is None or len(str(r)) > len(str(best)):
            best = r
    return best


def main():
    ap = argparse.ArgumentParser(description="Verify integrity of recovered files")
    ap.add_argument("roots", nargs="+", help="Directories to scan")
    ap.add_argument("--max-suspect-samples", type=int, default=50)
    ap.add_argument("--max-mismatch-samples", type=int, default=50)
    args = ap.parse_args()

    roots = [Path(r).resolve() for r in args.roots]
    for r in roots:
        if not r.is_dir():
            print(f"ERROR: not a directory: {r}")
            sys.exit(2)

    all_files = []
    for r in roots:
        for dirpath, _, files in os.walk(r):
            for fn in files:
                all_files.append(os.path.join(dirpath, fn))
    print(f"[*] Found {len(all_files)} files. Classifying...")

    results = collections.Counter()
    by_ext = collections.defaultdict(collections.Counter)
    by_root = collections.defaultdict(collections.Counter)
    suspect_samples, mismatch_samples = [], []

    BATCH = 200
    for i in tqdm(range(0, len(all_files), BATCH), unit="batch"):
        batch = all_files[i:i + BATCH]
        try:
            out = subprocess.check_output(
                ["file", "-b", "--"] + batch, stderr=subprocess.DEVNULL
            ).decode("utf-8", "ignore").splitlines()
        except subprocess.CalledProcessError as e:
            out = (e.output or b"").decode("utf-8", "ignore").splitlines()

        if len(out) != len(batch):
            # libmagic glitched on this batch — fall back to per-file
            for p in batch:
                try:
                    ft = subprocess.check_output(
                        ["file", "-b", p], stderr=subprocess.DEVNULL
                    ).decode(errors="ignore").strip()
                except Exception:
                    ft = "data"
                ext = p.rsplit(".", 1)[-1].lower() if "." in os.path.basename(p) else ""
                cls, _ = classify(ft, ext)
                results[cls] += 1
                by_ext[ext][cls] += 1
                rt = root_for(p, roots)
                if rt is not None:
                    by_root[str(rt)][cls] += 1
                if cls == "SUSPECT" and len(suspect_samples) < args.max_suspect_samples:
                    suspect_samples.append((p, ft))
                if cls == "MISMATCH" and len(mismatch_samples) < args.max_mismatch_samples:
                    mismatch_samples.append((p, ft))
            continue

        for p, ft in zip(batch, out):
            ext = p.rsplit(".", 1)[-1].lower() if "." in os.path.basename(p) else ""
            cls, _ = classify(ft, ext)
            results[cls] += 1
            by_ext[ext][cls] += 1
            rt = root_for(p, roots)
            if rt is not None:
                by_root[str(rt)][cls] += 1
            if cls == "SUSPECT" and len(suspect_samples) < args.max_suspect_samples:
                suspect_samples.append((p, ft))
            if cls == "MISMATCH" and len(mismatch_samples) < args.max_mismatch_samples:
                mismatch_samples.append((p, ft))

    total = sum(results.values())
    print()
    print("============ INTEGRITY REPORT ============")
    print(f"Total recovered files scanned: {total}")
    for cls in ("GOOD", "MISMATCH", "SUSPECT"):
        c = results.get(cls, 0)
        pct = (c * 100.0 / total) if total else 0
        print(f"  {cls:9s}: {c:6d}   ({pct:5.1f}%)")

    print("\n--- Per-source breakdown ---")
    for root, cnt in by_root.items():
        tot_r = sum(cnt.values())
        print(f"  {root}: {tot_r} files")
        for cls in ("GOOD", "MISMATCH", "SUSPECT"):
            c = cnt.get(cls, 0)
            pct = (c * 100.0 / tot_r) if tot_r else 0
            print(f"      {cls:9s}: {c:6d}  ({pct:5.1f}%)")

    print("\n--- Per-extension breakdown (top 25) ---")
    ext_totals = sorted(by_ext.items(), key=lambda x: -sum(x[1].values()))[:25]
    print(f'  {"ext":10s} {"total":>8s} {"good":>8s} {"mismatch":>10s} {"suspect":>10s}')
    for ext, cnt in ext_totals:
        tot = sum(cnt.values())
        print(f"  {ext:10s} {tot:8d} {cnt.get('GOOD',0):8d} "
              f"{cnt.get('MISMATCH',0):10d} {cnt.get('SUSPECT',0):10d}")

    if suspect_samples:
        print(f"\n--- Suspect samples (up to {args.max_suspect_samples}) ---")
        for p, ft in suspect_samples:
            print(f"  [{ft[:55]:55s}] {p}")
    if mismatch_samples:
        print(f"\n--- Mismatch samples (up to {args.max_mismatch_samples}) ---")
        for p, ft in mismatch_samples:
            print(f"  [{ft[:60]:60s}] {p}")


if __name__ == "__main__":
    main()
