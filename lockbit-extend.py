#!/usr/bin/env python3
"""
lockbit-extend.py -- Phase 11 automation.
=========================================
After `lockbit-rescue.py` finishes its main flow, the files in oracle-having
batches whose `fei_len` exceeds the oracle's natural coverage (~106 bytes)
remain unrecovered. This tool extends the keystream byte-by-byte across each
batch, climbing the ladder of fei_lens via known-plaintext brute force, and
decrypts each newly-unlocked file's body using its recovered file_encryption_key.

Pipeline per batch:
  1. Scan all files, find longest-named (= longest fei_len) as oracle.
  2. Sort batch files by fei_len ascending.
  3. For each non-oracle file, run brute_extend3 with the accumulated
     keystream extension. If gap <= --max-brute-bytes, brute-force succeeds
     and yields the file's `file_encryption_key`. The newly-discovered
     keystream bytes are appended to the running extension for the next
     iteration.
  4. Run direct-decrypt with that FEK to recover the file body.
  5. Verify with libmagic and save under OUTPUT/group_<kek>/<basename>.

Resume-aware: skips files already in OUTPUT.

Requires:
  - brute-extend (build of brute_extend3.c)
  - direct-decrypt (build of direct_decrypt.c)
  - stream-reuse (build of stream-reuse.c) -- only used as a fallback
  - Python `tqdm`
"""
import argparse
import collections
import hashlib
import os
import re
import struct
import subprocess
import sys
import time
import shutil
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: tqdm not installed. Run: pip install tqdm")
    sys.exit(1)

RANSOM_EXT_DEFAULT = ".MoHsVxKYI"  # auto-detected from source if not provided

# Magic byte signatures for known-plaintext brute force validation.
# Use ≥7 byte magics to make false positives ~2^-56 per trial (negligible).
# Keys are lowercase extensions (after stripping the ransomware ext).
MAGIC_DB = {
    # Images
    "jpg":  ["ffd8ffe000104a464946", "ffd8ffe100", "ffd8ffdb", "ffd8ffe2", "ffd8ffe800"],
    "jpeg": ["ffd8ffe000104a464946", "ffd8ffe100", "ffd8ffdb"],
    "png":  ["89504e470d0a1a0a"],
    "gif":  ["474946383961", "474946383761"],
    "bmp":  ["424d", None],   # too short alone; pair with width/height
    "tif":  ["49492a00", "4d4d002a"],
    "tiff": ["49492a00", "4d4d002a"],
    "webp": ["52494646", None],  # RIFF + WEBP later; loose
    # Documents
    "pdf":  ["25504446 2d 31 2e"],   # %PDF-1.
    "doc":  ["d0cf11e0a1b11ae1"],     # Composite Document
    "xls":  ["d0cf11e0a1b11ae1"],
    "ppt":  ["d0cf11e0a1b11ae1"],
    "msi":  ["d0cf11e0a1b11ae1"],
    "msg":  ["d0cf11e0a1b11ae1"],
    "docx": ["504b0304140006"],
    "xlsx": ["504b0304140006"],
    "pptx": ["504b0304140006"],
    "odt":  ["504b0304"],
    "ods":  ["504b0304"],
    "odp":  ["504b0304"],
    "rtf":  ["7b5c727466 31"],          # {\rtf1
    "txt":  None,                       # no reliable magic, skip
    # Archives
    "zip":  ["504b0304", "504b0506"],
    "rar":  ["526172211a07"],
    "7z":   ["377abcaf271c"],
    "gz":   ["1f8b08"],
    "bz2":  ["425a68"],
    "xz":   ["fd377a585a 00"],
    # Video
    "mp4":  ["00000018 66747970", "00000020 66747970"],   # ftyp at offset 4
    "mov":  ["00000014 66747970", "00000020 66747970"],
    "m4v":  ["00000020 66747970"],
    "mkv":  ["1a45dfa3"],
    "webm": ["1a45dfa3"],
    "avi":  ["52494646", None],          # RIFF... AVI -- weak
    # Audio
    "mp3":  ["49443304", "fffb"],
    "wav":  ["52494646"],
    "flac": ["664c6143"],
    "ogg":  ["4f676753"],
    "m4a":  ["00000020 66747970 4d3441"],
    # Design / misc
    "psd":  ["38425053"],
    "ai":   ["25504446 2d 31"],           # AI is PDF under the hood
    "html": ["3c21444f43545950 45", "3c68746d 6c", "3c4854 4d4c"],
    "htm":  ["3c21444f43545950 45", "3c68746d 6c"],
    "xml":  ["3c3f786d6c"],
    "json": None,
    "epub": ["504b0304"],
    "db":   ["53514c69746520666f726d6174"],  # SQLite format 3
    "sqlite": ["53514c69746520666f726d6174"],
}


def hex_clean(h):
    return h.replace(" ", "").replace(":", "").lower()


def kek_fingerprint(blob: bytes) -> str:
    return hashlib.md5(blob).hexdigest()[:12]


def read_footer_meta(path: Path):
    """Return (fei_len, kek_md5_short) by reading the 134-byte footer."""
    with open(path, "rb") as f:
        f.seek(-134, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-128, 2)
        kek = f.read(128)
    return fei_len, kek_fingerprint(kek)


def detect_extension(source: Path, sample_limit: int = 5000) -> str:
    counts = collections.Counter()
    seen = 0
    for dirpath, _, files in os.walk(source):
        for fn in files:
            if "." not in fn:
                continue
            ext = "." + fn.rsplit(".", 1)[-1]
            if len(ext) == 10 and ext[1:].isalnum() and not ext[1:].isdigit():
                counts[ext] += 1
                seen += 1
                if seen >= sample_limit:
                    break
        if seen >= sample_limit:
            break
    return counts.most_common(1)[0][0] if counts else ""


def scan_batches(source: Path, ransom_ext: str):
    """Walk source; group encrypted files by KEK fingerprint."""
    groups = collections.defaultdict(list)
    scanned = 0
    bar = tqdm(desc="Scanning", unit="file", mininterval=0.5)
    for dirpath, _, files in os.walk(source):
        if "RECOVERED" in dirpath:
            continue
        for fn in files:
            if not fn.endswith(ransom_ext):
                continue
            scanned += 1
            bar.update(1)
            p = Path(dirpath) / fn
            try:
                fei_len, kek = read_footer_meta(p)
                sz = os.path.getsize(p)
                groups[kek].append((fei_len, fn, str(p), sz))
            except (OSError, struct.error):
                continue
    bar.close()
    return groups, scanned


def file_ext(fname: str, ransom_ext: str) -> str:
    base = fname[: -len(ransom_ext)]
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[-1].lower()


def parse_brute(stdout: str):
    out = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def libmagic(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["file", "-b", str(path)], stderr=subprocess.DEVNULL, timeout=10
        ).decode(errors="ignore").strip()
    except Exception:
        return "unknown"


def is_bad(ftype: str) -> bool:
    f = (ftype or "").lower()
    return (f.startswith("data") or "corrupted" in f or f in ("", "empty"))


def fmt_size(b: int) -> str:
    for u in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}TB"


def process_batch(kek, files, output_root, scratch_root, brute_bin, direct_bin,
                  ransom_ext, max_brute_bytes, before_chunk, after_chunk,
                  skipped_hex, brute_timeout):
    """Climb the fei_len ladder for one batch."""
    # Stage all files locally so we don't hammer NAS reads
    # Actually: stage just oracle + each target on demand
    files = list(files)
    files.sort(key=lambda x: x[0])  # ascending by fei_len
    oracle_fei, oracle_fname, oracle_path, oracle_sz = files[-1]  # longest fei
    oracle_orig = oracle_fname[: -len(ransom_ext)]
    print(f"\n[batch {kek}]  oracle=\"{oracle_orig[:60]}\"  fei_len={oracle_fei}  ({len(files)} files)")

    # Stage oracle locally if it's on a slow filesystem
    scratch = scratch_root / f"batch_{kek}"
    scratch.mkdir(parents=True, exist_ok=True)
    local_oracle = scratch / f"_oracle{ransom_ext}"
    try:
        shutil.copy2(oracle_path, local_oracle)
    except Exception as e:
        print(f"  [!] oracle copy failed: {e}")
        return 0, 0

    group_out = output_root / f"group_{kek}"
    group_out.mkdir(parents=True, exist_ok=True)

    ks_extend_hex = ""  # accumulated keystream bytes past the 106-byte baseline
    ok = fail = skipped = 0

    targets = [t for t in files if t != files[-1]]  # everything except oracle
    bar = tqdm(targets, desc=f"  {kek}", unit="file", leave=False, mininterval=0.3)

    for (fei_len, fname, path, sz) in bar:
        orig = fname[: -len(ransom_ext)]
        out_path = group_out / orig
        short = (orig[:40] + "...") if len(orig) > 40 else orig
        bar.set_postfix({"cur": short, "fei": fei_len, "ok": ok, "fail": fail, "skip": skipped})

        if out_path.exists():
            ok += 1  # already recovered
            continue

        ext = file_ext(fname, ransom_ext)
        magics = MAGIC_DB.get(ext)
        if magics is None:
            skipped += 1
            continue

        # Stage target locally
        local_target = scratch / f"_target_{fei_len}{ransom_ext}"
        try:
            shutil.copy2(path, local_target)
        except Exception:
            fail += 1
            continue

        # Try each magic for this extension type until one works
        result = None
        used_magic = None
        for m in magics:
            if m is None:
                continue
            mhex = hex_clean(m)
            try:
                p = subprocess.run(
                    [str(brute_bin), str(local_target), str(local_oracle), oracle_orig,
                     mhex, str(max_brute_bytes),
                     str(before_chunk), str(after_chunk), skipped_hex,
                     ks_extend_hex],
                    capture_output=True, timeout=brute_timeout, text=True,
                )
            except subprocess.TimeoutExpired:
                continue
            parsed = parse_brute(p.stdout)
            status = parsed.get("STATUS", "")
            if status in ("OK_BRUTE", "OK_NOBRUTE"):
                result = parsed
                used_magic = m
                break
            # If GAP_TOO_BIG, larger magics won't help, abort this file
            if status == "GAP_TOO_BIG":
                break

        if not result:
            fail += 1
            try: local_target.unlink()
            except: pass
            continue

        fek_hex = result["FEK"]
        new_ks_ext = result.get("KSEXT", "")
        if new_ks_ext:
            ks_extend_hex = (ks_extend_hex + new_ks_ext).lower()

        # Decrypt the body via direct-decrypt
        try:
            p2 = subprocess.run(
                [str(direct_bin), str(local_target), str(out_path), fek_hex,
                 str(before_chunk), str(after_chunk), skipped_hex],
                capture_output=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            fail += 1
            try: local_target.unlink()
            except: pass
            continue

        if not out_path.exists() or out_path.stat().st_size == 0:
            fail += 1
            try: local_target.unlink()
            except: pass
            continue

        # libmagic sanity check
        ft = libmagic(out_path)
        if is_bad(ft):
            try: out_path.unlink()
            except: pass
            fail += 1
        else:
            ok += 1

        try: local_target.unlink()
        except: pass

    bar.close()
    print(f"  [batch {kek}] ok={ok} fail={fail} skipped_no_magic={skipped}")
    # Cleanup scratch
    try:
        shutil.rmtree(scratch)
    except: pass
    return ok, fail


def main():
    ap = argparse.ArgumentParser(
        description="Phase 11 keystream-extension automation for LockBit 3.0 recovery"
    )
    ap.add_argument("source", help="Directory containing encrypted files")
    ap.add_argument("output", help="Destination directory (will merge into group_<kek>/)")
    ap.add_argument("--ext", help="Ransomware extension (auto-detected if omitted)")
    ap.add_argument("--max-brute-bytes", type=int, default=4,
                    help="Max keystream bytes to brute-force per file (default: 4, ~9 min wall time)")
    ap.add_argument("--before-chunk", type=int, default=3,
                    help="LockBit intermittent encryption: before_chunk_count (default 3)")
    ap.add_argument("--after-chunk", type=int, default=3,
                    help="LockBit intermittent encryption: after_chunk_count (default 3)")
    ap.add_argument("--skipped-hex", default="0x520000",
                    help="LockBit intermittent encryption: skipped_bytes (default 0x520000)")
    ap.add_argument("--scratch", default=None,
                    help="Scratch directory (default: <output>/.extend_scratch)")
    ap.add_argument("--brute-extend", default=None,
                    help="Path to brute_extend3 binary (default: ./brute-extend next to this script)")
    ap.add_argument("--direct-decrypt", default=None,
                    help="Path to direct_decrypt binary (default: ./direct-decrypt next to this script)")
    ap.add_argument("--brute-timeout", type=int, default=900,
                    help="Per-file brute-force timeout in seconds (default 900)")
    args = ap.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        print(f"ERROR: source not a directory: {source}")
        sys.exit(2)
    output.mkdir(parents=True, exist_ok=True)

    # Locate binaries
    here = Path(__file__).resolve().parent
    brute_bin = Path(args.brute_extend) if args.brute_extend else (here / "brute-extend")
    direct_bin = Path(args.direct_decrypt) if args.direct_decrypt else (here / "direct-decrypt")
    if not brute_bin.exists() or not os.access(brute_bin, os.X_OK):
        print(f"ERROR: brute-extend binary not found at {brute_bin}")
        sys.exit(3)
    if not direct_bin.exists() or not os.access(direct_bin, os.X_OK):
        print(f"ERROR: direct-decrypt binary not found at {direct_bin}")
        sys.exit(3)
    print(f"[i] brute-extend: {brute_bin}")
    print(f"[i] direct-decrypt: {direct_bin}")

    # Detect ransomware extension
    ransom_ext = args.ext or ""
    if not ransom_ext:
        print(f"[i] Detecting ransomware extension in {source}...")
        ransom_ext = detect_extension(source)
        if not ransom_ext:
            print("ERROR: could not auto-detect ransom extension; pass --ext .XYZ")
            sys.exit(4)
    if not ransom_ext.startswith("."):
        ransom_ext = "." + ransom_ext
    print(f"[i] Ransom extension: {ransom_ext}")

    scratch = Path(args.scratch) if args.scratch else (output / ".extend_scratch")
    scratch.mkdir(parents=True, exist_ok=True)

    # Scan
    print(f"[*] Scanning {source}...")
    t0 = time.time()
    groups, scanned = scan_batches(source, ransom_ext)
    print(f"[+] Scanned {scanned} encrypted files in {time.time()-t0:.1f}s")
    print(f"    {len(groups)} distinct batches found")

    # Filter to batches with multiple files (need oracle + at least 1 target)
    work_batches = [(k, v) for k, v in groups.items() if len(v) >= 2]
    work_batches.sort(key=lambda x: -len(x[1]))  # process largest batches first
    print(f"    {len(work_batches)} batches have ≥ 2 files (candidates for Phase 11)")

    # Plan
    total_targets = sum(len(v) - 1 for _, v in work_batches)
    print(f"    Total target files across all batches: {total_targets}")

    grand_ok = grand_fail = 0
    for bi, (kek, files) in enumerate(work_batches):
        oracle = max(files, key=lambda x: x[0])
        if oracle[0] < 90:
            # Oracle too short to give useful keystream; skip whole batch
            continue
        print(f"\n=== BATCH {bi+1}/{len(work_batches)} ===")
        ok, fail = process_batch(
            kek, files, output, scratch, brute_bin, direct_bin,
            ransom_ext, args.max_brute_bytes,
            args.before_chunk, args.after_chunk, args.skipped_hex,
            args.brute_timeout,
        )
        grand_ok += ok
        grand_fail += fail
        print(f"[running totals] ok={grand_ok} fail={grand_fail}")

    print(f"\n[*] FINISHED. Recovered: {grand_ok}  Failed: {grand_fail}")
    print(f"[*] Output: {output}")


if __name__ == "__main__":
    main()
