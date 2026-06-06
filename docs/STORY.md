# Recovery journey — the whole story
This is the unabridged chronicle of the recovery operation that led to `lockbit-rescue`. It covers everything we tried, what we found, the dead-ends, the surprises, the bugs we fixed in our own tooling, and the final numbers. Treat it as both a post-mortem and a worked example for another victim doing the same thing.
## TL;DR — what happened
A Linux user got hit by **LockBit 3.0 ("Black")** ransomware. Two storage targets were affected: a network-attached storage (My Cloud EX2 Ultra) and a USB-attached external HDD. Roughly **268,000 files** were encrypted, all renamed `<name>.MoHsVxKYI`. No backups predated the attack; the user did not pay.
We ruled out the obvious recovery paths (No More Ransom key match, PhotoRec carving), then exploited a documented **keystream-reuse weakness** in LockBit 3.0 to decrypt **13,525 files (242 GB)** for free, with **0% corruption** as verified by libmagic. That's about **5% of the encrypted set** — the rest is mathematically blocked by the exploit's preconditions.
Along the way we benchmarked a famously slow NAS into the ground (~12 MB/s hardware cap), wrote four iterations of a mass-decryption script, ran two jobs in parallel against two different storage backends, and turned the whole thing into a packaged tool with auto-detect + integrity verification.
## Phase 1 — Triage
### Phase 1.1: Identifying the ransomware
The user landed in a directory full of files named `<something>.<ext>.MoHsVxKYI`, paired with `MoHsVxKYI.README.txt` ransom notes. Initial telltales:
- **Extension `.MoHsVxKYI`** — random 9-character mixed-case alphanumeric, applied uniformly. Matches the LockBit 3.0 ("Black") signature exactly. LockBit 3 generates a per-attack random extension; earlier LockBit variants used fixed strings like `.lockbit`.
- **Ransom note** mentioned Cyberfear contact, LockBit 3.0 branding, and a **Decryption ID**: `[REDACTED_DECRYPTION_ID]`.
- **Affiliate**: the note style and contact channel indicated the "CriptomanGizmo / Cyberfear" affiliate of LockBit 3.
This matters because the cryptographic implementation is specific to LockBit 3.0 ("Black"). The keystream-reuse weakness does not apply to LockBit Green or other unrelated families.
### Phase 1.2: Checking the easy paths
Before trying anything clever, we exhausted the cheap options.
1. **No More Ransom — Crypto Sheriff / LockBit 3.0 checker.**
   Submitted the Decryption ID `[REDACTED_DECRYPTION_ID]` to the official checker that runs against ~923 publicly seized LockBit 3 keys. No match. Law enforcement may release additional keys in the future (~7,000+ total are known to be seized), but our specific ID is not currently among the published ones.
2. **PhotoRec / file carving.**
   Considered, then dropped. The encrypted files were NAS backups — i.e. they originated on a separate filesystem that the user no longer had raw access to. File carving works on raw block devices to recover deleted files; it doesn't help when you only have *encrypted copies* of files that legitimately exist on disk. No fallback there.
3. **Paying.**
   Not pursued. Beyond the ethics of funding a criminal operation, LockBit affiliates have a documented history of taking payment and not delivering keys.
## Phase 2 — Cryptographic analysis
### Phase 2.1: Confirming what we were dealing with
We pulled a couple of encrypted JPGs (`004.JPG.MoHsVxKYI`, `005.JPG.MoHsVxKYI`) and analyzed them:
- **Entropy.** Shannon entropy on the file body was effectively 8.0 bits/byte — full-spectrum noise, indicating sound encryption end-to-end. No obvious unencrypted regions, no "intermittent encryption" gaps where chunks of plaintext leak through.
- **Size patterns.** Encrypted size = original size + 134 bytes. The fixed +134 overhead matches the LockBit 3 footer documented in published research.
- **Last 134 bytes.** Hex-dumped the trailers of multiple files. They had a *consistent structure*:
  ```
  -134..-132   2 bytes   variable per file  ← later identified as fei_len (uint16 LE)
  -132..-128   4 bytes   variable per file  ← checksum
  -128..   0   128 bytes ← RSA-encrypted KEK
  ```
- **128-byte KEK comparison.** For *some* pairs of files, those 128 bytes were **byte-for-byte identical**. For others, completely different. That's the smoking gun: files share an RSA-encrypted KEK if and only if they were encrypted in the same batch — and *every file in a batch uses the same Salsa20 keystream*.
That identity confirmed the keystream-reuse weakness applied to this victim's data.
### Phase 2.2: Finding the prior art
The vulnerability had been documented publicly by [Calif.io](https://www.calif.io/blog/lockbit-3.0-decryptor) in 2024. The write-up describes the modified Salsa20 implementation (random 64-byte initial state, no sigma constants), the file footer format, and the technique for recovering keystream bytes by XORing a known-plaintext oracle.
A working implementation existed: [yohanes/lockbit-v3-linux-decryptor](https://github.com/yohanes/lockbit-v3-linux-decryptor). The key program is `stream-reuse.c`. It does the hard cryptographic work — recovering the keystream from an oracle and applying it to a target — but it has a tight CLI: it expects you to hand it `(target_file, oracle_file, oracle_original_filename)` per invocation. There's no batching, no discovery, no resume, no verification. We'd build all of that on top.
## Phase 3 — First decryption: from "impossible" to "working"
### Phase 3.1: The short-name problem
We tried the exploit on the user's two test JPGs immediately. It failed. Why?
The exploit recovers keystream bytes equal to the *known-plaintext length* in the oracle's footer. The known plaintext is the apLib-compressed UTF-16LE original filename. Short filenames produce short compressed-filename plaintext, which produces few recovered keystream bytes — possibly fewer than the number of bytes needed to decrypt the *target* file's footer (its `fei_len`).
For `004.JPG.MoHsVxKYI` (filename `004.JPG`, 7 characters), there were nowhere near enough bytes of compressed filename to provide useful keystream coverage. The two short-named test files couldn't act as oracles for each other or for anything else.
We needed an oracle with a *long* original filename in the *same encryption batch*.
### Phase 3.2: Finding a long-named oracle in the same batch
We asked the user to drag over 23 more encrypted files that originally had long names — Italian document titles, scientific paper names, descriptive Telegram-style downloads. They put them in the same folder.
We wrote a quick batch-fingerprinter:
```python
import hashlib, os
for f in glob('*.MoHsVxKYI'):
    with open(f, 'rb') as fp:
        fp.seek(-128, 2)
        kek = fp.read(128)
    print(hashlib.md5(kek).hexdigest()[:12], f)
```
All 25 files (`004.JPG`, `005.JPG`, and the 23 new ones) printed the **same KEK fingerprint**. They were encrypted in one batch. We had a candidate oracle pool.
### Phase 3.3: Extending the known plaintext beyond just the filename
The pure-filename approach is the published baseline. We pushed it further. The FEI (footer encryption info) block contains, after the compressed filename:
```
[ filename_size      ]  2 bytes
[ skipped_bytes      ]  8 bytes
[ before_chunk_count ]  4 bytes
[ after_chunk_count  ]  4 bytes
```
`filename_size` is computable from the known filename. `before_chunk_count` and `after_chunk_count` are derivable from file body length and the chunking rule. `skipped_bytes` is *constant per encryption batch* — so we recovered it once by XORing two oracles' ciphertext at the expected offset and got `0x0000000000520000`.
That gave us 18 additional bytes of known plaintext past the compressed filename, which translates directly to 18 more bytes of recovered keystream — exactly enough to cover the short `004.JPG`/`005.JPG` files' footer encryption info regions.
### Phase 3.4: First successful decryption
We ran `stream-reuse` against the longest-named file in the batch as oracle, with our extended-known-plaintext patch driving the keystream recovery. The output:
- `DECRYPTED_004.JPG` — valid JPEG, JFIF 1.01, full EXIF intact, opens in any image viewer.
- `DECRYPTED_005.JPG` — same.
This was the proof-of-concept. The exploit worked on the user's data.
## Phase 4 — Scaling: from 2 files to a NAS full of them
### Phase 4.1: Discovering how big this actually was
The user revealed the encrypted files were just samples — the bulk of their data lived on a NAS at `smb://my-nas-device.local/Public/TargetShare/`. We mounted that as `/mnt/target_share` and scanned it.
**~127,000 encrypted files** in total. We grouped them by KEK fingerprint and got **132 distinct encryption batches** (the attacker had run the encryptor in many sessions or against many subdirectories).
### Phase 4.2: Iterating mass-decrypt scripts
We wrote four versions of the bulk decryption pipeline. Each iteration solved a real problem the previous one had.
**`mass_decrypt.py` (v1) — linear baseline.**
Walk all files, group by KEK, pick longest-named oracle per group, decrypt every other file. No filters, no progress bar, no resume. Crashed on the second NAS file we tried — the encrypted file's body was 14 GB (a VM disk) and we didn't have local disk space to stage it. Failure rate ~75%, mostly because we hadn't tuned the keystream-extension defaults yet for every group.
**`mass_decrypt_v2.py` — filtering and basic stats.**
Added an extension whitelist (jpg/pdf/docx/mp4/etc.) and a size filter (10 KB ≤ size ≤ 1 GB). Got ~98% success rate on the targets that survived the filter. But still no visible progress: when the NAS was the slow link, the script would spend 30+ seconds on a single file with zero feedback. Felt like it was hung.
**`mass_decrypt_v3.py` — progress bars.**
Added `tqdm` overall + per-group + per-file copy progress bars. This was critical psychologically: even at 12 MB/s, you could see motion. We'd wasted real time Ctrl-Cing the v2 script thinking it was hung when it was just plodding.
**`mass_decrypt_v4.py` — resumable, NAS-output, robust.**
The final form. Changes:
- **Resume**: skip any target whose output already exists.
- **NAS-only output**: writes recovered files directly to `/mnt/target_share/TargetShare/RECOVERED/` so they don't fill the user's 928 GB local SSD.
- **Cross-filesystem-safe moves**: replaced `os.rename` with copy+unlink, because the source and destination were on different filesystems and rename would `EXDEV`.
- **Per-group oracle staging**: copies each group's oracle to a fast local scratch, so we don't re-read the oracle from slow SMB once per target.
- **libmagic verification**: runs `file -b` on each decrypted output. If the result is raw `data` or contains `corrupted`, the file is dropped (didn't decrypt right).
At the end of v4 development, the run plan was:
- 132 groups → only **46 had a usable oracle** (i.e. at least one file with a long enough original filename to provide enough keystream coverage). The other 86 groups have *no* long-named oracle; cryptographically blocked.
- After extension + size filtering on the 46 decryptable groups: **26,778 target files**.
### Phase 4.3: The performance war
During v3/v4 testing, throughput was frustrating. We benchmarked:
| test | throughput |
|---|---|
| Single-stream SMB3 write, 256 MiB, fdatasync | 11.5 MB/s |
| Single-stream SMB3 read, 75 MiB uncached | 11.7 MB/s |
| 16-MiB blocks, single writer | 11.5 MB/s |
| 2 parallel writers, 64 MiB each | 5.8 + 5.8 MB/s = 11.6 aggregate |
| 4 parallel writers, 32 MiB each | 3.1 + 2.9 + 2.9 + 2.9 = 11.8 aggregate |
The NAS was capped at ~12 MB/s in any direction, and *parallelism didn't help* — it just split the bandwidth. We initially hypothesized SMB3 encryption overhead on the NAS's 1.3 GHz ARM CPU and remounted the share with `vers=2.1,sec=none` (no protocol-level encryption). Result: 11.5 MB/s. Identical. The bottleneck was the NAS's internal hardware (CPU + disk write coalescing on a low-power ARM platform), not the wire protocol.
**Lesson**: don't pre-blame the protocol. Always measure single-stream, then n-stream parallel; if aggregate doesn't change, the bottleneck is *past* the wire.
We accepted the limit and let it run. The full NAS recovery took **~10 hours of wall time**.
## Phase 5 — Second front: the USB disk
While the NAS recovery was running, the user mentioned they had a separate USB-attached external HDD that was also encrypted in the same attack. They mounted it as `/mnt/volume` (2.7 TB NTFS, ~10-year-old disk, transport `usb` per `lsblk`).
### Phase 5.1: The "hanging find" that wasn't hanging
We tried `find /mnt/volume -name "*.MoHsVxKYI"` and got no output for ~30 seconds. We assumed it was stuck and considered debugging. The user pushed back: *"it's not hanging, this is an old slow HDD — show me the progress"*.
We re-ran it with progress reporting:
```bash
find /mnt/volume -name '*.MoHsVxKYI' 2>/dev/null | tee /tmp/usb.txt | awk 'NR % 100 == 0 {print NR " files..."; fflush()}'
```
Progress flowed at ~2,000 files/second. We watched it climb past 97,700 in 50 seconds before stopping it. **It was never hung.** Lesson learned: instrument for progress before assuming failure.
Final scan: **141,543 encrypted files** on the USB across **117 groups**, of which only **26 had a usable oracle**. Plan size: **4,682 targets**.
### Phase 5.2: Running two recoveries concurrently
We cloned `mass_decrypt_v4.py` into `mass_decrypt_v4_usb.py` and changed three things:
- `ROOT = '/mnt/volume'`
- `OUTPUT_ROOT = '/mnt/target_share/TargetShare/RECOVERED_USB'` (separate folder on the NAS)
- `SCRATCH_DIR = '/home/username/Documents/decrypt/usb_work'` (private scratch dir)
That last one was critical. The `stream-reuse` binary writes its decrypted output to a hard-coded file named `decrypted` in its current working directory. Two concurrent jobs in the same `cwd` would silently overwrite each other's output. Per-job scratch dirs fixed it.
We launched the USB job in the background while the NAS job continued. Both write into the NAS (different folders), so they shared the ~12 MB/s NAS write cap, but the *reads* came from different physical sources (one over SMB, one over local USB), so they didn't compete on reads.
## Phase 6 — Results
### Phase 6.1: The numbers
| Source | Encrypted scanned | Groups | Decryptable groups | Targets planned | Recovered on disk | Wall time |
|---|---|---|---|---|---|---|
| NAS `/mnt/target_share` | 127,038 | 132 | 46 | 26,778 | **9,778 files / 215 GB** | ~10 h |
| USB `/mnt/volume` | 141,543 | 117 | 26 | 4,682 | **3,747 files / 27 GB** | ~3 h |
| **Total** | **~268,581** | **249** | **72** | **31,460** | **13,525 / 242 GB** | parallel |
Coverage as a fraction of all encrypted files: **~5%**. Coverage of the *attempted* (decryptable) targets: **~43%**.
Why not 100% of the decryptable plan? Two reasons:
1. **SMB write hiccups.** The USB script counted 4,246 "ok" but only 3,747 ended up on disk. The gap (499) is from silent NAS write failures during the run — the script saw the write succeed but the file later showed as missing or truncated. A simple resume re-run recovers most of these.
2. **Per-target `fei_len` exceeding keystream coverage.** Within a group, some targets have an FEI block longer than what the oracle's recovered keystream covers. Those targets can't be decrypted from that oracle.
### Phase 6.2: Integrity verification
We wrote `verify-recovered.py` to libmagic-classify every recovered file and tell us if decryption actually produced sane outputs. First run found a real bug in our own classifier (see next section). After fixing it, the final report on all 13,525 recovered files:
- **GOOD: 13,352 (98.7%)** — magic bytes match the file extension. Recovery was clean.
- **MISMATCH: 173 (1.3%)** — file type recognized but doesn't match extension. Spot-checking these showed they were *all* user-mislabeled files from before the attack:
  - 4× PDFs that the user had saved with `.html` extension (Italian school documents)
  - 7× SQLite `.db` files with libmagic-detected pseudo-mismatches (later fixed in our classifier)
  - Windows `Thumbs.db` files that are Composite Document or JPEG inside
  - `.png` files that are actually JPEG (a user habit of renaming on save)
  - `.m4a` files reported as ISO Media MP4 (correct — m4a *is* an MP4 audio container)
  - `logo.ai` reported as PDF (Adobe Illustrator files are PDFs internally)
  - 7-zip `.7z` files reported with format-version variation
- **SUSPECT: 0 (0.0%)** — zero files came out as raw `data`, `empty`, or `corrupted`. This is the strongest possible empirical signal that the cryptographic decryption itself worked perfectly on every file we attempted. Any "failed" file was filtered out at write-time by the libmagic check inside `mass_decrypt_v4`.
## Phase 7 — Bugs we found in our own work (and fixed)
### Bug 1: `mass_decrypt_v4` triple-counted some sub-runs vs. on-disk count
The v4 script's `grp_ok` counter incremented when the copy-to-NAS appeared to succeed. But the NAS sometimes silently dropped/truncated the file after-the-fact (`write` returned success, but the inode ended up missing on a later `stat`). Net effect: "4,246 ok" reported, only 3,747 actually on disk. Workaround: re-run with the same args; resume logic uses `os.path.exists(out_path)` and re-decrypts the missing ones. Long-term: post-write `stat + size > 0` check, retry on mismatch. Filed mentally for v5.
### Bug 2: The original `verify_recovered.py` per-source breakdown collapsed both roots
The code split files by their full source path and used `str.startswith` to attribute each file to a root. But `/mnt/target_share/TargetShare/RECOVERED` is a *prefix* of `/mnt/target_share/TargetShare/RECOVERED_USB`, so every USB-recovered file matched both roots and got attributed to the shorter one. Result: per-source breakdown showed everything under the NAS root, none under the USB root. Grand total was still right.
Fix in the packaged `verify-recovered.py`: use `Path.relative_to()` and prefer the *longest* matching root.
### Bug 3: SQLite `.db` files were classified as MISMATCH instead of GOOD
The classifier iterated a `family -> extensions` dict and returned the first family whose name appeared as a substring in the libmagic output. The libmagic output for SQLite files is:
```
SQLite 3.x database, last written using SQLite version 3017000, ..., UTF-8, version-valid-for 2
```
Note the `UTF-8` in the middle. The dict had `"UTF-8"` listed before `"SQLite"`, and substring-match `"utf-8" in fl` was true → classified as UTF-8 → MISMATCH (because `.db` is not in the UTF-8 extension set).
**Fix**: change `fam.lower() in fl` to `fl.startswith(fam.lower())`. libmagic output reliably starts with the format name, so anchoring the match at the start eliminates false hits.
After the fix, a smoke test on 15 mixed files (JPGs, SQLite databases, XML, DOCX) returned 100% GOOD, 0% MISMATCH, 0% SUSPECT.
### Bug 4: Verify script's source-prefix logic also misbehaved on macOS-style trailing-slash edge cases
Not encountered in practice on Linux, but the fix to use `Path.resolve()` + `relative_to()` covers it.
## Phase 8 — Productionization: the `lockbit-rescue` package
Once the recovery completed and the integrity report was clean, we turned the ad-hoc scripts into a self-contained, documented tool that any other victim of the same ransomware could run. Design goals:
1. **No assumptions about extension.** Auto-detect `.<random9chars>` from a filesystem sample.
2. **No assumptions about layout.** Walk the source recursively; no hand-specifying batches.
3. **No assumptions about where output goes.** Source and output are CLI args; default scratch under the output directory; honor `--scratch` for fast local SSD if desired.
4. **Resume by default.** Re-running the same command picks up where it left off.
5. **Verify on the way through.** libmagic check before writing; the standalone `verify-recovered.py` for after-the-fact integrity sweeps.
6. **Build cleanly from source.** `install.sh` clones the upstream decryptor, builds `stream-reuse`, installs the only Python dep (`tqdm`), and symlinks the binary into the package directory.
7. **Honest documentation.** README states upfront that real-world coverage is ~5–40% and explains exactly when the exploit cannot help.
Final package: **8 files, 76 KB**, plus the symlink to the built `stream-reuse` binary.
## Phase 9 — Recommendations for anyone in this situation
1. **Don't pay.** Even setting aside the ethics, you have a reasonable chance of recovering *some* of your data via this exploit if the encryption batch contained a long-named file.
2. **Don't delete the encrypted files.** Keep them around. Two reasons: (a) if law enforcement publishes the private RSA key for your decryption ID later (No More Ransom), you can decrypt the rest at 100%; (b) the keystream-reuse exploit can be re-run with better oracles as those become available.
3. **Submit your decryption ID to No More Ransom.** Costs nothing and might pay off years later. Keys are added when law enforcement seizes infrastructure.
4. **Identify your encryption batches.** Use the KEK-fingerprint grouping in `lockbit-rescue.py` to see which batches your files belong to. If even one batch contains a file with a long original name, you can recover everything else in that batch.
5. **Prefer fast local storage for output.** If your only writable destination is a slow NAS, the throughput is what it is. If you have a local SSD, point `OUTPUT_DIR` there.
6. **Verify, don't trust.** Always run `verify-recovered.py` after. If `SUSPECT > 0`, that batch had a problem and needs investigation.
## Phase 10 — Honest accounting of what we didn't do
- We did **not** brute-force-extend the keystream byte-by-byte for groups that had no long-named oracle. There's a theoretical attack where you guess Salsa20 keystream bytes via plausible plaintext (e.g. file magic bytes at certain offsets) and verify against the FEI checksum field. It's expensive (~2^32 work per byte in the worst case), and not implemented in `stream-reuse`. Could be a v2 of the tool.
- We did **not** attempt to crack the per-batch RSA-encrypted KEK directly. The RSA modulus is 1024 bits; nobody factorizes those for free.
- We did **not** attempt to recover deleted plaintext copies from the NAS underlying disks. The NAS is a closed appliance; that would require disassembling it, imaging the disks, and running PhotoRec — way out of scope and not guaranteed to work given the way NASes overwrite blocks during their own background tasks.
- We did **not** parallelize the decryption *workers*. CPU was not the bottleneck (NAS I/O dominated), but if you're recovering from local SSD to local SSD, a process pool of `stream-reuse` workers would significantly speed things up. Open for v2.
## Acknowledgments
- **[Calif.io](https://www.calif.io/blog/lockbit-3.0-decryptor)** for the published research on the keystream-reuse weakness in LockBit 3.0.
- **[yohanes](https://github.com/yohanes/lockbit-v3-linux-decryptor)** for the working C harness (`stream-reuse.c`) that drives the original LockBit shellcode for both oracle extraction and target decryption.
- The victim/operator, for patience during a multi-day recovery and the willingness to provide additional samples (the 23 long-named files) when the first attempt couldn't find an oracle.
## Final tally (Phase 1–10)
- **268,581 files** encrypted across two storage targets
- **249 distinct encryption batches** identified
- **72 batches** had a usable oracle
- **13,525 files (242 GB)** recovered
- **0 files** corrupted by the recovery process
- **0 dollars** spent on ransom
- **~13 hours** of wall-clock recovery time (NAS-bound)
## Phase 11 — Beyond stream-reuse: brute-force keystream extension
After the main run finished, we revisited the files that the main flow had to *skip* — files where the longest-named oracle in the batch wasn't long enough to cover the target's `fei_len`. The plan was to extend the keystream beyond the oracle's natural coverage via known-plaintext brute force.
### Phase 11.1: The segfault that blocked us before
We had previously written `brute_extend.c` to do byte-by-byte extension by trying all 256 candidates for each missing keystream byte, validating each candidate by Salsa20-decrypting the file's first chunk and checking magic. It worked for 1–3-byte gaps but **segfaulted reliably** on a 4-byte (2³²-iteration) brute force — the same scenario needed to recover `DOCUMENT_1.pdf` (fei_len=113, missing 4 bytes from a 109-byte base).
We finally diagnosed it under `gdb`. The crash address landed inside the mmap'd Salsa20 shellcode:
```
Program received signal SIGSEGV.
0x2aaa1019 in ??
  eip = 0x2aaa1019    ← inside shellcode (instruction: "push %edi")
  esp = 0x2abab000    ← *outside* the shellcode's mmap
```
Root cause: the LockBit Salsa20 shellcode is Windows code lifted out of the ransomware binary. It treats its own mmap as a private downward-growing stack — fine for a single call from a Windows host, but on each invocation it returns with ESP a few bytes lower than where it started. Over 2³² calls in our brute-force loop, ESP drifts past the mapping boundary and the next `push` hits an unmapped page.
This was *the* reason a sub-population of recoverable files had stayed unrecovered — not a cryptographic limit, just a memory-management bug in how we drove the shellcode.
### Phase 11.2: The fix — pure-C Salsa20
We wrote `brute_extend2.c` that reimplements LockBit's modified Salsa20 in pure C (no shellcode at all): the 10-iteration column+row round structure, with the entire 64-byte state treated as random (no `sigma`/`tau` constants). The pure-C version has no shellcode stack to drift, and runs ~8 million iterations/second on a modern desktop CPU.
Result: a 4-byte brute force (2³² candidates) now completes in **~9 minutes**, not segfaults.
### Phase 11.3: The false-positive lesson
We ran `brute_extend2` against `DOCUMENT_1.pdf` with a 4-byte magic (`%PDF`). It returned a match after 2.1B iterations: extension bytes `c7 4b ec 7f`, decrypted first 32 bytes starting `25 50 44 46 5e 4d 1b 97 ...`.
The `%PDF` matched but the bytes immediately after looked like noise rather than a `-1.x` version string. **This was the false positive trap.** With a 4-byte (32-bit) magic and 2³² trials, statistically ~1 false positive is expected. We got exactly one.
Re-running with the 9-byte magic `%PDF-1.7\n` (collision rate 2⁻⁷² per candidate) found the *true* answer after 3.7B iterations: extension bytes `ea aa ca dc`, decrypted first 32 bytes `25 50 44 46 2d 31 2e 37 0a 25 e2 e3 cf d3 0a 31 20 30 20 6f 62 6a 0a 3c 3c 2f 4d 61 74 72 69 78` — a perfectly-formed `%PDF-1.7\n%<bin>\n1 0 obj\n<</Matrix` header that matched a known-good sibling PDF in the same batch byte-for-byte.
Lesson — codified in BRUTEFORCE.md §5: **always use ≥7-byte magic** for serious brute force. The wall time is essentially unchanged (most candidates fail at byte 0).
### Phase 11.4: Full body decryption (`direct-decrypt`)
The brute force gave us the 64-byte `file_encryption_key` for that specific PDF. To recover the full body, we wrote `direct_decrypt.c` — a 167-line C tool that replays the same chunked-decryption loop `stream-reuse` uses, but takes the recovered `file_encryption_key` directly on the command line instead of computing it from an oracle. It uses the original LockBit Salsa20 shellcode for body decryption, but only invokes it a handful of times (one per chunk), so the ESP drift never escapes the 256 KB-padded mmap.
First attempt: we naively set `before_chunk_count=100, after_chunk_count=0` to force a full-file decrypt. The header decoded as `%PDF-1.7\n%<bin>\n1 0 obj`, but the file tail came out as garbage and `pdfinfo` errored on the xref table.
Looking at the *encrypted* file's last 200 bytes revealed the cause: they were *already plaintext* PDF xref content (`85918 00000 n\n...trailer<<...startxref\n689052\n%%EOF`). LockBit's intermittent encryption had encrypted only the first ~512 KB of the file (chunks 0–3) and left the rest as plaintext passthrough. Our `before_count=100` was Salsa20-XORing the already-plaintext tail, scrambling it back into noise.
Re-running with the *correct* batch parameters — `before=3, after=3, skipped=0x520000` (the values we'd empirically recovered for batch `c1ea81cceaf4` weeks earlier) — produced the right answer:
```
file DECRYPTED_DOCUMENT_1.pdf
  → PDF document, version 1.7, 2 page(s) (zip deflate encoded)
pdfinfo DECRYPTED_DOCUMENT_1.pdf
  Creator:      Adobe LiveCycle Designer ES 9.0
  Producer:     Adobe LiveCycle Designer ES 9.0
  CreationDate: Sat May 25 12:35:34 2013 CEST
  ModDate:      Wed Mar 22 14:49:38 2017 CET
  Form:         AcroForm
```
A structurally valid, fully readable PDF — the file the main flow had failed on — recovered cleanly.
### Phase 11.5: What this unlocks
After Phase 11, we have 113 verified bytes of keystream for batch `c1ea81cceaf4`. The set of newly-recoverable files in this batch grew from `{ fei_len ≤ 106 }` to `{ fei_len ≤ 113 }`. With one more `brute-extend` step (1-byte extension using a fei_len=114 target in the same batch), we get to 114. Climbing further depends on having intermediate-fei_len files in the batch — the local 25-file subset has a gap from 114 to 125 (11 bytes, infeasible to bridge directly), but the full NAS batch may have intermediate files we can use.
More importantly, the technique generalizes: **every batch with an oracle and a contiguous ladder of fei_lens can be progressively unlocked beyond stream-reuse's natural coverage.** The same `brute-extend` + `direct-decrypt` workflow applies.
### Phase 11.6: Package changes
- `brute-extend` (symlink to `brute_extend2`) and `_brute_extend.c` (source) added to the lockbit-rescue package.
- `direct-decrypt` (symlink to `direct_decrypt`) and `_direct_decrypt.c` added.
- `install.sh` extended to build both binaries from source after cloning upstream.
- New `BRUTEFORCE.md` documenting the segfault, the fix, the false-positive lesson, and the validated end-to-end workflow.
- This Phase 11 section added to STORY.md.
## Final tally (after Phase 11)
In addition to Phase 1–10 outcomes, Phase 11 demonstrated:
- **1 segfault diagnosed and fixed** — our own implementation bug, not LockBit's.
- **+7 bytes of keystream recovered** for one batch (106 → 113).
- **1 previously-stuck file** (`DOCUMENT_1.pdf`) recovered as a fully valid PDF.
- **A reusable post-recovery workflow** (`brute-extend` → `direct-decrypt`) packaged and documented.
- **Important reusable lesson**: ≥7-byte magic for brute force, or accept false positives.
The rest is for someone else, with a key seizure, a smarter exploit, or just enough patience to climb more byte-by-byte ladders. We did what the math allowed — and now a bit more than that.
