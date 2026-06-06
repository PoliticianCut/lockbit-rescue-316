# Keystream extension via brute force — segfault diagnosis and fix

The `lockbit-rescue.py` main flow only decrypts files whose footer-encryption-info length (`fei_len`) fits within the keystream we can recover from a long-named oracle (typically 88 bytes of compressed filename + 18 bytes of fixed metadata = **106 bytes**). Files in the same batch with `fei_len > 106` are left behind by the main flow.

This document describes the second-stage attack: **byte-by-byte keystream extension via known-plaintext brute force**, why the original implementation segfaulted, and how to recover the previously-stuck files anyway.

## 1. What we're trying to do

Each file in a LockBit-3 encryption batch has a "footer encryption info" (FEI) region of variable length `fei_len`. The first `(fei_len - 64)` bytes are metadata; the last **64 bytes** are the *file encryption key* — the Salsa20 initial state used to encrypt that specific file's body.

All files in the same batch share the same keystream. So if we know keystream bytes `[0..K-1]`, we can XOR-decrypt the first `K` bytes of any file's FEI. To recover that file's `file_encryption_key` (the last 64 bytes of its FEI), we need `K ≥ fei_len`.

The main flow's K = 106. For files with fei_len > 106, we need to **extend** the keystream.

### The extension trick

Find a file in the same batch with `fei_len = K + 1`. Its FEI has one byte of ciphertext past our known keystream. We don't know the corresponding keystream byte, but we *can* guess all 256 values and test each:

1. For each candidate keystream byte `k`:
2. XOR `target_fei[K..K] = k`, plus our known keystream, against the full FEI to get a candidate `file_encryption_key`.
3. Use that key as a Salsa20 state, generate the first 64-byte keystream block.
4. XOR the file body's first chunk against that keystream → candidate plaintext.
5. Check if the candidate plaintext starts with a known **magic number** for the file's type (`%PDF` for PDFs, `\xFF\xD8\xFF` for JPEGs, etc.).

The right `k` produces valid magic. With a 4-byte magic, the false-positive rate per candidate is `2^-32`; brute-forcing 1 byte (256 candidates) gives ~1/16M false positives — effectively zero.

We then have `K+1` keystream bytes. Repeat with files of `fei_len = K+2`, `K+3`, etc. Each step costs only **256 × Salsa20-blocks**.

For files where no intermediate `fei_len` exists, we brute-force multiple bytes at once: `N` missing bytes = `256^N` candidates. Costs:

| Missing bytes | Iterations | Wall time @ 8 M iter/s |
|---|---|---|
| 1 | 256 | <1 ms |
| 2 | 65,536 | ~8 ms |
| 3 | 16,777,216 | ~2 s |
| 4 | 4.29 × 10⁹ | **~9 min** |
| 5 | 1.10 × 10¹² | ~38 hours |
| 6 | 2.81 × 10¹⁴ | ~1.1 years |

So 4-byte gaps are feasible, 5-byte gaps are painful, 6+ is impractical.

## 2. The segfault

The reference implementation `brute_extend.c` uses the original **LockBit Salsa20 shellcode** (loaded from `frank.h` into a `MAP_ANONYMOUS | MAP_EXEC` mapping). Each iteration of the brute-force loop calls `SALSA20_decrypt_func(...)` to compute the Salsa20 block.

This **segfaults after a variable number of iterations** — sometimes hundreds, sometimes thousands.

### Reproduction under gdb

```bash
gdb --batch \
    -ex 'run "DOCUMENT_1.pdf.MoHsVxKYI" "<long-named-oracle>.pdf.MoHsVxKYI" "<oracle-orig-name>" 25504446' \
    -ex 'bt' -ex 'info registers' \
    ./brute_extend_dbg
```

Output:

```
Program received signal SIGSEGV, Segmentation fault.
0x2aaa1019 in ?? ()

#0  0x2aaa1019 in ?? ()    ← inside the mmap'd shellcode
#1  0x0804df54 in __libc_start_call_main ()
#2  0x0804fa9c in __libc_start_main_impl ()
#3  0x0804b878 in _start ()

Registers:
  eip = 0x2aaa1019       ← inside shellcode, instruction is "push %edi"
  esp = 0x2abab000       ← *outside* the mmap region
  ebp = 0xffffd138       ← host C stack
```

The shellcode is mapped at `0x2aaa1000`. The instruction at `eip` is `push %edi`, which decrements ESP and writes — but `esp = 0x2abab000` is past the end of the mmap region. Push tries to write into an **unmapped page** → SIGSEGV.

### Root cause

The LockBit Salsa20 shellcode is **Windows code lifted out of the ransomware binary**. It assumes it has a private downward-growing stack inside its own mapping (a common pattern in payload-style shellcode where the host program might not have provided a usable stack pointer). Specifically:

- On entry, it sets `esp` to a high offset *within* the mmap'd region.
- It uses pushes / locals during the 20-round Salsa20 computation.
- It restores `esp` to the original value on return.

But the restore is **slightly imperfect**. Each invocation leaves ESP a few bytes lower than it should be. Over many invocations, the drift accumulates until ESP crosses the page boundary at the start of the mapping (or past the top of it, depending on how the shellcode initializes), landing in unmapped memory. The next `push` faults.

This is fine for the upstream `stream-reuse` tool, which calls the shellcode only **once or twice per file**. It is fatal for `brute_extend`, which calls it **256 to 2³² times in a tight loop**.

## 3. The fix

Two viable approaches:

### Option A (simple): pure-C Salsa20 reimplementation

Drop the shellcode entirely and reimplement modified-Salsa20 in C. The LockBit modification (no `sigma` / `tau` constants, full 64-byte random state) doesn't change the round function; only the initial-state construction differs from textbook Salsa20.

This is what `brute_extend2.c` does. The salsa20_block function is just the standard 10-iteration column+row round structure:

```c path=null start=null
static inline void salsa20_block(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, 64);
    for (int i = 0; i < 10; i++) {
        // 4 column quarter-rounds
        x[ 4] ^= ROTL32(x[ 0] + x[12],  7);
        x[ 8] ^= ROTL32(x[ 4] + x[ 0],  9);
        x[12] ^= ROTL32(x[ 8] + x[ 4], 13);
        x[ 0] ^= ROTL32(x[12] + x[ 8], 18);
        // ... (4 column QRs, then 4 row QRs)
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + state[i];
        out[i*4 + 0] = (v >>  0) & 0xFF;
        // ...
    }
}
```

Throughput on a modern desktop CPU: **~8 million Salsa20 blocks/second per thread**. That makes 4-byte brute force (2³² candidates) complete in ~9 minutes.

This is the path we use. Binary is shipped in this package as `brute-extend` (symlink to the built `brute_extend2`).

### Option B (deeper): increase the shellcode mmap size

If you really want to use the original shellcode (e.g. to validate that the pure-C reimplementation produces *bit-identical* output), pad the mmap region:

```c path=null start=null
#define SHELLCODE_STACK_PAD (256 * 1024)
void *salsa_mmap = mmap(NULL, salsa_crypt_len + SHELLCODE_STACK_PAD,
                        PROT_EXEC | PROT_WRITE | PROT_READ,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
memcpy(salsa_mmap, salsa_crypt, salsa_crypt_len);
SALSA20_decrypt_func = (FUNC_SALSA20_decrypt)salsa_mmap;
```

The ESP drift now has 256 KB of slack before crossing a page boundary. Empirically this delays the segfault by a factor of ~16 (since the drift per call is several bytes). For a 4-byte (2³²-call) brute force this still isn't enough — you'd need megabytes of pad. Pure-C is simpler.

## 4. Worked example

Our test batch (`kek_fingerprint = c1ea81cceaf4`) contains 25 local files. After main-flow recovery (oracle = the longest-named file, fei_len=170, gives 106 keystream bytes), we have keystream `[0..105]` known.

### Step 1: extend [106..108] via single-byte brute force

Targets: `DOCUMENT_2.pdf` (fei_len=107, missing 1), `EXAMPLE_ID.pdf` (fei_len=109, missing 3 after [106]).

Brute force is essentially instant. Recovered keystream bytes:
- `[106] = 0x56`
- `[107] = 0x23`
- `[108] = 0x8a`

These are passed to the next `brute-extend` invocation via `[ks_extend_hex]` so the next step starts from `known_len = 109`.

### Step 2: extend [109..112] via 4-byte brute force

Target: `DOCUMENT_1.pdf` (fei_len=113, missing 4 from base 109).

```bash path=null start=null
./brute-extend \
    "DOCUMENT_1.pdf.MoHsVxKYI" \
    "SAMPLE_ORACLE_DOCUMENT_LONG_FILENAME_20170519.pdf.MoHsVxKYI" \
    "SAMPLE_ORACLE_DOCUMENT_LONG_FILENAME_20170519.pdf" \
    255044462d312e370a 4 \
    3 3 0x520000
```

The last three arguments (`3 3 0x520000`) are the LockBit intermittent-encryption parameters for this batch: `before_chunk_count`, `after_chunk_count`, and `skipped_bytes`. These vary per encryption batch — recover them from any file's decrypted FEI (see §6 below) or pass the values from `lockbit-extend.py --before-chunk / --after-chunk / --skipped-hex`.

Result (after ~7.5 min wall time):
- `[109] = 0xea`, `[110] = 0xaa`, `[111] = 0xca`, `[112] = 0xdc`
- Decrypted first 32 bytes: `%PDF-1.7\n%<binary>\n1 0 obj\n<</Matrix` — matches a known-good sibling PDF in the same batch.

### Step 3: continue extending

With keystream `[0..112]` known (113 bytes), any file with `fei_len ≤ 113` is now decryptable directly. Files at 114 cost one more byte (instant). Files at 125 cost 12 unknown bytes from base 113 — out of reach unless we find files at 114, 115, …, 124 to climb byte-by-byte.

The local batch has a contiguous ladder of fei_lens: 98, 105, 107, 109, 113, 114, 125, 130, 131, 132, 140, 148, 150, 154, 170. The gap from 114 → 125 (11 bytes) blocks further byte-by-byte climbing on the local subset. Scanning the full NAS batch may reveal intermediate-fei_len files that fill the gap.

## 5. Important: magic length matters

The brute force returns on the **first** candidate whose decrypted first chunk matches the supplied magic. With a 4-byte magic and 2³² iterations, statistically ~1 false positive is expected.

**Always use ≥7-byte magic for serious brute force.** Recommended magics:

| File type | Hex magic (≥7 bytes) | ASCII |
|---|---|---|
| PDF 1.x | `25 50 44 46 2d 31 2e` | `%PDF-1.` |
| PDF 1.7 | `25 50 44 46 2d 31 2e 37 0a` | `%PDF-1.7\n` |
| JPEG JFIF | `ff d8 ff e0 00 10 4a 46 49 46` | `....JFIF` |
| JPEG EXIF | `ff d8 ff e1 ?? ?? 45 78 69 66` | `....Exif` (skip 2 length bytes) |
| PNG | `89 50 4e 47 0d 0a 1a 0a` | `.PNG....` |
| ZIP | `50 4b 03 04 14 00 00` | `PK....` |
| Office (OLE) | `d0 cf 11 e0 a1 b1 1a e1` | (DOC/XLS/PPT) |
| Office (OOXML) | `50 4b 03 04 14 00 06 00` | `PK......` |

For an empirical magic, look at the header of a **known-decrypted** file in the same batch (use `xxd <decrypted_file> | head -1`).

In our worked example, the first run with 4-byte magic `25504446` found a false positive `c7 4b ec 7f` after 2.1B iters. Re-running with 9-byte magic `255044462d312e370a` found the *true* answer `ea aa ca dc` after 3.7B iters. Both runs took roughly the same wall time (longer magic doesn't slow the loop appreciably since most candidates fail at byte 0).

## 6. Full file body decryption with `direct-decrypt`
Once you have the `file_encryption_key` for a specific target (the 64-byte Salsa20 state of that file's body), use the `direct-decrypt` tool shipped with this package to recover the complete file.
```bash path=null start=null
direct-decrypt <encrypted_file> <output_file> <key_hex_64> \
               <before_chunk_count> <after_chunk_count> <skipped_bytes_hex>
```
### The chunking pattern
LockBit 3 doesn't blindly Salsa20-encrypt the whole body. It applies *intermittent encryption*:
1. Decrypt `before_chunk_count + 1` chunks of 128 KB each from the start of the body.
2. Skip the next `skipped_bytes` bytes (they are written **plaintext** into the file).
3. Decrypt `after_chunk_count + 1` more chunks.
4. Repeat the skip / decrypt cycle until EOF.
For *small* files (body smaller than `(before+1)·128 KB + skipped`), only the leading chunks are encrypted and the tail is left as plaintext. Trying to "decrypt" the plaintext tail with Salsa20 will scramble it. **You must pass the correct `before/after/skipped` values to `direct-decrypt`.**
The `skipped_bytes` value is *per encryption batch* (constant across all files in the same batch). The `before` and `after` counts typically are too. Empirical defaults for the worked-example batch (`c1ea81cceaf4`): `before=3`, `after=3`, `skipped=0x520000`.
### Recovering the chunking parameters from any one file's FEI
If you don't know `(before, after, skipped)` for your batch, XOR any single file's encrypted FEI with your known keystream and read them out of the plaintext FEI layout:
```
[ apLib(filename_utf16le)     ] N bytes
[ filename_size               ] 2 bytes  uint16 LE
[ skipped_bytes               ] 8 bytes  uint64 LE
[ before_chunk_count          ] 4 bytes  uint32 LE
[ after_chunk_count           ] 4 bytes  uint32 LE
[ file_encryption_key         ] 64 bytes
```
### Validated example (this package's test recovery)
After `brute-extend` recovered the `file_encryption_key` for `DOCUMENT_1.pdf`:
```bash path=null start=null
direct-decrypt \
    "DOCUMENT_1.pdf.MoHsVxKYI" \
    "DECRYPTED_DOCUMENT_1.pdf" \
    "258d162481 9b2395d3 7bd7d72a dfbefd 048fd4b4 46e4aae8 5d053370 87dfeffa 2c0ec2e4 cf1fe108 93afad7a cc650bbf 9d382299 d31b3f0a bb12867e 59ff4ce9" \
    3 3 0x520000
```
Produces a 703 KB output file that `pdfinfo` reads as:
```
Creator:         Adobe LiveCycle Designer ES 9.0
Producer:        Adobe LiveCycle Designer ES 9.0
CreationDate:    Sat May 25 12:35:34 2013 CEST
ModDate:         Wed Mar 22 14:49:38 2017 CET
Form:            AcroForm
```
A full, structurally valid, openable PDF — recovered from a file we couldn't touch before the segfault fix.
### Why `direct-decrypt` doesn't segfault
It calls the LockBit Salsa20 shellcode only **once per chunk** — at most a few dozen calls per file. The cumulative ESP drift never escapes the mapping, especially with the extra 256 KB of `MMAP_PAD` we add. So the shellcode is safe in `direct-decrypt` even though it isn't in `brute-extend` (which makes up to 2³² calls).
## 7. Summary

- The original brute-force tool segfaults because the LockBit Salsa20 shellcode uses its own mmap as a private stack and leaks ESP a few bytes per call. After many calls, ESP escapes the mapping and the next push faults.
- The fix is `brute_extend2.c`: a pure-C reimplementation of modified-Salsa20 that has no such issue.
- Pure-C runs at ~8 M iter/s on a modern desktop; 4-byte brute force completes in ~9 minutes.
- **Always use ≥7-byte magic** to avoid false positives at 2³² iterations.
- With brute force, we extended the keystream for our test batch from 106 → 113 bytes, unlocking previously-stuck files. The same technique applies to any batch where you have intermediate-fei_len files to climb byte-by-byte.
