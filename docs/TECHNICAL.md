# Technical reference: LockBit 3.0 ("Black") keystream-reuse decryption

This document captures the practical cryptographic details we relied on to build `lockbit-rescue`. For the original research and theoretical write-up see Calif.io's [LockBit 3.0 decryptor blog post](https://www.calif.io/blog/lockbit-3.0-decryptor).

## 1. Cipher

LockBit 3.0 ("Black") encrypts file content with a **modified Salsa20**. Two notable changes from textbook Salsa20:

1. The 64-byte initial state contains **no fixed `sigma`/`tau` constants** — it is fully random per encryption batch. (Standard Salsa20 fixes 16 of the 64 bytes to ASCII `"expand 32-byte k"`.)
2. The block counter is initialized as part of the random state, so we cannot independently regenerate the keystream without recovering that state.

The implementation is shipped as obfuscated shellcode inside the LockBit binary. Reimplementing it from scratch is non-trivial — the `stream-reuse` tool wraps the *original* shellcode and re-invokes it on adversary-controlled input to extract keystream / decrypt.

## 2. File layout

For each victim file, the encrypted blob looks like:

```
+-------------------------------------------------------+
|  Encrypted body (chunked Salsa20 stream over plaintext) |
+-------------------------------------------------------+
|  Footer Encryption Info (FEI)  — variable length      |
|     <fei_len> bytes, encrypted with the SAME stream   |
|                                                       |
|     plaintext layout:                                 |
|       [ apLib(UTF-16LE original filename) ]   N bytes |
|       [ filename_size       ]               2 bytes   |
|       [ skipped_bytes        ]              8 bytes   |
|       [ before_chunk_count   ]              4 bytes   |
|       [ after_chunk_count    ]              4 bytes   |
+-------------------------------------------------------+
|  Footer tail (constant 134 bytes)                     |
|     [ fei_len               ]               2 bytes   |  ← uint16 LE
|     [ checksum              ]               4 bytes   |
|     [ RSA-encrypted KEK     ]             128 bytes   |
+-------------------------------------------------------+
```

The `fei_len` field at offset `-134` tells us how many bytes of encrypted footer come before the constant 132-byte tail.

The 128-byte KEK blob at offset `-128` is the RSA-encrypted Key Encryption Key. **It is byte-for-byte identical for every file encrypted in the same batch.** That makes it a perfect group identifier.

## 3. Grouping by batch

```python
def kek_fingerprint(blob):
    return hashlib.md5(blob).hexdigest()[:12]   # 12 hex chars is plenty for collision-free buckets
```

Walking the victim filesystem, we read the last 128 bytes of each encrypted file, hash them, and bucket files by that hash. Each bucket is one encryption session, and within a bucket all files share the same Salsa20 keystream.

## 4. Choosing an oracle

For each bucket we choose the file with the largest `fei_len` as the *oracle*. The oracle contributes the most known plaintext (because of its long original filename), and therefore the most recovered keystream bytes.

## 5. Recovering keystream bytes

Plaintext at the start of the FEI region is the apLib-compressed UTF-16LE original filename. We *know* the original filename (it's literally the encrypted file's name minus the ransomware extension), so we can reproduce that plaintext exactly. The 18 trailing bytes of FEI plaintext are also recoverable empirically:

- `filename_size` is computable from the known filename (2 bytes).
- `skipped_bytes` is constant per batch and recoverable by comparing two oracles — for the user's actual run it was `0x0000000000520000`.
- `before_chunk_count` and `after_chunk_count` are determined by the encrypted body length.

Coverage in bytes for an oracle with `fei_len = L`:

```
coverage = (L - 82) + 18
         = (apLib(filename) length) + (18-byte metadata suffix)
```

The `- 82` term subtracts the *non-filename* fixed overhead inside the FEI; the `+ 18` term re-adds the 18 trailing metadata bytes whose plaintext we also know.

## 6. Decrypting other targets

Any other file in the same batch whose own `fei_len ≤ coverage` has its entire FEI block within the keystream bytes we just recovered. The `stream-reuse` tool then:

1. XORs the recovered keystream with that target's ciphertext FEI → plaintext FEI.
2. Parses `skipped_bytes`, `before_chunk_count`, `after_chunk_count` from plaintext FEI to learn the chunking parameters used to encrypt the body.
3. Calls the *original* Salsa20 shellcode (preserved inside `stream-reuse`) at the correct stream offset to recover body keystream bytes, then XORs to recover body plaintext.

The "stream offset" tricks the shellcode into producing the *same* keystream slice that was used to encrypt the target body, because the entire batch reuses one Salsa20 instance.

## 7. Resume safety

`lockbit-rescue` uses simple file-existence checks (`OUTPUT/group_<kek>/<basename>`) to decide whether to skip an already-recovered file. There is no on-disk database; resume is "the filesystem". This is robust to crashes — interrupting in the middle of a file leaves nothing recoverable in OUTPUT for that file (write happens via `copy_with_progress` *after* decryption succeeds), so the next run will retry it cleanly.

## 8. Cases the exploit cannot help

- Batch where every file has a small `fei_len` (i.e. all files had short filenames). `coverage` is too short to cover any target's FEI block.
- Files whose encrypted body extends past the keystream offset we can re-derive. Typically only files larger than ~4 GiB hit this.
- LockBit variants that don't reuse the keystream across files in a batch. So far the published research is specific to **LockBit 3.0 "Black"** ("LockBit3" with `.<random9chars>` extensions and Cyberfear ransom note style).

## 9. Pointers to the upstream code

- `stream-reuse.c` (in [yohanes/lockbit-v3-linux-decryptor](https://github.com/yohanes/lockbit-v3-linux-decryptor)) — the C harness that drives the LockBit shellcode for both keystream extraction and target decryption.
- `frank.c` / `frank.h` — the (extracted) modified-Salsa20 shellcode shim from the original ransomware binary.
- `aplib.a` / `aplib.h` — apLib decompression library, used both by the ransomware and by `stream-reuse` to compress the original filename plaintext for XOR.

`lockbit-rescue.py` does not reimplement any of these — it invokes `stream-reuse` per target file with the right oracle.
