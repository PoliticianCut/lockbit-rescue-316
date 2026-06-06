/*
 * direct_decrypt.c -- decrypt a LockBit-3-encrypted file body given the
 * already-recovered file_encryption_key (64-byte Salsa20 state).
 *
 * Useful when keystream-extension brute force (e.g. via brute_extend2)
 * recovered the file_encryption_key but the standard stream-reuse path
 * isn't usable (e.g. fei_len exceeds the oracle's coverage).
 *
 * The body decryption uses the original LockBit Salsa20 shellcode. The
 * shellcode is invoked only a handful of times per file (one per encrypted
 * chunk), so the cumulative ESP drift that segfaults brute_extend doesn't
 * apply here. We additionally pad the mmap region by 256 KB just to be safe.
 *
 * Usage:
 *   direct_decrypt <encrypted_file> <output_file> <key_hex_64_bytes>
 *                  <before_chunk_count> <after_chunk_count> <skipped_bytes_hex>
 *
 * Example (DOCUMENT_1.pdf recovery):
 *   direct_decrypt "DOCUMENT_1.pdf.MoHsVxKYI" "DECRYPTED_DOCUMENT_1.pdf" \
 *       "258d162481[…64 hex bytes total…]59ff4ce9" 3 3 0x520000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "frank.h"

#define OFFSET_KEY_ENCRYPTION_INFO  0x86
#define CHUNK_SIZE                  0x20000
#define MMAP_PAD                    (256 * 1024)

typedef void (__attribute__((stdcall)) *FUNC_SALSA20_decrypt)(uint32_t, void *, void *);
static FUNC_SALSA20_decrypt SALSA20_decrypt_func = NULL;

static void prepare_salsa(void) {
    void *p = mmap(NULL, salsa_crypt_len + MMAP_PAD,
                   PROT_EXEC | PROT_WRITE | PROT_READ,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    memcpy(p, salsa_crypt, salsa_crypt_len);
    SALSA20_decrypt_func = (FUNC_SALSA20_decrypt)p;
}

static int parse_hex_key(const char *s, uint8_t key[64]) {
    int n = 0;
    for (const char *p = s; *p && n < 64; ) {
        if (*p == ' ' || *p == ':' || *p == ',') { p++; continue; }
        if (!p[1]) return -1;
        unsigned int v;
        if (sscanf(p, "%2x", &v) != 1) return -1;
        key[n++] = (uint8_t)v;
        p += 2;
    }
    return n;
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        fprintf(stderr,
            "Usage: %s <encrypted> <output> <key_hex_64> <before_count> <after_count> <skipped_hex>\n",
            argv[0]);
        return 1;
    }
    const char *in_path     = argv[1];
    const char *out_path    = argv[2];
    const char *key_hex     = argv[3];
    uint32_t before_count   = (uint32_t)strtoul(argv[4], NULL, 0);
    uint32_t after_count    = (uint32_t)strtoul(argv[5], NULL, 0);
    uint64_t skipped_bytes  = (uint64_t)strtoull(argv[6], NULL, 0);

    uint8_t key[64] = { 0 };
    int kn = parse_hex_key(key_hex, key);
    if (kn != 64) {
        fprintf(stderr, "ERROR: key hex must be exactly 64 bytes (128 hex chars), got %d bytes\n", kn);
        return 2;
    }
    fprintf(stderr, "[+] key parsed (64 bytes). before=%u, after=%u, skipped=0x%llx\n",
            before_count, after_count, (unsigned long long)skipped_bytes);

    prepare_salsa();

    FILE *fi = fopen(in_path, "rb");
    if (!fi) { perror(in_path); return 3; }
    fseek(fi, 0, SEEK_END);
    long total = ftell(fi);
    long body_end = total - OFFSET_KEY_ENCRYPTION_INFO;
    /* Determine fei_len so we can find the actual body length */
    fseek(fi, -OFFSET_KEY_ENCRYPTION_INFO, SEEK_END);
    uint16_t fei_len;
    if (fread(&fei_len, 2, 1, fi) != 1) { fprintf(stderr, "read fei_len failed\n"); return 4; }
    body_end -= fei_len;
    fprintf(stderr, "[+] file size=%ld, fei_len=%u, body_end=%ld (%.1f KB body)\n",
            total, fei_len, body_end, body_end / 1024.0);

    FILE *fo = fopen(out_path, "wb");
    if (!fo) { perror(out_path); return 5; }

    fseek(fi, 0, SEEK_SET);
    uint8_t *chunk = (uint8_t *)malloc(CHUNK_SIZE);
    uint8_t  key_copy[64];

    /* Replay the stream-reuse `do_decrypt` loop */
    int is_skip = 0;
    uint32_t decrypt_chunk_count = before_count;
    long cur = 0;

    while (cur < body_end) {
        if (is_skip) {
            /* Skip phase: copy bytes through unchanged */
            uint64_t toskip = skipped_bytes;
            fprintf(stderr, "[+] SKIPPING 0x%llx bytes at body offset 0x%lx\n",
                    (unsigned long long)toskip, cur);
            while (toskip > 0 && cur < body_end) {
                size_t want = (toskip > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)toskip;
                if (cur + (long)want > body_end) want = (size_t)(body_end - cur);
                size_t got = fread(chunk, 1, want, fi);
                fwrite(chunk, 1, got, fo);
                toskip -= got;
                cur    += got;
                if (got == 0) break;  /* EOF */
            }
            decrypt_chunk_count = after_count;
            is_skip = 0;
        } else {
            /* Decrypt one chunk */
            long want = body_end - cur;
            if (want > CHUNK_SIZE) want = CHUNK_SIZE;
            size_t got = fread(chunk, 1, want, fi);
            if (got == 0) break;
            /* Re-prime key for this chunk: the shellcode mutates state across
             * chunks within a contiguous encrypted region, but we replay each
             * encrypted region from the file_encryption_key as initial state.
             * This matches the do_decrypt logic in stream-reuse.c, where the
             * `&fnfn->fei.file_encryption_key` argument is the SAME pointer
             * each call -- and the shellcode treats it as state that advances
             * naturally across calls within a contiguous decryption phase.
             *
             * That means: within a contiguous "before" or "after" phase, we
             * must NOT reset the key between chunk calls. We only reset it
             * conceptually because we KEEP THE SAME key pointer.
             */
            (void)key_copy;
            SALSA20_decrypt_func((uint32_t)got, chunk, key);
            fwrite(chunk, 1, got, fo);
            cur += got;
            fprintf(stderr, "[+] DECRYPTED chunk @ body offset 0x%lx (%zu bytes)\n",
                    cur - got, got);

            if (decrypt_chunk_count == 0) {
                is_skip = 1;
            } else {
                decrypt_chunk_count -= 1;
            }
        }
    }

    free(chunk);
    fclose(fi);
    fclose(fo);
    fprintf(stderr, "[+] Done. Wrote %s\n", out_path);
    return 0;
}
