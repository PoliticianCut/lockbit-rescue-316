/*
 * brute_extend3.c -- generalized version of brute_extend2.
 *
 * Differences from brute_extend2.c:
 *   1. No batch-specific hardcoded keystream bytes (0x56/0x23/0x8a etc.).
 *      brute_extend3 always starts from the natural 106-byte coverage that
 *      the oracle's known plaintext gives, then optionally accepts more
 *      keystream bytes via --ks-extend HEX.
 *   2. Output is machine-parseable: lines begin with `KSEXT:`, `FEK:`,
 *      `DEC32:` so a Python driver can extract recovered keystream bytes
 *      and the file_encryption_key reliably.
 *   3. Same pure-C Salsa20 internals -- no shellcode, no segfault risk.
 *
 * Usage:
 *   brute_extend3 <target_enc> <oracle_enc> <oracle_orig_name> <magic_hex> \
 *                 <max_bytes> <before_count> <after_count> <skipped_hex> \
 *                 [ks_extend_hex]
 *
 * Where:
 *   <before_count>  LockBit intermittent encryption: before_chunk_count
 *   <after_count>   LockBit intermittent encryption: after_chunk_count
 *   <skipped_hex>   LockBit intermittent encryption: skipped_bytes (e.g. 0x520000)
 *   <ks_extend_hex> is an OPTIONAL contiguous-keystream-extension byte
 *   string (e.g. "5623 8a") that extends the natural 106-byte oracle
 *   baseline to (106 + len(ks_extend)) bytes before brute-forcing.
 *
 * Stdout (one match):
 *   KSEXT:<hex of newly-brute-forced bytes>
 *   FEK:<hex of recovered file_encryption_key, 64 bytes>
 *   DEC32:<hex of decrypted first 32 plaintext bytes>
 *   STATUS:OK
 *
 * On failure:
 *   STATUS:NO_MATCH
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include "aplib.h"
#include <iconv.h>

#define OFFSET_KEY_ENCRYPTION_INFO  0x86
#define CHUNK_SIZE                  0x20000
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline void salsa20_block(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, 64);
    for (int i = 0; i < 10; i++) {
        x[ 4] ^= ROTL32(x[ 0] + x[12],  7);
        x[ 8] ^= ROTL32(x[ 4] + x[ 0],  9);
        x[12] ^= ROTL32(x[ 8] + x[ 4], 13);
        x[ 0] ^= ROTL32(x[12] + x[ 8], 18);
        x[ 9] ^= ROTL32(x[ 5] + x[ 1],  7);
        x[13] ^= ROTL32(x[ 9] + x[ 5],  9);
        x[ 1] ^= ROTL32(x[13] + x[ 9], 13);
        x[ 5] ^= ROTL32(x[ 1] + x[13], 18);
        x[14] ^= ROTL32(x[10] + x[ 6],  7);
        x[ 2] ^= ROTL32(x[14] + x[10],  9);
        x[ 6] ^= ROTL32(x[ 2] + x[14], 13);
        x[10] ^= ROTL32(x[ 6] + x[ 2], 18);
        x[ 3] ^= ROTL32(x[15] + x[11],  7);
        x[ 7] ^= ROTL32(x[ 3] + x[15],  9);
        x[11] ^= ROTL32(x[ 7] + x[ 3], 13);
        x[15] ^= ROTL32(x[11] + x[ 7], 18);
        x[ 1] ^= ROTL32(x[ 0] + x[ 3],  7);
        x[ 2] ^= ROTL32(x[ 1] + x[ 0],  9);
        x[ 3] ^= ROTL32(x[ 2] + x[ 1], 13);
        x[ 0] ^= ROTL32(x[ 3] + x[ 2], 18);
        x[ 6] ^= ROTL32(x[ 5] + x[ 4],  7);
        x[ 7] ^= ROTL32(x[ 6] + x[ 5],  9);
        x[ 4] ^= ROTL32(x[ 7] + x[ 6], 13);
        x[ 5] ^= ROTL32(x[ 4] + x[ 7], 18);
        x[11] ^= ROTL32(x[10] + x[ 9],  7);
        x[ 8] ^= ROTL32(x[11] + x[10],  9);
        x[ 9] ^= ROTL32(x[ 8] + x[11], 13);
        x[10] ^= ROTL32(x[ 9] + x[ 8], 18);
        x[12] ^= ROTL32(x[15] + x[14],  7);
        x[13] ^= ROTL32(x[12] + x[15],  9);
        x[14] ^= ROTL32(x[13] + x[12], 13);
        x[15] ^= ROTL32(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + state[i];
        out[i*4 + 0] = (v >>  0) & 0xFF;
        out[i*4 + 1] = (v >>  8) & 0xFF;
        out[i*4 + 2] = (v >> 16) & 0xFF;
        out[i*4 + 3] = (v >> 24) & 0xFF;
    }
}

static int compress_filename_utf16le(const char *long_name, uint8_t *output, int output_max) {
    iconv_t cd = iconv_open("UTF-16LE", "UTF-8");
    if (cd == (iconv_t)-1) return -1;
    size_t sourceLen = strlen(long_name);
    size_t bufferSize = sourceLen * 2 + 4;
    wchar_t *utf16Buffer = (wchar_t *)calloc(bufferSize + 1, sizeof(wchar_t));
    char *inbuf = (char *)long_name;
    char *outbuf = (char *)utf16Buffer;
    size_t inbytesleft = sourceLen;
    size_t outbytesleft = bufferSize * sizeof(wchar_t);
    if (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) == (size_t)-1) {
        iconv_close(cd); free(utf16Buffer); return -1;
    }
    iconv_close(cd);
    int finalLen = (bufferSize * sizeof(wchar_t)) - outbytesleft;
    finalLen += 2;  // null terminator pair
    void *workmem = malloc(aP_workmem_size(0));
    unsigned int sz = aP_pack(utf16Buffer, output, finalLen, workmem, NULL, NULL);
    free(workmem); free(utf16Buffer);
    return (int)sz;
}

static int parse_hex_bytes(const char *s, uint8_t *out, int max_bytes) {
    int n = 0;
    for (const char *p = s; *p && n < max_bytes; ) {
        if (*p == ' ' || *p == ':' || *p == ',') { p++; continue; }
        if (!p[1]) return -1;
        unsigned int v;
        if (sscanf(p, "%2x", &v) != 1) return -1;
        out[n++] = (uint8_t)v;
        p += 2;
    }
    return n;
}

int main(int argc, char *argv[]) {
    if (argc < 9) {
        fprintf(stderr, "Usage: %s <target> <oracle> <oracle_name> <magic_hex> <max_bytes> "
                        "<before_count> <after_count> <skipped_hex> [ks_extend_hex]\n",
                argv[0]);
        return 1;
    }
    const char *target = argv[1];
    const char *oracle_enc = argv[2];
    const char *oracle_name = argv[3];
    const char *magic_hex = argv[4];
    int max_bytes = atoi(argv[5]);
    uint32_t before_count = (uint32_t)strtoul(argv[6], NULL, 0);
    uint32_t after_count  = (uint32_t)strtoul(argv[7], NULL, 0);
    uint64_t skipped_bytes = (uint64_t)strtoull(argv[8], NULL, 0);
    const char *ks_extend_hex = (argc > 9) ? argv[9] : NULL;

    int magic_len = strlen(magic_hex) / 2;
    if (magic_len > 16) { fprintf(stderr, "Magic too long (max 16 bytes)\n"); return 1; }
    uint8_t magic[16];
    for (int i = 0; i < magic_len; i++) sscanf(magic_hex + 2*i, "%2hhx", &magic[i]);

    // Compute oracle's compressed filename
    uint8_t compressed[1024];
    int sz = compress_filename_utf16le(oracle_name, compressed, sizeof(compressed));
    if (sz <= 0) { fprintf(stderr, "compress fail\n"); return 1; }
    fprintf(stderr, "[+] oracle filename compressed: %d bytes\n", sz);

    // Load oracle FEI
    FILE *fo = fopen(oracle_enc, "rb"); if (!fo) { perror(oracle_enc); return 1; }
    fseek(fo, -OFFSET_KEY_ENCRYPTION_INFO, SEEK_END);
    uint16_t ofl; fread(&ofl, 2, 1, fo);
    fseek(fo, -(OFFSET_KEY_ENCRYPTION_INFO + ofl), SEEK_END);
    uint8_t *ofei = malloc(ofl); fread(ofei, 1, ofl, fo); fclose(fo);

    // Build oracle's 106-byte known plaintext (filename + 18 metadata)
    int known_len = sz + 18;
    uint8_t *kp = malloc(known_len);
    memcpy(kp, compressed, sz);
    kp[sz+0] = sz & 0xFF; kp[sz+1] = (sz>>8)&0xFF;
    /* skipped_bytes: 8-byte little-endian */
    kp[sz+2]  = (skipped_bytes >>  0) & 0xFF;
    kp[sz+3]  = (skipped_bytes >>  8) & 0xFF;
    kp[sz+4]  = (skipped_bytes >> 16) & 0xFF;
    kp[sz+5]  = (skipped_bytes >> 24) & 0xFF;
    kp[sz+6]  = (skipped_bytes >> 32) & 0xFF;
    kp[sz+7]  = (skipped_bytes >> 40) & 0xFF;
    kp[sz+8]  = (skipped_bytes >> 48) & 0xFF;
    kp[sz+9]  = (skipped_bytes >> 56) & 0xFF;
    /* before_chunk_count: 4-byte little-endian */
    kp[sz+10] = (before_count >>  0) & 0xFF;
    kp[sz+11] = (before_count >>  8) & 0xFF;
    kp[sz+12] = (before_count >> 16) & 0xFF;
    kp[sz+13] = (before_count >> 24) & 0xFF;
    /* after_chunk_count: 4-byte little-endian */
    kp[sz+14] = (after_count >>  0) & 0xFF;
    kp[sz+15] = (after_count >>  8) & 0xFF;
    kp[sz+16] = (after_count >> 16) & 0xFF;
    kp[sz+17] = (after_count >> 24) & 0xFF;
    if (known_len > ofl) { fprintf(stderr, "oracle too short\n"); return 1; }

    // Keystream buffer with extra room for extension
    uint8_t *ks = calloc(known_len + 4096, 1);
    for (int i = 0; i < known_len; i++) ks[i] = ofei[i] ^ kp[i];
    fprintf(stderr, "[+] keystream baseline from oracle: %d bytes\n", known_len);

    // Apply optional --ks-extend bytes (chained from a prior ladder climb)
    int ext_added = 0;
    if (ks_extend_hex) {
        ext_added = parse_hex_bytes(ks_extend_hex, ks + known_len, 4096);
        if (ext_added < 0) { fprintf(stderr, "bad ks_extend_hex\n"); return 1; }
        known_len += ext_added;
        fprintf(stderr, "[+] keystream extended via --ks-extend by %d bytes -> total %d\n",
                ext_added, known_len);
    }

    // Load target
    FILE *ft = fopen(target, "rb"); if (!ft) { perror(target); return 1; }
    fseek(ft, 0, SEEK_END); long tsize = ftell(ft);
    fseek(ft, -OFFSET_KEY_ENCRYPTION_INFO, SEEK_END);
    uint16_t tfl; fread(&tfl, 2, 1, ft);
    fseek(ft, -(OFFSET_KEY_ENCRYPTION_INFO + tfl), SEEK_END);
    uint8_t *tfei = malloc(tfl); fread(tfei, 1, tfl, ft);
    fseek(ft, 0, SEEK_SET);
    long content_size = tsize - tfl - OFFSET_KEY_ENCRYPTION_INFO;
    long chunk_size = content_size < CHUNK_SIZE ? content_size : CHUNK_SIZE;
    uint8_t *first_chunk = malloc(chunk_size);
    fread(first_chunk, 1, chunk_size, ft);
    fclose(ft);

    int missing = tfl - known_len;
    fprintf(stderr, "[+] target fei_len=%d, missing %d byte(s)\n", tfl, missing);

    if (missing < 0) {
        // No brute force needed -- target FEI already covered by keystream
        // Compute file_encryption_key directly via XOR
        int key_offset = tfl - 64;
        uint8_t fek[64];
        for (int i = 0; i < 64; i++) fek[i] = tfei[key_offset + i] ^ ks[key_offset + i];

        // Validate with magic
        uint32_t state[16];
        for (int i = 0; i < 16; i++) {
            state[i] = ((uint32_t)fek[i*4 + 0])
                     | ((uint32_t)fek[i*4 + 1]) << 8
                     | ((uint32_t)fek[i*4 + 2]) << 16
                     | ((uint32_t)fek[i*4 + 3]) << 24;
        }
        uint8_t keyblock[64];
        salsa20_block(state, keyblock);
        int ok = 1;
        for (int i = 0; i < magic_len; i++) {
            if ((first_chunk[i] ^ keyblock[i]) != magic[i]) { ok = 0; break; }
        }
        if (!ok) {
            fprintf(stderr, "[!] keystream covered target but magic check failed -- bad keystream\n");
            printf("STATUS:BAD_KEYSTREAM\n");
            return 2;
        }
        // Emit results
        printf("KSEXT:\n");  // no new bytes brute-forced
        printf("FEK:");
        for (int i = 0; i < 64; i++) printf("%02x", fek[i]);
        printf("\n");
        printf("DEC32:");
        for (int i = 0; i < 32; i++) printf("%02x", first_chunk[i] ^ keyblock[i]);
        printf("\n");
        printf("STATUS:OK_NOBRUTE\n");
        return 0;
    }

    if (missing > max_bytes) {
        fprintf(stderr, "missing %d > max %d\n", missing, max_bytes);
        printf("STATUS:GAP_TOO_BIG\n");
        return 3;
    }

    uint64_t total_iters = 1ULL << (missing * 8);
    fprintf(stderr, "[*] brute forcing %d byte(s) = %llu iterations\n",
            missing, (unsigned long long)total_iters);

    time_t start = time(NULL);
    uint64_t report_interval = total_iters > 100000000 ? total_iters / 100 : total_iters + 1;

    int key_offset = tfl - 64;
    uint32_t state[16];
    uint8_t keyblock[64];

    for (uint64_t guess = 0; guess < total_iters; guess++) {
        for (int i = 0; i < missing; i++) {
            ks[known_len + i] = (guess >> (i * 8)) & 0xFF;
        }
        for (int i = 0; i < 16; i++) {
            state[i] = ((uint32_t)(tfei[key_offset + i*4 + 0] ^ ks[key_offset + i*4 + 0]))
                     | ((uint32_t)(tfei[key_offset + i*4 + 1] ^ ks[key_offset + i*4 + 1])) << 8
                     | ((uint32_t)(tfei[key_offset + i*4 + 2] ^ ks[key_offset + i*4 + 2])) << 16
                     | ((uint32_t)(tfei[key_offset + i*4 + 3] ^ ks[key_offset + i*4 + 3])) << 24;
        }
        salsa20_block(state, keyblock);
        int ok = 1;
        for (int i = 0; i < magic_len; i++) {
            if ((first_chunk[i] ^ keyblock[i]) != magic[i]) { ok = 0; break; }
        }
        if (ok) {
            time_t elapsed = time(NULL) - start;
            fprintf(stderr, "[+] MATCH at guess=0x%llx after %llu iters (%lds)\n",
                    (unsigned long long)guess, (unsigned long long)(guess + 1), (long)elapsed);
            // Emit machine-parseable results
            printf("KSEXT:");
            for (int i = 0; i < missing; i++) printf("%02x", ks[known_len + i]);
            printf("\n");
            uint8_t fek[64];
            for (int i = 0; i < 64; i++) fek[i] = tfei[key_offset + i] ^ ks[key_offset + i];
            printf("FEK:");
            for (int i = 0; i < 64; i++) printf("%02x", fek[i]);
            printf("\n");
            printf("DEC32:");
            for (int i = 0; i < 32; i++) printf("%02x", first_chunk[i] ^ keyblock[i]);
            printf("\n");
            printf("STATUS:OK_BRUTE\n");
            return 0;
        }
        if (guess > 0 && (guess % report_interval) == 0) {
            time_t elapsed = time(NULL) - start;
            double rate = (double)guess / (elapsed > 0 ? elapsed : 1);
            double pct = 100.0 * (double)guess / (double)total_iters;
            long eta = (long)(((double)total_iters - guess) / rate);
            fprintf(stderr, "[..] %llu / %llu (%.2f%%) rate=%.0f/s ETA=%lds\n",
                    (unsigned long long)guess, (unsigned long long)total_iters, pct, rate, eta);
        }
    }
    fprintf(stderr, "[!] no match after %llu iterations\n", (unsigned long long)total_iters);
    printf("STATUS:NO_MATCH\n");
    return 4;
}
