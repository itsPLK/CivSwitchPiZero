/* LDN v2 encrypted advertisement validation; layout/KDF follows the local
 * esp32-ldn-civ7 reference. Keys are loaded from removable media, never logged. */
#ifndef CIVSWITCH_LDN_CRYPTO_H
#define CIVSWITCH_LDN_CRYPTO_H
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "ldn_advertisement.h"

static unsigned char ldn_keys[3][16];
static bool ldn_keys_ready;
static const char *ldn_key_status;
static int ldn_key_errno;
static unsigned ldn_key_mask;
static int ldn_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool ldn_load_keys(const char *path) {
    static const char *names[] = {"master_key_00", "aes_kek_generation_source", "aes_key_generation_source"};
    unsigned mask = 0;
    char line[512];
    OPENSSL_cleanse(ldn_keys, sizeof(ldn_keys)); ldn_keys_ready = false;
    ldn_key_status = "missing_entries"; ldn_key_errno = 0; ldn_key_mask = 0;
    FILE *f = fopen(path, "r");
    if (!f) { ldn_key_status = "open_failed"; ldn_key_errno = errno; return false; }
    bool valid = true;
    while (fgets(line, sizeof(line), f)) {
        bool long_line = !strchr(line, '\n') && !feof(f);
        if (long_line) { int c; while ((c = fgetc(f)) != '\n' && c != EOF) {} }
        char *p = line;
        if (strlen(p) >= 3 && !memcmp(p, "\xef\xbb\xbf", 3)) p += 3;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#') continue;
        char *eq = strchr(p, '='); if (!eq) continue;
        char *end = eq; while (end > p && isspace((unsigned char)end[-1])) end--;
        *end = 0;
        for (unsigned k = 0; k < 3; k++) if (!strcmp(p, names[k])) {
            if (long_line) { valid = false; break; }
            if (mask & (1u << k)) { valid = false; break; }
            char *v = eq + 1; while (isspace((unsigned char)*v)) v++;
            if (strlen(v) < 32) { valid = false; break; }
            for (unsigned i = 0; i < 16; i++) {
                int hi = ldn_hex(v[2*i]), lo = ldn_hex(v[2*i+1]);
                if (hi < 0 || lo < 0) { valid = false; break; }
                ldn_keys[k][i] = (unsigned char)((hi << 4) | lo);
            }
            v += 32; while (isspace((unsigned char)*v)) v++;
            if (*v && *v != '#') valid = false;
            mask |= 1u << k;
        }
        if (!valid) break;
    }
    if (!valid) ldn_key_status = "malformed_or_duplicate_entry";
    if (ferror(f)) { valid = false; ldn_key_status = "read_failed"; ldn_key_errno = errno; }
    ldn_key_mask = mask;
    fclose(f); OPENSSL_cleanse(line, sizeof(line));
    ldn_keys_ready = valid && mask == 7;
    if (ldn_keys_ready) ldn_key_status = "loaded";
    if (!ldn_keys_ready) OPENSSL_cleanse(ldn_keys, sizeof(ldn_keys));
    return ldn_keys_ready;
}
static bool ldn_cipher(const EVP_CIPHER *cipher, const unsigned char key[16],
                       const unsigned char *iv, const unsigned char *in,
                       int size, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int n = 0, tail = 0;
    bool ok = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_DecryptUpdate(ctx, out, &n, in, size) == 1 &&
        EVP_DecryptFinal_ex(ctx, out + n, &tail) == 1 && n + tail == size;
    EVP_CIPHER_CTX_free(ctx); return ok;
}
/* Return true only after the complete decrypted body passes SHA-256 validation. */
static bool ldn_decrypt_advertisement(const unsigned char *frame, size_t size,
                                      unsigned char body[1280]) {
    static const unsigned char source[16] = {0x19,0x18,0x84,0x74,0x3e,0x24,0xc7,0x7d,0x87,0xc6,0x9e,0x42,0x07,0xd0,0xc4,0x38};
    LdnAdvertisement a;
    unsigned char kek[16], next[16], key[16], digest[32], iv[16] = {0};
    unsigned char plain[1328], check[1352];
    unsigned int digest_size = 0;
    bool ok = false;
    memset(body, 0, 1280);
    if (!ldn_keys_ready || !ldn_advertisement_parse(frame, size, &a)) return false;
    if (!ldn_cipher(EVP_aes_128_ecb(), ldn_keys[0], NULL, ldn_keys[1], 16, kek) ||
        !ldn_cipher(EVP_aes_128_ecb(), kek, NULL, source, 16, next) ||
        !ldn_cipher(EVP_aes_128_ecb(), next, NULL, ldn_keys[2], 16, kek) ||
        EVP_Digest(a.network_id, 32, digest, &digest_size, EVP_sha256(), NULL) != 1 ||
        !ldn_cipher(EVP_aes_128_ecb(), kek, NULL, digest, 16, key)) goto done;
    memcpy(iv, a.nonce, 4);
    if (!ldn_cipher(EVP_aes_128_ctr(), key, iv, a.ciphertext, (int)a.ciphertext_size, plain)) goto done;
    memcpy(check, frame + 36, 40); memset(check + 40, 0, 32);
    memcpy(check + 72, plain + 32, 1280);
    if (EVP_Digest(check, sizeof(check), digest, &digest_size, EVP_sha256(), NULL) != 1 ||
        digest_size != 32 || CRYPTO_memcmp(digest, plain, 32)) goto done;
    memcpy(body, plain + 32, 1280); ok = true;
done:
    OPENSSL_cleanse(kek, sizeof(kek)); OPENSSL_cleanse(next, sizeof(next));
    OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(plain, sizeof(plain));
    OPENSSL_cleanse(check, sizeof(check)); OPENSSL_cleanse(digest, sizeof(digest));
    return ok;
}
#endif
