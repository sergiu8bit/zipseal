#include "../include/zipseal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// out must be at least EVP_MAX_MD_SIZE (64) bytes.
// algo is a name like "sha256", "sha512", "sha1", "md5", "sha3-256"...
// Returns the digest length on success, -1 on error.
int calcHash(const char *path, const char *algo, int skip, unsigned char *out)
{
    const EVP_MD *md = EVP_get_digestbyname(algo);
    if (!md) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long total = ftell(f);
    long to_hash = total - skip;
    if (to_hash < 0) { fclose(f); return -1; }
    rewind(f);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[BUFSIZ];
    long remaining = to_hash;
    while (remaining > 0) {
        size_t chunk = (size_t)(remaining < (long)sizeof(buf) ? remaining : (long)sizeof(buf));
        size_t n = fread(buf, 1, chunk, f);
        if (n == 0) break;
        EVP_DigestUpdate(ctx, buf, n);
        remaining -= (long)n;
    }

    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);

    EVP_MD_CTX_free(ctx);
    fclose(f);
    return (int)len;
}

char *toBase64(const unsigned char *data, int len) {
    size_t sz = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(sz);
    if (!out) return NULL;
    int n = EVP_EncodeBlock((unsigned char *)out, data, len);
    out[n] = '\0';
    return out;
}

// Sign a pre-computed hash with a PEM private key.
// Caller must free *out. Returns signature length or -1 on error.
int signHash(const unsigned char *hash, int hash_len, const char *key,
             unsigned char **out)
{
    FILE *kf = fopen(key, "r");
    if (!kf) return -1;

    EVP_PKEY *pkey = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);
    if (!pkey) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { EVP_PKEY_free(pkey); return -1; }

    size_t sig_len = 0;
    int ok = EVP_PKEY_sign_init(ctx) == 1
          && EVP_PKEY_sign(ctx, NULL, &sig_len, hash, (size_t)hash_len) == 1;

    unsigned char *sig = NULL;
    if (ok) {
        sig = malloc(sig_len);
        ok = sig && EVP_PKEY_sign(ctx, sig, &sig_len, hash, (size_t)hash_len) == 1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok) { free(sig); return -1; }

    *out = sig;
    return (int)sig_len;
}

int applySeal(const char *zip, const char *b64, int b64_len)
{
    zip_t *za = zip_open(zip, 0, NULL);
    if (!za) return -1;

    if (zip_set_archive_comment(za, b64, (zip_uint16_t)b64_len) != 0) {
        zip_discard(za);
        return -1;
    }

    if (zip_close(za) != 0) return -1;
    return b64_len;
}

// Read the zip archive comment. Caller must free *b64_out.
// Returns comment length or -1 on error.
int extractSeal(const char *zip, char **b64_out)
{
    zip_t *za = zip_open(zip, ZIP_RDONLY, NULL);
    if (!za) return -1;

    int len = 0;
    const char *comment = zip_get_archive_comment(za, &len, 0);
    if (!comment || len <= 0) { zip_close(za); return -1; }

    char *buf = malloc((size_t)len + 1);
    if (!buf) { zip_close(za); return -1; }
    memcpy(buf, comment, (size_t)len);
    buf[len] = '\0';

    zip_close(za);
    *b64_out = buf;
    return len;
}

// Returns 1 = valid, 0 = invalid signature, -1 = error.
int verifySeal(const unsigned char *hash, int hash_len,
               const unsigned char *sig, int sig_len, const char *pub_key)
{
    FILE *kf = fopen(pub_key, "r");
    if (!kf) return -1;

    EVP_PKEY *pkey = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
    fclose(kf);
    if (!pkey) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { EVP_PKEY_free(pkey); return -1; }

    int rc = -1;
    if (EVP_PKEY_verify_init(ctx) == 1) {
        int v = EVP_PKEY_verify(ctx, sig, (size_t)sig_len,
                                hash, (size_t)hash_len);
        rc = (v == 1) ? 1 : 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}