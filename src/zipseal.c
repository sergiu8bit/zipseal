#include "../include/zipseal.h"
#include <stdio.h>
#include <openssl/evp.h>

// out must be at least EVP_MAX_MD_SIZE (64) bytes.
// algo is a name like "sha256", "sha512", "sha1", "md5", "sha3-256"...
// Returns the digest length on success, -1 on error.
int calcHash(const char *path, const char *algo, unsigned char *out)
{
    const EVP_MD *md = EVP_get_digestbyname(algo);
    if (!md) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[BUFSIZ];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);

    EVP_MD_CTX_free(ctx);
    fclose(f);
    return (int)len;
}

void toBase64(const unsigned char *hash, int len, char *out) {
    int n = EVP_EncodeBlock((unsigned char *)out, hash, len);
    out[n] = '\0';
}