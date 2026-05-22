#include "../include/zipseal.h"
#include <stdio.h>

int calcHash(const char *path, unsigned char out[32]) 
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    unsigned char buf[BUFSIZ];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    unsigned int len;
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return 0;
}

void toBase64(const unsigned char hash[32], char out[45]) {
    int n = EVP_EncodeBlock((unsigned char *)out, hash, 32);
    out[n] = '\0';
}