#ifndef ZIPSEAL_H_INCLUDED
#define ZIPSEAL_H_INCLUDED

#include <zip.h>
#include <openssl/evp.h>

char *toBase64(const unsigned char *data, int len);

int calcHash(const char *path, const char *algo, int skip, unsigned char *out);

int signHash(const unsigned char *hash, int hash_len, const char *key,
             unsigned char **out);

int applySeal(const char *zip, const char *b64, int b64_len);

int extractSeal(const char *zip, char **b64_out);

int verifySeal(const unsigned char *hash, int hash_len,
               const unsigned char *sig, int sig_len, const char *pub_key);

#endif