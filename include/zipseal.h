#ifndef ZIPSEAL_H_INCLUDED
#define ZIPSEAL_H_INCLUDED

#include <zip.h>
#include <openssl/evp.h>

void toBase64(const unsigned char *hash, int len, char *out);

int calcHash(const char *path, const char *algo, unsigned char *out);

int signHash(const char *zip, const char *key);

int applySeal();

int extractSeal();

int verifySeal();

int compareSeals();

#endif