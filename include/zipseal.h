#ifndef ZIPSEAL_H_INCLUDED
#define ZIPSEAL_H_INCLUDED

#include <zip.h>
#include <openssl/evp.h>

int calcHash(const char *path, unsigned char hash[32]);

int signHash(const char *zip, const char *key);

int applySeal();

int extractSeal();

int verifySeal();

int compareSeals();

#endif