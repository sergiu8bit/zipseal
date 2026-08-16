#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

extern "C" {
    #include "../include/zipseal.h"
}

// Helper: convert hash bytes to lowercase hex string
static std::string toHex(const unsigned char *hash, int len) {
    std::string s(len * 2, '\0');
    for (int i = 0; i < len; i++)
        sprintf(&s[i * 2], "%02x", hash[i]);
    return s;
}

// Helper: generate a throwaway RSA key pair, write PEM files
static void generateKeyPair(const char *priv_path, const char *pub_path) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    FILE *f = fopen(priv_path, "w");
    PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    f = fopen(pub_path, "w");
    PEM_write_PUBKEY(f, pkey);
    fclose(f);

    EVP_PKEY_free(pkey);
}

// Helper: write bytes to a temp file
static void writeFile(const char *path, const void *data, size_t n) {
    std::ofstream f(path, std::ios::binary);
    f.write(static_cast<const char*>(data), n);
}

// Helper: create a minimal valid zip with one empty file inside
static void createZip(const char *path) {
    zip_t *za = zip_open(path, ZIP_CREATE | ZIP_TRUNCATE, NULL);
    zip_source_t *src = zip_source_buffer(za, "", 0, 0);
    zip_file_add(za, "dummy", src, ZIP_FL_OVERWRITE);
    zip_close(za);
}

class CalcHashTest : public ::testing::Test {
protected:
    const char *empty_path   = "empty.zip";
    const char *known_path   = "test.zip";
    const char *missing_path = "calchash_does_not_exist.zip";

    void SetUp() override {
        writeFile(empty_path, "", 0);
        writeFile(known_path, "abc", 3);
        std::remove(missing_path);
    }

    void TearDown() override {
        std::remove(empty_path);
        std::remove(known_path);
    }
};

TEST_F(CalcHashTest, EmptyFileMatchesKnownDigest) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    int len = calcHash(empty_path, "sha256", 0, hash);
    ASSERT_EQ(len, 32);
    // SHA-256("") = e3b0c442...
    EXPECT_EQ(toHex(hash, len),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(CalcHashTest, KnownContentMatchesKnownDigest) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    int len = calcHash(known_path, "sha256", 0, hash);
    ASSERT_EQ(len, 32);
    // SHA-256("abc") = ba7816bf...
    EXPECT_EQ(toHex(hash, len),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(CalcHashTest, MissingFileReturnsError) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    EXPECT_EQ(calcHash(missing_path, "sha256", 0, hash), -1);
}

TEST_F(CalcHashTest, UnknownAlgorithmReturnsError) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    EXPECT_EQ(calcHash(known_path, "not-a-real-algo", 0, hash), -1);
}

TEST_F(CalcHashTest, DeterministicAcrossCalls) {
    unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
    ASSERT_EQ(calcHash(known_path, "sha256", 0, a), 32);
    ASSERT_EQ(calcHash(known_path, "sha256", 0, b), 32);
    EXPECT_EQ(0, std::memcmp(a, b, 32));
}

TEST_F(CalcHashTest, DifferentContentDifferentHash) {
    unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
    ASSERT_EQ(calcHash(empty_path, "sha256", 0, a), 32);
    ASSERT_EQ(calcHash(known_path, "sha256", 0, b), 32);
    EXPECT_NE(0, std::memcmp(a, b, 32));
}

TEST_F(CalcHashTest, Sha512ProducesCorrectLength) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    int len = calcHash(known_path, "sha512", 0, hash);
    ASSERT_EQ(len, 64);
    // SHA-512("abc")
    EXPECT_EQ(toHex(hash, len),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

class SignHashTest : public ::testing::Test {
protected:
    const char *priv_key = "test_priv.pem";
    const char *pub_key  = "test_pub.pem";

    void SetUp() override { generateKeyPair(priv_key, pub_key); }
    void TearDown() override {
        std::remove(priv_key);
        std::remove(pub_key);
    }
};

TEST_F(SignHashTest, SignsAndVerifies) {
    unsigned char hash[32];
    std::memset(hash, 0xAB, sizeof(hash));

    char *b64 = toBase64(hash, 32);
    ASSERT_NE(b64, nullptr);

    unsigned char *sig = NULL;
    int sig_len = signHash((unsigned char *)b64, (int)strlen(b64), priv_key, &sig);
    ASSERT_GT(sig_len, 0);
    ASSERT_NE(sig, nullptr);

    FILE *f = fopen(pub_key, "r");
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ASSERT_EQ(EVP_PKEY_verify_init(ctx), 1);
    EXPECT_EQ(EVP_PKEY_verify(ctx, sig, (size_t)sig_len,
              (unsigned char *)b64, (size_t)strlen(b64)), 1);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig);
    free(b64);
}

TEST_F(SignHashTest, MissingKeyReturnsError) {
    unsigned char hash[32] = {};
    unsigned char *sig = NULL;
    EXPECT_EQ(signHash(hash, 32, "no_such_key.pem", &sig), -1);
}

TEST_F(SignHashTest, DifferentHashDifferentSignature) {
    unsigned char h1[32], h2[32];
    std::memset(h1, 0xAA, 32);
    std::memset(h2, 0xBB, 32);

    char *b1 = toBase64(h1, 32);
    char *b2 = toBase64(h2, 32);

    unsigned char *s1 = NULL, *s2 = NULL;
    int l1 = signHash((unsigned char *)b1, (int)strlen(b1), priv_key, &s1);
    int l2 = signHash((unsigned char *)b2, (int)strlen(b2), priv_key, &s2);
    ASSERT_GT(l1, 0);
    ASSERT_GT(l2, 0);

    EXPECT_TRUE(l1 != l2 || std::memcmp(s1, s2, (size_t)l1) != 0);
    free(s1); free(s2);
    free(b1); free(b2);
}

class ApplySealTest : public ::testing::Test {
protected:
    const char *zip_path = "seal_test.zip";

    void SetUp() override { createZip(zip_path); }
    void TearDown() override { std::remove(zip_path); }
};

TEST_F(ApplySealTest, WritesCommentAndReadsBack) {
    const char *seal = "dGVzdHNlYWw=";
    int len = (int)strlen(seal);

    ASSERT_EQ(applySeal(zip_path, seal, len), len);

    zip_t *za = zip_open(zip_path, ZIP_RDONLY, NULL);
    ASSERT_NE(za, nullptr);
    int comment_len = 0;
    const char *comment = zip_get_archive_comment(za, &comment_len, 0);
    EXPECT_EQ(comment_len, len);
    EXPECT_EQ(std::string(comment, comment_len), seal);
    zip_close(za);
}

TEST_F(ApplySealTest, OverwritesExistingComment) {
    applySeal(zip_path, "first", 5);
    applySeal(zip_path, "second", 6);

    zip_t *za = zip_open(zip_path, ZIP_RDONLY, NULL);
    int comment_len = 0;
    const char *comment = zip_get_archive_comment(za, &comment_len, 0);
    EXPECT_EQ(std::string(comment, comment_len), "second");
    zip_close(za);
}

TEST_F(ApplySealTest, InvalidZipReturnsError) {
    EXPECT_EQ(applySeal("no_such.zip", "abc", 3), -1);
}

class VerifySealTest : public ::testing::Test {
protected:
    const char *priv_key = "test_priv.pem";
    const char *pub_key  = "test_pub.pem";

    void SetUp() override { generateKeyPair(priv_key, pub_key); }
    void TearDown() override {
        std::remove(priv_key);
        std::remove(pub_key);
    }
};

TEST_F(VerifySealTest, Valid) {
    unsigned char hash[32];
    std::memset(hash, 0xAB, sizeof(hash));

    char *b64 = toBase64(hash, 32);
    unsigned char *sig = NULL;
    int sig_len = signHash((unsigned char *)b64, (int)strlen(b64), priv_key, &sig);
    ASSERT_GT(sig_len, 0);

    EXPECT_EQ(verifySeal((unsigned char *)b64, (int)strlen(b64),
                         sig, sig_len, pub_key), 1);
    free(sig);
    free(b64);
}

TEST_F(VerifySealTest, WrongHash) {
    unsigned char hash[32];
    std::memset(hash, 0xAB, sizeof(hash));

    char *b64 = toBase64(hash, 32);
    unsigned char *sig = NULL;
    int sig_len = signHash((unsigned char *)b64, (int)strlen(b64), priv_key, &sig);
    ASSERT_GT(sig_len, 0);

    unsigned char wrong[32];
    std::memset(wrong, 0xCC, sizeof(wrong));
    char *wrong_b64 = toBase64(wrong, 32);

    EXPECT_EQ(verifySeal((unsigned char *)wrong_b64, (int)strlen(wrong_b64),
                         sig, sig_len, pub_key), 0);
    free(sig);
    free(b64);
    free(wrong_b64);
}

TEST_F(VerifySealTest, MissingKeyReturnsError) {
    unsigned char hash[32] = {};
    unsigned char sig[32] = {};
    EXPECT_EQ(verifySeal(hash, 32, sig, 32, "no_such_pub.pem"), -1);
}