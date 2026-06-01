#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <openssl/evp.h>

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

// Helper: write bytes to a temp file
static void writeFile(const char *path, const void *data, size_t n) {
    std::ofstream f(path, std::ios::binary);
    f.write(static_cast<const char*>(data), n);
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
    int len = calcHash(empty_path, "sha256", hash);
    ASSERT_EQ(len, 32);
    // SHA-256("") = e3b0c442...
    EXPECT_EQ(toHex(hash, len),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(CalcHashTest, KnownContentMatchesKnownDigest) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    int len = calcHash(known_path, "sha256", hash);
    ASSERT_EQ(len, 32);
    // SHA-256("abc") = ba7816bf...
    EXPECT_EQ(toHex(hash, len),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(CalcHashTest, MissingFileReturnsError) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    EXPECT_EQ(calcHash(missing_path, "sha256", hash), -1);
}

TEST_F(CalcHashTest, UnknownAlgorithmReturnsError) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    EXPECT_EQ(calcHash(known_path, "not-a-real-algo", hash), -1);
}

TEST_F(CalcHashTest, DeterministicAcrossCalls) {
    unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
    ASSERT_EQ(calcHash(known_path, "sha256", a), 32);
    ASSERT_EQ(calcHash(known_path, "sha256", b), 32);
    EXPECT_EQ(0, std::memcmp(a, b, 32));
}

TEST_F(CalcHashTest, DifferentContentDifferentHash) {
    unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
    ASSERT_EQ(calcHash(empty_path, "sha256", a), 32);
    ASSERT_EQ(calcHash(known_path, "sha256", b), 32);
    EXPECT_NE(0, std::memcmp(a, b, 32));
}

TEST_F(CalcHashTest, Sha512ProducesCorrectLength) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    int len = calcHash(known_path, "sha512", hash);
    ASSERT_EQ(len, 64);
    // SHA-512("abc")
    EXPECT_EQ(toHex(hash, len),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}