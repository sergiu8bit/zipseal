// test_calchash.cpp
#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include <fstream>

extern "C" {
    #include "../include/zipseal.h"
}

// Helper: convert hash bytes to lowercase hex string
static std::string toHex(const unsigned char hash[32]) {
    char buf[65];
    for (int i = 0; i < 32; i++) sprintf(buf + i * 2, "%02x", hash[i]);
    buf[64] = '\0';
    return std::string(buf);
}

// Helper: write bytes to a temp file
static void writeFile(const char *path, const void *data, size_t n) {
    std::ofstream f(path, std::ios::binary);
    f.write(static_cast<const char*>(data), n);
}

class CalcHashTest : public ::testing::Test {
protected:
    const char *empty_path  = "empty.zip";
    const char *known_path  = "test.zip";
    const char *missing_path = "calchash_does_not_exist.zip";

    void SetUp() override {
        // Empty file -- SHA-256 of "" is well known
        writeFile(empty_path, "", 0);

        // Known content -- SHA-256 of "abc" is well known
        writeFile(known_path, "abc", 3);

        // Make sure the missing file really is missing
        std::remove(missing_path);
    }

    void TearDown() override {
        std::remove(empty_path);
        std::remove(known_path);
    }
};

TEST_F(CalcHashTest, EmptyFileMatchesKnownDigest) {
    unsigned char hash[32];
    ASSERT_EQ(calcHash(empty_path, hash), 0);
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    EXPECT_EQ(toHex(hash),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(CalcHashTest, KnownContentMatchesKnownDigest) {
    unsigned char hash[32];
    ASSERT_EQ(calcHash(known_path, hash), 0);
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    EXPECT_EQ(toHex(hash),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(CalcHashTest, MissingFileReturnsError) {
    unsigned char hash[32];
    EXPECT_NE(calcHash(missing_path, hash), 0);
}

TEST_F(CalcHashTest, DeterministicAcrossCalls) {
    unsigned char a[32], b[32];
    ASSERT_EQ(calcHash(known_path, a), 0);
    ASSERT_EQ(calcHash(known_path, b), 0);
    EXPECT_EQ(0, std::memcmp(a, b, 32));
}

TEST_F(CalcHashTest, DifferentContentDifferentHash) {
    unsigned char a[32], b[32];
    ASSERT_EQ(calcHash(empty_path, a), 0);
    ASSERT_EQ(calcHash(known_path, b), 0);
    EXPECT_NE(0, std::memcmp(a, b, 32));
}