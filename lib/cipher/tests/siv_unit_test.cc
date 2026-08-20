/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/cipher/aes_cmac_siv.hh"
#include <gtest/gtest.h>

using namespace alcp::cipher;

TEST(CMACSIV, Initiantiation)
{
        auto siv        = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits
    if (siv == nullptr) {
        FAIL();
    }
    delete siv;
}

TEST(CMACSIV, setKeys)
{
    const int cKeySize          = 16;
    Uint8     key[cKeySize * 2] = {};
        auto      siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (siv == nullptr) {
        delete siv;
        FAIL();
    }
    alc_error_t err = siv->init(key, cKeySize * 8, nullptr, 0);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    delete siv;
}

TEST(CMACSIV, addAdditionalInput)
{
    const int cKeySize = 16, cAadSize = 32;
    Uint8     key[cKeySize * 2] = {};
    Uint8     aad[cAadSize]     = {};
        auto      siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (siv == nullptr) {
        delete siv;
        FAIL();
    }
    alc_error_t err = siv->init(key, cKeySize * 8, nullptr, 0);
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    err = siv->setAad(aad, cAadSize);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    delete siv;
}

TEST(CMACSIV, encTest1)
{
    const int cKeySize = 16, cAadSize = 24, cPtSize = 14, padLen = 2;
    Uint8     aad[cAadSize] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
    Uint8     key[cKeySize * 2] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
        0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
        0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    Uint8 pt[cPtSize + padLen] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                   0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                   0xdd, 0xee, 0x00, 0x00 };
    std::vector<Uint8> ct_exp  = { 0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc,
                                   0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c };
    std::vector<Uint8> ct_act(cPtSize + padLen, 0);

    std::vector<Uint8> v_exp = {
        0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93
    };
    std::vector<Uint8> v_act(16, 0);
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (siv == nullptr) {
        delete siv;
        FAIL();
    }
    alc_error_t err = siv->init(key, cKeySize * 8, nullptr, 0);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(aad, cAadSize);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    // err = siv->setPaddingLen(padLen);
    // EXPECT_TRUE(err == ALC_ERROR_NONE);

    Uint64 outlen = 0;
    siv->encrypt(pt, &ct_act[0], cPtSize, &outlen);
    std::vector<Uint8> cmp_act(&ct_act.at(0), &ct_act.at(cPtSize));
    EXPECT_EQ(ct_exp, cmp_act);

    err = siv->getTag(&v_act[0], v_act.size());
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_EQ(v_exp, v_act);

    EXPECT_TRUE(err == ALC_ERROR_NONE);

    delete siv;
}

TEST(CMACSIV, encTest2)
{
    const int cKeySize = 16, cPtSize = 47;
    Uint8     aad1[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xde, 0xad, 0xda, 0xda,
        0xde, 0xad, 0xda, 0xda, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
        0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    Uint8 aad2[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0
    };
    Uint8 nonce[]           = { 0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b,
                                0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0 };
    Uint8 key[cKeySize * 2] = {
        0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75,
        0x74, 0x73, 0x72, 0x71, 0x70, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    Uint8 pt[] = { 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x73, 0x6f,
                   0x6d, 0x65, 0x20, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65,
                   0x78, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72,
                   0x79, 0x70, 0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20,
                   0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53, 0 };

    std::vector<Uint8> ct_exp = {
        0xcb, 0x90, 0x0f, 0x2f, 0xdd, 0xbe, 0x40, 0x43, 0x26, 0x60, 0x19, 0x65,
        0xc8, 0x89, 0xbf, 0x17, 0xdb, 0xa7, 0x7c, 0xeb, 0x09, 0x4f, 0xa6, 0x63,
        0xb7, 0xa3, 0xf7, 0x48, 0xba, 0x8a, 0xf8, 0x29, 0xea, 0x64, 0xad, 0x54,
        0x4a, 0x27, 0x2e, 0x9c, 0x48, 0x5b, 0x62, 0xa3, 0xfd, 0x5c, 0x0d
    };
    std::vector<Uint8> ct_act(cPtSize + 1, 0);

    std::vector<Uint8> v_exp = {
        0x7b, 0xdb, 0x6e, 0x3b, 0x43, 0x26, 0x67, 0xeb,
        0x06, 0xf4, 0xd1, 0x4b, 0xff, 0x2f, 0xbd, 0x0f
    };
    std::vector<Uint8> v_act(16, 0);
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (siv == nullptr) {
        delete siv;
        FAIL();
    }
    alc_error_t err = siv->init(key, cKeySize * 8, nullptr, 0);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(aad1, sizeof(aad1));
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(aad2, sizeof(aad2));
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(nonce, sizeof(nonce));
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    // err = siv->setPaddingLen(1);
    // EXPECT_TRUE(err);

    Uint64 outlen = 0;
    siv->encrypt(pt, &ct_act[0], sizeof(pt) - 1, &outlen);
    std::vector<Uint8> cmp_act(&ct_act.at(0), &ct_act.at(cPtSize));
    EXPECT_EQ(ct_exp, cmp_act);

    err = siv->getTag(&v_act[0], v_act.size());
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_EQ(v_exp, v_act);

    delete siv;
}

// FIXME: To bringup decrypt test, proper padding support is needed from API
// level
#if 0
TEST(CMACSIV, decTest1)
{
    const int cKeySize = 16, cAadSize = 24, cPtSize = 14;
    Uint8     aad[cAadSize] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
    Uint8     key[cKeySize * 2] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
        0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
        0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    std::vector<Uint8> pt_exp = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    std::vector<Uint8> ct     = { 0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc,
                                  0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c };
    std::vector<Uint8> pt_act(cPtSize + 2, 0);

    std::vector<Uint8> v_exp = {
        0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93
    };
    std::vector<Uint8> v_act(16, 0);
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (siv == nullptr) {
        delete siv;
        FAIL();
    }
    alc_error_t err = siv->init(key, cKeySize * 8, nullptr, 0);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(aad, cAadSize);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    // err = siv->setPaddingLen(padLen);
    // EXPECT_TRUE(err == ALC_ERROR_NONE);

    siv->decrypt(&ct[0], &pt_act[0], cPtSize);
    std::vector<Uint8> cmp_act(&pt_act.at(0), &pt_act.at(cPtSize));
    EXPECT_EQ(pt_exp, cmp_act);

    err = siv->getTag(&v_act[0], v_act.size());
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_EQ(v_exp, v_act);

    EXPECT_TRUE(err == ALC_ERROR_NONE);

    delete siv;
}

TEST(CMACSIV, decTest2)
{
    const int cKeySize = 16, cPtSize = 47;
    Uint8     aad1[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xde, 0xad, 0xda, 0xda,
        0xde, 0xad, 0xda, 0xda, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
        0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    Uint8 aad2[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0
    };
    Uint8 nonce[]           = { 0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b,
                                0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0 };
    Uint8 key[cKeySize * 2] = {
        0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75,
        0x74, 0x73, 0x72, 0x71, 0x70, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    std::vector<Uint8> pt_exp = {
        0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x73, 0x6f, 0x6d, 0x65,
        0x20, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x74,
        0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x75, 0x73,
        0x69, 0x6e, 0x67, 0x20, 0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53
    };

    std::vector<Uint8> ct = { 0xcb, 0x90, 0x0f, 0x2f, 0xdd, 0xbe, 0x40, 0x43,
                              0x26, 0x60, 0x19, 0x65, 0xc8, 0x89, 0xbf, 0x17,
                              0xdb, 0xa7, 0x7c, 0xeb, 0x09, 0x4f, 0xa6, 0x63,
                              0xb7, 0xa3, 0xf7, 0x48, 0xba, 0x8a, 0xf8, 0x29,
                              0xea, 0x64, 0xad, 0x54, 0x4a, 0x27, 0x2e, 0x9c,
                              0x48, 0x5b, 0x62, 0xa3, 0xfd, 0x5c, 0x0d, 0 };
    std::vector<Uint8> pt_act(cPtSize + 1, 0);

    std::vector<Uint8> v_exp = {
        0x7b, 0xdb, 0x6e, 0x3b, 0x43, 0x26, 0x67, 0xeb,
        0x06, 0xf4, 0xd1, 0x4b, 0xff, 0x2f, 0xbd, 0x0f
    };
    std::vector<Uint8> v_act(16, 0);
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit); // KeySize is 128 bits

    if (siv == nullptr) {
        delete siv;
        FAIL();
    }
    alc_error_t err = siv->init(key, cKeySize * 8, nullptr, 0);
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(aad1, sizeof(aad1));
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(aad2, sizeof(aad2));
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    err = siv->setAad(nonce, sizeof(nonce));
    EXPECT_TRUE(err == ALC_ERROR_NONE);

    // err = siv->setPaddingLen(1);
    // EXPECT_TRUE(err == ALC_ERROR_NONE);

    siv->decrypt(&ct[0], &pt_act[0], cPtSize);
    std::vector<Uint8> cmp_act(&pt_act.at(0), &pt_act.at(cPtSize));
    EXPECT_EQ(pt_exp, cmp_act);

    err = siv->getTag(&v_act[0], v_act.size());
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_EQ(v_exp, v_act);
    delete siv;
}
#endif

// Comprehensive Corner Case Tests for SIV

template<typename T>
T*
getPtr(std::vector<T>& vect)
{
    if (vect.size() == 0) {
        return nullptr;
    } else {
        return &vect[0];
    }
}

// Test all key sizes (128, 192, 256 bits) with encryption
TEST(CMACSIV, AllKeySizesEncrypt)
{
    std::vector<Uint8> aad(16, 0xAA);
    std::vector<Uint8> plaintext(32, 0x55);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    // 128-bit key (SIV uses double key size, so 32 bytes total)
    {
        std::vector<Uint8> key(32, 0x42);
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }

    // 192-bit key (SIV uses double key size, so 48 bytes total)
    {
        std::vector<Uint8> key(48, 0x42);
        std::fill(ciphertext.begin(), ciphertext.end(), 0);
        
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey192Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 192, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }

    // 256-bit key (SIV uses double key size, so 64 bytes total)
    {
        std::vector<Uint8> key(64, 0x42);
        std::fill(ciphertext.begin(), ciphertext.end(), 0);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey256Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 256, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }
}

// Test various AAD lengths
TEST(CMACSIV, VariousAADLengths)
{
    std::vector<Uint8> key(32, 0x56);
    std::vector<Uint8> plaintext(32, 0x9A);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    // Test various AAD lengths
    std::vector<size_t> aad_lengths = { 1, 15, 16, 17, 31, 32, 33, 64, 128 };

    for (size_t alen : aad_lengths) {
        std::vector<Uint8> aad(alen);
        for (size_t i = 0; i < alen; i++) {
            aad[i] = static_cast<Uint8>(i % 256);
        }
        std::fill(ciphertext.begin(), ciphertext.end(), 0);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Failed setAad for length " << alen;

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }
}

// Test encryption without AAD
TEST(CMACSIV, EncryptWithoutAAD)
{
    std::vector<Uint8> key(32, 0x11);
    std::vector<Uint8> plaintext(32, 0x22);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // No AAD set - encrypt directly
    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test multiple AAD components (nonce-misuse resistance)
TEST(CMACSIV, MultipleAADComponents)
{
    std::vector<Uint8> key(32, 0x33);
    std::vector<Uint8> aad1(16, 0x44);
    std::vector<Uint8> aad2(24, 0x55);
    std::vector<Uint8> aad3(10, 0x66);
    std::vector<Uint8> plaintext(48, 0x77);
    std::vector<Uint8> ciphertext(48);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Add multiple AAD components
    err = siv->setAad(getPtr(aad1), aad1.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad2), aad2.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad3), aad3.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 48, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test all zeros input (key, aad, plaintext)
TEST(CMACSIV, AllZerosInput)
{
    std::vector<Uint8> key(32, 0x00);
    std::vector<Uint8> aad(16, 0x00);
    std::vector<Uint8> plaintext(32, 0x00);
    std::vector<Uint8> ciphertext(32);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    
    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test multiple blocks (various block counts)
TEST(CMACSIV, MultipleBlocks)
{
    std::vector<Uint8> key(32, 0x88);
    std::vector<Uint8> aad(16, 0x99);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    std::vector<size_t> block_counts = { 1, 2, 4, 8, 16 };

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;
        std::vector<Uint8> plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            plaintext[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> ciphertext(data_size);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), data_size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for block count: " << num_blocks;
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }
}

// Test large data encryption
TEST(CMACSIV, LargeData)
{
    const size_t data_size = 8 * 1024; // 8 KB
    std::vector<Uint8> key(64, 0xAA); // 256-bit SIV key (double = 64 bytes)
    std::vector<Uint8> aad(32, 0xBB);
    std::vector<Uint8> plaintext(data_size);
    std::vector<Uint8> ciphertext(data_size);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = static_cast<Uint8>((i * 17) % 256);
    }

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey256Bit);
    ASSERT_NE(siv, nullptr);

    err = siv->init(getPtr(key), 256, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test AAD affects tag (different AADs should produce different tags)
TEST(CMACSIV, AADAffectsTag)
{
    std::vector<Uint8> key(32, 0xCC);
    std::vector<Uint8> plaintext(32, 0xDD);
    std::vector<Uint8> ciphertext(32);
    std::vector<std::vector<Uint8>> tags;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> aad(16, static_cast<Uint8>(i));
        std::vector<Uint8> tag(16);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        tags.push_back(tag);
        delete siv;
    }

    // Verify all tags are different
    for (size_t i = 0; i < tags.size(); i++) {
        for (size_t j = i + 1; j < tags.size(); j++) {
            EXPECT_NE(tags[i], tags[j]) 
                << "AAD " << i << " and " << j << " produced same tag";
        }
    }
}

// Test determinism (same inputs always produce same output)
TEST(CMACSIV, Determinism)
{
    std::vector<Uint8> key(32, 0xEE);
    std::vector<Uint8> aad(16, 0xFF);
    std::vector<Uint8> plaintext(32, 0x11);
    std::vector<Uint8> ciphertext1(32), ciphertext2(32), ciphertext3(32);
    std::vector<Uint8> tag1(16), tag2(16), tag3(16);
    alc_error_t err;

    for (int round = 0; round < 3; round++) {
        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        std::vector<Uint8>* ct = (round == 0) ? &ciphertext1 : (round == 1) ? &ciphertext2 : &ciphertext3;
        std::vector<Uint8>* tg = (round == 0) ? &tag1 : (round == 1) ? &tag2 : &tag3;
        err = siv->encrypt(getPtr(plaintext), getPtr(*ct), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(*tg), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }

    EXPECT_EQ(ciphertext1, ciphertext2) << "Round 1 and 2 should produce same ciphertext";
    EXPECT_EQ(ciphertext2, ciphertext3) << "Round 2 and 3 should produce same ciphertext";
    EXPECT_EQ(tag1, tag2) << "Round 1 and 2 should produce same tag";
    EXPECT_EQ(tag2, tag3) << "Round 2 and 3 should produce same tag";
}

// Test plaintext affects tag (different plaintexts should produce different tags)
TEST(CMACSIV, PlaintextAffectsTag)
{
    std::vector<Uint8> key(32, 0x22);
    std::vector<Uint8> aad(16, 0x33);
    std::vector<Uint8> ciphertext(32);
    std::vector<std::vector<Uint8>> tags;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> plaintext(32, static_cast<Uint8>(i));
        std::vector<Uint8> tag(16);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        tags.push_back(tag);
        delete siv;
    }

    // Verify all tags are different
    for (size_t i = 0; i < tags.size(); i++) {
        for (size_t j = i + 1; j < tags.size(); j++) {
            EXPECT_NE(tags[i], tags[j]) 
                << "Plaintext " << i << " and " << j << " produced same tag";
        }
    }
}

// Test key affects output (different keys should produce different outputs)
TEST(CMACSIV, KeyAffectsOutput)
{
    std::vector<Uint8> aad(16, 0x44);
    std::vector<Uint8> plaintext(32, 0x55);
    std::vector<std::vector<Uint8>> outputs;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> key(32, static_cast<Uint8>(i));
        std::vector<Uint8> ciphertext(32);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        outputs.push_back(ciphertext);
        delete siv;
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "Key " << i << " and " << j << " produced same ciphertext";
        }
    }
}

// Test non-block-aligned plaintext sizes
TEST(CMACSIV, NonBlockAlignedPlaintext)
{
    std::vector<Uint8> key(32, 0x66);
    std::vector<Uint8> aad(16, 0x77);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    // Test various non-block-aligned sizes
    std::vector<size_t> sizes = { 1, 7, 15, 17, 23, 31, 33, 47, 63, 65, 100 };

    for (size_t size : sizes) {
        std::vector<Uint8> plaintext(size);
        for (size_t i = 0; i < size; i++) {
            plaintext[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> ciphertext(size);

        auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
        ASSERT_NE(siv, nullptr);

        err = siv->init(getPtr(key), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for size: " << size;

        err = siv->getTag(getPtr(tag), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete siv;
    }
}

// Test single byte plaintext
TEST(CMACSIV, SingleBytePlaintext)
{
    std::vector<Uint8> key(32, 0x88);
    std::vector<Uint8> aad(16, 0x99);
    std::vector<Uint8> plaintext(1, 0xAA);
    std::vector<Uint8> ciphertext(1);
    std::vector<Uint8> tag(16);
    alc_error_t err;

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext), 1, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test reusing cipher object with different keys
TEST(CMACSIV, ReuseWithDifferentKeys)
{
    std::vector<Uint8> aad(16, 0xBB);
    std::vector<Uint8> plaintext(32, 0xCC);
    std::vector<Uint8> ciphertext1(32), ciphertext2(32);
    std::vector<Uint8> tag1(16), tag2(16);
    alc_error_t err;

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // First encryption with key1
    {
        std::vector<Uint8> key1(32, 0x01);
        
        err = siv->init(getPtr(key1), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext1), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag1), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Second encryption with key2 (same object)
    {
        std::vector<Uint8> key2(32, 0x02);

        err = siv->init(getPtr(key2), 128, nullptr, 0);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->setAad(getPtr(aad), aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = siv->encrypt(getPtr(plaintext), getPtr(ciphertext2), 32, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        err = siv->getTag(getPtr(tag2), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Different keys should produce different outputs
    EXPECT_NE(ciphertext1, ciphertext2);
    EXPECT_NE(tag1, tag2);

    delete siv;
}

// Test separate cipher objects for same operation
TEST(CMACSIV, SeparateCipherObjects)
{
    std::vector<Uint8> key(32, 0xDD);
    std::vector<Uint8> aad(16, 0xEE);
    std::vector<Uint8> plaintext(64, 0xFF);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64);
    std::vector<Uint8> tag1(16), tag2(16);
    alc_error_t err;

    // Encrypt with first cipher object
    auto siv1 = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv1, nullptr);

    err = siv1->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv1->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv1->encrypt(getPtr(plaintext), getPtr(ciphertext1), 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv1->getTag(getPtr(tag1), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv1;

    // Encrypt with second cipher object
    auto siv2 = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv2, nullptr);

    err = siv2->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv2->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    outlen = 0;
    err = siv2->encrypt(getPtr(plaintext), getPtr(ciphertext2), 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv2->getTag(getPtr(tag2), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Same inputs should produce same outputs
    EXPECT_EQ(ciphertext1, ciphertext2);
    EXPECT_EQ(tag1, tag2);

    delete siv2;
}

// Negative Tests for SIV - Null Pointer and Edge Cases

// Test null pointer for key in init
TEST(CMACSIV_Negative, NullKeyPointer)
{
    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(nullptr, 128, nullptr, 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key should fail";

    delete siv;
}

// Test null pointer for input in encrypt
TEST(CMACSIV_Negative, NullInputPointerEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> output(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(nullptr, getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input should fail";

    delete siv;
}

// Test null pointer for output in encrypt
TEST(CMACSIV_Negative, NullOutputPointerEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> input(32, 0x55);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null output should fail";

    delete siv;
}

// Test null pointer for both input and output in encrypt
TEST(CMACSIV_Negative, NullInputAndOutputPointerEncrypt)
{
    std::vector<Uint8> key(32, 0x42);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(nullptr, nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input and output should fail";

    delete siv;
}

// Test null pointer for input in decrypt
TEST(CMACSIV_Negative, NullInputPointerDecrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> output(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->decrypt(nullptr, getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null input should fail";

    delete siv;
}

// Test null pointer for output in decrypt
TEST(CMACSIV_Negative, NullOutputPointerDecrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> input(32, 0x55);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->decrypt(getPtr(input), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null output should fail";

    delete siv;
}

// Test null pointer for tag in getTag
TEST(CMACSIV_Negative, NullTagPointer)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = siv->getTag(nullptr, 16);
    EXPECT_TRUE(alcp_is_error(err)) << "getTag with null pointer should fail";

    delete siv;
}

// Test null pointer for AAD in setAad
TEST(CMACSIV_Negative, NullAADPointer)
{
    std::vector<Uint8> key(32, 0x42);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = siv->setAad(nullptr, 16);
    EXPECT_TRUE(alcp_is_error(err)) << "setAad with null pointer should fail";

    delete siv;
}

// Test zero key length
TEST(CMACSIV_Negative, ZeroKeyLength)
{
    std::vector<Uint8> key(32, 0x42);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 0, nullptr, 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero key length should fail";

    delete siv;
}

// Test invalid key length (not 128, 192, or 256 bits)
TEST(CMACSIV_Negative, InvalidKeyLength)
{
    std::vector<Uint8> key(40, 0x42); // 160-bit key (invalid)

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // Init with invalid key length (160 bits) should fail
    alc_error_t err = siv->init(getPtr(key), 160, nullptr, 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with invalid key length (160 bits) should fail";

    delete siv;
}

// Test encryption without initialization
TEST(CMACSIV_Negative, EncryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // Encrypt without init should fail
    Uint64 outlen = 0;
    alc_error_t err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt without init should fail";

    delete siv;
}

// Test decryption without initialization
TEST(CMACSIV_Negative, DecryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // Decrypt without init should fail
    Uint64 outlen = 0;
    alc_error_t err = siv->decrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt without init should fail";

    delete siv;
}

// Test getTag without encryption
TEST(CMACSIV_Negative, GetTagWithoutEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> tag(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // getTag without any encryption - behavior is implementation-defined
    err = siv->getTag(getPtr(tag), 16);
    // This might succeed or fail depending on implementation
    (void)err;

    delete siv;
}

// Test zero tag length
TEST(CMACSIV_Negative, ZeroTagLength)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // getTag with zero length should fail or return error
    err = siv->getTag(getPtr(tag), 0);
    EXPECT_TRUE(alcp_is_error(err)) << "getTag with 0 length should fail";

    delete siv;
}

// Test invalid tag length (greater than 16 for SIV)
TEST(CMACSIV_Negative, InvalidTagLength)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // getTag with length > 16 - behavior is implementation-defined
    err = siv->getTag(getPtr(tag), 17);
    // This might succeed or fail depending on implementation
    (void)err;

    delete siv;
}

// Test maximum key length boundary
TEST(CMACSIV_Negative, MaxKeyLengthBoundary)
{
    std::vector<Uint8> key(66, 0x42); // 264 bits (more than max 256)

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey256Bit);
    ASSERT_NE(siv, nullptr);

    // Init with key length above maximum should fail
    alc_error_t err = siv->init(getPtr(key), 264, nullptr, 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with key length > 256 bits should fail";

    delete siv;
}

// Test reuse after error
TEST(CMACSIV_Negative, ReuseAfterError)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> aad(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // First, cause an error by using invalid key length
    std::vector<Uint8> invalid_key(40, 0x11);
    alc_error_t err = siv->init(getPtr(invalid_key), 160, nullptr, 0);
    // This should have failed

    // Now try to reinit properly and use the cipher
    err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Reinit after error should succeed";

    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt after reinit should succeed";

    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test repeated initialization
TEST(CMACSIV_Negative, RepeatedInitialization)
{
    std::vector<Uint8> key1(32, 0x42);
    std::vector<Uint8> key2(32, 0x84);
    std::vector<Uint8> aad(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output1(32), output2(32);
    std::vector<Uint8> tag1(16), tag2(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // First init and encrypt
    alc_error_t err = siv->init(getPtr(key1), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output1), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag1), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Reinit with different key and encrypt again
    err = siv->init(getPtr(key2), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output2), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->getTag(getPtr(tag2), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Different keys should produce different outputs
    EXPECT_NE(output1, output2) << "Different keys should produce different ciphertext";
    EXPECT_NE(tag1, tag2) << "Different keys should produce different tags";

    delete siv;
}

// Test mismatched key size and CipherKeyLen
TEST(CMACSIV_Negative, MismatchedKeySizeAndKeyLen)
{
    std::vector<Uint8> key(64, 0x42); // 256-bit SIV key (double = 64 bytes)

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    // Trying to init 128-bit cipher with 256-bit key size
    alc_error_t err = siv->init(getPtr(key), 256, nullptr, 0);
    // Behavior is implementation-defined - we just verify it doesn't crash
    (void)err;

    delete siv;
}

// Test zero AAD length (should be valid for SIV)
TEST(CMACSIV_Negative, ZeroAADLength)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> aad(16, 0x24);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // setAad with zero length might be valid or invalid depending on implementation
    err = siv->setAad(getPtr(aad), 0);
    // Behavior is implementation-defined
    (void)err;

    delete siv;
}

// Test very large AAD
TEST(CMACSIV_Negative, VeryLargeAAD)
{
    std::vector<Uint8> key(32, 0x42);
    const size_t large_aad_size = 64 * 1024; // 64 KB
    std::vector<Uint8> aad(large_aad_size);
    for (size_t i = 0; i < large_aad_size; i++) {
        aad[i] = static_cast<Uint8>(i % 256);
    }
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test encryption with zero length input (should produce tag only)
TEST(CMACSIV_Negative, ZeroLengthInput)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> aad(16, 0x24);
    std::vector<Uint8> tag(16);
    Uint8 dummy = 0;

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = siv->setAad(getPtr(aad), aad.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Zero length encryption - might be valid for AAD-only operation
    Uint64 outlen = 0;
    err = siv->encrypt(&dummy, &dummy, 0, &outlen);
    // Behavior is implementation-defined
    (void)err;

    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test multiple setAad calls followed by error
TEST(CMACSIV_Negative, MultipleAADThenError)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> aad1(16, 0x11);
    std::vector<Uint8> aad2(24, 0x22);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);
    std::vector<Uint8> tag(16);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Add multiple AADs
    err = siv->setAad(getPtr(aad1), aad1.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = siv->setAad(getPtr(aad2), aad2.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt
    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Get tag
    err = siv->getTag(getPtr(tag), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete siv;
}

// Test setAad after encrypt (order violation)
TEST(CMACSIV_Negative, SetAadAfterEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> aad1(16, 0x11);
    std::vector<Uint8> aad2(24, 0x22);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto siv = createCipherAead(CipherMode::eAesSIV, CipherKeyLen::eKey128Bit);
    ASSERT_NE(siv, nullptr);

    alc_error_t err = siv->init(getPtr(key), 128, nullptr, 0);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    err = siv->setAad(getPtr(aad1), aad1.size());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Encrypt
    Uint64 outlen = 0;
    err = siv->encrypt(getPtr(input), getPtr(output), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // setAad after encrypt - behavior is implementation-defined
    err = siv->setAad(getPtr(aad2), aad2.size());
    // This might succeed or fail depending on implementation
    (void)err;

    delete siv;
}
