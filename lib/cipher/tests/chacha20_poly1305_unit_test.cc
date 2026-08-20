/*
 * Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/cipher/chacha20_poly1305.hh"
#include "alcp/utils/benchmark.hh"
#include "gtest/gtest.h"
#include <algorithm>
#include <openssl/bio.h>

#if 1
using namespace alcp::cipher;
class ChaChaPolyTest : public testing::Test
{
  public:
    bool               is_encrypt_test = true;
    std::vector<Uint8> key = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                               0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                               0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                               0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };

    std::vector<Uint8> AAD = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                               0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    std::vector<Uint8> nonce = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    std::vector<Uint8> expected_plaintext = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47,
        0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66,
        0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
        0x62, 0x65, 0x20, 0x69, 0x74, 0x2e
    };

    std::vector<Uint8> expected_ciphertext = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
        0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
        0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
        0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16
    };

    std::vector<Uint8> expected_tag = { 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
                                        0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
                                        0xd0, 0x60, 0x06, 0x91 };

    std::vector<Uint8> tag;
    std::vector<Uint8> plaintext;
    std::vector<Uint8> ciphertext;

    // Todo: Add tests for zen4
    // Factory removed
    iCipherAead*                aead = nullptr;

    static constexpr unsigned short chacha20_poly1305_tag_size = 16;
    void                            SetUp() override
    {
        tag.resize(chacha20_poly1305_tag_size);
        plaintext.resize(expected_plaintext.size());
        ciphertext.resize(expected_ciphertext.size());
        static_assert(
            chacha20_poly1305_tag_size
            == 16); // Tag size should always be 16. The test expects
                    // it to be so. If for some reason it has to be
                    // modified this validation will fail acting as an alert
        ASSERT_EQ(
            plaintext.size(),
            ciphertext.size()); // If for some reason someone modifies the
                                // plaintext or ciphertext input data to
                                // different lengths these validation will fail
    }

    void createChachaPolyObject()
    {
        aead = createCipherAead(CipherMode::eCHACHA20_POLY1305, CipherKeyLen::eKey256Bit);
        if (aead == nullptr) {
            FAIL();
        }
    }

    void destroyChachaPolyObject() { delete aead; }

    void setInputValues()
    {
        alc_error_t err = ALC_ERROR_NONE;

        // setNonce has to be called before setKey.
        err = aead->init(&key[0], key.size() * 8, &nonce[0], nonce.size());
        ASSERT_EQ(err, ALC_ERROR_NONE);

        err = aead->setAad(&AAD[0], AAD.size());
        ASSERT_EQ(err, ALC_ERROR_NONE);
    }

    void encryptDecryptTest(bool                isEncryptTest,
                            std::vector<Uint8>& plaintext,
                            std::vector<Uint8>& ciphertext,
                            Uint64              size)
    {
        alc_error_t err = ALC_ERROR_NONE;

        if (isEncryptTest) {
            Uint64 outlen = 0;
            err           = aead->encrypt(&expected_plaintext[0],
                                &ciphertext[0],
                                expected_plaintext.size(),
                                &outlen);
            ASSERT_EQ(err, ALC_ERROR_NONE);
            EXPECT_EQ(ciphertext, expected_ciphertext)
                << "Failed Encryption: Input Size" << size << std::endl;
        } else {
            Uint64 outlen = 0;
            err           = aead->decrypt(&expected_ciphertext[0],
                                &plaintext[0],
                                expected_ciphertext.size(),
                                &outlen);
            ASSERT_EQ(err, ALC_ERROR_NONE);
            EXPECT_EQ(plaintext, expected_plaintext)
                << "Failed Encryption: Input Size" << size << std::endl;
            ;
        }

        err = aead->getTag(&tag[0], 16);
#ifdef DEBUG
        std::cout << "Tag is " << std::endl;
        BIO_dump_fp(stdout, &tag[0], tag.size());
#endif

        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(tag, expected_tag)
            << "FAILED for input size " << size << std::endl;
    }
    void testChacha20Poly1305(Uint64 size)
    {
        createChachaPolyObject();
        setInputValues();
        encryptDecryptTest(is_encrypt_test, plaintext, ciphertext, size);
        destroyChachaPolyObject();
    }

    void testChacha20Poly1305MultiBytes()
    {
        for (Uint64 i = 0; i < plaintext.size(); i++) {
            testChacha20Poly1305(i);
        }
    }
};
TEST_F(ChaChaPolyTest, EncryptTest)
{
    is_encrypt_test = true;
    testChacha20Poly1305(plaintext.size());
}

TEST_F(ChaChaPolyTest, DecryptTest)
{
    is_encrypt_test = false;
    testChacha20Poly1305(ciphertext.size());
}

TEST_F(ChaChaPolyTest, MultiBytesEncryptTest)
{
    is_encrypt_test = true;
    testChacha20Poly1305MultiBytes();
}

TEST_F(ChaChaPolyTest, MultiBytesDecryptTest)
{
    is_encrypt_test = false;
    testChacha20Poly1305MultiBytes();
}

TEST(Chacha20Poly1305, PerformanceTest)
{
    ref::ChaChaPoly256 chacha_poly;
    Uint8              key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                                 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };

    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    std::vector<Uint8> plaintext(256);
    std::vector<Uint8> ciphertext(plaintext.size());

    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_poly.setAad(AAD, sizeof(AAD));

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 1000000000; k++) {
        ALCP_CRYPT_TIMER_START
        Uint64 outlen3 = 0;
        chacha_poly.encrypt(
            &plaintext[0], &ciphertext[0], plaintext.size(), &outlen3);
        ALCP_CRYPT_GET_TIME(0, "Encrypt")
        if (totalTimeElapsed > 1) {
            std::cout << "\n\n"
                      << std::setw(5) << (k * plaintext.size())
                      << " Encrypted bytes per second\n";
            break;
        }
    }
}

// Comprehensive Corner Case Tests for ChaCha20-Poly1305

// Test determinism (same inputs always produce same output)
TEST(Chacha20Poly1305, Determinism)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x42);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64), ciphertext3(64);
    std::vector<Uint8> tag1(16), tag2(16), tag3(16);

    for (int round = 0; round < 3; round++) {
        ref::ChaChaPoly256 chacha_poly;
        chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_poly.setAad(AAD, sizeof(AAD));

        std::vector<Uint8>* ct = (round == 0) ? &ciphertext1 : (round == 1) ? &ciphertext2 : &ciphertext3;
        std::vector<Uint8>* tg = (round == 0) ? &tag1 : (round == 1) ? &tag2 : &tag3;
        Uint64 outlen = 0;
        chacha_poly.encrypt(plaintext.data(), ct->data(), plaintext.size(), &outlen);
        chacha_poly.getTag(tg->data(), 16);
    }

    EXPECT_EQ(ciphertext1, ciphertext2) << "Round 1 and 2 should produce same ciphertext";
    EXPECT_EQ(ciphertext2, ciphertext3) << "Round 2 and 3 should produce same ciphertext";
    EXPECT_EQ(tag1, tag2) << "Round 1 and 2 should produce same tag";
    EXPECT_EQ(tag2, tag3) << "Round 2 and 3 should produce same tag";
}

// Test key affects output (different keys should produce different outputs)
TEST(Chacha20Poly1305, KeyAffectsOutput)
{
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x55);
    std::vector<std::vector<Uint8>> outputs;
    std::vector<std::vector<Uint8>> tags;

    for (int i = 0; i < 5; i++) {
        Uint8 key[32];
        for (int j = 0; j < 32; j++) {
            key[j] = static_cast<Uint8>((i + j) % 256);
        }
        std::vector<Uint8> ciphertext(64);
        std::vector<Uint8> tag(16);

        ref::ChaChaPoly256 chacha_poly;
        chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_poly.setAad(AAD, sizeof(AAD));

        Uint64 outlen = 0;
        chacha_poly.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen);
        chacha_poly.getTag(tag.data(), 16);
        outputs.push_back(ciphertext);
        tags.push_back(tag);
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "Key " << i << " and " << j << " produced same ciphertext";
            EXPECT_NE(tags[i], tags[j])
                << "Key " << i << " and " << j << " produced same tag";
        }
    }
}

// Test nonce affects output (different nonces should produce different outputs)
TEST(Chacha20Poly1305, NonceAffectsOutput)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x66);
    std::vector<std::vector<Uint8>> outputs;
    std::vector<std::vector<Uint8>> tags;

    for (int i = 0; i < 5; i++) {
        Uint8 nonce[12];
        for (int j = 0; j < 12; j++) {
            nonce[j] = static_cast<Uint8>((i + j) % 256);
        }
        std::vector<Uint8> ciphertext(64);
        std::vector<Uint8> tag(16);

        ref::ChaChaPoly256 chacha_poly;
        chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_poly.setAad(AAD, sizeof(AAD));

        Uint64 outlen = 0;
        chacha_poly.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen);
        chacha_poly.getTag(tag.data(), 16);
        outputs.push_back(ciphertext);
        tags.push_back(tag);
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "Nonce " << i << " and " << j << " produced same ciphertext";
            EXPECT_NE(tags[i], tags[j])
                << "Nonce " << i << " and " << j << " produced same tag";
        }
    }
}

// Test AAD affects tag (different AAD should produce different tags)
TEST(Chacha20Poly1305, AADAffectsTag)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> plaintext(64, 0x77);
    std::vector<std::vector<Uint8>> tags;

    for (int i = 0; i < 5; i++) {
        Uint8 AAD[12];
        for (int j = 0; j < 12; j++) {
            AAD[j] = static_cast<Uint8>((i + j) % 256);
        }
        std::vector<Uint8> ciphertext(64);
        std::vector<Uint8> tag(16);

        ref::ChaChaPoly256 chacha_poly;
        chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_poly.setAad(AAD, sizeof(AAD));

        Uint64 outlen = 0;
        chacha_poly.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen);
        chacha_poly.getTag(tag.data(), 16);
        tags.push_back(tag);
    }

    // Verify all tags are different
    for (size_t i = 0; i < tags.size(); i++) {
        for (size_t j = i + 1; j < tags.size(); j++) {
            EXPECT_NE(tags[i], tags[j])
                << "AAD " << i << " and " << j << " produced same tag";
        }
    }
}

// Test various data sizes
TEST(Chacha20Poly1305, VariousDataSizes)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    std::vector<size_t> sizes = { 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 255, 256, 1000 };

    for (size_t size : sizes) {
        std::vector<Uint8> plaintext(size);
        for (size_t i = 0; i < size; i++) {
            plaintext[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> ciphertext(size), decrypted(size);
        std::vector<Uint8> tag(16);

        ref::ChaChaPoly256 chacha_enc, chacha_dec;
        chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_enc.setAad(AAD, sizeof(AAD));
        
        Uint64 outlen1 = 0;
        chacha_enc.encrypt(plaintext.data(), ciphertext.data(), size, &outlen1);
        chacha_enc.getTag(tag.data(), 16);

        chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_dec.setAad(AAD, sizeof(AAD));
        
        Uint64 outlen2 = 0;
        chacha_dec.decrypt(ciphertext.data(), decrypted.data(), size, &outlen2);

        EXPECT_EQ(decrypted, plaintext) << "Mismatch for size: " << size;
    }
}

// Test empty AAD
TEST(Chacha20Poly1305, EmptyAAD)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> plaintext(64, 0x88);
    std::vector<Uint8> ciphertext(64), decrypted(64);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    // No AAD set
    
    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    // No AAD set
    
    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), ciphertext.size(), &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test large AAD
TEST(Chacha20Poly1305, LargeAAD)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> AAD(1024);
    for (size_t i = 0; i < AAD.size(); i++) {
        AAD[i] = static_cast<Uint8>(i % 256);
    }
    std::vector<Uint8> plaintext(64, 0x99);
    std::vector<Uint8> ciphertext(64), decrypted(64);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD.data(), AAD.size());
    
    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD.data(), AAD.size());
    
    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), ciphertext.size(), &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test single byte
TEST(Chacha20Poly1305, SingleByte)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(1, 0xAA);
    std::vector<Uint8> ciphertext(1), decrypted(1);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD, sizeof(AAD));
    
    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), 1, &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD, sizeof(AAD));
    
    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), 1, &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test large data (1 MB)
TEST(Chacha20Poly1305, LargeData)
{
    const size_t data_size = 1024 * 1024; // 1 MB
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(data_size);
    std::vector<Uint8> ciphertext(data_size), decrypted(data_size);
    std::vector<Uint8> tag(16);

    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = static_cast<Uint8>((i * 17) % 256);
    }

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD, sizeof(AAD));
    
    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), data_size, &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD, sizeof(AAD));
    
    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), data_size, &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test plaintext affects both ciphertext and tag
TEST(Chacha20Poly1305, PlaintextAffectsOutput)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<std::vector<Uint8>> outputs;
    std::vector<std::vector<Uint8>> tags;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> plaintext(64, static_cast<Uint8>(i));
        std::vector<Uint8> ciphertext(64);
        std::vector<Uint8> tag(16);

        ref::ChaChaPoly256 chacha_poly;
        chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_poly.setAad(AAD, sizeof(AAD));

        Uint64 outlen = 0;
        chacha_poly.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen);
        chacha_poly.getTag(tag.data(), 16);
        outputs.push_back(ciphertext);
        tags.push_back(tag);
    }

    // Verify all outputs and tags are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "Plaintext " << i << " and " << j << " produced same ciphertext";
            EXPECT_NE(tags[i], tags[j])
                << "Plaintext " << i << " and " << j << " produced same tag";
        }
    }
}

// Test separate cipher objects produce identical results
TEST(Chacha20Poly1305, SeparateCipherObjects)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0xBB);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64);
    std::vector<Uint8> tag1(16), tag2(16);

    // Encrypt with first object
    ref::ChaChaPoly256 chacha1;
    chacha1.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha1.setAad(AAD, sizeof(AAD));
    Uint64 outlen1 = 0;
    chacha1.encrypt(plaintext.data(), ciphertext1.data(), plaintext.size(), &outlen1);
    chacha1.getTag(tag1.data(), 16);

    // Encrypt with second object
    ref::ChaChaPoly256 chacha2;
    chacha2.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha2.setAad(AAD, sizeof(AAD));
    Uint64 outlen2 = 0;
    chacha2.encrypt(plaintext.data(), ciphertext2.data(), plaintext.size(), &outlen2);
    chacha2.getTag(tag2.data(), 16);

    EXPECT_EQ(ciphertext1, ciphertext2);
    EXPECT_EQ(tag1, tag2);
}

// Test 64-byte block (one ChaCha20 block)
TEST(Chacha20Poly1305, OneBlock)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0xCC);
    std::vector<Uint8> ciphertext(64), decrypted(64);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD, sizeof(AAD));
    
    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), 64, &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD, sizeof(AAD));
    
    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), 64, &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test block boundary sizes (around 64-byte boundaries)
TEST(Chacha20Poly1305, BlockBoundarySizes)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    std::vector<size_t> sizes = { 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257 };

    for (size_t size : sizes) {
        std::vector<Uint8> plaintext(size, 0xDD);
        std::vector<Uint8> ciphertext(size), decrypted(size);
        std::vector<Uint8> tag(16);

        ref::ChaChaPoly256 chacha_enc, chacha_dec;
        chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_enc.setAad(AAD, sizeof(AAD));
        
        Uint64 outlen1 = 0;
        chacha_enc.encrypt(plaintext.data(), ciphertext.data(), size, &outlen1);
        chacha_enc.getTag(tag.data(), 16);

        chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        chacha_dec.setAad(AAD, sizeof(AAD));
        
        Uint64 outlen2 = 0;
        chacha_dec.decrypt(ciphertext.data(), decrypted.data(), size, &outlen2);

        EXPECT_EQ(decrypted, plaintext) << "Mismatch for size: " << size;
    }
}

// Test fixture for AEAD lifecycle scenarios: split init, nonce re-init,
// multi-update streaming, and zero-length payloads. Each test compares
// reused-object output against a fresh-object reference to verify that
// internal state resets correctly between operations.
class ChaCha20Poly1305Lifecycle : public ::testing::Test
{
  protected:
    iCipherAead*
    createAead()
    {
        return createCipherAead(CipherMode::eCHACHA20_POLY1305,
                                CipherKeyLen::eKey256Bit);
    }

    void
    setAad(iCipherAead* aead, const Uint8* aad, Uint64 aadLen)
    {
        ASSERT_NE(aead, nullptr);
        alc_error_t err = aead->setAad(aad, aadLen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
    }

    void
    initAndSetAad(iCipherAead*   aead,
                  const Uint8*   key,
                  Uint64         keyLen,
                  const Uint8*   nonce,
                  Uint64         nonceLen,
                  const Uint8*   aad,
                  Uint64         aadLen)
    {
        ASSERT_NE(aead, nullptr);
        alc_error_t err = aead->init(key, keyLen, nonce, nonceLen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        setAad(aead, aad, aadLen);
    }

    void
    encryptAndGetTag(iCipherAead*         aead,
                     const Uint8*         plaintext,
                     Uint64               plaintextLen,
                     std::vector<Uint8>&  ciphertext,
                     std::vector<Uint8>&  tag)
    {
        ASSERT_NE(aead, nullptr);
        Uint64 outlen = 0;
        alc_error_t err =
            aead->encrypt(plaintext, ciphertext.data(), plaintextLen, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, plaintextLen);

        err = aead->getTag(tag.data(), tag.size());
        ASSERT_EQ(err, ALC_ERROR_NONE);
    }

    void
    decryptAndGetTag(iCipherAead*         aead,
                     const Uint8*         ciphertext,
                     Uint64               ciphertextLen,
                     std::vector<Uint8>&  plaintext,
                     std::vector<Uint8>&  tag)
    {
        ASSERT_NE(aead, nullptr);
        Uint64 outlen = 0;
        alc_error_t err =
            aead->decrypt(ciphertext, plaintext.data(), ciphertextLen, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, ciphertextLen);

        err = aead->getTag(tag.data(), tag.size());
        ASSERT_EQ(err, ALC_ERROR_NONE);
    }

    void
    encryptWithFreshObject(const Uint8*       key,
                           Uint64             keyLen,
                           const Uint8*       nonce,
                           Uint64             nonceLen,
                           const Uint8*       aad,
                           Uint64             aadLen,
                           const Uint8*       plaintext,
                           Uint64             plaintextLen,
                           std::vector<Uint8>& ciphertext,
                           std::vector<Uint8>& tag)
    {
        auto aead = createAead();
        ASSERT_NE(aead, nullptr);

        initAndSetAad(aead, key, keyLen, nonce, nonceLen, aad, aadLen);
        encryptAndGetTag(aead, plaintext, plaintextLen, ciphertext, tag);

        delete aead;
    }

    void
    decryptWithFreshObject(const Uint8*       key,
                           Uint64             keyLen,
                           const Uint8*       nonce,
                           Uint64             nonceLen,
                           const Uint8*       aad,
                           Uint64             aadLen,
                           const Uint8*       ciphertext,
                           Uint64             ciphertextLen,
                           std::vector<Uint8>& plaintext,
                           std::vector<Uint8>& tag)
    {
        auto aead = createAead();
        ASSERT_NE(aead, nullptr);

        initAndSetAad(aead, key, keyLen, nonce, nonceLen, aad, aadLen);
        decryptAndGetTag(aead, ciphertext, ciphertextLen, plaintext, tag);

        delete aead;
    }
};

// Lifecycle: init(key only) -> init(nonce only) -> setAad -> encrypt+tag
//         -> compare against fresh-object reference output.
TEST_F(ChaCha20Poly1305Lifecycle, KeyOnlyInitThenNonceInit)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x42);
    std::vector<Uint8> ciphertext(plaintext.size()), expected_ciphertext(plaintext.size());
    std::vector<Uint8> tag(16), expected_tag(16);

    // Reference behavior from a fresh object.
    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce,
                           sizeof(nonce),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           expected_ciphertext,
                           expected_tag);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);

    // Split init: set key now, and defer nonce to a later call.
    alc_error_t err = aead->init(key, sizeof(key) * 8, nullptr, 0);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Complete init by setting only nonce.
    err = aead->init(nullptr, 0, nonce, sizeof(nonce));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    setAad(aead, aad, sizeof(aad));
    encryptAndGetTag(
        aead, plaintext.data(), plaintext.size(), ciphertext, tag);

    // Split-init path must match fresh-object output.
    EXPECT_EQ(ciphertext, expected_ciphertext);
    EXPECT_EQ(tag, expected_tag);

    delete aead;
}

// Lifecycle: init(key,nonce1) -> setAad -> encrypt+tag
//         -> init(nonce2 only, key reused) -> setAad -> encrypt+tag
//         -> compare each record against fresh-object references.
TEST_F(ChaCha20Poly1305Lifecycle, EncryptThenNonceReinitThenEncrypt)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce1[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                       0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 nonce2[12];
    std::copy(std::begin(nonce1), std::end(nonce1), nonce2);
    nonce2[11] ^= 0x01;
    Uint8 aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x42);
    std::vector<Uint8> ciphertext1(plaintext.size()), ciphertext2(plaintext.size());
    std::vector<Uint8> expected_ciphertext1(plaintext.size()),
        expected_ciphertext2(plaintext.size());
    std::vector<Uint8> tag1(16), tag2(16), expected_tag1(16), expected_tag2(16);

    // Record 1 reference (fresh object, nonce1).
    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce1,
                           sizeof(nonce1),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           expected_ciphertext1,
                           expected_tag1);
    // Record 2 reference (fresh object, nonce2).
    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce2,
                           sizeof(nonce2),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           expected_ciphertext2,
                           expected_tag2);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);

    // Record 1 on reused object.
    initAndSetAad(
        aead, key, sizeof(key) * 8, nonce1, sizeof(nonce1), aad, sizeof(aad));
    encryptAndGetTag(
        aead, plaintext.data(), plaintext.size(), ciphertext1, tag1);

    // Record 2 on same object: nonce-only re-init, key state is reused.
    alc_error_t err = aead->init(nullptr, 0, nonce2, sizeof(nonce2));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    setAad(aead, aad, sizeof(aad));
    encryptAndGetTag(
        aead, plaintext.data(), plaintext.size(), ciphertext2, tag2);

    // Reused-object output must match per-record fresh-object output.
    EXPECT_EQ(ciphertext1, expected_ciphertext1);
    EXPECT_EQ(tag1, expected_tag1);
    EXPECT_EQ(ciphertext2, expected_ciphertext2);
    EXPECT_EQ(tag2, expected_tag2);
    // Different nonce must produce different record output.
    EXPECT_NE(ciphertext1, ciphertext2);
    EXPECT_NE(tag1, tag2);

    delete aead;
}

// Lifecycle: init -> setAad -> encrypt(chunk1..chunk4) -> getTag
//         -> compare against single-shot fresh-object reference.
TEST_F(ChaCha20Poly1305Lifecycle, EncryptMultiUpdate)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = static_cast<Uint8>(i % 256);
    }
    std::vector<Uint8> ciphertext(plaintext.size()), expected_ciphertext(plaintext.size());
    std::vector<Uint8> tag(16), expected_tag(16);

    // Reference single-shot output.
    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce,
                           sizeof(nonce),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           expected_ciphertext,
                           expected_tag);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);

    // Streaming path under test: same message via four updates.
    initAndSetAad(
        aead, key, sizeof(key) * 8, nonce, sizeof(nonce), aad, sizeof(aad));

    Uint64 outlen = 0;
    alc_error_t err = aead->encrypt(
        plaintext.data(), ciphertext.data(), 16, &outlen);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 16);

    err = aead->encrypt(
        plaintext.data() + 16, ciphertext.data() + 16, 16, &outlen);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 16);

    err = aead->encrypt(
        plaintext.data() + 32, ciphertext.data() + 32, 16, &outlen);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 16);

    err = aead->encrypt(
        plaintext.data() + 48, ciphertext.data() + 48, 16, &outlen);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 16);

    err = aead->getTag(tag.data(), tag.size());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // Multi-update and single-shot must produce identical output.
    EXPECT_EQ(ciphertext, expected_ciphertext);
    EXPECT_EQ(tag, expected_tag);

    delete aead;
}

TEST_F(ChaCha20Poly1305Lifecycle, EncryptBatchedKeystreamThirtyTwoUpdates)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(512);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = static_cast<Uint8>((i * 7) & 0xff);
    }
    std::vector<Uint8> ciphertext(plaintext.size()), expected_ciphertext(plaintext.size());
    std::vector<Uint8> tag(16), expected_tag(16);

    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce,
                           sizeof(nonce),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           expected_ciphertext,
                           expected_tag);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);
    initAndSetAad(
        aead, key, sizeof(key) * 8, nonce, sizeof(nonce), aad, sizeof(aad));

    for (size_t off = 0; off < plaintext.size(); off += 16) {
        Uint64 outlen = 0;
        alc_error_t err =
            aead->encrypt(plaintext.data() + off, ciphertext.data() + off, 16, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, 16);
    }
    alc_error_t err = aead->getTag(tag.data(), tag.size());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(ciphertext, expected_ciphertext);
    EXPECT_EQ(tag, expected_tag);
    delete aead;
}

TEST_F(ChaCha20Poly1305Lifecycle, DecryptBatchedKeystreamThirtyTwoUpdates)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(512);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = static_cast<Uint8>((i * 11) & 0xff);
    }
    std::vector<Uint8> ciphertext(plaintext.size()), decrypted(plaintext.size());
    std::vector<Uint8> tag(16), expected_tag(16);

    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce,
                           sizeof(nonce),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           ciphertext,
                           expected_tag);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);
    initAndSetAad(
        aead, key, sizeof(key) * 8, nonce, sizeof(nonce), aad, sizeof(aad));

    for (size_t off = 0; off < ciphertext.size(); off += 16) {
        Uint64 outlen = 0;
        alc_error_t err =
            aead->decrypt(ciphertext.data() + off, decrypted.data() + off, 16, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, 16);
    }
    alc_error_t err = aead->getTag(tag.data(), tag.size());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(decrypted, plaintext);
    EXPECT_EQ(tag, expected_tag);
    delete aead;
}

TEST_F(ChaCha20Poly1305Lifecycle, EncryptBatchedKeystreamMixedUpdates)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    const std::vector<size_t> chunks = { 17, 31, 5, 96, 13, 128, 222 };
    std::vector<Uint8> plaintext(512);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = static_cast<Uint8>((i * 13 + 3) & 0xff);
    }
    std::vector<Uint8> ciphertext(plaintext.size()), expected_ciphertext(plaintext.size());
    std::vector<Uint8> tag(16), expected_tag(16);

    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce,
                           sizeof(nonce),
                           aad,
                           sizeof(aad),
                           plaintext.data(),
                           plaintext.size(),
                           expected_ciphertext,
                           expected_tag);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);
    initAndSetAad(
        aead, key, sizeof(key) * 8, nonce, sizeof(nonce), aad, sizeof(aad));

    size_t off = 0;
    for (size_t chunk : chunks) {
        Uint64 outlen = 0;
        alc_error_t err =
            aead->encrypt(plaintext.data() + off, ciphertext.data() + off, chunk, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, chunk);
        off += chunk;
    }
    EXPECT_EQ(off, plaintext.size());
    alc_error_t err = aead->getTag(tag.data(), tag.size());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(ciphertext, expected_ciphertext);
    EXPECT_EQ(tag, expected_tag);
    delete aead;
}

// Lifecycle: init -> setAad -> encrypt(len=0) -> getTag
//         -> repeat with same AAD and changed AAD to validate determinism/sensitivity.
TEST_F(ChaCha20Poly1305Lifecycle, ZeroLengthPlaintextWithAad)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 aad1[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                     0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    Uint8 aad2[12];
    std::copy(std::begin(aad1), std::end(aad1), aad2);
    aad2[0] ^= 0x01;
    Uint8 dummy = 0;
    std::vector<Uint8> tag1(16), tag1_repeat(16), tag2(16), zeros(16, 0x00);

    auto run_zero_length_case = [&](const Uint8* aad,
                                    Uint64       aadLen,
                                    std::vector<Uint8>& tag) {
        auto aead = createAead();
        ASSERT_NE(aead, nullptr);

        alc_error_t err = aead->init(key, sizeof(key) * 8, nonce, sizeof(nonce));
        ASSERT_EQ(err, ALC_ERROR_NONE);
        setAad(aead, aad, aadLen);

        // Use non-zero sentinel to confirm zero-length call returns outlen=0.
        Uint64 outlen = 7;
        err = aead->encrypt(&dummy, &dummy, 0, &outlen);
        ASSERT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, 0);

        err = aead->getTag(tag.data(), tag.size());
        ASSERT_EQ(err, ALC_ERROR_NONE);

        delete aead;
    };

    run_zero_length_case(aad1, sizeof(aad1), tag1);
    run_zero_length_case(aad1, sizeof(aad1), tag1_repeat);
    run_zero_length_case(aad2, sizeof(aad2), tag2);

    // Same key/nonce/AAD must be deterministic.
    EXPECT_EQ(tag1, tag1_repeat);
    // A non-empty AAD-only tag should not be an all-zero block.
    EXPECT_NE(tag1, zeros);
    // Changing AAD should change the tag.
    EXPECT_NE(tag1, tag2);
}

// Lifecycle: precompute record refs -> init(key,nonce1) decrypt+tag
//         -> init(nonce2 only, key reused) decrypt+tag
//         -> compare each record against fresh-object decrypt references.
TEST_F(ChaCha20Poly1305Lifecycle, NonceReinitThenDecrypt)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce1[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                       0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 nonce2[12];
    std::copy(std::begin(nonce1), std::end(nonce1), nonce2);
    nonce2[11] ^= 0x01;
    Uint8 aad1[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                     0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    Uint8 aad2[12];
    std::copy(std::begin(aad1), std::end(aad1), aad2);
    aad2[0] ^= 0x01;
    std::vector<Uint8> plaintext1(64, 0x42);
    std::vector<Uint8> plaintext2(64);
    for (size_t i = 0; i < plaintext2.size(); i++) {
        plaintext2[i] = static_cast<Uint8>(i % 256);
    }
    std::vector<Uint8> ciphertext1(plaintext1.size()), ciphertext2(plaintext2.size());
    std::vector<Uint8> expected_ciphertext1(plaintext1.size()),
        expected_ciphertext2(plaintext2.size());
    std::vector<Uint8> decrypt_expected1(plaintext1.size()),
        decrypt_expected2(plaintext2.size());
    std::vector<Uint8> decrypted1(plaintext1.size()), decrypted2(plaintext2.size());
    std::vector<Uint8> encrypt_tag1(16), encrypt_tag2(16), decrypt_expected_tag1(16),
        decrypt_expected_tag2(16), decrypt_tag1(16), decrypt_tag2(16);

    // Precompute per-record ciphertext/tag references.
    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce1,
                           sizeof(nonce1),
                           aad1,
                           sizeof(aad1),
                           plaintext1.data(),
                           plaintext1.size(),
                           expected_ciphertext1,
                           encrypt_tag1);
    encryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce2,
                           sizeof(nonce2),
                           aad2,
                           sizeof(aad2),
                           plaintext2.data(),
                           plaintext2.size(),
                           expected_ciphertext2,
                           encrypt_tag2);

    // Precompute per-record decrypt references from fresh objects.
    decryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce1,
                           sizeof(nonce1),
                           aad1,
                           sizeof(aad1),
                           expected_ciphertext1.data(),
                           expected_ciphertext1.size(),
                           decrypt_expected1,
                           decrypt_expected_tag1);
    decryptWithFreshObject(key,
                           sizeof(key) * 8,
                           nonce2,
                           sizeof(nonce2),
                           aad2,
                           sizeof(aad2),
                           expected_ciphertext2.data(),
                           expected_ciphertext2.size(),
                           decrypt_expected2,
                           decrypt_expected_tag2);

    auto aead = createAead();
    ASSERT_NE(aead, nullptr);

    // Record 1 decrypt on reused object.
    initAndSetAad(
        aead, key, sizeof(key) * 8, nonce1, sizeof(nonce1), aad1, sizeof(aad1));
    decryptAndGetTag(aead,
                     expected_ciphertext1.data(),
                     expected_ciphertext1.size(),
                     decrypted1,
                     decrypt_tag1);

    // Record 2 decrypt after nonce-only re-init.
    alc_error_t err = aead->init(nullptr, 0, nonce2, sizeof(nonce2));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    setAad(aead, aad2, sizeof(aad2));
    decryptAndGetTag(aead,
                     expected_ciphertext2.data(),
                     expected_ciphertext2.size(),
                     decrypted2,
                     decrypt_tag2);

    // Fresh-object references and reused-object output must match.
    EXPECT_EQ(decrypt_expected1, plaintext1);
    EXPECT_EQ(decrypt_expected2, plaintext2);
    EXPECT_EQ(decrypt_expected_tag1, encrypt_tag1);
    EXPECT_EQ(decrypt_expected_tag2, encrypt_tag2);
    EXPECT_EQ(decrypted1, decrypt_expected1);
    EXPECT_EQ(decrypt_tag1, decrypt_expected_tag1);
    EXPECT_EQ(decrypted2, decrypt_expected2);
    EXPECT_EQ(decrypt_tag2, decrypt_expected_tag2);

    delete aead;
}

// Negative Tests for ChaCha20-Poly1305 - Null Pointer and Edge Cases

// Test null pointer for key with non-zero keyLen in init
// key=NULL with keyLen=0 is valid when reusing the stored key state,
// but key=NULL with non-zero keyLen is invalid.
TEST(Chacha20Poly1305_Negative, NullKeyPointer)
{
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    ref::ChaChaPoly256 chacha_poly;
    alc_error_t err = chacha_poly.init(nullptr, 256, nonce, sizeof(nonce));
    EXPECT_TRUE(alcp_is_error(err)) << "init with null key should fail";
}

// Test null pointer for nonce in init
TEST(Chacha20Poly1305_Negative, NullNoncePointer)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };

    ref::ChaChaPoly256 chacha_poly;
    alc_error_t err = chacha_poly.init(key, sizeof(key) * 8, nullptr, 12);
    EXPECT_TRUE(alcp_is_error(err)) << "init with null nonce should fail";
}

// Test null pointer for input in encrypt
TEST(Chacha20Poly1305_Negative, NullInputPointerEncrypt)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> output(32);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));

    Uint64 outlen = 0;
    alc_error_t err = chacha_poly.encrypt(nullptr, output.data(), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input should fail";
}

// Test null pointer for output in encrypt
TEST(Chacha20Poly1305_Negative, NullOutputPointerEncrypt)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> input(32, 0x55);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));

    Uint64 outlen = 0;
    alc_error_t err = chacha_poly.encrypt(input.data(), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null output should fail";
}

// Test null pointer for input in decrypt
TEST(Chacha20Poly1305_Negative, NullInputPointerDecrypt)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> output(32);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));

    Uint64 outlen = 0;
    alc_error_t err = chacha_poly.decrypt(nullptr, output.data(), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null input should fail";
}

// Test null pointer for output in decrypt
TEST(Chacha20Poly1305_Negative, NullOutputPointerDecrypt)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> input(32, 0x55);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));

    Uint64 outlen = 0;
    alc_error_t err = chacha_poly.decrypt(input.data(), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null output should fail";
}

// Test null pointer for AAD in setAad
TEST(Chacha20Poly1305_Negative, NullAADPointer)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    alc_error_t err = chacha_poly.setAad(nullptr, 12);
    EXPECT_TRUE(alcp_is_error(err)) << "setAad with null AAD should fail";
}

// Test null pointer for tag in getTag
TEST(Chacha20Poly1305_Negative, NullTagPointerGetTag)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    std::vector<Uint8> plaintext(32, 0x55);
    std::vector<Uint8> ciphertext(32);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));

    Uint64 outlen = 0;
    chacha_poly.encrypt(plaintext.data(), ciphertext.data(), 32, &outlen);
    alc_error_t err = chacha_poly.getTag(nullptr, 16);
    EXPECT_TRUE(alcp_is_error(err)) << "getTag with null tag should fail";
}

// Test zero key length
TEST(Chacha20Poly1305_Negative, ZeroKeyLength)
{
    Uint8 key[32] = { 0 };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    ref::ChaChaPoly256 chacha_poly;
    alc_error_t err = chacha_poly.init(key, 0, nonce, sizeof(nonce));
    EXPECT_TRUE(alcp_is_error(err)) << "init with zero key length should fail";
}

// Test zero nonce length
TEST(Chacha20Poly1305_Negative, ZeroNonceLength)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[12] = { 0 };

    ref::ChaChaPoly256 chacha_poly;
    alc_error_t err = chacha_poly.init(key, sizeof(key) * 8, nonce, 0);
    EXPECT_TRUE(alcp_is_error(err)) << "init with zero nonce length should fail";
}

// Test zero length input (should succeed or be handled gracefully)
TEST(Chacha20Poly1305_Negative, ZeroLengthInput)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    Uint8 dummy = 0;
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_poly.setAad(AAD, sizeof(AAD));

    Uint64 outlen = 0;
    // Zero length encryption should be handled gracefully
    chacha_poly.encrypt(&dummy, &dummy, 0, &outlen);
    chacha_poly.getTag(tag.data(), 16);
    // No crash means success - tag should still be valid
}

// Test in-place encryption (input == output)
TEST(Chacha20Poly1305_Negative, InPlaceEncryption)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> data(64, 0x77);
    std::vector<Uint8> original = data;
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_poly.setAad(AAD, sizeof(AAD));

    // In-place encryption (input == output)
    Uint64 outlen = 0;
    chacha_poly.encrypt(data.data(), data.data(), data.size(), &outlen);
    chacha_poly.getTag(tag.data(), 16);

    // Data should be changed (encrypted)
    EXPECT_NE(data, original) << "In-place encryption should change data";
}

// Test in-place decryption (input == output)
TEST(Chacha20Poly1305_Negative, InPlaceDecryption)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x88);
    std::vector<Uint8> data(64);
    std::vector<Uint8> tag(16);

    // First encrypt to get ciphertext
    ref::ChaChaPoly256 chacha_enc;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD, sizeof(AAD));
    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), data.data(), plaintext.size(), &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    // Now decrypt in-place
    ref::ChaChaPoly256 chacha_dec;
    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD, sizeof(AAD));
    Uint64 outlen2 = 0;
    chacha_dec.decrypt(data.data(), data.data(), data.size(), &outlen2);

    // In-place decryption should recover plaintext
    EXPECT_EQ(data, plaintext) << "In-place decryption should recover plaintext";
}

// Test repeated init calls
TEST(Chacha20Poly1305_Negative, RepeatedInit)
{
    Uint8 key1[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                     0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                     0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                     0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 key2[] = { 0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98,
                     0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
                     0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88,
                     0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80 };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64, 0x55);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64);
    std::vector<Uint8> tag1(16), tag2(16);

    ref::ChaChaPoly256 chacha_poly;

    // First init and encrypt
    chacha_poly.init(key1, sizeof(key1) * 8, nonce, sizeof(nonce));
    chacha_poly.setAad(AAD, sizeof(AAD));
    Uint64 outlen1 = 0;
    chacha_poly.encrypt(plaintext.data(), ciphertext1.data(), plaintext.size(), &outlen1);
    chacha_poly.getTag(tag1.data(), 16);

    // Second init (overwriting first) and encrypt
    chacha_poly.init(key2, sizeof(key2) * 8, nonce, sizeof(nonce));
    chacha_poly.setAad(AAD, sizeof(AAD));
    Uint64 outlen2 = 0;
    chacha_poly.encrypt(plaintext.data(), ciphertext2.data(), plaintext.size(), &outlen2);
    chacha_poly.getTag(tag2.data(), 16);

    // Different keys should produce different outputs
    EXPECT_NE(ciphertext1, ciphertext2) << "Different keys should produce different ciphertext";
    EXPECT_NE(tag1, tag2) << "Different keys should produce different tag";
}

// Test very large data
TEST(Chacha20Poly1305_Negative, VeryLargeData)
{
    const size_t data_size = 64 * 1024; // 64 KB
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(data_size);
    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = static_cast<Uint8>(i % 256);
    }
    std::vector<Uint8> ciphertext(data_size), decrypted(data_size);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD, sizeof(AAD));

    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), data_size, &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD, sizeof(AAD));

    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), data_size, &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test all zeros input
TEST(Chacha20Poly1305_Negative, AllZerosInput)
{
    Uint8 key[32] = { 0 };
    Uint8 nonce[12] = { 0 };
    Uint8 AAD[12] = { 0 };
    std::vector<Uint8> plaintext(64, 0x00);
    std::vector<Uint8> ciphertext(64), decrypted(64);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_enc, chacha_dec;
    chacha_enc.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_enc.setAad(AAD, sizeof(AAD));

    Uint64 outlen1 = 0;
    chacha_enc.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen1);
    chacha_enc.getTag(tag.data(), 16);

    chacha_dec.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_dec.setAad(AAD, sizeof(AAD));

    Uint64 outlen2 = 0;
    chacha_dec.decrypt(ciphertext.data(), decrypted.data(), ciphertext.size(), &outlen2);

    EXPECT_EQ(decrypted, plaintext);
}

// Test encrypt doesn't modify input
TEST(Chacha20Poly1305_Negative, EncryptDoesNotModifyInput)
{
    Uint8 key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    std::vector<Uint8> plaintext(64);
    for (size_t i = 0; i < 64; i++) {
        plaintext[i] = static_cast<Uint8>(i);
    }
    std::vector<Uint8> original_plaintext = plaintext;
    std::vector<Uint8> ciphertext(64);
    std::vector<Uint8> tag(16);

    ref::ChaChaPoly256 chacha_poly;
    chacha_poly.init(key, sizeof(key) * 8, nonce, sizeof(nonce));
    chacha_poly.setAad(AAD, sizeof(AAD));

    Uint64 outlen = 0;
    chacha_poly.encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &outlen);
    chacha_poly.getTag(tag.data(), 16);

    // Verify input was not modified
    EXPECT_EQ(plaintext, original_plaintext);
}

#endif
