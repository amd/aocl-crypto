/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include <gtest/gtest.h>
#include <string.h>

#include "alcp/base.hh"
#include "alcp/error.h"
#include "alcp/rsa.hh"
#include "alcp/types.hh"

namespace {

using namespace std;
using namespace alcp;
using namespace rsa;

static const Uint8 Modulus[] = {
    0xef, 0x4f, 0xa2, 0xcd, 0x00, 0xea, 0x99, 0xeb, 0x12, 0xa8, 0x3a, 0x1b,
    0xc5, 0x5d, 0x49, 0x04, 0x18, 0xcd, 0x96, 0x69, 0xc9, 0x28, 0x2c, 0x36,
    0x40, 0x9a, 0x15, 0x40, 0x05, 0x6b, 0x35, 0x6f, 0x89, 0x76, 0xf3, 0xb9,
    0xe3, 0xac, 0x4d, 0x2a, 0xe4, 0xba, 0xd9, 0x6e, 0xb8, 0xa4, 0x05, 0x0b,
    0xc5, 0x8e, 0xdf, 0x15, 0x33, 0xfc, 0x81, 0x2b, 0xb5, 0xf4, 0x3a, 0x0b,
    0x67, 0x2d, 0x7d, 0x7c, 0x41, 0x8c, 0xc0, 0x46, 0x93, 0x7d, 0xe9, 0x95,
    0x90, 0x1e, 0xdd, 0xc0, 0xf4, 0xfc, 0x23, 0x90, 0xbb, 0x14, 0x73, 0x5e,
    0xcc, 0x86, 0x45, 0x6a, 0x9c, 0x15, 0x46, 0x92, 0xf3, 0xac, 0x24, 0x8f,
    0x0c, 0x28, 0x25, 0x17, 0xb1, 0xb8, 0x3f, 0xa5, 0x9c, 0x61, 0xbd, 0x2c,
    0x10, 0x7a, 0x5c, 0x47, 0xe0, 0xa2, 0xf1, 0xf3, 0x24, 0xca, 0x37, 0xc2,
    0x06, 0x78, 0xa4, 0xad, 0x0e, 0xbd, 0x72, 0xeb
};

static const Uint8 P[] = { 0xfa, 0x5e, 0xa7, 0x98, 0x7d, 0x19, 0x66, 0xdf,
                           0x91, 0xd7, 0xe7, 0xf6, 0xbe, 0xb7, 0xdf, 0x51,
                           0x99, 0x61, 0xb8, 0x08, 0xff, 0xcd, 0xe1, 0xf4,
                           0x42, 0x0a, 0xc4, 0x01, 0xf8, 0xcb, 0x85, 0xd1,
                           0x64, 0xe0, 0x86, 0x66, 0xe3, 0x0b, 0xcc, 0x3b,
                           0x2f, 0xca, 0xc0, 0x47, 0x62, 0x8d, 0x4d, 0x0e,
                           0xf5, 0x81, 0x63, 0xa0, 0x70, 0x78, 0xb3, 0x69,
                           0xfa, 0xdd, 0x55, 0xd8, 0x53, 0xf2, 0xb1, 0xd3 };

static const Uint8 Q[] = { 0xf4, 0xb1, 0x51, 0x68, 0x20, 0x7b, 0x71, 0xd9,
                           0x69, 0x67, 0xe1, 0x5b, 0xdf, 0x98, 0x76, 0xae,
                           0x02, 0xc8, 0x76, 0xd9, 0xbd, 0x5a, 0xf5, 0x8d,
                           0x95, 0xa1, 0x5e, 0x66, 0xff, 0x67, 0xed, 0x0f,
                           0xa1, 0x8f, 0x78, 0xa0, 0x85, 0x6c, 0x6a, 0xae,
                           0x51, 0xcc, 0xd1, 0xed, 0x62, 0xb7, 0x9f, 0x7c,
                           0x75, 0xd3, 0xf7, 0x7a, 0x1a, 0xb7, 0x28, 0x06,
                           0x1a, 0x9d, 0x2a, 0x26, 0x05, 0x0b, 0xf3, 0x89 };

static const Uint8 DP[] = { 0x57, 0x7a, 0x0e, 0xf0, 0x96, 0x74, 0xf3, 0x9e,
                            0x95, 0xa4, 0x6c, 0x25, 0xa8, 0x09, 0x32, 0x7b,
                            0x9e, 0x2d, 0xa8, 0x51, 0x6c, 0x9f, 0x10, 0x9d,
                            0x79, 0x1d, 0xad, 0xd2, 0x4a, 0x8d, 0x41, 0x9a,
                            0x21, 0xb6, 0xd8, 0xfe, 0xc5, 0xc1, 0x6f, 0x80,
                            0x16, 0x78, 0xae, 0xa9, 0xc2, 0x63, 0x40, 0x53,
                            0x43, 0xb0, 0x0b, 0x91, 0x18, 0xfa, 0xf3, 0x24,
                            0xca, 0x43, 0xdf, 0x24, 0x90, 0x60, 0x31, 0x85 };

static const Uint8 DQ[] = { 0x1d, 0x7e, 0xf2, 0x6d, 0x36, 0xdd, 0x2a, 0x90,
                            0x26, 0xa0, 0x9b, 0x0d, 0xd4, 0x1a, 0x30, 0xd4,
                            0x31, 0x09, 0xb1, 0x29, 0xf6, 0x25, 0x6c, 0xcc,
                            0x30, 0x69, 0x4f, 0x53, 0xe3, 0x1d, 0xc7, 0xf9,
                            0xc6, 0x63, 0xe1, 0x0a, 0x98, 0x8a, 0xc5, 0x21,
                            0x56, 0x42, 0xf6, 0x5b, 0x43, 0x37, 0x17, 0x46,
                            0x8d, 0x7d, 0x8b, 0xab, 0x70, 0x64, 0xfb, 0xb2,
                            0x20, 0xab, 0x29, 0x55, 0x83, 0xee, 0x38, 0xe1 };

static const Uint8 QINV[] = { 0xad, 0xad, 0xc8, 0xfd, 0xd8, 0xc9, 0x60, 0x63,
                              0xfd, 0xe8, 0xcd, 0xff, 0xa1, 0x0a, 0x23, 0x2d,
                              0x0d, 0x1e, 0x3f, 0x53, 0xe4, 0x4d, 0xea, 0x8c,
                              0x8f, 0x1f, 0xd9, 0x41, 0xef, 0x87, 0x21, 0x9b,
                              0x89, 0xc7, 0x27, 0x1c, 0xb3, 0x7d, 0xa9, 0xe4,
                              0x66, 0x6d, 0x8e, 0x59, 0x1c, 0x01, 0xc4, 0x14,
                              0x7d, 0x69, 0x77, 0xb2, 0xbe, 0xb6, 0xd2, 0x8c,
                              0x43, 0xcc, 0xfd, 0x41, 0x43, 0x02, 0x45, 0xde };

static const Uint64 PublicKeyExponent = 0x10001;

TEST(RsaTest, PublicEncryptPrivateDecryptTest)
{
    Rsa rsa_obj;

    Uint64 key_size = rsa_obj.getKeySize();

    auto p_text = std::make_unique<Uint8[]>(key_size);
    auto p_mod  = std::make_unique<Uint8[]>(key_size);
    auto p_enc  = std::make_unique<Uint8[]>(key_size);
    auto p_dec  = std::make_unique<Uint8[]>(key_size);

    std::fill(p_text.get(), p_text.get() + key_size, 0x31);

    Status status =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(p_text.get(), key_size, p_enc.get());
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.setPrivateKey(DP, DQ, P, Q, QINV, Modulus, sizeof(P));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.decryptPrivate(p_enc.get(), key_size, p_dec.get());
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    EXPECT_EQ(memcmp(p_dec.get(), p_text.get(), key_size), 0);
}

TEST(RsaTest, PubKeyEncryptValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 size = rsa_obj.getKeySize();

    auto p_mod  = std::make_unique<Uint8[]>(size);
    auto p_text = std::make_unique<Uint8[]>(size);
    auto p_enc  = std::make_unique<Uint8[]>(size);

    Status status =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(p_text.get(), size, p_enc.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptInValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 size   = rsa_obj.getKeySize();
    auto   p_mod  = std::make_unique<Uint8[]>(size);
    auto   p_text = std::make_unique<Uint8[]>(size);
    auto   p_enc  = std::make_unique<Uint8[]>(size);

    Status status =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(p_text.get(), size + 1, p_enc.get());
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 key_size   = rsa_obj.getKeySize();
    auto   p_buff     = std::make_unique<Uint8[]>(key_size);
    auto   p_buff_enc = std::make_unique<Uint8[]>(key_size);

    auto p_modulus = std::make_unique<Uint8[]>(key_size);

    Status status =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(p_buff.get(), key_size, p_buff_enc.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptInValidBuffTest)
{
    Rsa rsa_obj;

    Status status =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(nullptr, rsa_obj.getKeySize(), nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize();

    auto p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    Status status =
        rsa_obj.setPrivateKey(DP, DQ, P, Q, QINV, Modulus, sizeof(P));
    ASSERT_EQ(status.code(), ErrorCode::eOk);

    status =
        rsa_obj.decryptPrivate(p_buff_enc.get(), enc_size, p_buff_dec.get());

    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptInvalidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize() + 1;

    Status status = rsa_obj.decryptPrivate(nullptr, enc_size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size   = rsa_obj.getKeySize();
    auto   p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto   p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    Status status =
        rsa_obj.decryptPrivate(p_buff_enc.get(), enc_size, p_buff_dec.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptInValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize();

    Status status = rsa_obj.decryptPrivate(nullptr, enc_size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyWithValidModulusTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size    = rsa_obj.getKeySize();
    auto p_buff     = std::make_unique<Uint8[]>(pub_key.size);
    pub_key.modulus = p_buff.get();
    Status status   = rsa_obj.getPublickey(pub_key);
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyWithInValidModulusTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size    = rsa_obj.getKeySize();
    pub_key.modulus = nullptr;
    Status status   = rsa_obj.getPublickey(pub_key);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyWithInvalidSizeTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size  = rsa_obj.getKeySize() + 1;
    Status status = rsa_obj.getPublickey(pub_key);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyWithValidSizeTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;

    pub_key.size = rsa_obj.getKeySize();
    auto p_buff  = std::make_unique<Uint8[]>(pub_key.size);

    pub_key.modulus = p_buff.get();
    Status status   = rsa_obj.getPublickey(pub_key);
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, KeySizeTest)
{
    Rsa rsa_obj;
    EXPECT_NE(rsa_obj.getKeySize(), 0UL);
}

} // namespace
