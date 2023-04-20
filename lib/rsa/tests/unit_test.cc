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

TEST(RsaTest, PublicEncryptPrivateDecryptTest)
{
    Rsa rsa_obj;

    Uint64 key_size = rsa_obj.getKeySize();

    auto p_text = std::make_unique<Uint8[]>(key_size);
    auto p_mod  = std::make_unique<Uint8[]>(key_size);
    auto p_enc  = std::make_unique<Uint8[]>(key_size);
    auto p_dec  = std::make_unique<Uint8[]>(key_size);

    std::fill(p_text.get(), p_text.get() + key_size, 0x31);

    RsaPublicKey pub_key;
    pub_key.modulus = p_mod.get();
    pub_key.size    = key_size;
    Status status   = rsa_obj.getPublickey(pub_key);

    rsa_obj.encryptPublic(
        ALCP_RSA_PADDING_NONE, pub_key, p_text.get(), key_size, p_enc.get());

    rsa_obj.decryptPrivate(
        ALCP_RSA_PADDING_NONE, p_enc.get(), key_size, p_dec.get());

    EXPECT_EQ(memcmp(p_dec.get(), p_text.get(), key_size), 0);
}

TEST(RsaTest, PubKeyEncryptPaddingTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size = rsa_obj.getKeySize();

    auto p_mod  = std::make_unique<Uint8[]>(pub_key.size);
    auto p_text = std::make_unique<Uint8[]>(pub_key.size);
    auto p_enc  = std::make_unique<Uint8[]>(pub_key.size);

    pub_key.modulus = p_mod.get();

    Status status = rsa_obj.encryptPublic(ALCP_RSA_PADDING_NONE,
                                          pub_key,
                                          p_text.get(),
                                          pub_key.size,
                                          p_enc.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(
        ALCP_RSA_PKCS1_PADDING, pub_key, nullptr, pub_key.size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);

    status = rsa_obj.encryptPublic(
        ALCP_RSA_PKCS1_OAEP_PADDING, pub_key, nullptr, pub_key.size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptValidSizeTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size = rsa_obj.getKeySize();

    auto p_mod  = std::make_unique<Uint8[]>(pub_key.size);
    auto p_text = std::make_unique<Uint8[]>(pub_key.size);
    auto p_enc  = std::make_unique<Uint8[]>(pub_key.size);

    pub_key.modulus = p_mod.get();

    Status status = rsa_obj.encryptPublic(ALCP_RSA_PADDING_NONE,
                                          pub_key,
                                          p_text.get(),
                                          pub_key.size,
                                          p_enc.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptInValidSizeTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;

    pub_key.size = rsa_obj.getKeySize();
    auto p_mod   = std::make_unique<Uint8[]>(pub_key.size);
    auto p_text  = std::make_unique<Uint8[]>(pub_key.size);
    auto p_enc   = std::make_unique<Uint8[]>(pub_key.size);

    pub_key.modulus = p_mod.get();

    Status status = rsa_obj.encryptPublic(ALCP_RSA_PADDING_NONE,
                                          pub_key,
                                          p_text.get(),
                                          pub_key.size + 1,
                                          p_enc.get());
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 key_size   = rsa_obj.getKeySize();
    auto   p_buff     = std::make_unique<Uint8[]>(key_size);
    auto   p_buff_enc = std::make_unique<Uint8[]>(key_size);

    auto p_modulus = std::make_unique<Uint8[]>(key_size);

    RsaPublicKey pub_key;
    pub_key.modulus = p_modulus.get();
    pub_key.size    = key_size;

    Status status = rsa_obj.encryptPublic(ALCP_RSA_PADDING_NONE,
                                          pub_key,
                                          p_buff.get(),
                                          pub_key.size,
                                          p_buff_enc.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PubKeyEncryptInValidBuffTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size    = rsa_obj.getKeySize();
    pub_key.modulus = nullptr;

    Status status = rsa_obj.encryptPublic(
        ALCP_RSA_PADDING_NONE, pub_key, nullptr, pub_key.size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptPaddingTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize();

    auto p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    Status status = rsa_obj.decryptPrivate(
        ALCP_RSA_PADDING_NONE, p_buff_enc.get(), enc_size, p_buff_dec.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);

    status = rsa_obj.decryptPrivate(
        ALCP_RSA_PKCS1_PADDING, nullptr, enc_size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);

    status = rsa_obj.decryptPrivate(
        ALCP_RSA_PKCS1_OAEP_PADDING, nullptr, enc_size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize();

    auto p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    Status status = rsa_obj.decryptPrivate(
        ALCP_RSA_PADDING_NONE, p_buff_enc.get(), enc_size, p_buff_dec.get());

    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptInvalidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize() + 1;

    Status status = rsa_obj.decryptPrivate(
        ALCP_RSA_PADDING_NONE, nullptr, enc_size, nullptr);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size   = rsa_obj.getKeySize();
    auto   p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto   p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    Status status = rsa_obj.decryptPrivate(
        ALCP_RSA_PADDING_NONE, p_buff_enc.get(), enc_size, p_buff_dec.get());
    EXPECT_EQ(status.code(), ErrorCode::eOk);
}

TEST(RsaTest, PrivKeyDecryptInValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = rsa_obj.getKeySize();

    Status status = rsa_obj.decryptPrivate(
        ALCP_RSA_PADDING_NONE, nullptr, enc_size, nullptr);
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
    EXPECT_NE(rsa_obj.getKeySize(), 0);
}

} // namespace
