/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "../../rng/include/hardware_rng.hh"
#include "alcp/digest.h"
#include "digest.hh"
#include "digest/sha2.hh"
#include "openssl/bio.h"
#include "rng/drbg_hmac.hh"
#include "gtest/gtest.h"
#include <iostream>

// #include "types.h"
using namespace alcp::random_number::drbg;
using namespace alcp::random_number;
using namespace alcp::digest;

typedef std::tuple<alc_digest_type_t,  // Digest Class
                   std::vector<Uint8>, // Entropy Input
                   std::vector<Uint8>, // Reseed Entropy
                   std::vector<Uint8>, // nonce
                   std::vector<Uint8>  // Generated Bits
                   >
                                                      hmac_kat_tuple_t;
typedef std::map<const std::string, hmac_kat_tuple_t> known_answer_map_t;

/*
    Example Encodings
        E50B_R0B_N8B_G64B
        E50B  -> Entropy 50 Bytes
        R0B   -> Reseed Entropy 0 Bytes
        N8B   -> Nonce 8 Bytes
        G64B  -> Generated 64 Bytes

    _CROSS is appended if cross test detected failure

    Tuple order
        {DigestClass,Entropy,ReseedEntropy,Nonce,GeneratedBits}
*/
// clang-format off
known_answer_map_t KATDatasetSha256{
    {
         "E50B_R0B_N8B_G64B",
         {
            ALC_DIGEST_TYPE_SHA2,
            {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36},
            {},
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
            {0xD6,0x7B,0x8C,0x17,0x34,0xF4,0x6F,0xA3,0xF7,0x63,0xCF,0x57,0xC6,0xF9,0xF4,0xF2,0xDC,0x10,0x89,0xBD,0x8B,0xC1,0xF6,0xF0,0x23,0x95,0x0B,0xFC,0x56,0x17,0x63,0x52,0x08,0xC8,0x50,0x12,0x38,0xAD,0x7A,0x44,0x00,0xDE,0xFE,0xE4,0x6C,0x64,0x0B,0x61,0xAF,0x77,0xC2,0xD1,0xA3,0xBF,0xAA,0x90,0xED,0xE5,0xD2,0x07,0x40,0x6E,0x54,0x03},
         }
    } 
};
// clang-format on

class HmacDrbgKat
    : public testing::TestWithParam<
          std::pair<const std::string, hmac_kat_tuple_t>>
{
  public:
    std::unique_ptr<HmacDrbg> m_hmacDrbg;
    Digest*                   p_shaObj;
    alc_digest_type_t         m_digestClass;
    std::vector<Uint8> m_entropy = {}, m_reseedEntropy = {}, m_nonce = {},
                       m_generatedBits = {};
};

class HmacDrbgKatSha224 : public HmacDrbgKat
{
  public:
    void SetUp() override
    {
        // Tuple order
        // {DigestClass,Entropy,ReseedEntropy,Nonce,GeneratedBits}

        const auto params   = GetParam();
        const auto testName = params.first;
        const auto [digestClass, entropy, reseedEntropy, nonce, generatedBits] =
            params.second;

        m_digestClass   = digestClass;
        m_entropy       = entropy;
        m_reseedEntropy = reseedEntropy;
        m_nonce         = nonce;
        m_generatedBits = generatedBits;

        switch (m_digestClass) {
            case ALC_DIGEST_TYPE_SHA2:
                p_shaObj = new Sha224();
            case ALC_DIGEST_TYPE_SHA3:
                // TODO: Implement
                break;
            default:
                // TODO: Raise an exeception
                break;
        }
        m_hmacDrbg =
            std::make_unique<HmacDrbg>(p_shaObj->getHashSize(), p_shaObj);
    }
    void TearDown() override
    {
        switch (m_digestClass) {
            case ALC_DIGEST_TYPE_SHA2:
                delete static_cast<Sha224*>(p_shaObj);
            case ALC_DIGEST_TYPE_SHA3:
                // TODO: Implement
                break;
            default:
                // TODO: Raise an exeception
                break;
        }
    }
};

class HmacDrbgKatSha256 : public HmacDrbgKat
{
  public:
    void SetUp() override
    {
        // Tuple order
        // {DigestClass,Entropy,ReseedEntropy,Nonce,GeneratedBits}

        const auto params   = GetParam();
        const auto testName = params.first;
        const auto [digestClass, entropy, reseedEntropy, nonce, generatedBits] =
            params.second;

        m_digestClass   = digestClass;
        m_entropy       = entropy;
        m_reseedEntropy = reseedEntropy;
        m_nonce         = nonce;
        m_generatedBits = generatedBits;

        switch (m_digestClass) {
            case ALC_DIGEST_TYPE_SHA2:
                p_shaObj = new Sha256();
            case ALC_DIGEST_TYPE_SHA3:
                // TODO: Implement
                break;
            default:
                // TODO: Raise an exeception
                break;
        }
        m_hmacDrbg =
            std::make_unique<HmacDrbg>(p_shaObj->getHashSize(), p_shaObj);
    }
    void TearDown() override
    {
        switch (m_digestClass) {
            case ALC_DIGEST_TYPE_SHA2:
                delete static_cast<Sha256*>(p_shaObj);
            case ALC_DIGEST_TYPE_SHA3:
                // TODO: Implement
                break;
            default:
                // TODO: Raise an exeception
                break;
        }
    }
};

TEST_P(HmacDrbgKatSha256, SHA)
{
    std::vector<Uint8>       output(m_generatedBits.size());
    const std::vector<Uint8> PersonalizationString(0);
    const std::vector<Uint8> AdditionalInput(0);
    m_hmacDrbg.get()->Instantiate(m_entropy, m_nonce, PersonalizationString);
    m_hmacDrbg.get()->Generate(AdditionalInput, output);
    EXPECT_EQ(m_generatedBits, output);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    HmacDrbgKatSha256,
    testing::ValuesIn(KATDatasetSha256),
    [](const testing::TestParamInfo<HmacDrbgKatSha256::ParamType>& info) {
        return info.param.first;
    });

TEST(Instantiate, SHA256)
{
    const std::vector<Uint8> EntropyInput = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
    };

    const std::vector<Uint8> nonce = { 0x20, 0x21, 0x22, 0x23,
                                       0x24, 0x25, 0x26, 0x27 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    alcp::digest::Digest* sha_obj = new alcp::digest::Sha256();

    HmacDrbg hmacDrbg(32, sha_obj);

    std::vector<Uint8> key_exp = { 0x3D, 0xDA, 0x54, 0x3E, 0x7E, 0xEF, 0x14,
                                   0xF9, 0x36, 0x23, 0x7B, 0xE6, 0x5D, 0x09,
                                   0x4B, 0x4D, 0xDC, 0x96, 0x9C, 0x0B, 0x2B,
                                   0x5E, 0xAF, 0xB5, 0xD8, 0x05, 0xE8, 0x6C,
                                   0xFA, 0x64, 0xD7, 0x41 };
    std::vector<Uint8> v_exp   = {
        0x2D, 0x02, 0xC2, 0xF8, 0x22, 0x51, 0x7D, 0x54, 0xB8, 0x17, 0x27,
        0x9A, 0x59, 0x49, 0x1C, 0x41, 0xA1, 0x98, 0x9B, 0x3E, 0x38, 0x2D,
        0xEB, 0xE8, 0x0D, 0x2C, 0x7F, 0x66, 0x0F, 0x44, 0x76, 0xC4
    };

    hmacDrbg.Instantiate(EntropyInput, nonce, PersonalizationString);

    EXPECT_EQ(key_exp, hmacDrbg.GetKCopy());
    EXPECT_EQ(v_exp, hmacDrbg.GetVCopy());
}

TEST(DRBGGeneration, SHA256_NO_RESEED_0)
{
    const std::vector<Uint8> EntropyInput = {
        0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde,
        0x1c, 0xbd, 0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb,
        0x93, 0x5e, 0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88
    };

    const std::vector<Uint8> nonce = { 0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d,
                                       0xc6, 0x9f, 0xc9, 0x02, 0x94, 0x08,
                                       0x05, 0xec, 0x0c, 0xa8 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    const std::vector<Uint8> expReturnedBits = {
        0xe5, 0x28, 0xe9, 0xab, 0xf2, 0xde, 0xce, 0x54, 0xd4, 0x7c, 0x7e, 0x75,
        0xe5, 0xfe, 0x30, 0x21, 0x49, 0xf8, 0x17, 0xea, 0x9f, 0xb4, 0xbe, 0xe6,
        0xf4, 0x19, 0x96, 0x97, 0xd0, 0x4d, 0x5b, 0x89, 0xd5, 0x4f, 0xbb, 0x97,
        0x8a, 0x15, 0xb5, 0xc4, 0x43, 0xc9, 0xec, 0x21, 0x03, 0x6d, 0x24, 0x60,
        0xb6, 0xf7, 0x3e, 0xba, 0xd0, 0xdc, 0x2a, 0xba, 0x6e, 0x62, 0x4a, 0xbf,
        0x07, 0x74, 0x5b, 0xc1, 0x07, 0x69, 0x4b, 0xb7, 0x54, 0x7b, 0xb0, 0x99,
        0x5f, 0x70, 0xde, 0x25, 0xd6, 0xb2, 0x9e, 0x2d, 0x30, 0x11, 0xbb, 0x19,
        0xd2, 0x76, 0x76, 0xc0, 0x71, 0x62, 0xc8, 0xb5, 0xcc, 0xde, 0x06, 0x68,
        0x96, 0x1d, 0xf8, 0x68, 0x03, 0x48, 0x2c, 0xb3, 0x7e, 0xd6, 0xd5, 0xc0,
        0xbb, 0x8d, 0x50, 0xcf, 0x1f, 0x50, 0xd4, 0x76, 0xaa, 0x04, 0x58, 0xbd,
        0xab, 0xa8, 0x06, 0xf4, 0x8b, 0xe9, 0xdc, 0xb8
    };

    alcp::digest::Digest* sha_obj = new alcp::digest::Sha256();

    HmacDrbg hmacDrbg(32, sha_obj);

    hmacDrbg.Instantiate(EntropyInput, nonce, PersonalizationString);

    DebugPrint(
        hmacDrbg.GetKCopy(), "Test Instantiate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Instantiate : v", __FILE__, __LINE__);

    std::vector<Uint8> output(expReturnedBits.size(), 0x01);
    hmacDrbg.Generate(AdditionalInput, output);
    hmacDrbg.Generate(AdditionalInput, output);

    DebugPrint(hmacDrbg.GetKCopy(), "Test Generate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Generate : v", __FILE__, __LINE__);

    EXPECT_EQ(expReturnedBits, output);

    DebugPrint(expReturnedBits, "Expected Bits", __FILE__, __LINE__);
    DebugPrint(output, "Output Bits", __FILE__, __LINE__);
}

TEST(DRBGGeneration, SHA256_NO_RESEED_1)
{
    const std::vector<Uint8> EntropyInput = {
        0x79, 0x73, 0x74, 0x79, 0xba, 0x4e, 0x76, 0x42, 0xa2, 0x21, 0xfc,
        0xfd, 0x1b, 0x82, 0x0b, 0x13, 0x4e, 0x9e, 0x35, 0x40, 0xa3, 0x5b,
        0xb4, 0x8f, 0xfa, 0xe2, 0x9c, 0x20, 0xf5, 0x41, 0x8e, 0xa3
    };

    const std::vector<Uint8> nonce = { 0x35, 0x93, 0x25, 0x9c, 0x09, 0x2b,
                                       0xef, 0x41, 0x29, 0xbc, 0x2c, 0x6c,
                                       0x9e, 0x19, 0xf3, 0x43 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    const std::vector<Uint8> expReturnedBits = {
        0xcf, 0x5a, 0xd5, 0x98, 0x4f, 0x9e, 0x43, 0x91, 0x7a, 0xa9, 0x08, 0x73,
        0x80, 0xda, 0xc4, 0x6e, 0x41, 0x0d, 0xdc, 0x8a, 0x77, 0x31, 0x85, 0x9c,
        0x84, 0xe9, 0xd0, 0xf3, 0x1b, 0xd4, 0x36, 0x55, 0xb9, 0x24, 0x15, 0x94,
        0x13, 0xe2, 0x29, 0x3b, 0x17, 0x61, 0x0f, 0x21, 0x1e, 0x09, 0xf7, 0x70,
        0xf1, 0x72, 0xb8, 0xfb, 0x69, 0x3a, 0x35, 0xb8, 0x5d, 0x3b, 0x9e, 0x5e,
        0x63, 0xb1, 0xdc, 0x25, 0x2a, 0xc0, 0xe1, 0x15, 0x00, 0x2e, 0x9b, 0xed,
        0xfb, 0x4b, 0x5b, 0x6f, 0xd4, 0x3f, 0x33, 0xb8, 0xe0, 0xea, 0xfb, 0x2d,
        0x07, 0x2e, 0x1a, 0x6f, 0xee, 0x1f, 0x15, 0x9d, 0xf9, 0xb5, 0x1e, 0x6c,
        0x8d, 0xa7, 0x37, 0xe6, 0x0d, 0x50, 0x32, 0xdd, 0x30, 0x54, 0x4e, 0xc5,
        0x15, 0x58, 0xc6, 0xf0, 0x80, 0xbd, 0xbd, 0xab, 0x1d, 0xe8, 0xa9, 0x39,
        0xe9, 0x61, 0xe0, 0x6b, 0x5f, 0x1a, 0xca, 0x37
    };

    alcp::digest::Digest* sha_obj = new alcp::digest::Sha256();

    HmacDrbg hmacDrbg(32, sha_obj);

    hmacDrbg.Instantiate(EntropyInput, nonce, PersonalizationString);

    DebugPrint(
        hmacDrbg.GetKCopy(), "Test Instantiate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Instantiate : v", __FILE__, __LINE__);

    std::vector<Uint8> output(expReturnedBits.size(), 0x01);
    hmacDrbg.Generate(AdditionalInput, output);
    hmacDrbg.Generate(AdditionalInput, output);

    DebugPrint(hmacDrbg.GetKCopy(), "Test Generate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Generate : v", __FILE__, __LINE__);

    EXPECT_EQ(expReturnedBits, output);

    DebugPrint(expReturnedBits, "Expected Bits", __FILE__, __LINE__);
    DebugPrint(output, "Output Bits", __FILE__, __LINE__);
}

TEST(DRBGGeneration, SHA256_RESEED_0)
{
    const std::vector<Uint8> EntropyInput = {
        0x06, 0x03, 0x2c, 0xd5, 0xee, 0xd3, 0x3f, 0x39, 0x26, 0x5f, 0x49,
        0xec, 0xb1, 0x42, 0xc5, 0x11, 0xda, 0x9a, 0xff, 0x2a, 0xf7, 0x12,
        0x03, 0xbf, 0xfa, 0xf3, 0x4a, 0x9c, 0xa5, 0xbd, 0x9c, 0x0d
    };

    const std::vector<Uint8> nonce = { 0x0e, 0x66, 0xf7, 0x1e, 0xdc, 0x43,
                                       0xe4, 0x2a, 0x45, 0xad, 0x3c, 0x6f,
                                       0xc6, 0xcd, 0xc4, 0xdf };

    const std::vector<Uint8> EntropyInputReseed = {
        0x01, 0x92, 0x0a, 0x4e, 0x66, 0x9e, 0xd3, 0xa8, 0x5a, 0xe8, 0xa3,
        0x3b, 0x35, 0xa7, 0x4a, 0xd7, 0xfb, 0x2a, 0x6b, 0xb4, 0xcf, 0x39,
        0x5c, 0xe0, 0x03, 0x34, 0xa9, 0xc9, 0xa5, 0xa5, 0xd5, 0x52
    };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    const std::vector<Uint8> AdditionalInputReseed(0);

    const std::vector<Uint8> expReturnedBits = {
        0x76, 0xfc, 0x79, 0xfe, 0x9b, 0x50, 0xbe, 0xcc, 0xc9, 0x91, 0xa1, 0x1b,
        0x56, 0x35, 0x78, 0x3a, 0x83, 0x53, 0x6a, 0xdd, 0x03, 0xc1, 0x57, 0xfb,
        0x30, 0x64, 0x5e, 0x61, 0x1c, 0x28, 0x98, 0xbb, 0x2b, 0x1b, 0xc2, 0x15,
        0x00, 0x02, 0x09, 0x20, 0x8c, 0xd5, 0x06, 0xcb, 0x28, 0xda, 0x2a, 0x51,
        0xbd, 0xb0, 0x38, 0x26, 0xaa, 0xf2, 0xbd, 0x23, 0x35, 0xd5, 0x76, 0xd5,
        0x19, 0x16, 0x08, 0x42, 0xe7, 0x15, 0x8a, 0xd0, 0x94, 0x9d, 0x1a, 0x9e,
        0xc3, 0xe6, 0x6e, 0xa1, 0xb1, 0xa0, 0x64, 0xb0, 0x05, 0xde, 0x91, 0x4e,
        0xac, 0x2e, 0x9d, 0x4f, 0x2d, 0x72, 0xa8, 0x61, 0x6a, 0x80, 0x22, 0x54,
        0x22, 0x91, 0x82, 0x50, 0xff, 0x66, 0xa4, 0x1b, 0xd2, 0xf8, 0x64, 0xa6,
        0xa3, 0x8c, 0xc5, 0xb6, 0x49, 0x9d, 0xc4, 0x3f, 0x7f, 0x2b, 0xd0, 0x9e,
        0x1e, 0x0f, 0x8f, 0x58, 0x85, 0x93, 0x51, 0x24
    };

    alcp::digest::Digest* sha_obj = new alcp::digest::Sha256();

    HmacDrbg hmacDrbg(32, sha_obj);

    hmacDrbg.Instantiate(EntropyInput, nonce, PersonalizationString);

    DebugPrint(
        hmacDrbg.GetKCopy(), "Test Instantiate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Instantiate : v", __FILE__, __LINE__);

    hmacDrbg.Reseed(EntropyInputReseed, AdditionalInputReseed);

    DebugPrint(hmacDrbg.GetKCopy(), "Test Reseed : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Reseed : v", __FILE__, __LINE__);

    std::vector<Uint8> output(expReturnedBits.size(), 0x01);
    hmacDrbg.Generate(AdditionalInput, output);

    DebugPrint(hmacDrbg.GetKCopy(), "Test Generate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Generate : v", __FILE__, __LINE__);

    hmacDrbg.Generate(AdditionalInput, output);

    DebugPrint(hmacDrbg.GetKCopy(), "Test Generate : key", __FILE__, __LINE__);

    DebugPrint(hmacDrbg.GetVCopy(), "Test Generate : v", __FILE__, __LINE__);

    EXPECT_EQ(expReturnedBits, output);

    DebugPrint(expReturnedBits, "Expected Bits", __FILE__, __LINE__);
    DebugPrint(output, "Output Bits", __FILE__, __LINE__);
}

#if 0
int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    auto default_printer =
        listeners.Release(listeners.default_result_printer());

    ConfigurableEventListener* listener =
        new ConfigurableEventListener(default_printer);

    listener->showEnvironment    = true;
    listener->showTestCases      = true;
    listener->showTestNames      = true;
    listener->showSuccesses      = true;
    listener->showInlineFailures = true;
    listeners.Append(listener);
    return RUN_ALL_TESTS();
}
#endif
