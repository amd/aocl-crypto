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

#include "../../rng/include/hardware_rng.hh"
#include "alcp/digest.h"
#include "digest.hh"
#include "digest/sha2.hh"
#include "openssl/bio.h"
#include "rng/drbg_hmac.hh"
#include "gtest/gtest.h"
#include <iostream>

// #include "types.h"
using namespace alcp::rng::drbg;
using namespace alcp::rng;
using namespace alcp::digest;

typedef std::tuple<int,                // Number of generate Calls
                   alc_digest_type_t,  // Digest Class
                   std::vector<Uint8>, // Entropy Input
                   std::vector<Uint8>, // Reseed Entropy
                   std::vector<Uint8>, // nonce
                   std::vector<Uint8>, // Personalization String
                   std::vector<Uint8>, // Additional Input Reseed
                   std::vector<Uint8>, // Additional Input 1
                   std::vector<Uint8>, // Additional Input 2
                   std::vector<Uint8>  // Generated Bits
                   >
                                                      hmac_kat_tuple_t;
typedef std::map<const std::string, hmac_kat_tuple_t> known_answer_map_t;

/*
    Example Encodings
        I2_E50B_R0B_N8B_P0B_A0B_A0B_A0B_G64B
        I2    -> Generated bytes are of 2nd call.
        E50B  -> Entropy 50 Bytes
        R0B   -> Reseed Entropy 0 Bytes
        N8B   -> Nonce 8 Bytes
        P0B   -> Personalization String 0 Bytes
        A0B   -> Additional Input Reseed 0 Bytes
        A0B   -> Additional Input 1 0 Bytes
        A0B   -> Additional Input 2 0 Bytes
        G64B  -> Generated 64 Bytes

    _CROSS is appended if cross test detected failure

    Tuple order
        {
            DigestClass,Entropy,ReseedEntropy,Nonce,
            PersonalizationStr,AdditionalInpt,GeneratedBits
        }
*/

class TestingHmacDrbg : public HmacDrbg
{
  public:
    using HmacDrbg::HmacDrbg;

    void reseed(const std::vector<Uint8>& entropy_input,
                const std::vector<Uint8>& additional_input)
    {
        internalReseed(entropy_input, additional_input);
    }
    void reseed(const Uint8* entropy_input,
                const Uint64 entropy_input_len,
                const Uint8* additional_input,
                const Uint64 additional_input_len)
    {
        internalReseed(entropy_input,
                       entropy_input_len,
                       additional_input,
                       additional_input_len);
    }
};

// clang-format off
known_answer_map_t KATDatasetSha256{
    {
         "I1_E50B_R0B_N8B_P0B_A0B_A0B_A0B_G64B",
         {
            1,
            ALC_DIGEST_TYPE_SHA2,
            {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36},
            {},
            {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27},
            {},
            {},
            {},
            {},
            {0xD6,0x7B,0x8C,0x17,0x34,0xF4,0x6F,0xA3,0xF7,0x63,0xCF,0x57,0xC6,0xF9,0xF4,0xF2,0xDC,0x10,0x89,0xBD,0x8B,0xC1,0xF6,0xF0,0x23,0x95,0x0B,0xFC,0x56,0x17,0x63,0x52,0x08,0xC8,0x50,0x12,0x38,0xAD,0x7A,0x44,0x00,0xDE,0xFE,0xE4,0x6C,0x64,0x0B,0x61,0xAF,0x77,0xC2,0xD1,0xA3,0xBF,0xAA,0x90,0xED,0xE5,0xD2,0x07,0x40,0x6E,0x54,0x03},
         }
    },
    {
         "I2_E55B_R0B_N16B_P0B_A0B_A0B_A0B_G128B",
         {
            2,
            ALC_DIGEST_TYPE_SHA2,
            {0xca,0x85,0x19,0x11,0x34,0x93,0x84,0xbf,0xfe,0x89,0xde,0x1c,0xbd,0xc4,0x6e,0x68,0x31,0xe4,0x4d,0x34,0xa4,0xfb,0x93,0x5e,0xe2,0x85,0xdd,0x14,0xb7,0x1a,0x74,0x88},
            {},
            {0x65,0x9b,0xa9,0x6c,0x60,0x1d,0xc6,0x9f,0xc9,0x02,0x94,0x08,0x05,0xec,0x0c,0xa8},
            {},
            {},
            {},
            {},
            {0xe5,0x28,0xe9,0xab,0xf2,0xde,0xce,0x54,0xd4,0x7c,0x7e,0x75,0xe5,0xfe,0x30,0x21,0x49,0xf8,0x17,0xea,0x9f,0xb4,0xbe,0xe6,0xf4,0x19,0x96,0x97,0xd0,0x4d,0x5b,0x89,0xd5,0x4f,0xbb,0x97,0x8a,0x15,0xb5,0xc4,0x43,0xc9,0xec,0x21,0x03,0x6d,0x24,0x60,0xb6,0xf7,0x3e,0xba,0xd0,0xdc,0x2a,0xba,0x6e,0x62,0x4a,0xbf,0x07,0x74,0x5b,0xc1,0x07,0x69,0x4b,0xb7,0x54,0x7b,0xb0,0x99,0x5f,0x70,0xde,0x25,0xd6,0xb2,0x9e,0x2d,0x30,0x11,0xbb,0x19,0xd2,0x76,0x76,0xc0,0x71,0x62,0xc8,0xb5,0xcc,0xde,0x06,0x68,0x96,0x1d,0xf8,0x68,0x03,0x48,0x2c,0xb3,0x7e,0xd6,0xd5,0xc0,0xbb,0x8d,0x50,0xcf,0x1f,0x50,0xd4,0x76,0xaa,0x04,0x58,0xbd,0xab,0xa8,0x06,0xf4,0x8b,0xe9,0xdc,0xb8},
         }
    },
    {
         "I2_E32B_R0B_N16B_P0B_A0B_A0B_A0B_G128B",
         {
            2,
            ALC_DIGEST_TYPE_SHA2,
            {0x79,0x73,0x74,0x79,0xba,0x4e,0x76,0x42,0xa2,0x21,0xfc,0xfd,0x1b,0x82,0x0b,0x13,0x4e,0x9e,0x35,0x40,0xa3,0x5b,0xb4,0x8f,0xfa,0xe2,0x9c,0x20,0xf5,0x41,0x8e,0xa3},
            {},
            {0x35,0x93,0x25,0x9c,0x09,0x2b,0xef,0x41,0x29,0xbc,0x2c,0x6c,0x9e,0x19,0xf3,0x43},
            {},
            {},
            {},
            {},
            {0xcf,0x5a,0xd5,0x98,0x4f,0x9e,0x43,0x91,0x7a,0xa9,0x08,0x73,0x80,0xda,0xc4,0x6e,0x41,0x0d,0xdc,0x8a,0x77,0x31,0x85,0x9c,0x84,0xe9,0xd0,0xf3,0x1b,0xd4,0x36,0x55,0xb9,0x24,0x15,0x94,0x13,0xe2,0x29,0x3b,0x17,0x61,0x0f,0x21,0x1e,0x09,0xf7,0x70,0xf1,0x72,0xb8,0xfb,0x69,0x3a,0x35,0xb8,0x5d,0x3b,0x9e,0x5e,0x63,0xb1,0xdc,0x25,0x2a,0xc0,0xe1,0x15,0x00,0x2e,0x9b,0xed,0xfb,0x4b,0x5b,0x6f,0xd4,0x3f,0x33,0xb8,0xe0,0xea,0xfb,0x2d,0x07,0x2e,0x1a,0x6f,0xee,0x1f,0x15,0x9d,0xf9,0xb5,0x1e,0x6c,0x8d,0xa7,0x37,0xe6,0x0d,0x50,0x32,0xdd,0x30,0x54,0x4e,0xc5,0x15,0x58,0xc6,0xf0,0x80,0xbd,0xbd,0xab,0x1d,0xe8,0xa9,0x39,0xe9,0x61,0xe0,0x6b,0x5f,0x1a,0xca,0x37},
         }
    },
    {
         "I2_E32B_R32B_N16B_P0B_A0B_A0B_A0B_G128B",
         {
            2,
            ALC_DIGEST_TYPE_SHA2,
            {0x06,0x03,0x2c,0xd5,0xee,0xd3,0x3f,0x39,0x26,0x5f,0x49,0xec,0xb1,0x42,0xc5,0x11,0xda,0x9a,0xff,0x2a,0xf7,0x12,0x03,0xbf,0xfa,0xf3,0x4a,0x9c,0xa5,0xbd,0x9c,0x0d},
            {0x01,0x92,0x0a,0x4e,0x66,0x9e,0xd3,0xa8,0x5a,0xe8,0xa3,0x3b,0x35,0xa7,0x4a,0xd7,0xfb,0x2a,0x6b,0xb4,0xcf,0x39,0x5c,0xe0,0x03,0x34,0xa9,0xc9,0xa5,0xa5,0xd5,0x52},
            {0x0e,0x66,0xf7,0x1e,0xdc,0x43,0xe4,0x2a,0x45,0xad,0x3c,0x6f,0xc6,0xcd,0xc4,0xdf},
            {},
            {},
            {},
            {},
            {0x76,0xfc,0x79,0xfe,0x9b,0x50,0xbe,0xcc,0xc9,0x91,0xa1,0x1b,0x56,0x35,0x78,0x3a,0x83,0x53,0x6a,0xdd,0x03,0xc1,0x57,0xfb,0x30,0x64,0x5e,0x61,0x1c,0x28,0x98,0xbb,0x2b,0x1b,0xc2,0x15,0x00,0x02,0x09,0x20,0x8c,0xd5,0x06,0xcb,0x28,0xda,0x2a,0x51,0xbd,0xb0,0x38,0x26,0xaa,0xf2,0xbd,0x23,0x35,0xd5,0x76,0xd5,0x19,0x16,0x08,0x42,0xe7,0x15,0x8a,0xd0,0x94,0x9d,0x1a,0x9e,0xc3,0xe6,0x6e,0xa1,0xb1,0xa0,0x64,0xb0,0x05,0xde,0x91,0x4e,0xac,0x2e,0x9d,0x4f,0x2d,0x72,0xa8,0x61,0x6a,0x80,0x22,0x54,0x22,0x91,0x82,0x50,0xff,0x66,0xa4,0x1b,0xd2,0xf8,0x64,0xa6,0xa3,0x8c,0xc5,0xb6,0x49,0x9d,0xc4,0x3f,0x7f,0x2b,0xd0,0x9e,0x1e,0x0f,0x8f,0x58,0x85,0x93,0x51,0x24},
         }
    },
};

known_answer_map_t KATDatasetSha224{
    {
         "I2_E24B_R0B_N12B_P24B_A0B_A24B_A24B_G112B",
         {
            2,
            ALC_DIGEST_TYPE_SHA2,
            {0xe3,0x50,0xff,0x0d,0x2d,0xfc,0x72,0x87,0xbc,0xee,0xb3,0x58,0x90,0xa8,0xc1,0x5d,0x38,0xdd,0xe5,0x2b,0x61,0x9a,0xd8,0x74},
            {},
            {0x27,0x6d,0x55,0x1d,0x78,0xfb,0x5f,0xd9,0xca,0x97,0x57,0x33},
            {0x26,0x08,0x2f,0xcd,0x90,0x8f,0x3a,0xbe,0x2a,0xa8,0x4d,0x99,0x4e,0xde,0xdf,0x86,0x44,0x07,0x4f,0x45,0x33,0xb0,0xc3,0x0d},
            {},
            {0x82,0xde,0xda,0x3a,0xdf,0x69,0x3b,0x1f,0xe1,0x88,0xfe,0xe4,0x04,0x17,0x2f,0xe7,0xf0,0x4e,0x7e,0x50,0x06,0x71,0x0c,0xc6},
            {0x30,0xc1,0xb7,0xad,0x05,0x7f,0xc6,0xaa,0x6d,0x88,0xb8,0x45,0x8b,0x10,0x8f,0xea,0x96,0xfb,0x0f,0xbf,0xdd,0x40,0xf7,0x7d},
            {0x05,0x03,0xdc,0x00,0x06,0xcc,0xb7,0x29,0xfa,0x9e,0xd9,0xc8,0xf1,0x26,0x50,0x4d,0x7b,0x61,0xa4,0x2a,0x34,0x51,0xcb,0xb6,0xf5,0xb0,0xdf,0x87,0x7a,0xf0,0x83,0x08,0x3f,0x1a,0x0c,0xae,0xb0,0x7d,0x77,0x0c,0x96,0xbe,0x4a,0x98,0xfd,0xac,0x5d,0xad,0x75,0xc2,0xbb,0x6f,0xf3,0xee,0xf5,0xa7,0x62,0x68,0xb4,0x08,0x0b,0x3b,0x52,0x66,0x6c,0xc4,0x76,0x17,0x0b,0x17,0xb9,0x66,0x10,0xda,0x63,0xdb,0xcc,0x81,0x83,0xd9,0x66,0xfa,0x1c,0xb6,0x08,0xf3,0x93,0xf8,0x7c,0x09,0xef,0x37,0xa0,0x97,0x6f,0xa8,0x8f,0xbc,0x21,0x71,0xf8,0x26,0x31,0x96,0x4d,0x17,0x72,0x20,0x91,0x25,0x9a,0x8c},
         }
    },
    {
        "I2_E24B_R24B_N12B_P24B_A24B_A24B_A24B_G112B",
        {
            2,
            ALC_DIGEST_TYPE_SHA2,
            {0x12,0x32,0x72,0x85,0x53,0x5b,0x38,0x66,0xcd,0x62,0x4a,0x17,0xfb,0x67,0x23,0xed,0xff,0x25,0x8d,0x16,0x59,0x91,0x77,0x30},
            {0x5b,0xef,0xfe,0xf6,0xdd,0x09,0x8c,0x43,0x2a,0xf5,0x37,0x23,0x30,0xc9,0x6c,0x03,0x4c,0xa0,0xb0,0xc0,0x92,0x80,0xc6,0xa2},
            {0x89,0x7c,0x8e,0x7f,0x57,0x67,0xdd,0x7b,0x2a,0x94,0xc2,0xf2},
            {0x50,0xc0,0x18,0x53,0xf8,0x45,0x41,0x30,0x1a,0x6c,0x50,0x7b,0x49,0x09,0x71,0xc9,0x88,0x1d,0x9d,0xa5,0x3d,0x8c,0x05,0xff},
            {0x49,0xfc,0x68,0xe4,0xfa,0x5e,0x48,0x45,0x11,0x27,0x57,0x14,0x64,0x9b,0xb7,0x35,0x77,0xe1,0x63,0xf0,0x00,0x17,0x80,0x6a},
            {0x05,0x97,0xf3,0xcd,0x8c,0xc9,0x67,0x0b,0x79,0xac,0xc0,0x45,0xfe,0x26,0x56,0x9e,0x91,0x52,0xd5,0x98,0x81,0xd7,0xfe,0xa1},
            {0xb9,0x48,0xdf,0x86,0x7c,0x7c,0x57,0x6a,0xc1,0x69,0xdb,0xd6,0x7e,0x1a,0xde,0x5f,0x58,0x30,0x49,0x7f,0x4f,0xc6,0x27,0xa5},
            {0x51,0xea,0xcd,0xa3,0x7b,0x5e,0x3c,0xf1,0xb0,0xb5,0x08,0xa2,0xa7,0xd7,0x70,0x4b,0x33,0xf5,0xc8,0xa5,0x96,0x60,0xef,0xc8,0xc7,0xe1,0xe8,0xf1,0x6d,0x4c,0xfb,0x40,0x75,0x80,0x09,0x94,0x6b,0x2a,0xeb,0xef,0x5c,0xf9,0xdb,0xca,0xda,0x11,0xb6,0x2e,0xeb,0xc5,0xf7,0xee,0x6c,0x64,0xb0,0xc5,0xe6,0x00,0x73,0x64,0x46,0xa9,0x9c,0xed,0xbe,0x1e,0x79,0xd1,0x12,0xff,0x6e,0x8f,0x67,0xa6,0xc9,0x06,0x50,0x03,0xc7,0xb1,0xeb,0xca,0xe6,0xfc,0x9a,0x0f,0x75,0x2e,0x1b,0xa1,0xcb,0x48,0x7d,0xc1,0x29,0x1f,0x0f,0x9c,0x1a,0x5d,0x24,0x9c,0x54,0x8a,0x9e,0xe0,0x60,0xd8,0x94,0xa2,0x7e,0x75},
        }
    },
};
// clang-format on

class HmacDrbgKat
    : public testing::TestWithParam<
          std::pair<const std::string, hmac_kat_tuple_t>>
{
  public:
    std::unique_ptr<TestingHmacDrbg> m_hmacDrbg;
    alc_digest_type_t                m_digestClass;
    int                              m_genCount = {};
    std::vector<Uint8> m_entropy = {}, m_reseedEntropy = {}, m_nonce = {},
                       m_pstr = {}, m_add_reseed = {}, m_add1 = {}, m_add2 = {},
                       m_generatedBits = {};

  public:
    void getParams()
    {
        // Tuple order
        // {
        //     DigestClass,Entropy,ReseedEntropy,Nonce,
        //     PersonalizationStr,AdditionalInpt,GeneratedBits
        // }
        const auto params   = GetParam();
        const auto testName = params.first;

        std::tie(m_genCount,
                 m_digestClass,
                 m_entropy,
                 m_reseedEntropy,
                 m_nonce,
                 m_pstr,
                 m_add_reseed,
                 m_add1,
                 m_add2,
                 m_generatedBits) = params.second;
    }

    void SetUp() override { getParams(); }
};

template<typename SHA_CLASS, alc_digest_len_t len>
class HmacDrbgKatTemplate : public HmacDrbgKat
{
    std::shared_ptr<SHA_CLASS> p_shaObj;

  public:
    void SetUp() override
    {
        HmacDrbgKat::SetUp();
        alc_digest_mode_t digest_mode = {};
        switch (len) {
            case ALC_DIGEST_LEN_224:
                digest_mode.dm_sha3 = ALC_SHA3_224;
                break;
            case ALC_DIGEST_LEN_256:
                digest_mode.dm_sha3 = ALC_SHA3_224;
                break;
            default:
                break;
        }
        alc_digest_info_t digest_info = {
            ALC_DIGEST_TYPE_SHA3, len, {}, digest_mode, {}
        };
        switch (m_digestClass) {
            case ALC_DIGEST_TYPE_SHA2:
                p_shaObj = std::make_shared<SHA_CLASS>();
            case ALC_DIGEST_TYPE_SHA3:
                p_shaObj = std::make_shared<SHA_CLASS>(digest_info);
                break;
            default:
                // TODO: Raise an exeception
                ASSERT_TRUE(false);
                break;
        }
        m_hmacDrbg = std::make_unique<TestingHmacDrbg>(p_shaObj->getHashSize(),
                                                       p_shaObj);
    }
};

class HmacDrbgKatSHA2_256
    : public HmacDrbgKatTemplate<Sha256, ALC_DIGEST_LEN_256>
{};

class HmacDrbgKatSHA2_224
    : public HmacDrbgKatTemplate<Sha224, ALC_DIGEST_LEN_224>
{};

TEST_P(HmacDrbgKatSHA2_256, SHA2)
{
    std::vector<Uint8> output(m_generatedBits.size());
    m_hmacDrbg->instantiate(m_entropy, m_nonce, m_pstr);
    if (m_reseedEntropy.size()) {
        m_hmacDrbg->reseed(m_reseedEntropy, m_add_reseed);
    }
    m_hmacDrbg->generate(m_add1, output);
    if (m_genCount > 1) {
        m_hmacDrbg->generate(m_add2, output);
    }
    EXPECT_EQ(m_generatedBits, output);
}

TEST_P(HmacDrbgKatSHA2_224, SHA2)
{
    std::vector<Uint8> output(m_generatedBits.size());
    m_hmacDrbg->instantiate(m_entropy, m_nonce, m_pstr);
    if (m_reseedEntropy.size()) {
        m_hmacDrbg->reseed(m_reseedEntropy, m_add_reseed);
    }
    m_hmacDrbg->generate(m_add1, output);
    if (m_genCount > 1) {
        m_hmacDrbg->generate(m_add2, output);
    }
    EXPECT_EQ(m_generatedBits, output);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    HmacDrbgKatSHA2_256,
    testing::ValuesIn(KATDatasetSha256),
    [](const testing::TestParamInfo<HmacDrbgKatSHA2_256::ParamType>& info) {
        return info.param.first;
    });

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    HmacDrbgKatSHA2_224,
    testing::ValuesIn(KATDatasetSha224),
    [](const testing::TestParamInfo<HmacDrbgKatSHA2_224::ParamType>& info) {
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

    std::shared_ptr<alcp::digest::Digest> sha_obj =
        std::make_shared<alcp::digest::Sha256>();

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

    hmacDrbg.instantiate(EntropyInput, nonce, PersonalizationString);

    EXPECT_EQ(key_exp, hmacDrbg.GetKCopy());
    EXPECT_EQ(v_exp, hmacDrbg.GetVCopy());
}

TEST(SHA2, SHA224KAT1)
{
    const std::vector<Uint8> EntropyInput = {
        0x59, 0x10, 0x75, 0xa5, 0x5c, 0x82, 0x63, 0xc3, 0x23, 0x39, 0x45, 0x5b,
        0x3e, 0x92, 0x94, 0x82, 0xbe, 0xa1, 0xec, 0x97, 0x07, 0xf1, 0xce, 0x1d
    };

    const std::vector<Uint8> nonce = { 0x88, 0x4b, 0x66, 0xa1, 0xbd, 0xd6,
                                       0x46, 0x41, 0x55, 0x7b, 0x82, 0x8a };

    const std::vector<Uint8> PersonalizationString = {
        0x6c, 0x4d, 0x23, 0x25, 0x9b, 0x35, 0xc9, 0x28, 0x6f, 0xd9, 0xea, 0xfb,
        0x81, 0xe9, 0x6f, 0x9d, 0x2a, 0x7b, 0xc3, 0x4d, 0x6d, 0x81, 0xb0, 0xfb
    };

    const std::vector<Uint8> EntropyInputReseed = {
        0xe1, 0xc0, 0x5f, 0xce, 0xd3, 0xfd, 0xc8, 0x29, 0x93, 0xe9, 0xa7, 0x66,
        0x0f, 0x19, 0xe6, 0xe6, 0xc1, 0x6b, 0xaa, 0xb8, 0xa4, 0xa9, 0xb0, 0x18
    };
    const std::vector<Uint8> AdditionalInputReseed = {
        0xae, 0x15, 0x42, 0x38, 0x0b, 0xbb, 0x82, 0xc7, 0x9d, 0x1b, 0xfc, 0x3f,
        0xd2, 0x43, 0x31, 0x59, 0xdf, 0x5a, 0x9f, 0x66, 0x94, 0x66, 0x1f, 0x7e
    };

    const std::vector<Uint8> AdditionalInput1 = {
        0x32, 0xd9, 0x31, 0x12, 0x5a, 0x43, 0x2f, 0xa2, 0x82, 0x5c, 0x75, 0xda,
        0x70, 0x90, 0x0b, 0xdd, 0x9d, 0xa7, 0x15, 0xae, 0xbc, 0xae, 0x64, 0x25
    };

    const std::vector<Uint8> AdditionalInput2 = {
        0x0c, 0xe8, 0x2d, 0x2a, 0xab, 0x13, 0x43, 0x64, 0x59, 0x31, 0x13, 0x80,
        0xc2, 0x9d, 0xa5, 0x37, 0xcc, 0xd6, 0x67, 0x70, 0x67, 0xea, 0xb6, 0xdb
    };

    const std::vector<Uint8> ReturnedBits = {
        0x08, 0x6f, 0x39, 0x05, 0xc0, 0xc9, 0x5d, 0xca, 0x7c, 0x8b, 0xef, 0x66,
        0xb3, 0x0f, 0xa6, 0x42, 0xde, 0xff, 0x68, 0xd1, 0xf0, 0x8f, 0x6d, 0x46,
        0xf5, 0xdc, 0x52, 0x3b, 0xd2, 0x7c, 0xa5, 0xd9, 0x84, 0xe2, 0x6d, 0x5c,
        0xdf, 0xe7, 0xa4, 0x5d, 0xf6, 0x78, 0xde, 0x4f, 0x4b, 0x05, 0xef, 0x5e,
        0xbe, 0xab, 0xac, 0xad, 0xa2, 0xce, 0x25, 0x9f, 0xab, 0x95, 0x3c, 0xd0,
        0xbd, 0xb9, 0xb2, 0x07, 0x04, 0x6b, 0x8c, 0xa3, 0x07, 0xd3, 0x87, 0xa6,
        0xee, 0xf2, 0x87, 0xad, 0xfb, 0x3e, 0x16, 0xc7, 0x2f, 0x37, 0x8c, 0xbc,
        0xa3, 0x40, 0x6a, 0x2d, 0x85, 0xb8, 0xa1, 0x43, 0x4c, 0xf8, 0x7e, 0xdd,
        0x98, 0xa4, 0xac, 0x4f, 0xdb, 0x5b, 0xb1, 0x23, 0xf8, 0x53, 0x5b, 0x29,
        0x40, 0xfb, 0xf0, 0xce
    };

    const std::vector<Uint8> key_init_exp = {
        0x61, 0xa7, 0xf2, 0xad, 0x0e, 0x21, 0x64, 0xce, 0x0f, 0x5c,
        0x56, 0x83, 0xb3, 0xc4, 0x8e, 0x22, 0x51, 0x0a, 0xef, 0xd8,
        0xfb, 0x70, 0x06, 0x95, 0x29, 0xf4, 0x46, 0x0f
    };

    const std::vector<Uint8> v_init_exp = { 0x4d, 0xdc, 0x77, 0x1a, 0x51, 0x52,
                                            0xc2, 0x0b, 0x2a, 0x9a, 0x6d, 0x0f,
                                            0x51, 0x5a, 0x7a, 0x63, 0x4d, 0x3e,
                                            0xf4, 0x95, 0xd5, 0xbb, 0xe5, 0xa7,
                                            0x18, 0x4d, 0xc0, 0x52 };

    const std::vector<Uint8> key_reseed_exp = {
        0x1c, 0x9c, 0x9b, 0x91, 0xad, 0xa0, 0xca, 0xff, 0xc5, 0xa5,
        0xc9, 0x7d, 0x31, 0x1e, 0x28, 0xcf, 0xd8, 0xa0, 0x25, 0x16,
        0xa6, 0xf7, 0xa1, 0x3d, 0xf8, 0x72, 0x53, 0x12
    };

    const std::vector<Uint8> v_reseed_exp = {
        0xd1, 0xfb, 0x1e, 0x6a, 0xe3, 0xa2, 0x14, 0xcd, 0x8b, 0x03,
        0x8e, 0x0c, 0x16, 0x9a, 0xd7, 0x3e, 0x69, 0x7c, 0x1c, 0x7f,
        0xdc, 0x5f, 0x86, 0x70, 0xeb, 0x3c, 0xbc, 0x2b
    };

    const std::vector<Uint8> key_exp1 = { 0x23, 0xb0, 0xd0, 0x9c, 0x73, 0x1b,
                                          0x40, 0x77, 0xee, 0xd1, 0xbc, 0xe9,
                                          0x5a, 0xbf, 0x77, 0x3c, 0x97, 0x60,
                                          0x49, 0x79, 0xd1, 0x45, 0x6c, 0x45,
                                          0x63, 0x39, 0xba, 0xdf };

    const std::vector<Uint8> v_exp1 = { 0x4b, 0x63, 0xf8, 0x3b, 0x69, 0x86,
                                        0xaf, 0x8e, 0x0d, 0x15, 0x2e, 0x71,
                                        0xa4, 0x37, 0x48, 0xb5, 0x68, 0x72,
                                        0xd9, 0x88, 0xe5, 0xde, 0xcf, 0x31,
                                        0x40, 0x44, 0x86, 0xe7 };

    const std::vector<Uint8> key_exp2 = { 0xff, 0x82, 0x89, 0x3a, 0x60, 0x68,
                                          0x1f, 0xfe, 0xd4, 0xd5, 0x51, 0x23,
                                          0x79, 0x25, 0xa9, 0x34, 0x55, 0x48,
                                          0xdf, 0xd3, 0x5b, 0x39, 0x4d, 0x61,
                                          0x63, 0x24, 0x50, 0xca };

    const std::vector<Uint8> v_exp2 = { 0x53, 0xb0, 0x39, 0xd6, 0x19, 0x73,
                                        0x0e, 0x2c, 0xb7, 0x01, 0x9d, 0x31,
                                        0xab, 0x63, 0x74, 0x11, 0x7d, 0x7b,
                                        0x26, 0xea, 0x2b, 0x01, 0xd9, 0xb3,
                                        0x58, 0xec, 0xe5, 0xae };

    std::vector<Uint8> output(ReturnedBits.size());

    auto sha_obj = std::make_shared<alcp::digest::Sha224>();

    TestingHmacDrbg hmacDrbg(sha_obj->getHashSize(), sha_obj);

    hmacDrbg.instantiate(EntropyInput, nonce, PersonalizationString);
    EXPECT_EQ(key_init_exp, hmacDrbg.GetKCopy());
    EXPECT_EQ(v_init_exp, hmacDrbg.GetVCopy());

    hmacDrbg.reseed(EntropyInputReseed, AdditionalInputReseed);
    EXPECT_EQ(key_reseed_exp, hmacDrbg.GetKCopy());
    EXPECT_EQ(v_reseed_exp, hmacDrbg.GetVCopy());

    hmacDrbg.generate(AdditionalInput1, output);
    EXPECT_EQ(key_exp1, hmacDrbg.GetKCopy());
    EXPECT_EQ(v_exp1, hmacDrbg.GetVCopy());

    hmacDrbg.generate(AdditionalInput2, output);
    EXPECT_EQ(key_exp2, hmacDrbg.GetKCopy());
    EXPECT_EQ(v_exp2, hmacDrbg.GetVCopy());

    EXPECT_EQ(ReturnedBits, output);
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
