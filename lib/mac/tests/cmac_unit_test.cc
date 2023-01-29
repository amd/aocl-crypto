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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "mac/cmac.hh"
#include "utils/copy.hh"
#include "gtest/gtest.h"
#include <tuple>

#include "alcp/utils/cpuid.hh"

using alcp::base::Status;

using alcp::mac::Cmac;

// Fixme: Add unit testing for LeftShift but as avx2 specific
/* TEST(LeftShift128, Test1)
{
    reg_128 reg1, reg2, expected;
    reg1.reg = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0);
    expected.reg =
        _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0x01, 0xfe, 0, 0, 0, 0, 0, 0, 0);
    Cmac::left_shift_1(reg1, reg2);
    EXPECT_EQ(memcmp(expected.u8, reg2.u8, 16), 0);
}
TEST(LeftShift128, Test2)
{
    reg_128 reg1, reg2, expected;
    reg1.reg = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0);
    expected.reg =
        _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0x01, 0x0, 0, 0, 0, 0, 0, 0, 0);
    Cmac::left_shift_1(reg1, reg2);
    EXPECT_EQ(memcmp(expected.u8, reg2.u8, 16), 0);
}
TEST(LeftShift128, Test3)
{
    reg_128 reg1, reg2, expected;
    reg1.reg     = _mm_set_epi8(0x7d,
                            0xf7,
                            0x6b,
                            0x0c,
                            0x1a,
                            0xb8,
                            0x99,
                            0xb3,
                            0x3e,
                            0x42,
                            0xf0,
                            0x47,
                            0xb9,
                            0x1b,
                            0x54,
                            0x6f);
    expected.reg = _mm_set_epi8(0xfb,
                                0xee,
                                0xd6,
                                0x18,
                                0x35,
                                0x71,
                                0x33,
                                0x66,
                                0x7c,
                                0x85,
                                0xe0,
                                0x8f,
                                0x72,
                                0x36,
                                0xa8,
                                0xde);
    Cmac::left_shift_1(reg1, reg2);
    EXPECT_EQ(memcmp(expected.u8, reg2.u8, 16), 0);
}
 */

typedef std::tuple<std::vector<Uint8>, // key
                   std::vector<Uint8>, // plaintext
                   std::vector<Uint8>  // mac
                   >
    param_tuple;

typedef std::map<const std::string, param_tuple> known_answer_map_t;

// clang-format off
known_answer_map_t KAT_ShaDataset{
    { "TESTCASE1_AES_128_BLOCK_1_INCOMPLETE",
      { { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
          0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C 
        },
        {},
        { 
          0xBB,0x1D,0x69,0x29,0xE9,0x59,0x37,0x28,
          0x7F,0xA3,0x7D,0x12,0x9B,0x75,0x67,0x46
        }
      } 
    },
    { "TESTCASE2_AES_128_BLOCK_1_COMPLETE",
      { { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
          0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C 
        },
        { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
          0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        },
        { 0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D,0x41, 0x44, 
          0xF7, 0x9B, 0xDD, 0x9D,0xD0, 0x4A, 0x28, 0x7C 
        }
      } 
    },
    {
        "TESTCASE3_AES_128_BLOCK_2_INCOMPLETE",
      {
        { 0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,
          0x15,0x88,0x09,0xCF,0x4F,0x3C
        },
        {
         0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,0xE9,0x3D,0x7E,
         0x11,0x73,0x93,0x17,0x2A,0xAE,0x2D,0x8A,0x57    
        },
        {
          0x7D,0x85,0x44,0x9E,0xA6,0xEA,0x19,0xC8,0x23,0xA7,0xBF,
          0x78,0x83,0x7D,0xFA,0xDE
        }
      }
    },
        {
        "TESTCASE4_AES_128_BLOCK_4_COMPLETE",
      {
        { 0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,
          0x15,0x88,0x09,0xCF,0x4F,0x3C
        },
        {
         0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,0xE9,0x3D,0x7E,0x11,0x73,
         0x93,0x17,0x2A,0xAE,0x2D,0x8A,0x57,0x1E,0x03,0xAC,0x9C,0x9E,0xB7,
         0x6F,0xAC,0x45,0xAF,0x8E,0x51,0x30,0xC8,0x1C,0x46,0xA3,0x5C,0xE4,
         0x11,0xE5,0xFB,0xC1,0x19,0x1A,0x0A,0x52,0xEF,0xF6,0x9F,0x24,0x45,
         0xDF,0x4F,0x9B,0x17,0xAD,0x2B,0x41,0x7B,0xE6,0x6C,0x37,0x10
        },
        {
          0x51,0xF0,0xBE,0xBF,0x7E,0x3B,0x9D,0x92,0xFC,0x49,0x74,0x17,0x79,
          0x36,0x3C,0xFE
        }
      }
    }
    ,
    {"TESTCASE5_AES_256_BLOCK_1_COMPLETE",
      {
        { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 
        },
        { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40,0x9F, 0x96, 
            0xE9, 0x3D, 0x7E, 0x11,0x73, 0x93, 0x17, 0x2A 
        },
        { 0x28, 0xA7, 0x02, 0x3F, 0x45, 0x2E,0x8F, 0x82, 
            0xBD, 0x4B, 0xF2, 0x8D,0x8C, 0x37, 0xC3, 0x5C 
        }
      },
    },
      {
        "TESTCASE6_AES_192_BLOCK_1_INCOMPLETE",
      {
        { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
          0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
          0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B 
        },
        {
         0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,0xE9,0x3D,
         0x7E,0x11,0x73,0x93,0x17,0x2A    
        },
        {
          0x9E,0x99,0xA7,0xBF,0x31,0xE7,0x10,0x90,0x06,0x62,
          0xF6,0x5E,0x61,0x7C,0x51,0x84
        }
      }
      }

    
    
    
};
// clang-format on

class CMACFuncionalityTest
    : public ::testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    alc_key_info_t                   kinfo;
    alc_cipher_info_t                cinfo;
    std::unique_ptr<alcp::mac::Cmac> cmac;
    std::vector<Uint8>               key, plain_text, expected_mac, mac;

    void SetUp() override
    {
        const auto params       = GetParam();
        auto       tuple_values = params.second;

        tie(key, plain_text, expected_mac) = tuple_values;

        kinfo = {
            .type = ALC_KEY_TYPE_SYMMETRIC,
            .fmt  = ALC_KEY_FMT_RAW,
            .len  = static_cast<Uint32>(key.size()) * 8,
            .key  = &key[0],
        };

        cinfo = {
            .ci_type      = ALC_CIPHER_TYPE_AES,
            .ci_key_info  = kinfo,
            .ci_algo_info = { .ai_mode = ALC_AES_MODE_NONE, .ai_iv = nullptr },
        };
        cmac = std::make_unique<alcp::mac::Cmac>(cinfo, kinfo);
        mac  = std::vector<Uint8>(expected_mac.size());
    }

    void splitToEqualHalves(std::vector<Uint8>& singleblock,
                            std::vector<Uint8>& block1,
                            std::vector<Uint8>& block2)
    {
        int block1_size = singleblock.size() / 2;

        block1 = std::vector<Uint8>(singleblock.begin(),
                                    singleblock.begin() + block1_size);
        block2 = std::vector<Uint8>(singleblock.begin() + block1_size,
                                    singleblock.end());
    }
};

TEST_P(CMACFuncionalityTest, CMAC_SINGLE_UPDATE)
{

    cmac->update(&plain_text[0], plain_text.size());
    cmac->finalize(nullptr, 0);
    cmac->copy(&mac[0], mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST_P(CMACFuncionalityTest, CMAC_SINGLE_FINALIZE)
{
    cmac->finalize(&plain_text[0], plain_text.size());
    cmac->copy(&mac[0], mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST_P(CMACFuncionalityTest, CMAC_UPDATE_FINALIZE)
{
    cmac->finalize(&plain_text[0], plain_text.size());
    cmac->copy(&mac[0], mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST_P(CMACFuncionalityTest, CMAC_MULTIPLE_UPDATE)
{

    std::vector<Uint8> block1, block2;
    splitToEqualHalves(plain_text, block1, block2);

    assert(block1.size() <= plain_text.size());
    assert(block2.size() <= plain_text.size());

    cmac->update(&block1[0], block1.size());
    cmac->update(&block2[0], block2.size());
    cmac->finalize(nullptr, 0);
    cmac->copy(&mac[0], mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST_P(CMACFuncionalityTest, CMAC_RESET)
{
    cmac->update(&plain_text[0], plain_text.size());
    cmac->reset();
    cmac->update(&plain_text[0], plain_text.size());
    cmac->finalize(nullptr, 0);
    cmac->copy(&mac[0], mac.size());

    EXPECT_EQ(mac, expected_mac);
}

INSTANTIATE_TEST_SUITE_P(
    CMACTest,
    CMACFuncionalityTest,
    testing::ValuesIn(KAT_ShaDataset),
    [](const testing::TestParamInfo<CMACFuncionalityTest::ParamType>& info) {
        return info.param.first;
    });
