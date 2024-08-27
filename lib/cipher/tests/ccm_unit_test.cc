/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes_ccm.hh"
#include <gtest/gtest.h>

// KAT Data
// clang-format off
typedef std::tuple<std::vector<Uint8>, // key
                   std::vector<Uint8>, // nonce
                   std::vector<Uint8>, // aad
                   std::vector<Uint8>, // plaintext
                   std::vector<Uint8>, // ciphertext
                   std::vector<Uint8> // tag
                  >
            param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

/* Example Encodings
P_K128b_N7B_A0B_P0B_C0B_T4B
P     -> Pass, F -> Fail
K128b -> Key 128 bit
N7B   -> Nonce 7 byte
A0B   -> Additional Data 0 byte
P0B   -> PlainText 0 byte
C0B   -> CipherText 0 byte
T4B   -> Tag 4 byte

_CROSS is appended if cross test detected failure

Tuple order
{key,nonce,aad,plain,ciphertext,tag}
*/
known_answer_map_t KATDataset{
    {
      "P_K128b_N7B_A0B_P0B_C0B_T4B",
      {
        {0x4a,0xe7,0x01,0x10,0x3c,0x63,0xde,0xca,0x5b,0x5a,0x39,0x39,0xd7,0xd0,0x59,0x92},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {},
        {},
        {0x02,0x20,0x9f,0x55},
      }
    },
    {
      "P_K128b_N10B_A10B_P16B_C16B_T16B_CROSS",
      {
        {0xbc,0x9b,0x47,0x29,0x81,0xb1,0x3e,0xb5,0x49,0xac,0x65,0xe4,0x38,0x03,0x3d,0x11},
        {0x8d,0x78,0x6d,0x03,0x09,0x71,0x38,0x56,0xce,0x8c},
        {0x66,0x19,0xe2,0x91,0x16,0xa6,0xed,0x8c,0xe6,0xf6,0x77,0xdc,0x1e},
        {0xaf,0xe6,0x01,0x9d,0xc6,0xd4,0x33,0x40,0xdb,0x08,0x17,0xe9,0x8c,0x4b,0x48,0x9f},
        {0x53,0xf2,0xa3,0xe3,0xfd,0x04,0x07,0x06,0x51,0x5b,0x51,0xaa,0x89,0x4f,0x2a,0x59},
        {0xe5,0xdb,0xc3,0xdc,0xad,0xbe,0x5f,0xa7,0xa0,0xf7,0xb2,0xc0,0x1f,0x5d,0xc7,0x7e},
      }
    },
    {
      "P_K128b_N10B_A12B_P32B_C32B_T16B_CROSS",
      {
        {0xab,0x1b,0x85,0x85,0xb7,0x03,0xad,0xbb,0xda,0x01,0xbd,0x00,0x58,0xe3,0x9c,0xcc},
        {0x41,0xb5,0x46,0xd9,0xdb,0x08,0x3b,0xad,0x24},
        {0xee,0x9f,0xb9,0xb4,0xd2,0x7a,0xb7,0xe4,0xdb,0xe2,0x3a,0x62},
        {0x21,0x8f,0x23,0xb5,0xcf,0xdb,0x86,0x4e,0x4c,0xb9,0x21,0xa8,0xd0,0x93,0x9d,0xe7,0x70,0x89,0xa4,0xb1,0x06,0xda,0x9d,0x2d,0x40,0xff,0xfb,0xd7,0xf2,0xfb,0xda,0xe3},
        {0x1c,0xdc,0x6a,0x01,0xc9,0x49,0x5b,0x18,0xe8,0x1b,0xf5,0xe1,0xc9,0x92,0xe0,0x5c,0x40,0x33,0x7e,0x35,0x46,0x7c,0x33,0x01,0x05,0xc2,0xbd,0xa1,0xf8,0xc7,0xd0,0x11},
        {0x93,0x34,0x7e,0xe2,0xa1,0xfc,0x2a,0x0d,0x6c,0xeb,0x98,0x94,0xf0,0xf0,0x3e,0x20},
      }
    },
    {
      "P_K128b_N7B_A0B_P24B_C24B_T4B",
      {
        {0x19,0xeb,0xfd,0xe2,0xd5,0x46,0x8b,0xa0,0xa3,0x03,0x1b,0xde,0x62,0x9b,0x11,0xfd},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {0x37,0x96,0xcf,0x51,0xb8,0x72,0x66,0x52,0xa4,0x20,0x47,0x33,0xb8,0xfb,0xb0,0x47,0xcf,0x00,0xfb,0x91,0xa9,0x83,0x7e,0x22},
        {0xa9,0x0e,0x8e,0xa4,0x40,0x85,0xce,0xd7,0x91,0xb2,0xfd,0xb7,0xfd,0x44,0xb5,0xcf,0x0b,0xd7,0xd2,0x77,0x18,0x02,0x9b,0xb7},
        {0x03,0xe1,0xfa,0x6b },
      }
    },
    {
      "F_K128b_N7B_A0B_P0B_C0B_T4B",
      {
        {0x4a,0xe7,0x01,0x10,0x3c,0x63,0xde,0xca,0x5b,0x5a,0x39,0x39,0xd7,0xd0,0x59,0x92},
        {0x37,0x96,0xcf,0x51,0xb8,0x72,0x66},
        {},
        {},
        {},
        {0x9a,0x04,0xc2,0x41},
      }
    },
    {
      "P_K128b_N7B_A0B_P0B_C0B_T16B",
      {
        {0x4b,0xb3,0xc4,0xa4,0xf8,0x93,0xad,0x8c,0x9b,0xdc,0x83,0x3c,0x32,0x5d,0x62,0xb3},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {},
        {},
        {0x75,0xd5,0x82,0xdb,0x43,0xce,0x9b,0x13,0xab,0x4b,0x6f,0x7f,0x14,0x34,0x13,0x30},
      }
    },
    {
      "P_K128b_N13B_A0B_P0B_C0B_T4B",
      {
        {0x4b,0xb3,0xc4,0xa4,0xf8,0x93,0xad,0x8c,0x9b,0xdc,0x83,0x3c,0x32,0x5d,0x62,0xb3},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9,0x40,0x3a,0xff,0x85,0x9f,0xbb},
        {},
        {},
        {},
        {0x90,0x15,0x6f,0x3f},
      }
    },
    {
      "P_K128b_N13B_A0B_P0B_C0B_T4B_1",
      {
        {0x4b,0xb3,0xc4,0xa4,0xf8,0x93,0xad,0x8c,0x9b,0xdc,0x83,0x3c,0x32,0x5d,0x62,0xb3},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9,0x40,0x3a,0xff,0x85,0x9f,0xbb},
        {},
        {},
        {},
        {0x90,0x15,0x6f,0x3f},
      }
    },
    {
      "P_K128b_N7B_A0B_P24B_C24B_T4B_1",
      {
        {0x19,0xeb,0xfd,0xe2,0xd5,0x46,0x8b,0xa0,0xa3,0x03,0x1b,0xde,0x62,0x9b,0x11,0xfd},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {0x37,0x96,0xcf,0x51,0xb8,0x72,0x66,0x52,0xa4,0x20,0x47,0x33,0xb8,0xfb,0xb0,0x47,0xcf,0x00,0xfb,0x91,0xa9,0x83,0x7e,0x22},
        {0xa9,0x0e,0x8e,0xa4,0x40,0x85,0xce,0xd7,0x91,0xb2,0xfd,0xb7,0xfd,0x44,0xb5,0xcf,0x0b,0xd7,0xd2,0x77,0x18,0x02,0x9b,0xb7},
        {0x03,0xe1,0xfa,0x6b},
      }
    },
    {
      "P_K128b_N13B_A0B_P0B_C0B_T4B_2",
      {
        {0x4b,0xb3,0xc4,0xa4,0xf8,0x93,0xad,0x8c,0x9b,0xdc,0x83,0x3c,0x32,0x5d,0x62,0xb3},
        {0x93,0x5c,0x1e,0xf3,0xd4,0x03,0x2f,0xf0,0x90,0xf9,0x11,0x41,0xf3},
        {},
        {},
        {},
        {0x1b,0xc8,0x2b,0x3d},
      }
    },
    // 192 Keysize
    {
      "P_K192b_N7B_A0B_P0B_C0B_T4B",
      {
        {0xc9,0x8a,0xd7,0xf3,0x8b,0x2c,0x7e,0x97,0x0c,0x9b,0x96,0x5e,0xc8,0x7a,0x08,0x20,0x83,0x84,0x71,0x8f,0x78,0x20,0x6c,0x6c},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {},
        {},
        {0x9d,0x4b,0x7f,0x3b},
      }
    },
    {
      "F_K192b_N7B_A0B_P0B_C0B_T4B",
      {
        {0xc9,0x8a,0xd7,0xf3,0x8b,0x2c,0x7e,0x97,0x0c,0x9b,0x96,0x5e,0xc8,0x7a,0x08,0x20,0x83,0x84,0x71,0x8f,0x78,0x20,0x6c,0x6c},
        {0x37,0x96,0xcf,0x51,0xb8,0x72,0x66},
        {},
        {},
        {},
        {0x80,0x74,0x5d,0xe9},
      }
    },
    {
      "P_K192b_N7B_A0B_P0B_C0B_T16B",
      {
        {0x4b,0xb3,0xc4,0xa4,0xf8,0x93,0xad,0x8c,0x9b,0xdc,0x83,0x3c,0x32,0x5d,0x62,0xb3,0xd3,0xad,0x1b,0xcc,0xf9,0x28,0x2a,0x65},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {},
        {},
        {0x17,0x22,0x30,0x38,0xfa,0x99,0xd5,0x36,0x81,0xca,0x1b,0xea,0xbe,0x78,0xd1,0xb4},
      }
    },
    {
      "P_K192b_N7B_A32B_P0B_C0B_T4B",
      {
        {0x90,0x92,0x9a,0x4b,0x0a,0xc6,0x5b,0x35,0x0a,0xd1,0x59,0x16,0x11,0xfe,0x48,0x29,0x7e,0x03,0x95,0x6f,0x60,0x83,0xe4,0x51},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {0x37,0x96,0xcf,0x51,0xb8,0x72,0x66,0x52,0xa4,0x20,0x47,0x33,0xb8,0xfb,0xb0,0x47,0xcf,0x00,0xfb,0x91,0xa9,0x83,0x7e,0x22,0xec,0x22,0xb1,0xa2,0x68,0xf8,0x8e,0x2c},
        {},
        {},
        {0x1d,0x08,0x9a,0x5f},
      }
    },
    {
      "P_K192b_N7B_A0B_P24B_C24B_T4B",
      {
        {0x19,0xeb,0xfd,0xe2,0xd5,0x46,0x8b,0xa0,0xa3,0x03,0x1b,0xde,0x62,0x9b,0x11,0xfd,0x40,0x94,0xaf,0xcb,0x20,0x53,0x93,0xfa},
        {0x5a,0x8a,0xa4,0x85,0xc3,0x16,0xe9},
        {},
        {0x37,0x96,0xcf,0x51,0xb8,0x72,0x66,0x52,0xa4,0x20,0x47,0x33,0xb8,0xfb,0xb0,0x47,0xcf,0x00,0xfb,0x91,0xa9,0x83,0x7e,0x22},
        {0x41,0x19,0x86,0xd0,0x4d,0x64,0x63,0x10,0x0b,0xff,0x03,0xf7,0xd0,0xbd,0xe7,0xea,0x2c,0x34,0x88,0x78,0x43,0x78,0x13,0x8c},
        {0xdd,0xc9,0x3a,0x54},
      }
    },
    // 256 Keysize
    {
      "P_K256b_N7B_A0B_P0B_C0B_T4B",
      {
        {0xed,0xa3,0x2f,0x75,0x14,0x56,0xe3,0x31,0x95,0xf1,0xf4,0x99,0xcf,0x2d,0xc7,0xc9,0x7e,0xa1,0x27,0xb6,0xd4,0x88,0xf2,0x11,0xcc,0xc5,0x12,0x6f,0xbb,0x24,0xaf,0xa6},
        {0xa5,0x44,0x21,0x8d,0xad,0xd3,0xc1},
        {},
        {},
        {},
        {0x46,0x9c,0x90,0xbb},
      }
    },
    {
      "F_K256b_N7B_A0B_P0B_C0B_T4B",
      {
        {0xed,0xa3,0x2f,0x75,0x14,0x56,0xe3,0x31,0x95,0xf1,0xf4,0x99,0xcf,0x2d,0xc7,0xc9,0x7e,0xa1,0x27,0xb6,0xd4,0x88,0xf2,0x11,0xcc,0xc5,0x12,0x6f,0xbb,0x24,0xaf,0xa6},
        {0xd3,0xd5,0x42,0x4e,0x20,0xfb,0xec},
        {},
        {},
        {},
        {0x46,0xa9,0x08,0xed},
      }
    },
    {
      "P_K256b_N7B_A0B_P0B_C0B_T16B",
      {
        {0xe1,0xb8,0xa9,0x27,0xa9,0x5e,0xfe,0x94,0x65,0x66,0x77,0xb6,0x92,0x66,0x20,0x00,0x27,0x8b,0x44,0x1c,0x79,0xe8,0x79,0xdd,0x5c,0x0d,0xdc,0x75,0x8b,0xdc,0x9e,0xe8},
        {0xa5,0x44,0x21,0x8d,0xad,0xd3,0xc1},
        {},
        {},
        {},
        {0x82,0x07,0xeb,0x14,0xd3,0x38,0x55,0xa5,0x2a,0xcc,0xee,0xd1,0x7d,0xbc,0xbf,0x6e},
      }
    },
    {
      "P_K256b_N7B_A0B_P0B_C0B_T4B_1",
      {
        {0x1b,0x0e,0x8d,0xf6,0x3c,0x57,0xf0,0x5d,0x9a,0xc4,0x57,0x57,0x5e,0xa7,0x64,0x52,0x4b,0x86,0x10,0xae,0x51,0x64,0xe6,0x21,0x5f,0x42,0x6f,0x5a,0x7a,0xe6,0xed,0xe4},
        {0xa5,0x44,0x21,0x8d,0xad,0xd3,0xc1},
        {0xd3,0xd5,0x42,0x4e,0x20,0xfb,0xec,0x43,0xae,0x49,0x53,0x53,0xed,0x83,0x02,0x71,0x51,0x5a,0xb1,0x04,0xf8,0x86,0x0c,0x98,0x8d,0x15,0xb6,0xd3,0x6c,0x03,0x8e,0xab},
        {},
        {},
        {0x92,0xd0,0x0f,0xbe},
      }
    },
    {
      "P_K256b_N13B_A32B_P24B_C24B_T16B",
      {
        {0x31,0x4a,0x20,0x2f,0x83,0x6f,0x9f,0x25,0x7e,0x22,0xd8,0xc1,0x17,0x57,0x83,0x2a,0xe5,0x13,0x1d,0x35,0x7a,0x72,0xdf,0x88,0xf3,0xef,0xf0,0xff,0xce,0xe0,0xda,0x4e},
        {0xa5,0x44,0x21,0x8d,0xad,0xd3,0xc1,0x05,0x83,0xdb,0x49,0xcf,0x39},
        {0x3c,0x0e,0x28,0x15,0xd3,0x7d,0x84,0x4f,0x7a,0xc2,0x40,0xba,0x9d,0x6e,0x3a,0x0b,0x2a,0x86,0xf7,0x06,0xe8,0x85,0x95,0x9e,0x09,0xa1,0x00,0x5e,0x02,0x4f,0x69,0x07},
        {0xe8,0xde,0x97,0x0f,0x6e,0xe8,0xe8,0x0e,0xde,0x93,0x35,0x81,0xb5,0xbc,0xf4,0xd8,0x37,0xe2,0xb7,0x2b,0xaa,0x8b,0x00,0xc3},
        {0x8d,0x34,0xcd,0xca,0x37,0xce,0x77,0xbe,0x68,0xf6,0x5b,0xaf,0x33,0x82,0xe3,0x1e,0xfa,0x69,0x3e,0x63,0xf9,0x14,0xa7,0x81},
        {0x36,0x7f,0x30,0xf2,0xea,0xad,0x8c,0x06,0x3c,0xa5,0x07,0x95,0xac,0xd9,0x02,0x03},
      }
    },

};
// clang-format on

/**
 * @brief Key Size to Mode string
 *
 * @param keySize Key size in Bytes
 * @return std::string, mode
 */
std::string
keyToModStr(Uint64 keySize)
{
    std::string mode_str = "";
    switch (keySize) {
        case 16:
            mode_str = "aes-ccm-128";
            break;
        case 24:
            mode_str = "aes-ccm-192";
            break;
        case 32:
            mode_str = "aes-ccm-256";
            break;
        default:
            mode_str = "aes-ccm-128";
            std::cout
                << "Mode string defaulting to 'aes-ccm-128', invalid keysize"
                << std::endl;
    }
    return mode_str;
}

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

using namespace alcp::cipher;
class CCM_KAT
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    CipherFactory<iCipherAead>* alcpCipher = nullptr;
    iCipherAead*                pCcmObj    = nullptr;
    std::vector<Uint8> m_key, m_nonce, m_aad, m_plaintext, m_ciphertext, m_tag;
    std::string        m_test_name;
    alc_error_t        m_err;
    // Setup Test for Encrypt/Decrypt
    void SetUp() override
    {
        // Tuple order
        // {key,nonce,aad,plain,ciphertext,tag}
        const auto params = GetParam();
        const auto [key, nonce, aad, plaintext, ciphertext, tag] =
            params.second;
        const auto test_name = params.first;

        // Copy Values to class variables
        m_key        = key;
        m_nonce      = nonce;
        m_aad        = aad;
        m_plaintext  = plaintext;
        m_ciphertext = ciphertext;
        m_tag        = tag;
        m_test_name  = test_name;

        // Setup CCM Object
        alcpCipher = new CipherFactory<iCipherAead>;
        // FIXME: Add feature selection
        pCcmObj = alcpCipher->create(keyToModStr(m_key.size()));

        ASSERT_TRUE(pCcmObj != nullptr);
    }
    void TearDown() override { delete alcpCipher; }
};

TEST(CCM, Initiantiation)
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    // Setup CCM Object
    auto alcpCipher = new CipherFactory<iCipherAead>;
    // FIXME: Add feature selection
    auto pCcmObj = alcpCipher->create(keyToModStr(sizeof(key)));
    // clang-format on
    ASSERT_TRUE(pCcmObj != nullptr);

    delete alcpCipher;
}

// Test disabled as ZeroLength checks moved to C_API
/*
TEST(CCM, ZeroLEN)
{
    Uint8  iv[]  = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    Uint8  key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8  tagbuff[14];
    char   ad[]      = "This is a sample additional data";
    char   message[] = "This is a sample message to encrypt!";
    Uint8* output_ct = new Uint8[strlen(message)];
    const alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_CCM,
                                             .ai_iv   = iv };
    // clang-format off
    const alc_key_info_t keyInfo = { .len  = 128, .key  = key };
    // clang-format on
    Ccm         ccm_obj =Ccm(keyInfo.key, keyInfo.len);
    alc_error_t err;
    err = ccm_obj.setIv(0, iv);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    err = ccm_obj.setAad(reinterpret_cast<Uint8*>(ad), 0);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    err = ccm_obj.encrypt(
        reinterpret_cast<Uint8*>(message), output_ct, 0, iv);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = ccm_obj.getTag(tagbuff, 0);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
}
*/

TEST_P(CCM_KAT, Encrypt)
{
    std::vector<Uint8> out_tag(m_tag.size(), 0),
        out_ciphertext(m_plaintext.size(), 0);

    alc_error_t err;
    /* Encryption begins here */
    if (!m_tag.empty()) {
        err = pCcmObj->setTagLength(m_tag.size());
    }

    /* Initialization */
    pCcmObj->init(
        getPtr(m_key), m_key.size() * 8, getPtr(m_nonce), m_nonce.size());

    // Additional Data
    if (!m_aad.empty()) {
        err = pCcmObj->setAad(getPtr(m_aad), m_aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Encrypt the plaintext into ciphertext.
    if (!m_plaintext.empty()) {
        err = pCcmObj->encrypt(
            getPtr(m_plaintext), getPtr(out_ciphertext), m_plaintext.size());
        EXPECT_EQ(out_ciphertext, m_ciphertext);
    } else {
        // Call encrypt update with a valid memory if no plaintext
        Uint8 a;
        err = pCcmObj->encrypt(&a, &a, 0);
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // If there is tag, try to get the tag.
    if (!m_tag.empty()) {
        err = pCcmObj->getTag(getPtr(out_tag), m_tag.size());
        if (m_test_name.at(0) == 'P')
            EXPECT_EQ(out_tag, m_tag);
        else
            EXPECT_NE(out_tag, m_tag);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }
}

TEST_P(CCM_KAT, Encrypt_Double)
{
    {
        // 0x02 and 0x01 will be our signature for testing if algorithm never
        // touched the memory, during debugging
        std::vector<Uint8> out_tag(m_tag.size(), 0x02),
            out_ciphertext(m_plaintext.size(), 0x01);

        alc_error_t err;
        /* Encryption begins here */
        if (!m_tag.empty()) {
            err = pCcmObj->setTagLength(m_tag.size());
        }

        /* Initialization */
        pCcmObj->init(
            getPtr(m_key), m_key.size() * 8, getPtr(m_nonce), m_nonce.size());

        // Additional Data
        if (!m_aad.empty()) {
            err = pCcmObj->setAad(getPtr(m_aad), m_aad.size());
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }

        // Encrypt the plaintext into ciphertext.
        if (!m_plaintext.empty()) {
            err = pCcmObj->encrypt(getPtr(m_plaintext),
                                   getPtr(out_ciphertext),
                                   m_plaintext.size());
            EXPECT_EQ(out_ciphertext, m_ciphertext);
        } else {
            // Call encrypt update with a valid memory if no plaintext
            Uint8 a;
            err = pCcmObj->encrypt(&a, &a, 0);
        }
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // If there is tag, try to get the tag.
        if (!m_tag.empty()) {
            err = pCcmObj->getTag(getPtr(out_tag), m_tag.size());
            if (m_test_name.at(0) == 'P')
                EXPECT_EQ(out_tag, m_tag);
            else
                EXPECT_NE(out_tag, m_tag);
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }
    }
    {
        // 0x02 and 0x01 will be our signature for testing if algorithm never
        // touched the memory, during debugging
        std::vector<Uint8> out_tag(m_tag.size(), 0x02),
            out_ciphertext(m_plaintext.size(), 0x01);

        alc_error_t err;
        /* Encryption begins here */
        if (!m_tag.empty()) {
            err = pCcmObj->setTagLength(m_tag.size());
        }

        /* Initialization */
        pCcmObj->init(
            getPtr(m_key), m_key.size() * 8, getPtr(m_nonce), m_nonce.size());

        // Additional Data
        if (!m_aad.empty()) {
            err = pCcmObj->setAad(getPtr(m_aad), m_aad.size());
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }

        // Encrypt the plaintext into ciphertext.
        if (!m_plaintext.empty()) {
            err = pCcmObj->encrypt(getPtr(m_plaintext),
                                   getPtr(out_ciphertext),
                                   m_plaintext.size());
            EXPECT_EQ(out_ciphertext, m_ciphertext);
        } else {
            // Call encrypt update with a valid memory if no plaintext
            Uint8 a;
            err = pCcmObj->encrypt(&a, &a, 0);
        }
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // If there is tag, try to get the tag.
        if (!m_tag.empty()) {
            err = pCcmObj->getTag(getPtr(out_tag), m_tag.size());
            if (m_test_name.at(0) == 'P')
                EXPECT_EQ(out_tag, m_tag);
            else
                EXPECT_NE(out_tag, m_tag);
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }
    }
}

TEST_P(CCM_KAT, Decrypt)
{
    // 0x02 and 0x01 will be our signature for testing if algorithm never
    // touched the memory, during debugging
    std::vector<Uint8> out_tag(m_tag.size(), 0x02),
        out_plaintext(m_ciphertext.size(), 0x01);

    alc_error_t err;

    /* Decryption begins here*/
    if (!m_tag.empty()) {
        err = pCcmObj->setTagLength(m_tag.size());
    }

    /* Initialization */
    pCcmObj->init(
        getPtr(m_key), m_key.size() * 8, getPtr(m_nonce), m_nonce.size());

    // Additional Data
    if (!m_aad.empty()) {
        err = pCcmObj->setAad(getPtr(m_aad), m_aad.size());
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Decrypt the ciphertext into plaintext
    if (!m_ciphertext.empty()) {
        err = pCcmObj->decrypt(
            getPtr(m_ciphertext), getPtr(out_plaintext), m_ciphertext.size());
        EXPECT_EQ(out_plaintext, m_plaintext);
    } else {
        // Call decrypt update with a valid memory if no plaintext
        Uint8 a;
        err = pCcmObj->decrypt(&a, &a, 0);
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // If there is tag, try to get the tag.
    if (!m_tag.empty()) {
        err = pCcmObj->getTag(getPtr(out_tag), m_tag.size());
        if (m_test_name.at(0) == 'P')
            EXPECT_EQ(out_tag, m_tag);
        else
            EXPECT_NE(out_tag, m_tag);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }
}

TEST_P(CCM_KAT, Decrypt_Double)
{
    {
        // 0x02 and 0x01 will be our signature for testing if algorithm never
        // touched the memory, during debugging
        std::vector<Uint8> out_tag(m_tag.size(), 0x02),
            out_plaintext(m_ciphertext.size(), 0x01);

        alc_error_t err;

        /* Decryption begins here*/
        if (!m_tag.empty()) {
            err = pCcmObj->setTagLength(m_tag.size());
        }

        /* Initialization */
        pCcmObj->init(
            getPtr(m_key), m_key.size() * 8, getPtr(m_nonce), m_nonce.size());

        // Additional Data
        if (!m_aad.empty()) {
            err = pCcmObj->setAad(getPtr(m_aad), m_aad.size());
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }

        // Decrypt the ciphertext into plaintext
        if (!m_ciphertext.empty()) {
            err = pCcmObj->decrypt(getPtr(m_ciphertext),
                                   getPtr(out_plaintext),
                                   m_ciphertext.size());
            EXPECT_EQ(out_plaintext, m_plaintext);
        } else {
            // Call decrypt update with a valid memory if no plaintext
            Uint8 a;
            err = pCcmObj->decrypt(&a, &a, 0);
        }
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // If there is tag, try to get the tag.
        if (!m_tag.empty()) {
            err = pCcmObj->getTag(getPtr(out_tag), m_tag.size());
            if (m_test_name.at(0) == 'P')
                EXPECT_EQ(out_tag, m_tag);
            else
                EXPECT_NE(out_tag, m_tag);
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }
    }
    {
        // 0x02 and 0x01 will be our signature for testing if algorithm never
        // touched the memory, during debugging
        std::vector<Uint8> out_tag(m_tag.size(), 0x02),
            out_plaintext(m_ciphertext.size(), 0x01);

        alc_error_t err;

        /* Decryption begins here*/
        if (!m_tag.empty()) {
            err = pCcmObj->setTagLength(m_tag.size());
        }

        /* Initialization */
        pCcmObj->init(
            getPtr(m_key), m_key.size() * 8, getPtr(m_nonce), m_nonce.size());

        // Additional Data
        if (!m_aad.empty()) {
            err = pCcmObj->setAad(getPtr(m_aad), m_aad.size());
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }

        // Decrypt the ciphertext into plaintext
        if (!m_ciphertext.empty()) {
            err = pCcmObj->decrypt(getPtr(m_ciphertext),
                                   getPtr(out_plaintext),
                                   m_ciphertext.size());
            EXPECT_EQ(out_plaintext, m_plaintext);
        } else {
            // Call decrypt update with a valid memory if no plaintext
            Uint8 a;
            err = pCcmObj->decrypt(&a, &a, 0);
        }
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // If there is tag, try to get the tag.
        if (!m_tag.empty()) {
            err = pCcmObj->getTag(getPtr(out_tag), m_tag.size());
            if (m_test_name.at(0) == 'P')
                EXPECT_EQ(out_tag, m_tag);
            else
                EXPECT_NE(out_tag, m_tag);
            EXPECT_EQ(err, ALC_ERROR_NONE);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    CCM_KAT,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<CCM_KAT::ParamType>& info) {
        return info.param.first;
    });

TEST(CCM, InvalidTagLen)
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    // Setup CCM Object
    auto alcpCipher = new CipherFactory<iCipherAead>;
    // FIXME: Add feature selection
    auto pCcmObj = alcpCipher->create(keyToModStr(sizeof(key)));

    ASSERT_TRUE(pCcmObj != nullptr);

    alc_error_t err;

    // TODO: Create a parametrized test
    err = pCcmObj->setTagLength(17);

    EXPECT_EQ(err, ALC_ERROR_INVALID_ARG);

    delete alcpCipher;
}

TEST(CCM, InvalidNonceLen)
{
    Uint8              key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8              tagbuff[16];
    std::vector<Uint8> out_tag(sizeof(tagbuff), 0);
    std::vector<Uint8> nonce(14, 0);

    // Setup CCM Object
    auto alcpCipher = new CipherFactory<iCipherAead>;
    // FIXME: Add feature selection
    auto pCcmObj = alcpCipher->create(keyToModStr(sizeof(key)));

    ASSERT_TRUE(pCcmObj != nullptr);

    alc_error_t err;

    // TODO: Create a parametrized test
    err = pCcmObj->setTagLength(out_tag.size());

    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Nonce
    err = pCcmObj->init(key, sizeof(key) * 8, getPtr(nonce), nonce.size());

    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);

    delete alcpCipher;
}
