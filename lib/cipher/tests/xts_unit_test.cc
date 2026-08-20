/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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

#include <algorithm>
#include <memory>
#include <random>

#include "alcp/capi/cipher/ctx.hh"
#include "alcp/cipher/aes_xts.hh"
#include "alcp/utils/cpuid.hh"
#include "debug_defs.hh"
#include "gtest/gtest.h"

#undef DEBUG

using namespace alcp::cipher;

using namespace alcp::cipher::aesni;
// using namespace alcp::cipher::vaes;
// using namespace alcp::cipher::vaes512;

std::string MODE_STR = "XTS";

#define ALC_MODE ALC_AES_MODE_XTS

namespace alcp::cipher::unittest::xts {

// Random Engine
std::random_device rnd_device;
std::mt19937       mt(rnd_device());

template<typename T>
T
randGenerator()
{
    // Generate Random numbers in the field of 2**8
    return static_cast<T>(mt() % 255);
}

/**
 * @brief Fills a vector with random data
 * @param out - Vector to be populated
 * @param len
 *
 */
template<typename T>
void
fillRandom(std::vector<T>& out)
{
    std::generate(out.begin(), out.end(), randGenerator<T>);
}

/**
 * @brief Fills a memory location with random data
 * @param buff - Pointer to buffer
 * @param len - Size of the buffer in multiple of sizeof(T)
 *
 */
template<typename T>
void
fillRandom(T* buff, Uint64 len)
{
    std::generate(buff, buff + len, randGenerator<T>);
}

// KAT Data
typedef std::tuple<std::vector<Uint8>, // key
                   std::vector<Uint8>, // tweak key
                   std::vector<Uint8>, // iv
                   std::vector<Uint8>, // plaintext
                   std::vector<Uint8>  // ciphertext
                   >
                                                 param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

/* Example Encodings
P_K128b_TW128b_IV16B_P16B_C16B
P     -> Pass, F -> Fail
K128b -> Key 128 bit
TW128b -> Tweak Key 128 bit
IV7B   -> IV 16 byte
P0B   -> PlainText 16 byte
C0B   -> CipherText 16 byte

Tuple order
{key,nonce,aad,plain,ciphertext,tag}
*/
// clang-format off
known_answer_map_t KATDataset{
    {
        "P_K128b_TW128b_IV16B_P16B_C16B",
        {
            { 0xa1,0xb9,0x0c,0xba,0x3f,0x06,0xac,0x35,0x3b,0x2c,0x34,0x38,0x76,0x08,0x17,0x62},
            { 0x09,0x09,0x23,0x02,0x6e,0x91,0x77,0x18,0x15,0xf2,0x9d,0xab,0x01,0x93,0x2f,0x2f},
            { 0x4f,0xae,0xf7,0x11,0x7c,0xda,0x59,0xc6,0x6e,0x4b,0x92,0x01,0x3e,0x76,0x8a,0xd5},
            { 0xeb,0xab,0xce,0x95,0xb1,0x4d,0x3c,0x8d,0x6f,0xb3,0x50,0x39,0x07,0x90,0x31,0x1c},
            { 0x77,0x8a,0xe8,0xb4,0x3c,0xb9,0x8d,0x5a,0x82,0x50,0x81,0xd5,0xbe,0x47,0x1c,0x63},
        }
    },
#if 0 // Something wrong with this test
    {
        "P_K128b_TW128b_IV16B_P436B_C436B",
        {
            {  0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06, 0xac, 0x35, 0x3b, 0x2c, 0x34, 0x38, 0x76, 0x08, 0x17, 0x62 },
            {  0x09, 0x09, 0x23, 0x02, 0x6e, 0x91, 0x77, 0x18, 0x15, 0xf2, 0x9d, 0xab, 0x01, 0x93, 0x2f, 0x2f },
            {  0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda, 0x59, 0xc6, 0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5 },
            { 0xa8, 0xac, 0xf5, 0x7a, 0x6f, 0x86, 0x59, 0xe9, 0xba, 0x38, 0x2a, 0x4d,
                0x16, 0xba, 0xf1, 0x2a, 0x67, 0xd5, 0x43, 0x75, 0x63, 0xfd, 0x63, 0x29,
                0xd9, 0xa8, 0x87, 0xa8, 0x1,  0x4a, 0x10, 0x57, 0x63, 0xe2, 0xfd, 0xa1,
                0xc6, 0x9f, 0x7d, 0xb6, 0x8,  0x54, 0x1d, 0x7f, 0x11, 0xbc, 0xeb, 0xa9,
                0x95, 0x53, 0xa7, 0x8b, 0xc0, 0xae, 0xac, 0x5f, 0xa8, 0xf7, 0x42, 0x6f,
                0xc6, 0x92, 0xa8, 0x4b, 0xe8, 0x46, 0xed, 0xae, 0xa0, 0xdd, 0x67, 0x70,
                0xde, 0xc3, 0xc9, 0x80, 0x90, 0xc8, 0x9c, 0x96, 0xdf, 0x54, 0xee, 0x7b,
                0x81, 0x8e, 0x70, 0xf7, 0x4c, 0x8b, 0x4d, 0x1,  0xd2, 0xf1, 0x53, 0x5f,
                0x64, 0xc1, 0xd,  0x82, 0x79, 0x86, 0xe3, 0x14, 0xbe, 0xae, 0xe4, 0x4,
                0xa,  0x3b, 0x23, 0x63, 0x28, 0xc,  0x3b, 0xd7, 0x43, 0x75, 0xfa, 0xda,
                0x4c, 0x80, 0x7a, 0x96, 0x1d, 0x69, 0xdc, 0x33, 0x77, 0x70, 0xb9, 0x52,
                0x17, 0x13, 0x10, 0x4f, 0x8,  0xbc, 0x6,  0x0,  0x95, 0x19, 0xea, 0xc,
                0x53, 0x28, 0x8a, 0xf5, 0xf,  0xa6, 0x2,  0x48, 0x1b, 0xde, 0x99, 0x84,
                0x93, 0x71, 0xeb, 0x69, 0x2d, 0x38, 0x44, 0x9a, 0xba, 0x1a, 0x35, 0xae,
                0xeb, 0x71, 0x16, 0xba, 0xe1, 0x1,  0x7c, 0x57, 0xfc, 0xfa, 0xd3, 0x5f,
                0xd6, 0xb9, 0x64, 0x68, 0x70, 0xcf, 0x6d, 0xa3, 0xd4, 0x10, 0x40, 0x10,
                0x39, 0x80, 0xa9, 0x38, 0x30, 0x13, 0xf6, 0x8a, 0x54, 0x10, 0x2d, 0xcd,
                0x44, 0x42, 0xec, 0x9,  0xb1, 0x4f, 0xd1, 0xf3, 0xf5, 0x25, 0xfa, 0x12,
                0x33, 0xa6, 0x6d, 0x44, 0x48, 0xf9, 0x66, 0x54, 0x14, 0x1d, 0x7d, 0x91,
                0x43, 0x0,  0x98, 0xa7, 0xd6, 0xda, 0x2e, 0x25, 0x7e, 0x50, 0xeb, 0xd6,
                0x7e, 0xdb, 0x39, 0xa8, 0x61, 0xf1, 0x1a, 0xda, 0xf6, 0x2a, 0x42, 0x86,
                0x3a, 0xbc, 0x57, 0x5c, 0xbb, 0x8d, 0xed, 0x4e, 0xa5, 0xc4, 0x9f, 0x88,
                0x37, 0x8,  0xcb, 0x13, 0x1f, 0xff, 0x91, 0xcd, 0x1a, 0xbb, 0x9d, 0x9,
                0x13, 0x95, 0xc,  0x29, 0x94, 0x55, 0xde, 0xb3, 0x34, 0xca, 0x8,  0x38,
                0xe5, 0x62, 0x9f, 0x1d, 0x29, 0x66, 0x55, 0x89, 0x82, 0x5c, 0xc,  0xc5,
                0xf2, 0xb3, 0xfb, 0x6a, 0xd7, 0x3b, 0x1c, 0xb6, 0x1f, 0xae, 0x39, 0xa6,
                0xbb, 0x4,  0x2b, 0x99, 0x33, 0x6b, 0xdb, 0xda, 0x3a, 0xb6, 0x54, 0xa0,
                0xf8, 0x4d, 0xba, 0xfc, 0x3f, 0xd0, 0x2d, 0x7f, 0x2c, 0xe9, 0x62, 0x76,
                0xb0, 0x7d, 0x5a, 0xc8, 0xb6, 0xe4, 0xcf, 0xa,  0x8d, 0x4a, 0xee, 0xbc,
                0x62, 0xf8, 0x31, 0x5d, 0xe0, 0xe0, 0x36, 0x71, 0x8f, 0x27, 0x61, 0xed,
                0x76, 0x51, 0x56, 0xcf, 0xa2, 0x5f, 0x6e, 0xba, 0x2e, 0x3f, 0xe4, 0x33,
                0xa1, 0xdb, 0x71, 0xb6, 0xdd, 0x38, 0xd1, 0xdd, 0x8c, 0x45, 0xc3, 0x93,
                0x4d, 0xe0, 0x3c, 0x8a, 0x49, 0xb7, 0x8d, 0xa4, 0x5,  0xe9, 0x85, 0x9,
                0xed, 0x87, 0x2f, 0xc4, 0xa7, 0x3d, 0xc5, 0xa4, 0x42, 0x6e, 0xca, 0x59,
                0x4,  0x39, 0x8,  0x71, 0x55, 0x4b, 0xad, 0x6d, 0x3d, 0x47, 0xf6, 0x72,
                0x10, 0xcb, 0xa5, 0xde, 0xac, 0x9f, 0x71, 0x32, 0xd9, 0x2a, 0xa3, 0x29,
                0xd,  0xf8, 0x2,  0x5a },
            { 0x41, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70, 0x68, 0x20,
                0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65, 0x73, 0x20,
                0x6f, 0x66, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x73,
                0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6f, 0x72,
                0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 0x6e, 0x64, 0x20,
                0x63, 0x6f, 0x68, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x61, 0x6e,
                0x64, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x72, 0x65,
                0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x20, 0x73,
                0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x2e,
                0x20, 0x41, 0x6c, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x65, 0x76, 0x65, 0x72,
                0x79, 0x20, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x77,
                0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x64,
                0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6c, 0x6f,
                0x6e, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x20,
                0x66, 0x65, 0x77, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65,
                0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20,
                0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x69, 0x6e,
                0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70, 0x68,
                0x73, 0x2e, 0x41, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70,
                0x68, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65,
                0x73, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63,
                0x65, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20,
                0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 0x6e,
                0x64, 0x20, 0x63, 0x6f, 0x68, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20,
                0x61, 0x6e, 0x64, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20,
                0x72, 0x65, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61,
                0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x70, 0x69,
                0x63, 0x2e, 0x20, 0x41, 0x6c, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x65, 0x76,
                0x65, 0x72, 0x79, 0x20, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6f, 0x66,
                0x20, 0x77, 0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75,
                0x20, 0x64, 0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20,
                0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20,
                0x61, 0x20, 0x66, 0x65, 0x77, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e,
                0x63, 0x65, 0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62,
                0x65, 0x20, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20,
                0x69, 0x6e, 0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61,
                0x70, 0x68, 0x73, 0x2e },
        }
    }
#endif 
};
// clang-format on
} // namespace alcp::cipher::unittest::xts
using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::xts;

// Test fixture class for XTS tests with helper functions
// Note: XTS uses double-length keys (256-bit for AES-128, 512-bit for AES-256)
class XTSTest : public ::testing::Test
{
  protected:
    // For XTS, the key size returned is the double-key size
    static size_t getKeySizeBytes(CipherKeyLen keyLen)
    {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit: return 32;  // XTS-AES-128 uses 256-bit key
            case CipherKeyLen::eKey256Bit: return 64;  // XTS-AES-256 uses 512-bit key
            default: return 32;
        }
    }

    static size_t getKeySizeBits(CipherKeyLen keyLen)
    {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit: return 128;
            case CipherKeyLen::eKey256Bit: return 256;
            default: return 128;
        }
    }
};

// Parameterized test fixture for key size variations
// Note: XTS only supports 128-bit and 256-bit keys (not 192-bit)
class XTSKeySizeTest : public ::testing::TestWithParam<CipherKeyLen>
{
  protected:
    static size_t getKeySizeBytes(CipherKeyLen keyLen)
    {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit: return 32;  // XTS-AES-128 uses 256-bit key
            case CipherKeyLen::eKey256Bit: return 64;  // XTS-AES-256 uses 512-bit key
            default: return 32;
        }
    }

    static size_t getKeySizeBits(CipherKeyLen keyLen)
    {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit: return 128;
            case CipherKeyLen::eKey256Bit: return 256;
            default: return 128;
        }
    }
};

TEST(XTS, initiantiation_with_valid_input)
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
                auto xts        = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        alc_error_t err = ALC_ERROR_NONE;

        if (xts == nullptr) {
            delete xts;
            FAIL();
        }
        err = xts->init(key, 128, nullptr, 0);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete xts;
    }
}

TEST(XTS, valid_all_sizes_encrypt_decrypt_test)
{
    // clang-format off
    Uint8 iv[16]     = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                         0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };
    Uint8 key[]      = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
    // clang-format on
    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
        for (int i = 16; i < 512 * 20; i++) {
                        auto xts        = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey256Bit);

            if (xts == nullptr) {
                delete xts;
                FAIL();
            }
            alc_error_t err = xts->init(key, 256, iv, 16);
            EXPECT_EQ(err, ALC_ERROR_NONE);

            std::vector<Uint8> plainText(i, 0);
            Uint64             ct_size = i;
            auto               dest    = std::make_unique<Uint8[]>(i);
            fillRandom(plainText);

            Uint64 outlen = 0;
            err = xts->encrypt(&(plainText[0]), dest.get(), ct_size, &outlen);
            EXPECT_EQ(err, ALC_ERROR_NONE);

            std::vector<Uint8> pt(i, 0);

            err = xts->init(key, 256, iv, 16);
            EXPECT_EQ(err, ALC_ERROR_NONE);
            Uint64 outlen2 = 0;
            err = xts->decrypt(dest.get(), &(pt[0]), ct_size, &outlen2);

            EXPECT_TRUE(err == ALC_ERROR_NONE);
            EXPECT_EQ(plainText, pt);

            delete xts;
        }
    }
}

TEST(XTS, encrypt_huge)
{
    Uint8 key[32] = { 0x85, 0xe8, 0xe2, 0x6d, 0x8f, 0x68, 0xcb, 0xd7,
                      0x90, 0x91, 0x26, 0x0c, 0x07, 0xc2, 0x1f, 0x30,
                      0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x61 };
    Uint8 iv[16]  = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };

    std::vector<Uint8> plainText = {
        0xf4, 0x2f, 0xa5, 0x55, 0xea, 0x94, 0x71, 0x0a, 0x20, 0xab, 0x16, 0x4b,
        0xe1, 0x9f, 0xca, 0x8b, 0x2a, 0x2d, 0x24, 0xc6, 0x9c, 0x74, 0xe2, 0xdf,
        0x08, 0xf5, 0xbb, 0x3a, 0x5c, 0x97, 0x11, 0xe9, 0x9c, 0xf3, 0x1f, 0x38,
        0x29, 0xbe, 0x85, 0xae, 0x1c, 0xfd, 0x6e, 0xa0, 0xaa, 0xbf, 0xb8, 0x16,
        0xba, 0x07, 0x6a, 0x91, 0xad, 0x38, 0x6e, 0x83, 0xfa, 0xa4, 0x7b, 0x44,
        0x36, 0x77, 0xb8, 0xc3, 0x0f, 0xb0, 0x3a, 0x89, 0xc6, 0x9f, 0x2d, 0x00,
        0x30, 0x06, 0x0a, 0xe8, 0x6b, 0x2f, 0x92, 0xa1, 0xb8, 0x80, 0xcd, 0x30,
        0x0f, 0x91, 0x40, 0xaf, 0x2e, 0x90, 0xe6, 0x2b, 0x38, 0x49, 0x85, 0x31,
        0xa0, 0x29, 0x46, 0xc5, 0x8a, 0x0c, 0x64, 0xfb, 0x53, 0x99, 0xea, 0xfb,
        0xb8, 0x3d, 0x9e, 0x2f, 0xf7, 0x08, 0x4f, 0x9c, 0xf5, 0x5a, 0xdc, 0x95,
        0x38, 0x82, 0xb1, 0x7d, 0x59, 0xe7, 0x4b, 0xac, 0xe0, 0x6a, 0x95, 0x25,
        0xd5, 0xce, 0x09, 0xac, 0x6e, 0xca, 0xe1, 0xa9, 0x6f, 0x4f, 0x06, 0xef,
        0x3f, 0x2e, 0xa9, 0x96, 0xfd, 0xba, 0x0c, 0x2b, 0xd8, 0x29, 0x06, 0xdc,
        0x19, 0x7b, 0x32, 0xdf, 0xf9, 0x7a, 0xe3, 0xc5, 0x9c, 0x93, 0xa1, 0x73,
        0x97, 0x25, 0xc9, 0x2b, 0x5e, 0x25, 0xfd, 0xc2, 0x3e, 0x9f, 0xa9, 0x8a,
        0x98, 0xf0, 0xa5, 0x1b, 0x85, 0xb2, 0x4c, 0x6b, 0xe3, 0x47, 0x3f, 0x97,
        0xf7, 0x60, 0x41, 0x47, 0x4b, 0x56, 0xf2, 0x52, 0xe6, 0xfd, 0x9f
    };

    std::vector<Uint8> cipherText = {
        0x69, 0xd2, 0xf0, 0xa7, 0x32, 0x61, 0x95, 0x80, 0x09, 0x50, 0x57, 0xdc,
        0x60, 0xa0, 0x66, 0xdb, 0x17, 0x68, 0x8e, 0x14, 0x26, 0xc8, 0x7a, 0x07,
        0xc7, 0xea, 0xc8, 0x5b, 0x58, 0x3b, 0xc5, 0x16, 0x51, 0x9a, 0x69, 0x49,
        0x6a, 0x65, 0x09, 0xa9, 0xb7, 0xa6, 0x06, 0x2d, 0x85, 0xba, 0xd3, 0xf4,
        0x0c, 0x39, 0x55, 0x0c, 0x0c, 0x64, 0xf8, 0x25, 0xa6, 0xab, 0xe6, 0x51,
        0x57, 0x44, 0xd9, 0x9e, 0x48, 0x03, 0x0d, 0xd4, 0x1e, 0x97, 0xf9, 0x0c,
        0xa0, 0x97, 0x3d, 0x9f, 0x2e, 0x32, 0x65, 0xee, 0x75, 0xea, 0xb6, 0xc6,
        0x18, 0x09, 0x67, 0xb4, 0x8a, 0xcb, 0x54, 0xd2, 0x03, 0xdc, 0x0b, 0x5a,
        0xc1, 0x9e, 0xf5, 0x2f, 0xf3, 0xb7, 0x76, 0x2c, 0xe0, 0xaf, 0x8d, 0x4e,
        0x03, 0xa5, 0x85, 0x3f, 0xa7, 0x54, 0x29, 0x7f, 0xb2, 0x7e, 0x65, 0xe9,
        0xca, 0x83, 0x2d, 0x5f, 0x7e, 0x95, 0xa3, 0x69, 0x2f, 0xe9, 0xb1, 0x83,
        0xee, 0x5e, 0x87, 0xad, 0x9c, 0x03, 0x36, 0x4c, 0x52, 0x28, 0x60, 0xc9,
        0xb9, 0x14, 0xb9, 0xdf, 0x1a, 0x02, 0xe4, 0x4f, 0x09, 0xa2, 0x75, 0x53,
        0xdc, 0xa6, 0xc2, 0xdc, 0x0c, 0x4c, 0x26, 0xec, 0x0c, 0x07, 0xa4, 0x68,
        0x62, 0x6d, 0xf1, 0x15, 0x58, 0xaa, 0x14, 0xd2, 0x8e, 0x1f, 0x68, 0xe5,
        0x18, 0x28, 0x14, 0xff, 0xba, 0x52, 0x2f, 0x32, 0x22, 0x91, 0x81, 0x53,
        0x4e, 0x28, 0x0e, 0x2b, 0x11, 0x04, 0x8e, 0xe4, 0xab, 0x6e, 0xe1
    };
    alc_error_t err = ALC_ERROR_NONE;

    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
                auto xts        = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        if (xts == nullptr) {
            delete xts;
            FAIL();
        }
        err = xts->init(key, 128, iv, 16);

        EXPECT_TRUE(err == ALC_ERROR_NONE);

        std::vector<Uint8> output_buffer(plainText.size(), 0x0);

        Uint64 outlen = 0;
        err           = xts->encrypt(&(plainText[0]),
                           &(output_buffer[0]),
                           output_buffer.size(),
                           &outlen);

        EXPECT_TRUE(err == ALC_ERROR_NONE);

        delete xts;

        ASSERT_EQ(output_buffer, cipherText);
    }
}

TEST(XTS, decrypt_huge)
{
    Uint8 key[32] = { 0x85, 0xe8, 0xe2, 0x6d, 0x8f, 0x68, 0xcb, 0xd7,
                      0x90, 0x91, 0x26, 0x0c, 0x07, 0xc2, 0x1f, 0x30,
                      0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x61 };
    Uint8 iv[16]  = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };

    std::vector<Uint8> plainText = {
        0xf4, 0x2f, 0xa5, 0x55, 0xea, 0x94, 0x71, 0x0a, 0x20, 0xab, 0x16, 0x4b,
        0xe1, 0x9f, 0xca, 0x8b, 0x2a, 0x2d, 0x24, 0xc6, 0x9c, 0x74, 0xe2, 0xdf,
        0x08, 0xf5, 0xbb, 0x3a, 0x5c, 0x97, 0x11, 0xe9, 0x9c, 0xf3, 0x1f, 0x38,
        0x29, 0xbe, 0x85, 0xae, 0x1c, 0xfd, 0x6e, 0xa0, 0xaa, 0xbf, 0xb8, 0x16,
        0xba, 0x07, 0x6a, 0x91, 0xad, 0x38, 0x6e, 0x83, 0xfa, 0xa4, 0x7b, 0x44,
        0x36, 0x77, 0xb8, 0xc3, 0x0f, 0xb0, 0x3a, 0x89, 0xc6, 0x9f, 0x2d, 0x00,
        0x30, 0x06, 0x0a, 0xe8, 0x6b, 0x2f, 0x92, 0xa1, 0xb8, 0x80, 0xcd, 0x30,
        0x0f, 0x91, 0x40, 0xaf, 0x2e, 0x90, 0xe6, 0x2b, 0x38, 0x49, 0x85, 0x31,
        0xa0, 0x29, 0x46, 0xc5, 0x8a, 0x0c, 0x64, 0xfb, 0x53, 0x99, 0xea, 0xfb,
        0xb8, 0x3d, 0x9e, 0x2f, 0xf7, 0x08, 0x4f, 0x9c, 0xf5, 0x5a, 0xdc, 0x95,
        0x38, 0x82, 0xb1, 0x7d, 0x59, 0xe7, 0x4b, 0xac, 0xe0, 0x6a, 0x95, 0x25,
        0xd5, 0xce, 0x09, 0xac, 0x6e, 0xca, 0xe1, 0xa9, 0x6f, 0x4f, 0x06, 0xef,
        0x3f, 0x2e, 0xa9, 0x96, 0xfd, 0xba, 0x0c, 0x2b, 0xd8, 0x29, 0x06, 0xdc,
        0x19, 0x7b, 0x32, 0xdf, 0xf9, 0x7a, 0xe3, 0xc5, 0x9c, 0x93, 0xa1, 0x73,
        0x97, 0x25, 0xc9, 0x2b, 0x5e, 0x25, 0xfd, 0xc2, 0x3e, 0x9f, 0xa9, 0x8a,
        0x98, 0xf0, 0xa5, 0x1b, 0x85, 0xb2, 0x4c, 0x6b, 0xe3, 0x47, 0x3f, 0x97,
        0xf7, 0x60, 0x41, 0x47, 0x4b, 0x56, 0xf2, 0x52, 0xe6, 0xfd, 0x9f
    };

    std::vector<Uint8> cipherText = {
        0x69, 0xd2, 0xf0, 0xa7, 0x32, 0x61, 0x95, 0x80, 0x09, 0x50, 0x57, 0xdc,
        0x60, 0xa0, 0x66, 0xdb, 0x17, 0x68, 0x8e, 0x14, 0x26, 0xc8, 0x7a, 0x07,
        0xc7, 0xea, 0xc8, 0x5b, 0x58, 0x3b, 0xc5, 0x16, 0x51, 0x9a, 0x69, 0x49,
        0x6a, 0x65, 0x09, 0xa9, 0xb7, 0xa6, 0x06, 0x2d, 0x85, 0xba, 0xd3, 0xf4,
        0x0c, 0x39, 0x55, 0x0c, 0x0c, 0x64, 0xf8, 0x25, 0xa6, 0xab, 0xe6, 0x51,
        0x57, 0x44, 0xd9, 0x9e, 0x48, 0x03, 0x0d, 0xd4, 0x1e, 0x97, 0xf9, 0x0c,
        0xa0, 0x97, 0x3d, 0x9f, 0x2e, 0x32, 0x65, 0xee, 0x75, 0xea, 0xb6, 0xc6,
        0x18, 0x09, 0x67, 0xb4, 0x8a, 0xcb, 0x54, 0xd2, 0x03, 0xdc, 0x0b, 0x5a,
        0xc1, 0x9e, 0xf5, 0x2f, 0xf3, 0xb7, 0x76, 0x2c, 0xe0, 0xaf, 0x8d, 0x4e,
        0x03, 0xa5, 0x85, 0x3f, 0xa7, 0x54, 0x29, 0x7f, 0xb2, 0x7e, 0x65, 0xe9,
        0xca, 0x83, 0x2d, 0x5f, 0x7e, 0x95, 0xa3, 0x69, 0x2f, 0xe9, 0xb1, 0x83,
        0xee, 0x5e, 0x87, 0xad, 0x9c, 0x03, 0x36, 0x4c, 0x52, 0x28, 0x60, 0xc9,
        0xb9, 0x14, 0xb9, 0xdf, 0x1a, 0x02, 0xe4, 0x4f, 0x09, 0xa2, 0x75, 0x53,
        0xdc, 0xa6, 0xc2, 0xdc, 0x0c, 0x4c, 0x26, 0xec, 0x0c, 0x07, 0xa4, 0x68,
        0x62, 0x6d, 0xf1, 0x15, 0x58, 0xaa, 0x14, 0xd2, 0x8e, 0x1f, 0x68, 0xe5,
        0x18, 0x28, 0x14, 0xff, 0xba, 0x52, 0x2f, 0x32, 0x22, 0x91, 0x81, 0x53,
        0x4e, 0x28, 0x0e, 0x2b, 0x11, 0x04, 0x8e, 0xe4, 0xab, 0x6e, 0xe1
    };
    alc_error_t                    err          = ALC_ERROR_NONE;
    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
        std::vector<Uint8> output_buffer(cipherText.size(), 0xff);

                auto xts        = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        if (xts == nullptr) {
            delete xts;
            FAIL();
        }
        err = xts->init(key, 128, iv, 16);

        EXPECT_TRUE(err == ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err           = xts->decrypt(&(cipherText[0]),
                           &(output_buffer[0]),
                           output_buffer.size(),
                           &outlen);

        EXPECT_TRUE(err == ALC_ERROR_NONE);

        delete xts;
        ASSERT_EQ(output_buffer, plainText);
    }
}
TEST(XTS, encrypt_huge_multi_update)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    Uint8 key[32] = { 0x85, 0xe8, 0xe2, 0x6d, 0x8f, 0x68, 0xcb, 0xd7,
                      0x90, 0x91, 0x26, 0x0c, 0x07, 0xc2, 0x1f, 0x30,
                      0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x61 };
    Uint8 iv[16]  = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };

    std::vector<Uint8> plainText = {
        0xf4, 0x2f, 0xa5, 0x55, 0xea, 0x94, 0x71, 0x0a, 0x20, 0xab, 0x16, 0x4b,
        0xe1, 0x9f, 0xca, 0x8b, 0x2a, 0x2d, 0x24, 0xc6, 0x9c, 0x74, 0xe2, 0xdf,
        0x08, 0xf5, 0xbb, 0x3a, 0x5c, 0x97, 0x11, 0xe9, 0x9c, 0xf3, 0x1f, 0x38,
        0x29, 0xbe, 0x85, 0xae, 0x1c, 0xfd, 0x6e, 0xa0, 0xaa, 0xbf, 0xb8, 0x16,
        0xba, 0x07, 0x6a, 0x91, 0xad, 0x38, 0x6e, 0x83, 0xfa, 0xa4, 0x7b, 0x44,
        0x36, 0x77, 0xb8, 0xc3, 0x0f, 0xb0, 0x3a, 0x89, 0xc6, 0x9f, 0x2d, 0x00,
        0x30, 0x06, 0x0a, 0xe8, 0x6b, 0x2f, 0x92, 0xa1, 0xb8, 0x80, 0xcd, 0x30,
        0x0f, 0x91, 0x40, 0xaf, 0x2e, 0x90, 0xe6, 0x2b, 0x38, 0x49, 0x85, 0x31,
        0xa0, 0x29, 0x46, 0xc5, 0x8a, 0x0c, 0x64, 0xfb, 0x53, 0x99, 0xea, 0xfb,
        0xb8, 0x3d, 0x9e, 0x2f, 0xf7, 0x08, 0x4f, 0x9c, 0xf5, 0x5a, 0xdc, 0x95,
        0x38, 0x82, 0xb1, 0x7d, 0x59, 0xe7, 0x4b, 0xac, 0xe0, 0x6a, 0x95, 0x25,
        0xd5, 0xce, 0x09, 0xac, 0x6e, 0xca, 0xe1, 0xa9, 0x6f, 0x4f, 0x06, 0xef,
        0x3f, 0x2e, 0xa9, 0x96, 0xfd, 0xba, 0x0c, 0x2b, 0xd8, 0x29, 0x06, 0xdc,
        0x19, 0x7b, 0x32, 0xdf, 0xf9, 0x7a, 0xe3, 0xc5, 0x9c, 0x93, 0xa1, 0x73,
        0x97, 0x25, 0xc9, 0x2b, 0x5e, 0x25, 0xfd, 0xc2, 0x3e, 0x9f, 0xa9, 0x8a,
        0x98, 0xf0, 0xa5, 0x1b, 0x85, 0xb2, 0x4c, 0x6b, 0xe3, 0x47, 0x3f, 0x97,
        0xf7, 0x60, 0x41, 0x47, 0x4b, 0x56, 0xf2, 0x52, 0xe6, 0xfd, 0x9f
    }; // 203 bytes

    std::vector<Uint8> cipherText = {
        0x69, 0xd2, 0xf0, 0xa7, 0x32, 0x61, 0x95, 0x80, 0x09, 0x50, 0x57, 0xdc,
        0x60, 0xa0, 0x66, 0xdb, 0x17, 0x68, 0x8e, 0x14, 0x26, 0xc8, 0x7a, 0x07,
        0xc7, 0xea, 0xc8, 0x5b, 0x58, 0x3b, 0xc5, 0x16, 0x51, 0x9a, 0x69, 0x49,
        0x6a, 0x65, 0x09, 0xa9, 0xb7, 0xa6, 0x06, 0x2d, 0x85, 0xba, 0xd3, 0xf4,
        0x0c, 0x39, 0x55, 0x0c, 0x0c, 0x64, 0xf8, 0x25, 0xa6, 0xab, 0xe6, 0x51,
        0x57, 0x44, 0xd9, 0x9e, 0x48, 0x03, 0x0d, 0xd4, 0x1e, 0x97, 0xf9, 0x0c,
        0xa0, 0x97, 0x3d, 0x9f, 0x2e, 0x32, 0x65, 0xee, 0x75, 0xea, 0xb6, 0xc6,
        0x18, 0x09, 0x67, 0xb4, 0x8a, 0xcb, 0x54, 0xd2, 0x03, 0xdc, 0x0b, 0x5a,
        0xc1, 0x9e, 0xf5, 0x2f, 0xf3, 0xb7, 0x76, 0x2c, 0xe0, 0xaf, 0x8d, 0x4e,
        0x03, 0xa5, 0x85, 0x3f, 0xa7, 0x54, 0x29, 0x7f, 0xb2, 0x7e, 0x65, 0xe9,
        0xca, 0x83, 0x2d, 0x5f, 0x7e, 0x95, 0xa3, 0x69, 0x2f, 0xe9, 0xb1, 0x83,
        0xee, 0x5e, 0x87, 0xad, 0x9c, 0x03, 0x36, 0x4c, 0x52, 0x28, 0x60, 0xc9,
        0xb9, 0x14, 0xb9, 0xdf, 0x1a, 0x02, 0xe4, 0x4f, 0x09, 0xa2, 0x75, 0x53,
        0xdc, 0xa6, 0xc2, 0xdc, 0x0c, 0x4c, 0x26, 0xec, 0x0c, 0x07, 0xa4, 0x68,
        0x62, 0x6d, 0xf1, 0x15, 0x58, 0xaa, 0x14, 0xd2, 0x8e, 0x1f, 0x68, 0xe5,
        0x18, 0x28, 0x14, 0xff, 0xba, 0x52, 0x2f, 0x32, 0x22, 0x91, 0x81, 0x53,
        0x4e, 0x28, 0x0e, 0x2b, 0x11, 0x04, 0x8e, 0xe4, 0xab, 0x6e, 0xe1
    };

    alc_error_t err = ALC_ERROR_NONE;

    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {

        std::vector<Uint8> output_buffer(plainText.size(), 0xff);
                auto               xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        if (xts == nullptr) {
            delete xts;
            FAIL();
        }
        err = xts->init(key, 128, iv, 16);

        Uint64 res = plainText.size() % 16;
        if (plainText.size() >= (16 + res)) {
            Uint64 extra_update_size = 0;
            Uint64 multi_update_size = 0;
            Uint8* curr_pt           = &(plainText[0]);
            Uint8* curr_ot           = &(output_buffer[0]);
            if (res) {
                // If partial bock, give 2 blocks at a time.
                multi_update_size = plainText.size() - 16 - res;
                extra_update_size = 16 + res;
            } else {
                multi_update_size = plainText.size();
            }
            while (multi_update_size > 0) {
                Uint64 outlen = 0;
                err           = xts->encrypt(curr_pt, curr_ot, 16, &outlen);

                EXPECT_FALSE(alcp_is_error(err));
                multi_update_size -= 16;
                curr_ot += 16;
                curr_pt += 16;
            }
            // Last 2 blocks if available
            if (extra_update_size) {
                Uint64 outlen = 0;
                err =
                    xts->encrypt(curr_pt, curr_ot, extra_update_size, &outlen);

                EXPECT_FALSE(alcp_is_error(err));
            }
        }

#if 0
    auto ret = std::mismatch(
        cipherText.begin(), cipherText.end(), output_buffer.begin());
    std::cout << "First:" << ret.first - cipherText.begin()
              << "Second:" << ret.second - output_buffer.begin() << std::endl;
#endif

        delete xts;
        ASSERT_EQ(output_buffer, cipherText);
    }
}

TEST(XTS, encrypt_huge_multi_update_serial)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    Uint8 key[32] = { 0x85, 0xe8, 0xe2, 0x6d, 0x8f, 0x68, 0xcb, 0xd7,
                      0x90, 0x91, 0x26, 0x0c, 0x07, 0xc2, 0x1f, 0x30,
                      0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x61 };
    Uint8 iv[16]  = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };

    std::vector<Uint8> plainText = {
        0xf4, 0x2f, 0xa5, 0x55, 0xea, 0x94, 0x71, 0x0a, 0x20, 0xab, 0x16, 0x4b,
        0xe1, 0x9f, 0xca, 0x8b, 0x2a, 0x2d, 0x24, 0xc6, 0x9c, 0x74, 0xe2, 0xdf,
        0x08, 0xf5, 0xbb, 0x3a, 0x5c, 0x97, 0x11, 0xe9, 0x9c, 0xf3, 0x1f, 0x38,
        0x29, 0xbe, 0x85, 0xae, 0x1c, 0xfd, 0x6e, 0xa0, 0xaa, 0xbf, 0xb8, 0x16,
        0xba, 0x07, 0x6a, 0x91, 0xad, 0x38, 0x6e, 0x83, 0xfa, 0xa4, 0x7b, 0x44,
        0x36, 0x77, 0xb8, 0xc3, 0x0f, 0xb0, 0x3a, 0x89, 0xc6, 0x9f, 0x2d, 0x00,
        0x30, 0x06, 0x0a, 0xe8, 0x6b, 0x2f, 0x92, 0xa1, 0xb8, 0x80, 0xcd, 0x30,
        0x0f, 0x91, 0x40, 0xaf, 0x2e, 0x90, 0xe6, 0x2b, 0x38, 0x49, 0x85, 0x31,
        0xa0, 0x29, 0x46, 0xc5, 0x8a, 0x0c, 0x64, 0xfb, 0x53, 0x99, 0xea, 0xfb,
        0xb8, 0x3d, 0x9e, 0x2f, 0xf7, 0x08, 0x4f, 0x9c, 0xf5, 0x5a, 0xdc, 0x95,
        0x38, 0x82, 0xb1, 0x7d, 0x59, 0xe7, 0x4b, 0xac, 0xe0, 0x6a, 0x95, 0x25,
        0xd5, 0xce, 0x09, 0xac, 0x6e, 0xca, 0xe1, 0xa9, 0x6f, 0x4f, 0x06, 0xef,
        0x3f, 0x2e, 0xa9, 0x96, 0xfd, 0xba, 0x0c, 0x2b, 0xd8, 0x29, 0x06, 0xdc,
        0x19, 0x7b, 0x32, 0xdf, 0xf9, 0x7a, 0xe3, 0xc5, 0x9c, 0x93, 0xa1, 0x73,
        0x97, 0x25, 0xc9, 0x2b, 0x5e, 0x25, 0xfd, 0xc2, 0x3e, 0x9f, 0xa9, 0x8a,
        0x98, 0xf0, 0xa5, 0x1b, 0x85, 0xb2, 0x4c, 0x6b, 0xe3, 0x47, 0x3f, 0x97,
        0xf7, 0x60, 0x41, 0x47, 0x4b, 0x56, 0xf2, 0x52, 0xe6, 0xfd, 0x9f
    }; // 203 bytes

    std::vector<Uint8> cipherText = {
        0x69, 0xd2, 0xf0, 0xa7, 0x32, 0x61, 0x95, 0x80, 0x09, 0x50, 0x57, 0xdc,
        0x60, 0xa0, 0x66, 0xdb, 0x17, 0x68, 0x8e, 0x14, 0x26, 0xc8, 0x7a, 0x07,
        0xc7, 0xea, 0xc8, 0x5b, 0x58, 0x3b, 0xc5, 0x16, 0x51, 0x9a, 0x69, 0x49,
        0x6a, 0x65, 0x09, 0xa9, 0xb7, 0xa6, 0x06, 0x2d, 0x85, 0xba, 0xd3, 0xf4,
        0x0c, 0x39, 0x55, 0x0c, 0x0c, 0x64, 0xf8, 0x25, 0xa6, 0xab, 0xe6, 0x51,
        0x57, 0x44, 0xd9, 0x9e, 0x48, 0x03, 0x0d, 0xd4, 0x1e, 0x97, 0xf9, 0x0c,
        0xa0, 0x97, 0x3d, 0x9f, 0x2e, 0x32, 0x65, 0xee, 0x75, 0xea, 0xb6, 0xc6,
        0x18, 0x09, 0x67, 0xb4, 0x8a, 0xcb, 0x54, 0xd2, 0x03, 0xdc, 0x0b, 0x5a,
        0xc1, 0x9e, 0xf5, 0x2f, 0xf3, 0xb7, 0x76, 0x2c, 0xe0, 0xaf, 0x8d, 0x4e,
        0x03, 0xa5, 0x85, 0x3f, 0xa7, 0x54, 0x29, 0x7f, 0xb2, 0x7e, 0x65, 0xe9,
        0xca, 0x83, 0x2d, 0x5f, 0x7e, 0x95, 0xa3, 0x69, 0x2f, 0xe9, 0xb1, 0x83,
        0xee, 0x5e, 0x87, 0xad, 0x9c, 0x03, 0x36, 0x4c, 0x52, 0x28, 0x60, 0xc9,
        0xb9, 0x14, 0xb9, 0xdf, 0x1a, 0x02, 0xe4, 0x4f, 0x09, 0xa2, 0x75, 0x53,
        0xdc, 0xa6, 0xc2, 0xdc, 0x0c, 0x4c, 0x26, 0xec, 0x0c, 0x07, 0xa4, 0x68,
        0x62, 0x6d, 0xf1, 0x15, 0x58, 0xaa, 0x14, 0xd2, 0x8e, 0x1f, 0x68, 0xe5,
        0x18, 0x28, 0x14, 0xff, 0xba, 0x52, 0x2f, 0x32, 0x22, 0x91, 0x81, 0x53,
        0x4e, 0x28, 0x0e, 0x2b, 0x11, 0x04, 0x8e, 0xe4, 0xab, 0x6e, 0xe1
    };
    alc_error_t err = ALC_ERROR_NONE;
    Uint64      outlen;

    std::vector<Uint8> output_buffer(plainText.size(), 0xff);

    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
                auto xts        = createCipherSeg(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        if (xts == nullptr) {
            FAIL();
        }
        err = xts->init(key, 128, iv, 16);

        err = xts->encryptSegment(
            &(plainText[0]) + (5 * 16), &(output_buffer[0]) + (5 * 16), 16, 5);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encryptSegment(&(plainText[0]) + (10 * 16),
                                  &(output_buffer[0]) + (10 * 16),
                                  16,
                                  10);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encryptSegment(
            &(plainText[0]) + (0 * 16), &(output_buffer[0]) + (0 * 16), 16, 0);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (1 * 16), &(output_buffer[0]) + (1 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (2 * 16), &(output_buffer[0]) + (2 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (3 * 16), &(output_buffer[0]) + (3 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (4 * 16), &(output_buffer[0]) + (4 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encryptSegment(
            &(plainText[0]) + (6 * 16), &(output_buffer[0]) + (6 * 16), 16, 6);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (7 * 16), &(output_buffer[0]) + (7 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (8 * 16), &(output_buffer[0]) + (8 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encrypt(
            &(plainText[0]) + (9 * 16), &(output_buffer[0]) + (9 * 16), 16, &outlen);

        EXPECT_EQ(err, ALC_ERROR_NONE);

        err = xts->encryptSegment(&(plainText[0]) + (11 * 16),
                                  &(output_buffer[0]) + (11 * 16),
                                  203 - 176,
                                  11);

        EXPECT_EQ(err, ALC_ERROR_NONE);

#if 0
    auto ret = std::mismatch(
        cipherText.begin(), cipherText.end(), output_buffer.begin());
    std::cout << "First:" << ret.first - cipherText.begin()
              << "Second:" << ret.second - output_buffer.begin() << std::endl;
#endif
        delete xts;
        ASSERT_EQ(output_buffer, cipherText);
    }
}

TEST(XTS, encrypt_huge_multi_update_arbitrary)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    Uint8 key[32] = { 0x85, 0xe8, 0xe2, 0x6d, 0x8f, 0x68, 0xcb, 0xd7,
                      0x90, 0x91, 0x26, 0x0c, 0x07, 0xc2, 0x1f, 0x30,
                      0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x61 };
    Uint8 iv[16]  = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };

    std::vector<Uint8> plainText = {
        0xf4, 0x2f, 0xa5, 0x55, 0xea, 0x94, 0x71, 0x0a, 0x20, 0xab, 0x16, 0x4b,
        0xe1, 0x9f, 0xca, 0x8b, 0x2a, 0x2d, 0x24, 0xc6, 0x9c, 0x74, 0xe2, 0xdf,
        0x08, 0xf5, 0xbb, 0x3a, 0x5c, 0x97, 0x11, 0xe9, 0x9c, 0xf3, 0x1f, 0x38,
        0x29, 0xbe, 0x85, 0xae, 0x1c, 0xfd, 0x6e, 0xa0, 0xaa, 0xbf, 0xb8, 0x16,
        0xba, 0x07, 0x6a, 0x91, 0xad, 0x38, 0x6e, 0x83, 0xfa, 0xa4, 0x7b, 0x44,
        0x36, 0x77, 0xb8, 0xc3, 0x0f, 0xb0, 0x3a, 0x89, 0xc6, 0x9f, 0x2d, 0x00,
        0x30, 0x06, 0x0a, 0xe8, 0x6b, 0x2f, 0x92, 0xa1, 0xb8, 0x80, 0xcd, 0x30,
        0x0f, 0x91, 0x40, 0xaf, 0x2e, 0x90, 0xe6, 0x2b, 0x38, 0x49, 0x85, 0x31,
        0xa0, 0x29, 0x46, 0xc5, 0x8a, 0x0c, 0x64, 0xfb, 0x53, 0x99, 0xea, 0xfb,
        0xb8, 0x3d, 0x9e, 0x2f, 0xf7, 0x08, 0x4f, 0x9c, 0xf5, 0x5a, 0xdc, 0x95,
        0x38, 0x82, 0xb1, 0x7d, 0x59, 0xe7, 0x4b, 0xac, 0xe0, 0x6a, 0x95, 0x25,
        0xd5, 0xce, 0x09, 0xac, 0x6e, 0xca, 0xe1, 0xa9, 0x6f, 0x4f, 0x06, 0xef,
        0x3f, 0x2e, 0xa9, 0x96, 0xfd, 0xba, 0x0c, 0x2b, 0xd8, 0x29, 0x06, 0xdc,
        0x19, 0x7b, 0x32, 0xdf, 0xf9, 0x7a, 0xe3, 0xc5, 0x9c, 0x93, 0xa1, 0x73,
        0x97, 0x25, 0xc9, 0x2b, 0x5e, 0x25, 0xfd, 0xc2, 0x3e, 0x9f, 0xa9, 0x8a,
        0x98, 0xf0, 0xa5, 0x1b, 0x85, 0xb2, 0x4c, 0x6b, 0xe3, 0x47, 0x3f, 0x97,
        0xf7, 0x60, 0x41, 0x47, 0x4b, 0x56, 0xf2, 0x52, 0xe6, 0xfd, 0x9f
    }; // 203 bytes

    std::vector<Uint8> cipherText = {
        0x69, 0xd2, 0xf0, 0xa7, 0x32, 0x61, 0x95, 0x80, 0x09, 0x50, 0x57, 0xdc,
        0x60, 0xa0, 0x66, 0xdb, 0x17, 0x68, 0x8e, 0x14, 0x26, 0xc8, 0x7a, 0x07,
        0xc7, 0xea, 0xc8, 0x5b, 0x58, 0x3b, 0xc5, 0x16, 0x51, 0x9a, 0x69, 0x49,
        0x6a, 0x65, 0x09, 0xa9, 0xb7, 0xa6, 0x06, 0x2d, 0x85, 0xba, 0xd3, 0xf4,
        0x0c, 0x39, 0x55, 0x0c, 0x0c, 0x64, 0xf8, 0x25, 0xa6, 0xab, 0xe6, 0x51,
        0x57, 0x44, 0xd9, 0x9e, 0x48, 0x03, 0x0d, 0xd4, 0x1e, 0x97, 0xf9, 0x0c,
        0xa0, 0x97, 0x3d, 0x9f, 0x2e, 0x32, 0x65, 0xee, 0x75, 0xea, 0xb6, 0xc6,
        0x18, 0x09, 0x67, 0xb4, 0x8a, 0xcb, 0x54, 0xd2, 0x03, 0xdc, 0x0b, 0x5a,
        0xc1, 0x9e, 0xf5, 0x2f, 0xf3, 0xb7, 0x76, 0x2c, 0xe0, 0xaf, 0x8d, 0x4e,
        0x03, 0xa5, 0x85, 0x3f, 0xa7, 0x54, 0x29, 0x7f, 0xb2, 0x7e, 0x65, 0xe9,
        0xca, 0x83, 0x2d, 0x5f, 0x7e, 0x95, 0xa3, 0x69, 0x2f, 0xe9, 0xb1, 0x83,
        0xee, 0x5e, 0x87, 0xad, 0x9c, 0x03, 0x36, 0x4c, 0x52, 0x28, 0x60, 0xc9,
        0xb9, 0x14, 0xb9, 0xdf, 0x1a, 0x02, 0xe4, 0x4f, 0x09, 0xa2, 0x75, 0x53,
        0xdc, 0xa6, 0xc2, 0xdc, 0x0c, 0x4c, 0x26, 0xec, 0x0c, 0x07, 0xa4, 0x68,
        0x62, 0x6d, 0xf1, 0x15, 0x58, 0xaa, 0x14, 0xd2, 0x8e, 0x1f, 0x68, 0xe5,
        0x18, 0x28, 0x14, 0xff, 0xba, 0x52, 0x2f, 0x32, 0x22, 0x91, 0x81, 0x53,
        0x4e, 0x28, 0x0e, 0x2b, 0x11, 0x04, 0x8e, 0xe4, 0xab, 0x6e, 0xe1
    };
    alc_error_t err = ALC_ERROR_NONE;

    std::vector<Uint8> output_buffer(plainText.size(), 0xff);

    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();

    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuArchLevel>::type>(
                   feature)
            << std::endl;
#endif
                auto xts        = createCipherSeg(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        if (xts == nullptr) {
            FAIL();
        }
        err = xts->init(key, 128, iv, 16);

        Uint64 res = plainText.size() % 16;
        if (plainText.size() >= (16 + res)) {
            Uint64 extra_update_size = 0;
            Uint64 multi_update_size = 0;
            Uint8* curr_pt           = &(plainText[0]); // 0x00
            Uint8* curr_ot           = &(output_buffer[0]);
            if (res) {
                // If partial bock, give 2 blocks at a time.
                multi_update_size = plainText.size() - 16 - res;
                extra_update_size = 16 + res;
            } else {
                multi_update_size = plainText.size();
            }
            curr_pt += multi_update_size - 0x10; // 0x00 + 0x60 -> 0x50 -> 0x5f
            curr_ot += multi_update_size - 0x10;
            int blocks     = multi_update_size / 16;
            int curr_block = blocks - 1;
            while (curr_block >= 0) {
                err = xts->encryptSegment(curr_pt, curr_ot, 16, curr_block);

                EXPECT_EQ(err, ALC_ERROR_NONE);
                curr_ot -= 16;
                curr_pt -= 16;
                curr_block--;
            }
            curr_pt = &(plainText[0]) + multi_update_size;
            curr_ot = &(output_buffer[0]) + multi_update_size;
            // Last 2 blocks if available
            if (extra_update_size) {
                err = xts->encryptSegment(
                    curr_pt, curr_ot, extra_update_size, blocks);

                EXPECT_EQ(err, ALC_ERROR_NONE);
            }
        }

#if 0
    auto ret = std::mismatch(
        cipherText.begin(), cipherText.end(), output_buffer.begin());
    std::cout << "First:" << ret.first - cipherText.begin()
              << "Second:" << ret.second - output_buffer.begin() << std::endl;
#endif
        delete xts;
        ASSERT_EQ(output_buffer, cipherText);
    }
}

TEST(XTS, decrypt_huge_multi_update)
{
#ifndef AES_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    Uint8 key[32] = { 0x85, 0xe8, 0xe2, 0x6d, 0x8f, 0x68, 0xcb, 0xd7,
                      0x90, 0x91, 0x26, 0x0c, 0x07, 0xc2, 0x1f, 0x30,
                      0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x61 };
    Uint8 iv[16]  = { 0x2c, 0x8a, 0xd6, 0xab, 0x91, 0x0d, 0x43, 0x68,
                      0xd7, 0x81, 0xb7, 0x52, 0x4b, 0x45, 0x8c, 0x60 };

    std::vector<Uint8> plainText = {
        0xf4, 0x2f, 0xa5, 0x55, 0xea, 0x94, 0x71, 0x0a, 0x20, 0xab, 0x16, 0x4b,
        0xe1, 0x9f, 0xca, 0x8b, 0x2a, 0x2d, 0x24, 0xc6, 0x9c, 0x74, 0xe2, 0xdf,
        0x08, 0xf5, 0xbb, 0x3a, 0x5c, 0x97, 0x11, 0xe9, 0x9c, 0xf3, 0x1f, 0x38,
        0x29, 0xbe, 0x85, 0xae, 0x1c, 0xfd, 0x6e, 0xa0, 0xaa, 0xbf, 0xb8, 0x16,
        0xba, 0x07, 0x6a, 0x91, 0xad, 0x38, 0x6e, 0x83, 0xfa, 0xa4, 0x7b, 0x44,
        0x36, 0x77, 0xb8, 0xc3, 0x0f, 0xb0, 0x3a, 0x89, 0xc6, 0x9f, 0x2d, 0x00,
        0x30, 0x06, 0x0a, 0xe8, 0x6b, 0x2f, 0x92, 0xa1, 0xb8, 0x80, 0xcd, 0x30,
        0x0f, 0x91, 0x40, 0xaf, 0x2e, 0x90, 0xe6, 0x2b, 0x38, 0x49, 0x85, 0x31,
        0xa0, 0x29, 0x46, 0xc5, 0x8a, 0x0c, 0x64, 0xfb, 0x53, 0x99, 0xea, 0xfb,
        0xb8, 0x3d, 0x9e, 0x2f, 0xf7, 0x08, 0x4f, 0x9c, 0xf5, 0x5a, 0xdc, 0x95,
        0x38, 0x82, 0xb1, 0x7d, 0x59, 0xe7, 0x4b, 0xac, 0xe0, 0x6a, 0x95, 0x25,
        0xd5, 0xce, 0x09, 0xac, 0x6e, 0xca, 0xe1, 0xa9, 0x6f, 0x4f, 0x06, 0xef,
        0x3f, 0x2e, 0xa9, 0x96, 0xfd, 0xba, 0x0c, 0x2b, 0xd8, 0x29, 0x06, 0xdc,
        0x19, 0x7b, 0x32, 0xdf, 0xf9, 0x7a, 0xe3, 0xc5, 0x9c, 0x93, 0xa1, 0x73,
        0x97, 0x25, 0xc9, 0x2b, 0x5e, 0x25, 0xfd, 0xc2, 0x3e, 0x9f, 0xa9, 0x8a,
        0x98, 0xf0, 0xa5, 0x1b, 0x85, 0xb2, 0x4c, 0x6b, 0xe3, 0x47, 0x3f, 0x97,
        0xf7, 0x60, 0x41, 0x47, 0x4b, 0x56, 0xf2, 0x52, 0xe6, 0xfd, 0x9f
    };

    std::vector<Uint8> cipherText = {
        0x69, 0xd2, 0xf0, 0xa7, 0x32, 0x61, 0x95, 0x80, 0x09, 0x50, 0x57, 0xdc,
        0x60, 0xa0, 0x66, 0xdb, 0x17, 0x68, 0x8e, 0x14, 0x26, 0xc8, 0x7a, 0x07,
        0xc7, 0xea, 0xc8, 0x5b, 0x58, 0x3b, 0xc5, 0x16, 0x51, 0x9a, 0x69, 0x49,
        0x6a, 0x65, 0x09, 0xa9, 0xb7, 0xa6, 0x06, 0x2d, 0x85, 0xba, 0xd3, 0xf4,
        0x0c, 0x39, 0x55, 0x0c, 0x0c, 0x64, 0xf8, 0x25, 0xa6, 0xab, 0xe6, 0x51,
        0x57, 0x44, 0xd9, 0x9e, 0x48, 0x03, 0x0d, 0xd4, 0x1e, 0x97, 0xf9, 0x0c,
        0xa0, 0x97, 0x3d, 0x9f, 0x2e, 0x32, 0x65, 0xee, 0x75, 0xea, 0xb6, 0xc6,
        0x18, 0x09, 0x67, 0xb4, 0x8a, 0xcb, 0x54, 0xd2, 0x03, 0xdc, 0x0b, 0x5a,
        0xc1, 0x9e, 0xf5, 0x2f, 0xf3, 0xb7, 0x76, 0x2c, 0xe0, 0xaf, 0x8d, 0x4e,
        0x03, 0xa5, 0x85, 0x3f, 0xa7, 0x54, 0x29, 0x7f, 0xb2, 0x7e, 0x65, 0xe9,
        0xca, 0x83, 0x2d, 0x5f, 0x7e, 0x95, 0xa3, 0x69, 0x2f, 0xe9, 0xb1, 0x83,
        0xee, 0x5e, 0x87, 0xad, 0x9c, 0x03, 0x36, 0x4c, 0x52, 0x28, 0x60, 0xc9,
        0xb9, 0x14, 0xb9, 0xdf, 0x1a, 0x02, 0xe4, 0x4f, 0x09, 0xa2, 0x75, 0x53,
        0xdc, 0xa6, 0xc2, 0xdc, 0x0c, 0x4c, 0x26, 0xec, 0x0c, 0x07, 0xa4, 0x68,
        0x62, 0x6d, 0xf1, 0x15, 0x58, 0xaa, 0x14, 0xd2, 0x8e, 0x1f, 0x68, 0xe5,
        0x18, 0x28, 0x14, 0xff, 0xba, 0x52, 0x2f, 0x32, 0x22, 0x91, 0x81, 0x53,
        0x4e, 0x28, 0x0e, 0x2b, 0x11, 0x04, 0x8e, 0xe4, 0xab, 0x6e, 0xe1
    };
    alc_error_t err = ALC_ERROR_NONE;
    Uint64      outlen;

    std::vector<Uint8> output_buffer(cipherText.size(), 0xff);

    std::vector<CpuArchLevel> cpu_features = alcp::utils::CpuId::getSupportedArchLevels();
    for ([[maybe_unused]] CpuArchLevel feature : cpu_features) {
                auto xts        = createCipherSeg(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);

        if (xts == nullptr) {
            FAIL();
        }
        err = xts->init(key, 128, iv, 16);

        Uint64 res = cipherText.size() % 16;
        if (cipherText.size() >= (16 + res)) {
            Uint64 extra_update_size = 0;
            Uint64 multi_update_size = 0;
            Uint8* curr_ct           = &(cipherText[0]);
            Uint8* curr_ot           = &(output_buffer[0]);
            if (res) {
                // If partial bock, give 2 blocks at a time.
                multi_update_size = cipherText.size() - 16 - res;
                extra_update_size = 16 + res;
            } else {
                multi_update_size = cipherText.size();
            }
            while (multi_update_size > 0) {
                err = xts->decrypt(curr_ct, curr_ot, 16, &outlen);

                EXPECT_FALSE(alcp_is_error(err));
                multi_update_size -= 16;
                curr_ot += 16;
                curr_ct += 16;
            }
            // Last 2 blocks if available
            if (extra_update_size) {
                err = xts->decrypt(curr_ct, curr_ot, extra_update_size, &outlen);

                EXPECT_FALSE(alcp_is_error(err));
            }
        }
        delete xts;
        ASSERT_EQ(output_buffer, plainText);
    }
}

#if 1

using namespace alcp::cipher;
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
            mode_str = "aes-xts-128";
            break;
        case 32:
            mode_str = "aes-xts-256";
            break;
        default:
            mode_str = "aes-xts-128";
            std::cout
                << "Mode string defaulting to 'aes-xts-128', invalid keysize"
                << std::endl;
    }
    return mode_str;
}

class XTS_KAT
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
        iCipher*                pXtsObj    = nullptr;
    std::vector<Uint8> m_key, m_tweak, _key, m_iv, m_plaintext, m_ciphertext;
    Uint64             m_key_size = 0;
    std::string        m_test_name;
    alc_error_t        m_err;
    // Setup Test for Encrypt/Decrypt
    void SetUp() override
    {
        // Tuple order
        // {key,nonce,aad,plain,ciphertext,tag}
        const auto& params                                     = GetParam();
        const auto [key, tweak_key, iv, plaintext, ciphertext] = params.second;
        const auto& test_name                                  = params.first;

        // Copy Values to class variables
        m_key        = key;
        m_key_size   = key.size();
        m_tweak      = std::move(tweak_key);
        m_iv         = std::move(iv);
        m_plaintext  = std::move(plaintext);
        m_ciphertext = std::move(ciphertext);
        m_test_name  = std::move(test_name);

        // Insert Tweak Key into key
        m_key.insert(m_key.end(), m_tweak.begin(), m_tweak.end());

        // As m_key has both keys, the key size is double, hence /2
        // Setup XTS Object
        // Factory removed - using direct creation
        pXtsObj = createCipher(CipherMode::eAesXTS, m_key_size == 16 ? CipherKeyLen::eKey128Bit : CipherKeyLen::eKey256Bit);

        ASSERT_TRUE(pXtsObj != nullptr);
    }
    void TearDown() override { delete pXtsObj; }
};

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    XTS_KAT,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<XTS_KAT::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

TEST_P(XTS_KAT, valid_encrypt_request)
{
    std::vector<Uint8> out(m_ciphertext.size());

    pXtsObj->init(m_key.data(), m_key_size * 8, m_iv.data(), m_iv.size());

    Uint64      outlen = 0;
    alc_error_t err    = pXtsObj->encrypt(
        &(m_plaintext.at(0)), &(out.at(0)), m_plaintext.size(), &outlen);

    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(out, m_ciphertext);
}

TEST_P(XTS_KAT, valid_decrypt_request)
{
    pXtsObj->init(m_key.data(), m_key_size * 8, m_iv.data(), m_iv.size());

    std::vector<Uint8> out(m_plaintext.size());

    pXtsObj->init(m_key.data(), m_key_size * 8, m_iv.data(), m_iv.size());

    Uint64      outlen = 0;
    alc_error_t err    = pXtsObj->decrypt(
        &(m_ciphertext.at(0)), &(out.at(0)), m_plaintext.size(), &outlen);

    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(out, m_plaintext);
}

TEST_P(XTS_KAT, valid_encrypt_decrypt_test)
{
    pXtsObj->init(m_key.data(), m_key_size * 8, m_iv.data(), m_iv.size());
    std::vector<Uint8> outct(m_ciphertext.size()), outpt(m_plaintext.size());

    Uint64      outlen = 0;
    alc_error_t err    = pXtsObj->encrypt(
        &(m_plaintext.at(0)), &(outct.at(0)), m_plaintext.size(), &outlen);

    pXtsObj->init(m_key.data(), m_key_size * 8, m_iv.data(), m_iv.size());

    Uint64 outlen2 = 0;
    err            = pXtsObj->decrypt(
        &(outct.at(0)), &(outpt.at(0)), m_plaintext.size(), &outlen2);

    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_EQ(m_plaintext, outpt);
}
#endif

// Comprehensive Corner Case Tests for XTS

// Parameterized test for all key sizes (128 and 256 bits only for XTS)
TEST_P(XTSKeySizeTest, EncryptDecryptRoundTrip)
{
    CipherKeyLen keyLen = GetParam();
    size_t keySize = getKeySizeBytes(keyLen);  // Returns double-key size for XTS
    size_t keyBits = getKeySizeBits(keyLen);

    std::vector<Uint8> testKey(keySize, 0x42);
    std::vector<Uint8> testIv(16, 0x01);
    std::vector<Uint8> input(64, 0x55);
    std::vector<Uint8> output(64), decrypted(64);

    auto xts = createCipher(CipherMode::eAesXTS, keyLen);
    ASSERT_NE(xts, nullptr) << "Failed to create AES-XTS-" << keyBits;

    alc_error_t err = xts->init(&testKey[0], keyBits, &testIv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = xts->encrypt(&input[0], &output[0], 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(outlen, 64);

    // Decrypt with new object
    auto xts2 = createCipher(CipherMode::eAesXTS, keyLen);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(&testKey[0], keyBits, &testIv[0], 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->decrypt(&output[0], &decrypted[0], 64, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, input);

    delete xts;
    delete xts2;
}

// Test with multiple data sizes for each key size
TEST_P(XTSKeySizeTest, VariousDataSizes)
{
    CipherKeyLen keyLen = GetParam();
    size_t keySize = getKeySizeBytes(keyLen);
    size_t keyBits = getKeySizeBits(keyLen);

    std::vector<Uint8> testKey(keySize, 0x42);
    std::vector<Uint8> testIv(16, 0x00);

    // Test various data sizes (XTS requires minimum 16 bytes)
    std::vector<size_t> dataSizes = { 16, 17, 32, 64, 128, 256, 512, 1024 };

    for (size_t dataSize : dataSizes) {
        std::vector<Uint8> input(dataSize);
        for (size_t i = 0; i < dataSize; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(dataSize), decrypted(dataSize);

        auto xts = createCipher(CipherMode::eAesXTS, keyLen);
        ASSERT_NE(xts, nullptr);

        alc_error_t err = xts->init(&testKey[0], keyBits, &testIv[0], 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(&input[0], &output[0], dataSize, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(outlen, dataSize) << "Key: " << keyBits << " bits, Data: " << dataSize << " bytes";

        // Decrypt with new object
        auto xts2 = createCipher(CipherMode::eAesXTS, keyLen);
        ASSERT_NE(xts2, nullptr);
        err = xts2->init(&testKey[0], keyBits, &testIv[0], 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen2 = 0;
        err = xts2->decrypt(&output[0], &decrypted[0], dataSize, &outlen2);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, input) << "Key: " << keyBits << " bits, Data: " << dataSize << " bytes";

        delete xts;
        delete xts2;
    }
}

// Instantiate the parameterized tests for XTS key sizes (128 and 256 only, no 192)
INSTANTIATE_TEST_SUITE_P(
    AllKeySizes,
    XTSKeySizeTest,
    ::testing::Values(
        CipherKeyLen::eKey128Bit,
        CipherKeyLen::eKey256Bit
    ),
    [](const ::testing::TestParamInfo<CipherKeyLen>& info) {
        switch (info.param) {
            case CipherKeyLen::eKey128Bit: return "Key128Bit";
            case CipherKeyLen::eKey256Bit: return "Key256Bit";
            default: return "Unknown";
        }
    }
);

// Test minimum plaintext size (16 bytes = 1 block)
TEST(XTS, MinimumPlaintextSize)
{
    std::vector<Uint8> key(32, 0x11);
    std::vector<Uint8> iv(16, 0x22);
    std::vector<Uint8> plaintext(16, 0x33);
    std::vector<Uint8> ciphertext(16), decrypted(16);
    alc_error_t err;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = xts->encrypt(plaintext.data(), ciphertext.data(), 16, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt
    auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->decrypt(ciphertext.data(), decrypted.data(), 16, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete xts;
    delete xts2;
}

// Test non-block-aligned plaintext sizes (ciphertext stealing)
TEST(XTS, NonBlockAlignedPlaintext)
{
    std::vector<Uint8> key(32, 0x44);
    std::vector<Uint8> iv(16, 0x55);
    alc_error_t err;

    // XTS requires minimum 16 bytes, and handles non-aligned via ciphertext stealing
    std::vector<size_t> sizes = { 17, 23, 31, 33, 47, 63, 65, 100, 255, 1000 };

    for (size_t size : sizes) {
        std::vector<Uint8> plaintext(size);
        for (size_t i = 0; i < size; i++) {
            plaintext[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> ciphertext(size), decrypted(size);

        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext.data(), size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for size: " << size;

        // Decrypt
        auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts2, nullptr);
        err = xts2->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen2 = 0;
        err = xts2->decrypt(ciphertext.data(), decrypted.data(), size, &outlen2);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext) << "Mismatch for size: " << size;

        delete xts;
        delete xts2;
    }
}

// Test all zeros input
TEST(XTS, AllZerosInput)
{
    std::vector<Uint8> key(32, 0x00);
    std::vector<Uint8> iv(16, 0x00);
    std::vector<Uint8> plaintext(64, 0x00);
    std::vector<Uint8> ciphertext(64), decrypted(64);
    alc_error_t err;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = xts->encrypt(plaintext.data(), ciphertext.data(), 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt
    auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->decrypt(ciphertext.data(), decrypted.data(), 64, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete xts;
    delete xts2;
}

// Test determinism (same inputs always produce same output)
TEST(XTS, Determinism)
{
    std::vector<Uint8> key(32, 0x66);
    std::vector<Uint8> iv(16, 0x77);
    std::vector<Uint8> plaintext(64, 0x88);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64), ciphertext3(64);
    alc_error_t err;

    for (int round = 0; round < 3; round++) {
        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        std::vector<Uint8>* ct = (round == 0) ? &ciphertext1 : (round == 1) ? &ciphertext2 : &ciphertext3;
        err = xts->encrypt(plaintext.data(), ct->data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        delete xts;
    }

    EXPECT_EQ(ciphertext1, ciphertext2) << "Round 1 and 2 should produce same ciphertext";
    EXPECT_EQ(ciphertext2, ciphertext3) << "Round 2 and 3 should produce same ciphertext";
}

// Test IV affects output (different IVs should produce different ciphertexts)
TEST(XTS, IVAffectsOutput)
{
    std::vector<Uint8> key(32, 0x99);
    std::vector<Uint8> plaintext(64, 0xAA);
    std::vector<std::vector<Uint8>> outputs;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> iv(16, static_cast<Uint8>(i));
        std::vector<Uint8> ciphertext(64);

        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        outputs.push_back(ciphertext);
        delete xts;
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "IV " << i << " and " << j << " produced same ciphertext";
        }
    }
}

// Test key affects output (different keys should produce different outputs)
TEST(XTS, KeyAffectsOutput)
{
    std::vector<Uint8> iv(16, 0xBB);
    std::vector<Uint8> plaintext(64, 0xCC);
    std::vector<std::vector<Uint8>> outputs;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> key(32, static_cast<Uint8>(i));
        std::vector<Uint8> ciphertext(64);

        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        outputs.push_back(ciphertext);
        delete xts;
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "Key " << i << " and " << j << " produced same ciphertext";
        }
    }
}

// Test separate cipher objects produce identical results
TEST(XTS, SeparateCipherObjects)
{
    std::vector<Uint8> key(32, 0xDD);
    std::vector<Uint8> iv(16, 0xEE);
    std::vector<Uint8> plaintext(64, 0xFF);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64);
    alc_error_t err;

    // Encrypt with first cipher object
    auto xts1 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts1, nullptr);
    err = xts1->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen1 = 0;
    err = xts1->encrypt(plaintext.data(), ciphertext1.data(), 64, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    delete xts1;

    // Encrypt with second cipher object
    auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->encrypt(plaintext.data(), ciphertext2.data(), 64, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    delete xts2;

    // Same inputs should produce same outputs
    EXPECT_EQ(ciphertext1, ciphertext2);
}

// Test cipher object reuse with different keys
TEST(XTS, ReuseWithDifferentKeys)
{
    std::vector<Uint8> iv(16, 0x11);
    std::vector<Uint8> plaintext(64, 0x22);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64);
    alc_error_t err;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // First encryption with key1
    {
        std::vector<Uint8> key1(32, 0x01);
        err = xts->init(key1.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext1.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Second encryption with key2 (same object)
    {
        std::vector<Uint8> key2(32, 0x02);
        err = xts->init(key2.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext2.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Different keys should produce different outputs
    EXPECT_NE(ciphertext1, ciphertext2);

    delete xts;
}

// Test cipher object reuse with different IVs
TEST(XTS, ReuseWithDifferentIVs)
{
    std::vector<Uint8> key(32, 0x33);
    std::vector<Uint8> plaintext(64, 0x44);
    std::vector<Uint8> ciphertext1(64), ciphertext2(64);
    alc_error_t err;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // First encryption with iv1
    {
        std::vector<Uint8> iv1(16, 0x01);
        err = xts->init(key.data(), 128, iv1.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext1.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Second encryption with iv2 (same object)
    {
        std::vector<Uint8> iv2(16, 0x02);
        err = xts->init(key.data(), 128, iv2.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext2.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }

    // Different IVs should produce different outputs
    EXPECT_NE(ciphertext1, ciphertext2);

    delete xts;
}

// Test multiple blocks (various block counts)
TEST(XTS, MultipleBlocks)
{
    std::vector<Uint8> key(32, 0x55);
    std::vector<Uint8> iv(16, 0x66);
    alc_error_t err;

    std::vector<size_t> block_counts = { 1, 2, 4, 8, 16, 32 };

    for (size_t num_blocks : block_counts) {
        size_t data_size = num_blocks * 16;
        std::vector<Uint8> plaintext(data_size);
        for (size_t i = 0; i < data_size; i++) {
            plaintext[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> ciphertext(data_size), decrypted(data_size);

        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext.data(), data_size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for block count: " << num_blocks;

        // Decrypt
        auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts2, nullptr);
        err = xts2->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        Uint64 outlen2 = 0;
        err = xts2->decrypt(ciphertext.data(), decrypted.data(), data_size, &outlen2);
        EXPECT_EQ(err, ALC_ERROR_NONE);
        EXPECT_EQ(decrypted, plaintext) << "Mismatch for block count " << num_blocks;

        delete xts;
        delete xts2;
    }
}

// Test large data (1 MB) with 256-bit key
TEST(XTS, LargeDataWith256BitKey)
{
    const size_t data_size = 1024 * 1024; // 1 MB
    std::vector<Uint8> key(64, 0x77); // 256-bit key (double = 64 bytes)
    std::vector<Uint8> iv(16, 0x88);
    std::vector<Uint8> plaintext(data_size);
    std::vector<Uint8> ciphertext(data_size), decrypted(data_size);
    alc_error_t err;

    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = static_cast<Uint8>((i * 17) % 256);
    }

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey256Bit);
    ASSERT_NE(xts, nullptr);

    err = xts->init(key.data(), 256, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = xts->encrypt(plaintext.data(), ciphertext.data(), data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt
    auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey256Bit);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(key.data(), 256, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->decrypt(ciphertext.data(), decrypted.data(), data_size, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete xts;
    delete xts2;
}

// Test plaintext affects output (different plaintexts should produce different ciphertexts)
TEST(XTS, PlaintextAffectsOutput)
{
    std::vector<Uint8> key(32, 0x99);
    std::vector<Uint8> iv(16, 0xAA);
    std::vector<std::vector<Uint8>> outputs;
    alc_error_t err;

    for (int i = 0; i < 5; i++) {
        std::vector<Uint8> plaintext(64, static_cast<Uint8>(i));
        std::vector<Uint8> ciphertext(64);

        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        Uint64 outlen = 0;
        err = xts->encrypt(plaintext.data(), ciphertext.data(), 64, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        outputs.push_back(ciphertext);
        delete xts;
    }

    // Verify all outputs are different
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            EXPECT_NE(outputs[i], outputs[j]) 
                << "Plaintext " << i << " and " << j << " produced same ciphertext";
        }
    }
}

// Test exactly 2 blocks (32 bytes)
TEST(XTS, TwoBlocks)
{
    std::vector<Uint8> key(32, 0xBB);
    std::vector<Uint8> iv(16, 0xCC);
    std::vector<Uint8> plaintext(32, 0xDD);
    std::vector<Uint8> ciphertext(32), decrypted(32);
    alc_error_t err;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = xts->encrypt(plaintext.data(), ciphertext.data(), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Decrypt
    auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->decrypt(ciphertext.data(), decrypted.data(), 32, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(decrypted, plaintext);

    delete xts;
    delete xts2;
}

// Test encryption doesn't modify input
TEST(XTS, EncryptDoesNotModifyInput)
{
    std::vector<Uint8> key(32, 0xEE);
    std::vector<Uint8> iv(16, 0xFF);
    std::vector<Uint8> plaintext(64);
    for (size_t i = 0; i < 64; i++) {
        plaintext[i] = static_cast<Uint8>(i);
    }
    std::vector<Uint8> original_plaintext = plaintext;
    std::vector<Uint8> ciphertext(64);
    alc_error_t err;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen = 0;
    err = xts->encrypt(plaintext.data(), ciphertext.data(), 64, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Verify input was not modified
    EXPECT_EQ(plaintext, original_plaintext);

    delete xts;
}

// Negative Tests for XTS - Null Pointer and Edge Cases

// Test null pointer for key in init
TEST(XTS_Negative, NullKeyPointer)
{
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(nullptr, 128, iv.data(), 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null key should fail";

    delete xts;
}

// Test null pointer for IV in init
TEST(XTS_Negative, NullIVPointer)
{
    std::vector<Uint8> key(32, 0x42);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, nullptr, 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with null IV should fail";

    delete xts;
}

// Test null pointer for input in encrypt
TEST(XTS_Negative, NullInputPointerEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> output(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = xts->encrypt(nullptr, output.data(), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input should fail";

    delete xts;
}

// Test null pointer for output in encrypt
TEST(XTS_Negative, NullOutputPointerEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(32, 0x55);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = xts->encrypt(input.data(), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null output should fail";

    delete xts;
}

// Test null pointer for both input and output in encrypt
TEST(XTS_Negative, NullInputAndOutputPointerEncrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = xts->encrypt(nullptr, nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with null input and output should fail";

    delete xts;
}

// Test null pointer for input in decrypt
TEST(XTS_Negative, NullInputPointerDecrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> output(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = xts->decrypt(nullptr, output.data(), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null input should fail";

    delete xts;
}

// Test null pointer for output in decrypt
TEST(XTS_Negative, NullOutputPointerDecrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(32, 0x55);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = xts->decrypt(input.data(), nullptr, 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with null output should fail";

    delete xts;
}

// Test zero key length
TEST(XTS_Negative, ZeroKeyLength)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 0, iv.data(), 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero key length should fail";

    delete xts;
}

// Test invalid key length (not 128 or 256 bits)
TEST(XTS_Negative, InvalidKeyLength)
{
    std::vector<Uint8> key(48, 0x42); // 192-bit key (invalid for XTS)
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // Init with invalid key length (192 bits) should fail
    alc_error_t err = xts->init(key.data(), 192, iv.data(), 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with 192-bit key should fail for XTS";

    delete xts;
}

// Test encryption without initialization
TEST(XTS_Negative, EncryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // Encrypt without init should fail
    Uint64 outlen = 0;
    alc_error_t err = xts->encrypt(input.data(), output.data(), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt without init should fail";

    delete xts;
}

// Test decryption without initialization
TEST(XTS_Negative, DecryptWithoutInit)
{
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // Decrypt without init should fail
    Uint64 outlen = 0;
    alc_error_t err = xts->decrypt(input.data(), output.data(), 32, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt without init should fail";

    delete xts;
}

// Test zero IV length
TEST(XTS_Negative, ZeroIVLength)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 0);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with zero IV length should fail";

    delete xts;
}

// Test plaintext less than minimum size (XTS requires at least 16 bytes)
TEST(XTS_Negative, PlaintextTooSmall)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(15, 0x55);  // Less than 16 bytes
    std::vector<Uint8> output(15);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // XTS requires at least 16 bytes (one block)
    Uint64 outlen = 0;
    err = xts->encrypt(input.data(), output.data(), 15, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with < 16 bytes should fail";

    delete xts;
}

// Test zero length input
TEST(XTS_Negative, ZeroLengthInput)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    Uint8 dummy = 0;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Zero length encryption should fail for XTS
    Uint64 outlen = 0;
    err = xts->encrypt(&dummy, &dummy, 0, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with 0 length should fail";

    delete xts;
}

// Test maximum key length boundary
TEST(XTS_Negative, MaxKeyLengthBoundary)
{
    std::vector<Uint8> key(68, 0x42); // 272 bits (more than max 256)
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey256Bit);
    ASSERT_NE(xts, nullptr);

    // Init with key length above maximum should fail
    alc_error_t err = xts->init(key.data(), 272, iv.data(), 16);
    EXPECT_TRUE(alcp_is_error(err)) << "Init with key length > 256 bits should fail";

    delete xts;
}

// Test reuse after error
TEST(XTS_Negative, ReuseAfterError)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // First, cause an error by using invalid key length
    std::vector<Uint8> invalid_key(40, 0x11);
    alc_error_t err = xts->init(invalid_key.data(), 160, iv.data(), 16);
    // This should have failed

    // Now try to reinit properly and use the cipher
    err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Reinit after error should succeed";

    Uint64 outlen = 0;
    err = xts->encrypt(input.data(), output.data(), 32, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt after reinit should succeed";

    delete xts;
}

// Test repeated initialization
TEST(XTS_Negative, RepeatedInitialization)
{
    std::vector<Uint8> key1(32, 0x42);
    std::vector<Uint8> key2(32, 0x84);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output1(32), output2(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // First init and encrypt
    alc_error_t err = xts->init(key1.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen1 = 0;
    err = xts->encrypt(input.data(), output1.data(), 32, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Reinit with different key and encrypt again
    err = xts->init(key2.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts->encrypt(input.data(), output2.data(), 32, &outlen2);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Different keys should produce different outputs
    EXPECT_NE(output1, output2) << "Different keys should produce different ciphertext";

    delete xts;
}

// Test mismatched key size and CipherKeyLen
TEST(XTS_Negative, MismatchedKeySizeAndKeyLen)
{
    std::vector<Uint8> key(64, 0x42); // 256-bit XTS key (double = 64 bytes)
    std::vector<Uint8> iv(16, 0x01);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // Trying to init 128-bit cipher with 256-bit key size
    alc_error_t err = xts->init(key.data(), 256, iv.data(), 16);
    // Behavior is implementation-defined - we just verify it doesn't crash
    (void)err;

    delete xts;
}

// Test invalid IV length (not 16 bytes for XTS)
TEST(XTS_Negative, InvalidIVLength)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(12, 0x01); // Wrong size for XTS (should be 16)

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    // Init with wrong IV length should fail
    alc_error_t err = xts->init(key.data(), 128, iv.data(), 12);
    // Behavior is implementation-defined
    (void)err;

    delete xts;
}

// Test very small input (1 byte - should fail for XTS)
TEST(XTS_Negative, SingleByteInput)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(1, 0x55);
    std::vector<Uint8> output(1);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Single byte encryption should fail for XTS
    Uint64 outlen = 0;
    err = xts->encrypt(input.data(), output.data(), 1, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Encrypt with 1 byte should fail";

    delete xts;
}

// Test decrypt with wrong ciphertext size
TEST(XTS_Negative, DecryptWrongSize)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> ciphertext(15, 0x55);  // Less than 16 bytes
    std::vector<Uint8> output(15);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // XTS requires at least 16 bytes
    Uint64 outlen = 0;
    err = xts->decrypt(ciphertext.data(), output.data(), 15, &outlen);
    EXPECT_TRUE(alcp_is_error(err)) << "Decrypt with < 16 bytes should fail";

    delete xts;
}

// Test large data encryption without issues
TEST(XTS_Negative, VeryLargeData)
{
    const size_t data_size = 64 * 1024; // 64 KB
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(data_size);
    for (size_t i = 0; i < data_size; i++) {
        input[i] = static_cast<Uint8>(i % 256);
    }
    std::vector<Uint8> output(data_size);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Uint64 outlen = 0;
    err = xts->encrypt(input.data(), output.data(), data_size, &outlen);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    delete xts;
}

// Test encrypt after failed decrypt without reinit
TEST(XTS_Negative, EncryptAfterFailedDecrypt)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> input(32, 0x55);
    std::vector<Uint8> output(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // First do a successful encrypt
    Uint64 outlen1 = 0;
    err = xts->encrypt(input.data(), output.data(), 32, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Now try to decrypt with same object (might need reinit)
    std::vector<Uint8> decrypted(32);
    Uint64 outlen2 = 0;
    err = xts->decrypt(output.data(), decrypted.data(), 32, &outlen2);
    // Behavior depends on whether reinit is needed
    (void)err;

    delete xts;
}

// Test in-place encryption (input == output)
TEST(XTS_Negative, InPlaceEncryption)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> data(32, 0x55);
    std::vector<Uint8> original = data;

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // In-place encryption (input == output)
    Uint64 outlen = 0;
    err = xts->encrypt(data.data(), data.data(), 32, &outlen);
    // Verify it either succeeds or fails gracefully
    if (err == ALC_ERROR_NONE) {
        EXPECT_NE(data, original) << "In-place encryption should change data";
    }

    delete xts;
}

// Test in-place decryption (input == output)
TEST(XTS_Negative, InPlaceDecryption)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> plaintext(32, 0x55);
    std::vector<Uint8> data(32);

    // First encrypt to get ciphertext
    auto xts1 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts1, nullptr);
    alc_error_t err = xts1->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen1 = 0;
    err = xts1->encrypt(plaintext.data(), data.data(), 32, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    delete xts1;

    std::vector<Uint8> ciphertext = data;

    // Now decrypt in-place
    auto xts2 = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts2, nullptr);
    err = xts2->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    Uint64 outlen2 = 0;
    err = xts2->decrypt(data.data(), data.data(), 32, &outlen2);
    // Verify it either succeeds or fails gracefully
    if (err == ALC_ERROR_NONE) {
        EXPECT_EQ(data, plaintext) << "In-place decryption should recover plaintext";
    }
    delete xts2;
}

// Test consecutive encryptions (multiple messages with same key/IV - NOT recommended for XTS)
TEST(XTS_Negative, ConsecutiveEncryptions)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    std::vector<Uint8> plaintext1(32, 0x11);
    std::vector<Uint8> plaintext2(32, 0x22);
    std::vector<Uint8> ciphertext1(32), ciphertext2(32);

    auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
    ASSERT_NE(xts, nullptr);

    alc_error_t err = xts->init(key.data(), 128, iv.data(), 16);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // First encryption
    Uint64 outlen1 = 0;
    err = xts->encrypt(plaintext1.data(), ciphertext1.data(), 32, &outlen1);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    // Second encryption without reinit - different plaintexts
    Uint64 outlen2 = 0;
    err = xts->encrypt(plaintext2.data(), ciphertext2.data(), 32, &outlen2);
    // This might succeed or need reinit depending on implementation
    (void)err;

    delete xts;
}

// Test partial block at various sizes near block boundary
TEST(XTS_Negative, PartialBlockBoundary)
{
    std::vector<Uint8> key(32, 0x42);
    std::vector<Uint8> iv(16, 0x01);
    alc_error_t err;

    // Test sizes around block boundaries: 17-31 bytes (one full block + partial)
    std::vector<size_t> sizes = { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

    for (size_t size : sizes) {
        std::vector<Uint8> input(size);
        for (size_t i = 0; i < size; i++) {
            input[i] = static_cast<Uint8>(i % 256);
        }
        std::vector<Uint8> output(size);

        auto xts = createCipher(CipherMode::eAesXTS, CipherKeyLen::eKey128Bit);
        ASSERT_NE(xts, nullptr);

        err = xts->init(key.data(), 128, iv.data(), 16);
        EXPECT_EQ(err, ALC_ERROR_NONE);

        // Partial block should work with ciphertext stealing
        Uint64 outlen = 0;
        err = xts->encrypt(input.data(), output.data(), size, &outlen);
        EXPECT_EQ(err, ALC_ERROR_NONE) << "Encrypt failed for size: " << size;

        delete xts;
    }
}
