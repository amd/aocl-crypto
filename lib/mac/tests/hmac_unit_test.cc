/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.h"
#include "alcp/types.h"
#include "digest/sha2_512.hh"
#include "mac/hmac.hh"
#include "gtest/gtest.h"

// TODO: Remove DEBUG Once capi is complete
// #define DEBUG 1

// TODO: Add these helper functions to a common utility file outside of
// compat/integration testing
std::string
parseBytesToHexStr(const Uint8* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        // Convert int to hex
        il << std::hex << charRep;
        std::string ilStr = il.str();
        // 01 will be 0x1 so we need to make it 0x01
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    // return "something";
    return ss.str();
}

inline std::string
parseBytesToHexStr(std::vector<Uint8> bytes)
{
    return parseBytesToHexStr(&(bytes.at(0)), bytes.size());
}

Uint8
parseHexToNum(const unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

std::vector<Uint8>
parseHexStrToBin(const std::string in)
{
    std::vector<Uint8> vector;
    int                len = in.size();
    int                ind = 0;

    for (int i = 0; i < len; i += 2) {
        Uint8 val =
            parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
        vector.push_back(val);
        ind += 2;
    }
    return vector;
}

typedef std::tuple<std::string, // key
                   std::string, // ciphertext
                   std::string  // mac
                   >
                                                 param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

// clang-format off

//Order is key,ciphertext,mac
//B: Input Block Size
known_answer_map_t KATSHA256Dataset {
    {
        "SHA256_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"
        }

    },
    {
        "SHA256_KEYLEN_LT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E",
            "A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790"

        }
    },
    {
        "SHA256_KEYLEN_GT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
            "3132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D"
        }
    },
    {
        "SHA224_KEYLEN_LT_B",
        {
            "cf127579d6b2b0b3a607a6314bf8733061c32a043593195527544f8753c65c7a70d05874f718275b88d0fa288bd3199813f0",
            "fa7e18cc5443981f22c0a5aba2117915f89c7781c34f61f9f429cb13e0fcd0ce947103be684ca869d7f125f08d27b3f2c21d59adc7ab1b66ded96f0b4fa5f018b80156b7a51ca62b60e2a66e0bc69419ebbf178507907630f24d0862e51bec101037f900323af82e689b116f427584541c8a9a51ac89da1ed78c7f5ec9e52a7f",
            "354f87e98d276446836ea0430ce4529272a017c290039a9dfea4349b"

        }
    },
        {
        "SHA384_KEYLEN_LT_B",
        {
            "5eab0dfa27311260d7bddcf77112b23d8b42eb7a5d72a5a318e1ba7e7927f0079dbb701317b87a3340e156dbcee28ec3a8d9",
            "f41380123ccbec4c527b425652641191e90a17d45e2f6206cf01b5edbe932d41cc8a2405c3195617da2f420535eed422ac6040d9cd65314224f023f3ba730d19db9844c71c329c8d9d73d04d8c5f244aea80488292dc803e772402e72d2e9f1baba5a6004f0006d822b0b2d65e9e4a302dd4f776b47a972250051a701fab2b70",
            "7cf5a06156ad3de5405a5d261de90275f9bb36de45667f84d08fbcb308ca8f53a419b07deab3b5f8ea231c5b036f8875"

        }
        
    },
       {"SHA512_KEYLEN_LT_B",
         {
            "57c2eb677b5093b9e829ea4babb50bde55d0ad59fec34a618973802b2ad9b78e26b2045dda784df3ff90ae0f2cc51ce39cf54867320ac6f3ba2c6f0d72360480c96614ae66581f266c35fb79fd28774afd113fa5187eff9206d7cbe90dd8bf67c844e202",
            "2423dff48b312be864cb3490641f793d2b9fb68a7763b8e298c86f42245e4540eb01ae4d2d4500370b1886f23ca2cf9701704cad5bd21ba87b811daf7a854ea24a56565ced425b35e40e1acbebe03603e35dcf4a100e57218408a1d8dbcc3b99296cfea931efe3ebd8f719a6d9a15487b9ad67eafedf15559ca42445b0f9b42e",
            "33c511e9bc2307c62758df61125a980ee64cefebd90931cb91c13742d4714c06de4003faf3c41c06aefc638ad47b21906e6b104816b72de6269e045a1f4429d4"
        }
       }
};

// clang-format on

class HmacTestFixture
    : public ::testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    alc_mac_info_t                        mac_info;
    std::vector<Uint8>                    cipher_text;
    std::vector<Uint8>                    expected_mac;
    std::vector<Uint8>                    key;
    std::unique_ptr<alcp::mac::Hmac>      p_hmac;
    std::unique_ptr<alcp::digest::Sha256> p_sha256;
    std::unique_ptr<alcp::digest::Sha224> p_sha224;
    std::unique_ptr<alcp::digest::Sha384> p_sha384;
    std::unique_ptr<alcp::digest::Sha512> p_sha512;

  public:
    void setUp(const ParamType& params)
    {
        auto tuple_values = params.second;
        key               = parseHexStrToBin(std::get<0>(tuple_values));
        cipher_text       = parseHexStrToBin(std::get<1>(tuple_values));
        expected_mac      = parseHexStrToBin(std::get<2>(tuple_values));
#ifdef DEBUG
        std::cout << "Key Size is " << key.size() << std::endl;
        std::cout << "CipherText size is " << cipher_text.size() << std::endl;
#endif
        const alc_key_info_t kinfo = { .type     = ALC_KEY_TYPE_SYMMETRIC,
                                       .fmt      = ALC_KEY_FMT_RAW,
                                       .algo     = ALC_KEY_ALG_MAC,
                                       .len_type = ALC_KEY_LEN_128,
                                       .len = static_cast<Uint32>(key.size()),
                                       .key = &key.at(0) };
        mac_info = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_256,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_256,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };
    }
    void setUpHash(std::string test_name)
    {
        size_t      found     = test_name.find("_");
        std::string hash_name = test_name.substr(0, found);
        if (hash_name == "SHA256") {
            p_sha256 = std::make_unique<alcp::digest::Sha256>();
            p_hmac =
                std::make_unique<alcp::mac::Hmac>(mac_info, p_sha256.get());
        } else if (hash_name == "SHA224") {
            p_sha224 = std::make_unique<alcp::digest::Sha224>();
            p_hmac =
                std::make_unique<alcp::mac::Hmac>(mac_info, p_sha224.get());
        } else if (hash_name == "SHA384") {
            p_sha384 = std::make_unique<alcp::digest::Sha384>();
            p_hmac =
                std::make_unique<alcp::mac::Hmac>(mac_info, p_sha384.get());
        } else if (hash_name == "SHA512") {
            p_sha512 = std::make_unique<alcp::digest::Sha512>();
            p_hmac =
                std::make_unique<alcp::mac::Hmac>(mac_info, p_sha512.get());
        }
    }
};

TEST(HmacReliabilityTest, NullKeyNonNullKeyLength)
{

    const alc_key_info_t kinfo = { .type     = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt      = ALC_KEY_FMT_RAW,
                                   .algo     = ALC_KEY_ALG_MAC,
                                   .len_type = ALC_KEY_LEN_128,
                                   .len      = 32,   // Key Size is not zero but
                                   .key      = nullptr }; // Key is null
    const alc_mac_info_t  mac_info = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_256,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_256,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };
    alcp::digest::Sha256 sha256;
    alcp::mac::Hmac      hmac{ mac_info, &sha256 };
    ASSERT_EQ(hmac.getState(), INVALID);
}
TEST(HmacReliabilityTest, NonNullKeyNullKeyLength)
{

    auto key = std::vector<Uint8>(20, 0);

    const alc_key_info_t kinfo = { .type     = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt      = ALC_KEY_FMT_RAW,
                                   .algo     = ALC_KEY_ALG_MAC,
                                   .len_type = ALC_KEY_LEN_128,
                                   .len      = 0, // Key Size is not zero but
                                   .key      = &(key[0]) }; // Key is null
    const alc_mac_info_t  mac_info = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_256,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_256,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };
    alcp::digest::Sha256 sha256;
    alcp::mac::Hmac      hmac(mac_info, &sha256);
    ASSERT_EQ(hmac.getState(), INVALID);
}

TEST(HmacReliabilityTest, NullUpdate)
{
    auto        pos  = KATSHA256Dataset.find("SHA256_KEYLEN_EQ_B");
    param_tuple data = pos->second;

    auto key         = parseHexStrToBin(std::get<0>(data));
    auto cipher_text = parseHexStrToBin(std::get<1>(data));
    auto output_mac  = parseHexStrToBin(std::get<2>(data));

    const alc_key_info_t kinfo = { .type     = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt      = ALC_KEY_FMT_RAW,
                                   .algo     = ALC_KEY_ALG_MAC,
                                   .len_type = ALC_KEY_LEN_128,
                                   .len      = static_cast<Uint32>(
                                       key.size()), // Key Size is not zero but
                                   .key = &(key[0]) }; // Key is null
    const alc_mac_info_t  mac_info = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = ALC_DIGEST_LEN_256,
                    .dt_mode = {.dm_sha2 = ALC_SHA2_256,},
                }
            }
        },
        .mi_keyinfo = kinfo
    };
    alcp::digest::Sha256 sha256;
    alcp::mac::Hmac      hmac(mac_info, &sha256);
    hmac.update(nullptr, 0);
    ASSERT_EQ(hmac.getState(), VALID);
    hmac.update(cipher_text);
    hmac.finalize(nullptr, 0);
    auto mac = std::vector<Uint8>(hmac.getHashSize(), 0);
    hmac.copyHash(&mac.at(0), mac.size());
    EXPECT_EQ(mac, output_mac);
}

TEST_P(HmacTestFixture, HMAC_UPDATE)
{
    const auto params = GetParam();
    setUp(params);
    setUpHash(params.first);

    p_hmac->update(cipher_text);

    p_hmac->finalize(nullptr, 0);

    std::vector<Uint8> mac = std::vector<Uint8>(p_hmac->getHashSize(), 0);
    p_hmac->copyHash(&mac.at(0), mac.size());

    EXPECT_EQ(mac, expected_mac);
}

TEST_P(HmacTestFixture, HMAC_UPDATE_FINALISE)
{
    const auto params = GetParam();

    setUp(params);
    setUpHash(params.first);

    auto block1 = std::vector<Uint8>(
        cipher_text.begin(), cipher_text.begin() + cipher_text.size() / 2);

    auto block2 = std::vector<Uint8>(
        cipher_text.begin() + cipher_text.size() / 2, cipher_text.end());

#ifdef DEBUG
    std::cout << "block1                " << parseBytesToHexStr(block1)
              << std::endl;
    std::cout << "block2                " << parseBytesToHexStr(block2)
              << std::endl;
#endif

    p_hmac->update(block1);
    p_hmac->update(block2);
    p_hmac->finalize(nullptr, 0);

    std::vector<Uint8> mac = std::vector<Uint8>(p_hmac->getHashSize(), 0);
    p_hmac->copyHash(&mac.at(0), mac.size());

    EXPECT_EQ(mac, expected_mac);
}

INSTANTIATE_TEST_SUITE_P(
    HmacTest,
    HmacTestFixture,
    testing::ValuesIn(KATSHA256Dataset),
    [](const testing::TestParamInfo<HmacTestFixture::ParamType>& info) {
        return info.param.first;
    });
