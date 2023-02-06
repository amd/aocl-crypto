/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#include "digest/sha2_384.hh"
#include "digest/sha3.hh"
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
known_answer_map_t KAT_ShaDataset {
    {
        "SHA2_256_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"
        }

    },
    {
        "SHA2_256_KEYLEN_LT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E",
            "A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790"

        }
    },
    {
        "SHA2_256_KEYLEN_LT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
            "3132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D"
        }
    },
    {
        "SHA2_224_KEYLEN_LT_B",
        {
            "cf127579d6b2b0b3a607a6314bf8733061c32a043593195527544f8753c65c7a70d05874f718275b88d0fa288bd3199813f0",
            "fa7e18cc5443981f22c0a5aba2117915f89c7781c34f61f9f429cb13e0fcd0ce947103be684ca869d7f125f08d27b3f2c21d59adc7ab1b66ded96f0b4fa5f018b80156b7a51ca62b60e2a66e0bc69419ebbf178507907630f24d0862e51bec101037f900323af82e689b116f427584541c8a9a51ac89da1ed78c7f5ec9e52a7f",
            "354f87e98d276446836ea0430ce4529272a017c290039a9dfea4349b"

        }
    },
    {
        "SHA2_224_KEYLEN_EQ_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "C7405E3AE058E8CD30B08B4140248581ED174CB34E1224BCC1EFC81B"
        }
    },
    {
        "SHA2_224_KEYLEN_GT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "91C52509E5AF8531601AE6230099D90BEF88AAEFB961F4080ABC014D"
        }
    },
    {
        "SHA2_384_KEYLEN_LT_B",
        {
            "5eab0dfa27311260d7bddcf77112b23d8b42eb7a5d72a5a318e1ba7e7927f0079dbb701317b87a3340e156dbcee28ec3a8d9",
            "f41380123ccbec4c527b425652641191e90a17d45e2f6206cf01b5edbe932d41cc8a2405c3195617da2f420535eed422ac6040d9cd65314224f023f3ba730d19db9844c71c329c8d9d73d04d8c5f244aea80488292dc803e772402e72d2e9f1baba5a6004f0006d822b0b2d65e9e4a302dd4f776b47a972250051a701fab2b70",
            "7cf5a06156ad3de5405a5d261de90275f9bb36de45667f84d08fbcb308ca8f53a419b07deab3b5f8ea231c5b036f8875"

        }
    },
    {
        "SHA2_384_KEYLEN_EQ_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "63C5DAA5E651847CA897C95814AB830BEDEDC7D25E83EEF9195CD45857A37F448947858F5AF50CC2B1B730DDF29671A9"
        }
    },
    {
        "SHA2_384_KEYLEN_GT_B",
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "5B664436DF69B0CA22551231A3F0A3D5B4F97991713CFA84BFF4D0792EFF96C27DCCBBB6F79B65D548B40E8564CEF594"
        }
    },
    {
        "SHA2_512_KEYLEN_LT_B",
         {
            "57c2eb677b5093b9e829ea4babb50bde55d0ad59fec34a618973802b2ad9b78e26b2045dda784df3ff90ae0f2cc51ce39cf54867320ac6f3ba2c6f0d72360480c96614ae66581f266c35fb79fd28774afd113fa5187eff9206d7cbe90dd8bf67c844e202",
            "2423dff48b312be864cb3490641f793d2b9fb68a7763b8e298c86f42245e4540eb01ae4d2d4500370b1886f23ca2cf9701704cad5bd21ba87b811daf7a854ea24a56565ced425b35e40e1acbebe03603e35dcf4a100e57218408a1d8dbcc3b99296cfea931efe3ebd8f719a6d9a15487b9ad67eafedf15559ca42445b0f9b42e",
            "33c511e9bc2307c62758df61125a980ee64cefebd90931cb91c13742d4714c06de4003faf3c41c06aefc638ad47b21906e6b104816b72de6269e045a1f4429d4"
        }
    },
    {
        "SHA2_512_KEYLEN_EQ_B",
         {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "FC25E240658CA785B7A811A8D3F7B4CA48CFA26A8A366BF2CD1F836B05FCB024BD36853081811D6CEA4216EBAD79DA1CFCB95EA4586B8A0CE356596A55FB1347"
        }
    },
    {
        "SHA2_512_KEYLEN_GT_B",
         {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
            "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
            "D93EC8D2DE1AD2A9957CB9B83F14E76AD6B5E0CCE285079A127D3B14BCCB7AA7286D4AC0D4CE64215F2BC9E6870B33D97438BE4AAA20CDA5C5A912B48B8E27F3"
        }
    },
    {
        "SHA3_224_KEYLEN_LT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
            "332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04"
        }
    },
    {
        "SHA3_224_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "d8b733bcf66c644a12323d564e24dcf3fc75f231f3b67968359100c7"
        }
    },
    {
        "SHA3_224_KEYLEN_GT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab",
            "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e",
            "078695eecc227c636ad31d063a15dd05a7e819a66ec6d8de1e193e59"
        }
    },
    {
        "SHA3_256_KEYLEN_LT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
            "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"
        }
    },
    {
        "SHA3_256_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa"
        }
    },
    {
        "SHA3_256_KEYLEN_GT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7",
            "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e",
            "9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258"
        }
    },
    {
        "SHA3_384_KEYLEN_LT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
            "d588a3c51f3f2d906e8298c1199aa8ff6296218127f6b38a90b6afe2c5617725bc99987f79b22a557b6520db710b7f42"
        }
    },
    {
        "SHA3_384_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364656667",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "a27d24b592e8c8cbf6d4ce6fc5bf62d8fc98bf2d486640d9eb8099e24047837f5f3bffbe92dcce90b4ed5b1e7e44fa90"
        }
    },
    {
        "SHA3_384_KEYLEN_GT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091929394959697",
            "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e",
            "e5ae4c739f455279368ebf36d4f5354c95aa184c899d3870e460ebc288ef1f9470053f73f7c6da2a71bcaec38ce7d6ac"
        }
    },
    {
        "SHA3_512_KEYLEN_LT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
            "4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196"
        }
    },
    {
        "SHA3_512_KEYLEN_EQ_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647",
            "53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e",
            "544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da"
        }
    },
    {
        "SHA3_512_KEYLEN_GT_B",
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687",
            "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e",
            "5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915"
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
    std::unique_ptr<alcp::digest::Sha3>   p_sha3;

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
        size_t      type_index = test_name.find("_");
        std::string sha_type   = test_name.substr(0, type_index);

        size_t      algo_index = test_name.find("_");
        std::string hash_name =
            test_name.substr(type_index + 1, algo_index - 1);

        if (sha_type == "SHA2") {
            if (hash_name == "256") {
                p_sha256 = std::make_unique<alcp::digest::Sha256>();
                p_hmac   = std::make_unique<alcp::mac::Hmac>(
                    key.front(), key.size(), *p_sha256);
            } else if (hash_name == "224") {
                p_sha224 = std::make_unique<alcp::digest::Sha224>();
                p_hmac   = std::make_unique<alcp::mac::Hmac>(
                    key.front(), key.size(), *p_sha224);
            } else if (hash_name == "384") {
                p_sha384 = std::make_unique<alcp::digest::Sha384>();
                p_hmac   = std::make_unique<alcp::mac::Hmac>(
                    key.front(), key.size(), *p_sha384);
            } else if (hash_name == "512") {
                p_sha512 = std::make_unique<alcp::digest::Sha512>();
                p_hmac   = std::make_unique<alcp::mac::Hmac>(
                    key.front(), key.size(), *p_sha512);
            }
        } else if (sha_type == "SHA3") {
            mac_info.mi_algoinfo.hmac.hmac_digest.dt_type =
                ALC_DIGEST_TYPE_SHA3;
            if (hash_name == "224") {
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_len =
                    ALC_DIGEST_LEN_224;
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 =
                    ALC_SHA3_224;
            } else if (hash_name == "256") {
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_len =
                    ALC_DIGEST_LEN_256;
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 =
                    ALC_SHA3_256;
            } else if (hash_name == "384") {
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_len =
                    ALC_DIGEST_LEN_384;
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 =
                    ALC_SHA3_384;
            } else if (hash_name == "512") {
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_len =
                    ALC_DIGEST_LEN_512;
                mac_info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 =
                    ALC_SHA3_512;
            }
            p_sha3 = std::make_unique<alcp::digest::Sha3>(
                mac_info.mi_algoinfo.hmac.hmac_digest);
            p_hmac =
                std::make_unique<alcp::mac::Hmac>(key[0], key.size(), *p_sha3);
        }
    }
    void TearDown() override
    {
        if (p_hmac) {
            p_hmac->finish();
        }
    }
};

TEST(HmacReliabilityTest, NullUpdate)
{
    auto        pos  = KAT_ShaDataset.find("SHA2_256_KEYLEN_EQ_B");
    param_tuple data = pos->second;

    auto key         = parseHexStrToBin(std::get<0>(data));
    auto cipher_text = parseHexStrToBin(std::get<1>(data));
    auto output_mac  = parseHexStrToBin(std::get<2>(data));

    alcp::digest::Sha256 sha256;
    alcp::mac::Hmac      hmac(key.front(), key.size(), sha256);

    auto err = hmac.update(nullptr, 0);
    // EXPECT_EQ(err, ALC_ERROR_NONE);
    hmac.update(&cipher_text[0], cipher_text.size());
    hmac.finalize(nullptr, 0);
    auto mac = std::vector<Uint8>(hmac.getHashSize(), 0);
    hmac.copyHash(&mac.at(0), mac.size());
    EXPECT_EQ(mac, output_mac);
    hmac.finish();
}

TEST_P(HmacTestFixture, HMAC_UPDATE)
{
    const auto params = GetParam();
    setUp(params);
    setUpHash(params.first);

    p_hmac->update(&cipher_text[0], cipher_text.size());

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

    p_hmac->update(&block1[0], block1.size());
    p_hmac->update(&block2[0], block2.size());
    p_hmac->finalize(nullptr, 0);

    std::vector<Uint8> mac = std::vector<Uint8>(p_hmac->getHashSize(), 0);
    p_hmac->copyHash(&mac.at(0), mac.size());

    EXPECT_EQ(mac, expected_mac);
}

TEST(HmacReliabilityTest, Reset)
{
    auto        pos  = KAT_ShaDataset.find("SHA2_256_KEYLEN_EQ_B");
    param_tuple data = pos->second;

    auto key         = parseHexStrToBin(std::get<0>(data));
    auto cipher_text = parseHexStrToBin(std::get<1>(data));
    auto output_mac  = parseHexStrToBin(std::get<2>(data));

    alcp::digest::Sha256 sha256;
    alcp::mac::Hmac      hmac(key.front(), key.size(), sha256);
    hmac.update(&cipher_text[0], cipher_text.size());

    hmac.reset();

    hmac.update(&cipher_text[0], cipher_text.size());
    hmac.finalize(nullptr, 0);
    auto mac = std::vector<Uint8>(hmac.getHashSize(), 0);
    hmac.copyHash(&mac.at(0), mac.size());
    EXPECT_EQ(mac, output_mac);
    hmac.finish();
}

TEST(HmacReliabilityTest, UpdateFinalizeReset)
{
    auto        pos  = KAT_ShaDataset.find("SHA2_256_KEYLEN_EQ_B");
    param_tuple data = pos->second;

    auto key         = parseHexStrToBin(std::get<0>(data));
    auto cipher_text = parseHexStrToBin(std::get<1>(data));
    auto output_mac  = parseHexStrToBin(std::get<2>(data));

    auto block1 = std::vector<Uint8>(
        cipher_text.begin(), cipher_text.begin() + cipher_text.size() / 2);

    auto block2 = std::vector<Uint8>(
        cipher_text.begin() + cipher_text.size() / 2, cipher_text.end());

    alcp::digest::Sha256 sha256;
    alcp::mac::Hmac      hmac(key.front(), key.size(), sha256);
    hmac.update(&cipher_text.at(0), cipher_text.size());
    hmac.finalize(nullptr, 0);
    hmac.reset();

    hmac.update(&block1[0], block1.size());
    hmac.finalize(&block2[0], block2.size());
    auto mac = std::vector<Uint8>(hmac.getHashSize(), 0);
    hmac.copyHash(&mac.at(0), mac.size());
    EXPECT_EQ(mac, output_mac);
    hmac.finish();
}

INSTANTIATE_TEST_SUITE_P(
    HmacTest,
    HmacTestFixture,
    testing::ValuesIn(KAT_ShaDataset),
    [](const testing::TestParamInfo<HmacTestFixture::ParamType>& info) {
        return info.param.first;
    });
