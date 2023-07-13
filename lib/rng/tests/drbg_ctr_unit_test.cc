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

#include "alcp/base.hh"

#include "../../rng/include/hardware_rng.hh"
#include "alcp/rng/drbg_ctr.hh"
#include "openssl/bio.h"
#include "gtest/gtest.h"
#include <iostream>
#include <typeinfo>

using namespace alcp::rng::drbg;
using alcp::base::Status;
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

class TestingCtrDrbg : public CtrDrbg
{
  public:
    using CtrDrbg::CtrDrbg;

    void testingReseed(const std::vector<Uint8>& cEntropyInput,
                       const std::vector<Uint8>& cAdditionalInput)
    {
        internalReseed(cEntropyInput, cAdditionalInput);
    }

    void testingReseed(const Uint8* p_cEntropyInput,
                       const Uint64 cEntropyInputLen,
                       const Uint8* p_cAdditionalInput,
                       const Uint64 cAdditionalInputLen)
    {
        internalReseed(p_cEntropyInput,
                       cEntropyInputLen,
                       p_cAdditionalInput,
                       cAdditionalInputLen);
    }

    void testingUpdate(const Uint8* p_cProvidedData,
                       const Uint64 cProvidedDataLen)
    {
        update(p_cProvidedData, cProvidedDataLen);
    }

    void testingUpdate(const std::vector<Uint8>& cProvidedData)
    {
        update(cProvidedData);
    }

    void testingInstantiate(const Uint8* p_cEntropyInput,
                            const Uint64 cEntropyInputLen,
                            const Uint8* cNonce,
                            const Uint64 cNonceLen,
                            const Uint8* p_cPersonalizationString,
                            const Uint64 p_cPersonalizationStringLen)
    {
        instantiate(p_cEntropyInput,
                    cEntropyInputLen,
                    cNonce,
                    cNonceLen,
                    p_cPersonalizationString,
                    p_cPersonalizationStringLen);
    }

    void testingInstantiate(const std::vector<Uint8>& cEntropyInput,
                            const std::vector<Uint8>& cNonce,
                            const std::vector<Uint8>& cPersonalizationString)
    {
        instantiate(cEntropyInput, cNonce, cPersonalizationString);
    }

    void testingGenerate(const Uint8* p_cAdditionalInput,
                         const Uint64 cAdditionalInputLen,
                         Uint8*       p_cOutput,
                         const Uint64 cOutputLen)
    {
        generate(
            p_cAdditionalInput, cAdditionalInputLen, p_cOutput, cOutputLen);
    }

    void testingGenerate(const std::vector<Uint8>& cAdditionalInput,
                         std::vector<Uint8>&       cOutput)
    {
        generate(cAdditionalInput, cOutput);
    }

    std::vector<Uint8> testingGetKCopy() { return getKCopy(); }

    std::vector<Uint8> testingGetVCopy() { return getVCopy(); }
};

typedef std::map<const std::string, std::string> param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

// clang-format on
known_answer_map_t KAT_CtrDrbgDataset{
    { "TESTCASE1_AES_128",
      { { "EntropyInput",
          "ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc" },
        { "nonce", {} },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1", "96b20ff35faaf1b2e27f53e4f6a3f2a8" },
        { "value1", "cef7f49e164d55eaf957348dc3fb5b84" },
        { "key2", "2e8bf07c5a29b97633576a7c4d5343dd" },
        {
            "value2",
            "3f93dbc9dc724d654f5f2a45b818c7ec",
        },
        { "key3", "a103e1669b0641cae87caab70a741bf1" },
        { "value3", "fbe9d7c15217c737b408e31679170140" },
        { "generatedbits",
          "6545c0529d372443b392ceb3ae3a99a30f963eaf313280f1d1a1e87f9db373d361e7"
          "5d18018266499cccd64d9bbb8de0185f213383080faddec46bae1f784e5a" } } },
    { "TESTCASE2_AES_192",
      { { "EntropyInput",
          "f1ef7eb311c850e189be229df7e6d68f1795aa8e21d93504e75abe78f04139587354"
          "0386812a9a2a" },
        { "nonce", {} },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1", "3cdccc39d6bba7aa29b0f36ee5b1f2ba8f728ef22629cb45" },
        { "value1", "fb7cc03b74f1cf5859609060e31f744d" },
        { "key2", "6bc37530d95aa756ce246323f8405086852578cff8c0c838" },
        {
            "value2",
            "eeb89f00f173069578102c405301173b",
        },
        { "key3", "5e5ccdb3f2a74ba428f08cd465942ecedcacec77e93b1412" },
        { "value3", "528af6f2d453242e5cc77e24098bd66f" },
        { "generatedbits",
          "6bb0aa5b4b97ee83765736ad0e9068dfef0ccfc93b71c1d3425302ef7ba4635ffc09"
          "981d262177e208a7ec90a557b6d76112d56c40893892c3034835036d7a69" } } },
    { "TESTCASE3_AES_256",
      { { "EntropyInput",
          "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5531b"
          "51de16a30f769262474c73bec010" },
        { "nonce", {} },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1",
          "8c52f901632d522774c08fad0eb2c33b98a701a1861aecf3d8a25860941709fd" },
        { "value1", "217b52142105250243c0b2c206b8f59e" },
        { "key2",
          "72f4af5c93258eb3eeec8c0cacea6c1d1978a4fad44312725f1ac43b167f2d52" },
        {
            "value2",
            "e86f6d07dfb551cebad80e6bf6830ac4",
        },
        { "key3",
          "1a1c6e5f1cccc6974436e5fd3f015bc8e9dc0f90053b73e3c19d4dfd66d1b85a" },
        { "value3", "53c78ac61a0bac9d7d2e92b1e73e3392" },
        { "generatedbits",
          "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab2280b1"
          "dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5" } } },
    { "TESTCASE4_AES_256_WITH_AddInput",
      { { "EntropyInput",
          "f45e9d040c1456f1c7f26e7f146469fbe3973007fe037239ad57623046e7ec52221b"
          "22eec208b22ac4cf4ca8d6253874" },
        { "nonce", {} },
        { "PersonalizationString", {} },
        { "AdditionalInput1",
          "28819bc79b92fc8790ebdc99812cdcea5c96e6feab32801ec1851b9f46e80eb68000"
          "28e61fbccb6ccbe42b06bf5a0864" },
        { "AdditionalInput2",
          "418ca848027e1b3c84d66717e6f31bf89684d5db94cd2d579233f716ac70ab66cc7b"
          "01a6f9ab8c7665fcc37dba4af1ad" },
        { "key1",
          "a75117ffcb5160486e91da8ed0af1a702d30703ab3631957aa19a7e3fc14714a" },
        { "value1", "507b2124f5ae985e156db926a3230dfa" },
        { "key2",
          "d75e41010982abd243b4d75642b86ce07e13b3652a3725aad011b1097c32957a" },
        {
            "value2",
            "939fbb584e0103982d2e73e05779849f",
        },
        { "key3",
          "b0f80df4b33e5d2e3d72c8667ba9da1aa64a3a4936a3fdabf2c980d3104dfa13" },
        { "value3", "433abd3907feddce66cbcb216d5d833e" },
        { "generatedbits",
          "4f11406bd303c104243441a8f828bf0293cb20ac39392061429c3f56c1f426239f8f"
          "0c687b69897a2c7c8c2b4fb520b62741ffdd29f038b7c82a9d00a890a3ed" } } },
    { "TESTCASE5_AES_256_WITH_PersonalizationString",
      { { "EntropyInput",
          "22a89ee0e37b54ea636863d9fed10821f1952a428488d528eceb9d2ec69d573ec621"
          "6216fb3e8f72a148a5ada9d620b1" },
        { "nonce", {} },
        { "PersonalizationString",
          "953c10badcbcd45fb4e5475826477fc137ac96a49ad5005fb14bdaf6468ae7f46c5d"
          "0de22d304afc67989615adc2e983" },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1",
          "e49b04a1f882b60c7eee90701c5d046b089efcdb533dbe195aee820b3ae42dd2" },
        { "value1", "d81c6c3ee1a8effa1772c6367112fcbc" },
        { "key2",
          "df098aa913fc5182acb684d7f1bc573d7fcdd0fad2a9c5a22e33221c635fe73c" },
        {
            "value2",
            "8c960164b4afeffe826fb7d9160261e3",
        },
        { "key3",
          "16934bc0c8accda050463c65720b6c7d121f2e79bc253cf53f82f455b972e8ee" },
        { "value3", "55f1f21c57581386cc681ba2253a4122" },
        { "generatedbits",
          "f7fab6a6fcf445f0a0434b2aa0c610bdef5489ecd95414634623add18a9f888bca6b"
          "e151312d1b9e8f83bd0acad6234d3bccc11b63a40d6fbff448f67db0b91f" } } }

};

// clang-format on
class CtrDrbgFuncionalityTest
    : public ::testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    std::vector<Uint8> EntropyInput, nonce, PersonalizationString,
        AdditionalInput1, AdditionalInput2, expected_key1, expected_key2,
        expected_key3, expected_value1, expected_value2, expected_value3,
        expected_generated_bits;
    std::unique_ptr<TestingCtrDrbg> m_ctrDrbg;

    void SetUp() override
    {
        const auto  cParams      = GetParam();
        param_tuple tuple_values = cParams.second;
        EntropyInput = parseHexStrToBin(tuple_values.at("EntropyInput"));
        nonce        = parseHexStrToBin(tuple_values.at("nonce"));
        PersonalizationString =
            parseHexStrToBin(tuple_values.at("PersonalizationString"));
        AdditionalInput1 =
            parseHexStrToBin(tuple_values.at("AdditionalInput1"));
        AdditionalInput2 =
            parseHexStrToBin(tuple_values.at("AdditionalInput2"));
        expected_key1   = parseHexStrToBin(tuple_values.at("key1"));
        expected_key2   = parseHexStrToBin(tuple_values.at("key2"));
        expected_key3   = parseHexStrToBin(tuple_values.at("key3"));
        expected_value1 = parseHexStrToBin(tuple_values.at("value1"));
        expected_value2 = parseHexStrToBin(tuple_values.at("value2"));
        expected_value3 = parseHexStrToBin(tuple_values.at("value3"));
        expected_generated_bits =
            parseHexStrToBin(tuple_values.at("generatedbits"));

        m_ctrDrbg = std::make_unique<TestingCtrDrbg>();
        m_ctrDrbg->setKeySize(expected_key1.size());
    }
};

TEST_P(CtrDrbgFuncionalityTest, WithoutDf)
{

    m_ctrDrbg->testingInstantiate(EntropyInput, nonce, PersonalizationString);

    std::vector<Uint8> actual_key1   = m_ctrDrbg->testingGetKCopy();
    std::vector<Uint8> actual_value1 = m_ctrDrbg->testingGetVCopy();

    EXPECT_EQ(actual_key1, expected_key1);
    EXPECT_EQ(actual_value1, expected_value1);

    std::vector<Uint8> generated_bits(expected_generated_bits.size());

    m_ctrDrbg->testingGenerate(AdditionalInput1, generated_bits);
    std::vector<Uint8> actual_key2   = m_ctrDrbg->testingGetKCopy();
    std::vector<Uint8> actual_value2 = m_ctrDrbg->testingGetVCopy();

    EXPECT_EQ(actual_key2, expected_key2);
    EXPECT_EQ(actual_value2, expected_value2);

    m_ctrDrbg->testingGenerate(AdditionalInput2, generated_bits);
    std::vector<Uint8> actual_key3   = m_ctrDrbg->testingGetKCopy();
    std::vector<Uint8> actual_value3 = m_ctrDrbg->testingGetVCopy();
    EXPECT_EQ(actual_key3, expected_key3);
    EXPECT_EQ(actual_value3, expected_value3);

    EXPECT_EQ(expected_generated_bits, generated_bits);
}

INSTANTIATE_TEST_SUITE_P(
    CtrTest,
    CtrDrbgFuncionalityTest,
    testing::ValuesIn(KAT_CtrDrbgDataset),
    [](const testing::TestParamInfo<CtrDrbgFuncionalityTest::ParamType>& info) {
        return info.param.first;
    });