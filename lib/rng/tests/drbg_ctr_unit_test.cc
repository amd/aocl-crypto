/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#include "alcp/rng/drbg_ctr.hh"
#include "openssl/bio.h"
#include "gtest/gtest.h"
#include <iostream>
#include <typeinfo>

#include "alcp/utils/benchmark.hh"
using namespace alcp::rng::drbg;
using alcp::base::Status;
Uint8
parseHexToNum(const Uint8 c)
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

    void testingReseed(const Uint8* pCEntropyInput,
                       const Uint64 cEntropyInputLen,
                       const Uint8* pCAdditionalInput,
                       const Uint64 cAdditionalInputLen)
    {
        internalReseed(pCEntropyInput,
                       cEntropyInputLen,
                       pCAdditionalInput,
                       cAdditionalInputLen);
    }

    void testingUpdate(const Uint8* pCProvidedData,
                       const Uint64 cProvidedDataLen)
    {
        update(pCProvidedData, cProvidedDataLen);
    }

    void testingUpdate(const std::vector<Uint8>& cProvidedData)
    {
        update(cProvidedData);
    }

    void testingInstantiate(const Uint8* pCEntropyInput,
                            const Uint64 cEntropyInputLen,
                            const Uint8* cNonce,
                            const Uint64 cNonceLen,
                            const Uint8* pCPersonalizationString,
                            const Uint64 cPCPersonalizationStringLen)
    {
        instantiate(pCEntropyInput,
                    cEntropyInputLen,
                    cNonce,
                    cNonceLen,
                    pCPersonalizationString,
                    cPCPersonalizationStringLen);
    }

    void testingInstantiate(const std::vector<Uint8>& cEntropyInput,
                            const std::vector<Uint8>& cNonce,
                            const std::vector<Uint8>& cPersonalizationString)
    {
        instantiate(cEntropyInput, cNonce, cPersonalizationString);
    }

    void testingGenerate(const Uint8* pCAdditionalInput,
                         const Uint64 cAdditionalInputLen,
                         Uint8*       pCOutput,
                         const Uint64 cOutputLen)
    {
        generate(pCAdditionalInput, cAdditionalInputLen, pCOutput, cOutputLen);
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
        { "useDerivationFunction", { "false" } },
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
        { "useDerivationFunction", { "false" } },
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
        { "useDerivationFunction", { "false" } },
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
        { "useDerivationFunction", { "false" } },
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
        { "useDerivationFunction", { "false" } },
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
          "e151312d1b9e8f83bd0acad6234d3bccc11b63a40d6fbff448f67db0b91f" } } },

    { "TESTCASE5_AES_128_UseDf",
      { { "EntropyInput", "890eb067acf7382eff80b0c73bc872c6" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "aad471ef3ef1d203" } },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1", "75051a3f18bc432cd125186614c2755c" },
        { "value1", "a60f46bd042a606816badff34464158b" },
        { "key2", "5b5d086eef9f67a8b6fa0ba5f1898d97" },
        { "value2", "556c8d59d8d0c1d9407f39d6940c97c1" },
        { "key3", "a9336f42d0e164da9ea6c1e6a25b9625" },
        { "value3", "57d0e20c4a7cd0d4be641ac2c0547b0f" },
        { "generatedbits",
          "a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6cf18"
          "659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3" } } },
    { "TESTCASE6_AES_128_UseDf",
      { { "EntropyInput", "c47be8e8219a5a87c94064a512089f2b" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "f2a23e636aee75c6" } },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1", "9c60bc241ea7aa2b6ab64021ce38e7ff" },
        { "value1", "4e3fa813be0e2525489aa73cdbe8dcd8" },
        { "key2", "d9c9563c13dc2a06c6b546fca504b59c" },
        { "value2", "94a3cd0aa02612acd3e8248a76229788" },
        { "key3", "b0cfc78c7e618f9a6529f66b74dac63a" },
        { "value3", "28de627b00862b69cdb10721cd861959" },
        { "generatedbits",
          "5a1650bb6d6a16f6040591d56abcd5dd3db8772a9c75c44d9fc64d51b733d4a6759b"
          "d5a64ec4231a24e662fdd47c82db63b200daf8d098560eb5ba7bf3f9abf7" } } },
    { "TESTCASE7_AES_128_UseDf_With_AdditionalInput",
      { { "EntropyInput", "b408cefb5bc7157d3f26cb95a8b1d7ac" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "026c768fd577b92a" } },
        { "PersonalizationString", {} },
        { "AdditionalInput1", "5737ef81dee365b6dadb3feebf5d1084" },
        { "AdditionalInput2", "3368a516b3431a3daaa60dc8743c8297" },
        { "key1", "48169f8d2b5e966c50cbb825cdb922e7" },
        { "value1", "599e782be1c38d5e9832430d6befef35" },
        { "key2", "050ed4b8e38c6539abeb8d8baea38cd2" },
        { "value2", "c01fb50f288dc1793d611c7af27c12ed" },
        { "key3", "368a89ff9cfc27611d69ba7a2e5a5920" },
        { "value3", "43b5196e8467a1905e972438a288ba2a" },
        { "generatedbits",
          "4e909ebb24147a0004063a5e47ee044fead610d62324bd0f963f756fb91361e8b87e"
          "3a76a398143fe88130fe1b547b661a6480c711b739f18a9df3ae51d41bc9" } } },
    { "TESTCASE8_AES_128_UseDf_With_PersonalizationString",
      { { "EntropyInput", "e10bc28a0bfddfe93e7f5186e0ca0b3b" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "9ff477c18673840d" } },
        { "PersonalizationString", "c980dedf9882ed4464a674967868f143" },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1", "eee04d7c76113a5cec992ae320c24d27" },
        { "value1", "df905647c1066e6f52c03edfb82b6928" },
        { "key2", "6887a9327be161b4cd1e924dac007405" },
        { "value2", "2bbc5a8ffb1e39aa028ff44c0a117df9" },
        { "key3", "63c155afa7fed259a36db98220c7a8a2" },
        { "value3", "3241e408a5cc7d584523297f9abb39a5" },
        { "generatedbits",
          "35b00df6269b6641fd4ccb354d56d851de7a77527e034d60c9e1a9e1525a30ed361f"
          "ded89d3dccb978d4e7a9e100ebf63062735b52831c6f0a1d3e1bdc5ebc72" } } },
    { "TESTCASE9_AES_128_UseDf_With_PersonalizationString_AdditionalInput",
      { { "EntropyInput", "cae48dd80d298103ef1ec0bf1bb96270" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "d827f91613e0b47f" } },
        { "PersonalizationString", "cc928f3d2df31a29f4e444f3df08be21" },
        { "AdditionalInput1", "7eaa1bbec79393a7f4a8227b691ecb68" },
        { "AdditionalInput2", "6869c6c7b9e6653b3977f0789e94478a" },
        { "key1", "df72953061f682812801fa1c141d00f9" },
        { "value1", "3b92a7729b50e513ec96321f68562d57" },
        { "key2", "c830ef909594780238882b9c55b2bd0c" },
        { "value2", "ecbce92e40a2575a0a3ce3b19a84bfe5" },
        { "key3", "9c8d021d3c679686e2caae05e848badc" },
        { "value3", "3b2fdc49fb6be677ae53ab2c4dab8fd5" },
        { "generatedbits",
          "920132cd284695b868b5bc4b703afea4d996624a8f57e9fbf5e793b509cb15b4beaf"
          "702dac28712d249ae75090a91fd35775294bf24ddebfd24e45d13f4a1748" } } },
    { "TESTCASE10_AES_192_UseDf",
      { { "EntropyInput", "c35c2fa2a89d52a11fa32aa96c95b8f1c9a8f9cb245a8b40" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "f3a6e5a7fbd9d3c68e277ba9ac9bbb00" } },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1", "dc426103bc9ba6852141ff60ec9a8fadf692fbb0d7cc9f1c" },
        { "value1", "a052364df3cff6321ab3d085661b7b91" },
        { "key2", "0e93434b8f8da2f2c550dea97e2bff9b5bdf689f320a494a" },
        { "value2", "9369162c2b50180c3d636e5db84c4ac4" },
        { "key3", "4cd55bbbd3463aee44aae407cd8e64acf6bba5e1ccead453" },
        { "value3", "9ceca41a69b279304bac311862f4e66d" },
        { "generatedbits",
          "8c2e72abfd9bb8284db79e17a43a3146cd7694e35249fc3383914a7117f41368e6d4"
          "f148ff49bf29076b5015c59f457945662e3d3503843f4aa5a3df9a9df10d" } } },
    { "TESTCASE11_AES_256_UseDf",
      { { "EntropyInput",
          "36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14" },
        { "useDerivationFunction", { "true" } },
        { "nonce", { "496f25b0f1301b4f501be30380a137eb" } },
        { "PersonalizationString", {} },
        { "AdditionalInput1", {} },
        { "AdditionalInput2", {} },
        { "key1",
          "3363d9000e6db47c16d3fc65f2872c08a35f99b2d174afa537a66ec153052d98" },
        { "value1", "9ee8d2e9c618ccbb8e66b5eb5333dce1" },
        { "key2",
          "b1dff09c816af6d4b2111fe63c4507cb196154f8c59957a94a2b641a7c16cc01" },
        { "value2", "69eec01b2dd4ff3aab5fac9467f54485" },
        { "key3",
          "33a1f160b0bde1dd55fc314c3d1620c0581ace8b32f062fb1ed54cdecdc17694" },
        { "value3", "f537c07f36573a26b3f55c8b9f7246d1" },
        { "generatedbits",
          "5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a649"
          "12dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d" } } }

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
    bool                            use_derivation_function = false;
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

        use_derivation_function =
            tuple_values.at("useDerivationFunction") == "true";

        m_ctrDrbg = std::make_unique<TestingCtrDrbg>();
        m_ctrDrbg->setKeySize(expected_key1.size());
        m_ctrDrbg->setUseDerivationFunction(use_derivation_function);
    }
};

TEST_P(CtrDrbgFuncionalityTest, KAT)
{
    if (PersonalizationString.size() == 0) {
        PersonalizationString.reserve(1);
    }
    if (AdditionalInput1.size() == 0) {
        AdditionalInput1.reserve(1);
    }
    if (AdditionalInput2.size() == 0) {
        AdditionalInput2.reserve(1);
    }
    if (nonce.size() == 0) {
        nonce.reserve(1);
    }
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

// TODO: To be removed once API based benchmarks are up
TEST(CtrDrbg, PerformanceTest)
{
    CtrDrbg            m_ctr_drbg;
    constexpr int      cSizes = 31;
    std::vector<Uint8> entropy_input(cSizes);
    std::vector<Uint8> nonce(10000);
    std::vector<Uint8> personalization_string(32);
    std::vector<Uint8> additional_input(cSizes);
    std::vector<Uint8> generatedbits(cSizes);
    m_ctr_drbg.setKeySize(16);
    m_ctr_drbg.instantiate(entropy_input, nonce, personalization_string);

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) {
        ALCP_CRYPT_TIMER_START
        m_ctr_drbg.generate(additional_input, generatedbits);
        ALCP_CRYPT_GET_TIME(0, "Generate")
        if (totalTimeElapsed > 1) {
            std::cout << "\n\n"
                      << std::setw(5) << k * generatedbits.size()
                      << " Generated bytes per second\n";
            break;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    CtrTest,
    CtrDrbgFuncionalityTest,
    testing::ValuesIn(KAT_CtrDrbgDataset),
    [](const testing::TestParamInfo<CtrDrbgFuncionalityTest::ParamType>& info) {
        return info.param.first;
    });