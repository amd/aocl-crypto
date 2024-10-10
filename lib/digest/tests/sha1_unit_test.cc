/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest/sha1.hh"
#include "gtest/gtest.h"
#include <memory>
namespace {

/* Utilities */
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

using namespace std;
using namespace alcp::digest;

typedef tuple<const string, string>        ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;
static const KnownAnswerMap                message_digest = {
    { "Case1",
                     { "7c9c67323a1df1adbfe5ceb415eaef0155ece2820f4d50c1ec22cba4928ac656c83fe5"
                                      "85db6a78ce40bc42757aba7e5a3f582428d6ca68d0c3978336a6efb729613e8d997901"
                                      "6204bfd921322fdd5222183554447de5e6e9bbe6edf76d7b71e18dc2e8d6dc89b73983"
                                      "64f652fafc734329aafa3dcd45d4f31e388e4fafd7fc6495f37ca5cbab7f54d586463d"
                                      "a4bfeaa3bae09f7b8e9239d832b4f0a733aa609cc1f8d4",
                       "d8fd6a91ef3b6ced05b98358a99107c1fac8c807" } },
    { "Case2",
                     { "a489cc5f00c1835ddaf2f0586710850752abe68d001f4e4e180b2f0043041805308adc"
                                      "f8dc3af1861046167f2b23382c218197e4c48025da42212e39effa3e73452f40d5299d"
                                      "e360705842d4a258c30dfe6f3f92be7e646c9ce9583494489f70ec603f207251229305"
                                      "10bb7f5618ed51f05d28c27682d5ab2c4bf41ab95503a52c0522fe3cbe76c8d457cba9"
                                      "cfcc7da10033989a75f23e40fc304912e78932b90d063299114ca6a7e713b87a93da3c"
                                      "a434d9d842423868d2147ea045a54cf355974bb41978637cd7452ecb192cacf2039638"
                                      "30e365ba1b0a7a1f41db7b061021d3bcf3a6fa6bbe01f68e4caf22a866652e36e7a567"
                                      "e21e9038f974fbf11f4fc4c84236661ecc35cc031d8363fb38627302bc47afcf173b0b"
                                      "56f681cd90ff79e77ec3c4846ceea9e173c1b75e41c3acd51db3962a25c03823dafdaf"
                                      "7adf0f5631fe28e6266c3ae2e74e6432c77bb10d3284011d3df247de81cef5482a67b5"
                                      "ad4b4f5ae475a716a7879ced3ac732694d3241902411bc13f5cd39c89204ae5a47dc79"
                                      "400698a4ebc16966441886ed55347e5a46f3cd0e8c45ae245dd6313e67ed8d85c194b7"
                                      "eb22f934b451142b34dc8abeda0dd19a6d1a95cd969c5bd99f4265067ac7d5fc052115"
                                      "908cfc75df8f661699c6cc08a06325afd2976d6b22575577ee6039128d7952dd27f82d"
                                      "85c9875ba1b8286bde06771559642fb84c37f007edee40fe9392cf1c1b9effcc8a12a3"
                                      "24f3c307d19cf532525c2b6765473ef2bf8ead2100a03490e695a0a9c1cde16c27d461"
                                      "6ce889941a4480d1465ca460e3e721d40b26819a431a14d3fff4965f69cd0c3a5e97ef"
                                      "0cb9548cfbd586abc44de66f0a06587dee701f60df084d2db3227e62f7e5c6148497e8"
                                      "4a531bc9a493b72440f81b7edd559f5d416dcdb5d9071fa3a040095d41253a6a808120"
                                      "0ed6f4aa095b455181eaf9593c7f255412e380e9a28cbcd345be172c40f72dec3e8a10"
                                      "adfd8a9ab147e9022524e1aea74e934807e5ef144a64d381f5d477fe883f080e486893"
                                      "9f41b925988c7d31b1ce4f318701d290f077a3c88b1b8cc89cfbfb981703b23ffb0bbf"
                                      "e5e115af35d5cfff056460d339f660eae45f28d2b1b04d588253674356571742700848"
                                      "22b6c3b4445708aa4fb0d10f227122a40dfbe286400de9fb83a05a6b280f33ad3e7b22"
                                      "85086e9b6aaebe278c31b5ff15a46ed9af9a820247dbe5ad115b0a8bcd6c4e9b483293"
                                      "4425572ba1dd01f91c0501d23ed04e29c5d4b1ecf711c1a9372f12f5d607aa0e2b65b4"
                                      "bfe60c7984a1fb8befb8ef434a5b296e7ee17144345f5b9a397ac9582779b12c429f21"
                                      "80a0b780aa8df016632debcf7b63133bcbf22dda6ae22f9724265692277b7322009386"
                                      "1bc6738d4c951a9e4c3e6334773d2cc733ecb89f78f652e98f0d330b19e0a63554476a"
                                      "389ac1589c2a2145ec2b842a55ee86837074b6f45b3047320e0d0821ecb3963a9906cf"
                                      "300cf08bd3e56187340094a20a4a934c54d3fd3b4025075f4cd5c119ab579ba8ea1627"
                                      "e4d3c4202e92efaca716d6dea0ba7a7f5225f80ecf6e150539841b5e32cee456930e34"
                                      "71618b4cbefd6fbb5c9a6e783df4a82e2a40d1d7075e8f8c5956239b05024cdb5a0868"
                                      "3c520cdda21523b7f4bf8a936f6398bb4150f1925393fd3366bd985561e60b72e9f13b"
                                      "28331221df168e7aac65c2c0757b67585617140d446b04bdf06f1a52ee7b22f417155a"
                                      "7e2c08312ebcb64ea047aed4fda381e5709fd265d9e7ad00c6271a6e9f73f1f520e7ef"
                                      "300c8a0a10207802204641390d0c8cc4655400c29f4d64ec5ca2046eecf157f6147ee0"
                                      "0a0e29529ed29df7e694cb52698e970457ffd0ec1c7466923546d7c64264eb845d52a1"
                                      "1bab72698e3083933be86708ba13293808d03e53e5ed0bbc7afea8bb3face4721c5089"
                                      "12cfc1e14e8d697810ec9f246b003143d2c43f4487bc506955d99fca829db69e007f3e"
                                      "b6e391164a1860a2f8531c660a49f9d3f820d4602d231add0ebbe604399a69520a3a8f"
                                      "156486dfc5aed7a4971b214a502f6f0a577f8cca0fb8033e63e24a54a3e63bcf8e4ec3"
                                      "31b04ddedfeeffc3805ff15ba65de4f8b0dcce44effb227807d951ce98aa91381e0add"
                                      "5216903d9563a747ceef99e6cf95ed5a653ff3808a4b9d54db3490b44c6e7b671a91a8"
                                      "5d01bad138b02e340c7a41e9634e777485e9e897f64ae96a3f66e8adf11e985ce86e4f"
                                      "84cde7ac56de5f7c79f2e7dea5b7fda66e3f03005dbbf05645864673d46544e8690d5c"
                                      "ae25e5e70e450e18beafa12e4dca37eec093af517eee2b7a69395cea4e2700f77fcca8"
                                      "7abef4bfc95db9c8e5a455e7f47334a3f1284eeaa2c3b355ca4967aea16671b081552f"
                                      "0de205ecb68874b456fb5f671f381e0dcaa6ca69d94ba0d12040aa3d83629c9d014bfc"
                                      "70f28185928cecce55ac8e27d4d46ec3846fd51d0c5dbd9457ab8758e7a2ec8a6c0436"
                                      "9f9592b00626d15b0a4b0ee2f92ba0d086c16d016ce7b05654b4f9adf90875118a656f"
                                      "2d50011707901982ebb387f3a4a49759f37a17183957ad0c778f6ecb780dab2b4df30e"
                                      "05fa81e6386f38c0f0ba3f37287a050d6d97287ae53096c391d5f20fcff73977239ca5"
                                      "5c3657d1fd1f781f48e28057f136d890c28cc254324c8fff3862136861f956c321868c"
                                      "c66609470b7390ecb6ecfc63572d071312e0860efdcfec88c9f6108ea5dd30f55f2535"
                                      "90cc6038a66b2646a24565600d17f8c6bab37b7640a45eefad11393a79e45f2bb92ab6"
                                      "e595bdc69cfc210f9f97ada095fbebe5062241c11e1cd0dcae029c3f742ced1e9ca3f6"
                                      "f486d9b5d6ca981a007a396bb5a716e7462642aa709377d0ea974fdd3f67b75dda8da1"
                                      "c75febfaa742fddcfc925e04df158e86669af2bfc88b1c8cc2c24db9399d38bd205509"
                                      "a49c8ba64c662435d47257de52ce04d2c4cc488c4a634e5792d3681093885e2d7e4106"
                                      "fef17114336ee5349f0da8563b6d24496ef0898c8b2873619c8cc7225e70ddd88c34e5"
                                      "0a60bb83d3581ebd3736a217b74ae8fc23f36460b06410a44ba462ba2cd87b89adc5a1"
                                      "935d91efd550c94beebaa99984bc972ee47ef088e87e073c1e286b2f26a669095cf9d2"
                                      "e7b849ff51f279116be9ff7d6f45f3c95a5b6590e652f4ccb9849c55dc27d0a46e2dc9"
                                      "dd9a681d0dc6f293af0dcc3676f0c5a846489eb9837f6b388f003c0a8eecfd786d0f9b"
                                      "cd2212692135f2c1707fb1eeef324b499f19eba322215fe3ce19c9f000b698d2b2dab7"
                                      "145015046cc86d049ee15ad59dcd1564f30112e06444cb6ece06c01e54f4bc1dbbc959"
                                      "2d1467c6539c26c8cfe06cff51257e6b6a06952f415f3594876aba50ad283409540374"
                                      "1505b16784225ba3601cff4033e713e9caab6b3239bd5c2c1fcd22382b617f18df82a5"
                                      "4c94b4569bbf2c4af0723ed1672615b9a8b7a67274b0e6707dc93bd17bae31407c026f"
                                      "197ba4e9cd3531578938cae5123d172cf4b78b61dbaceacc41c4097c49a0d63aeb6c97"
                                      "bb52b8771a82833e853e996036292039a42b6d97fb161c79ca8a5f16fc1696210a9f20"
                                      "4c6f06710b5b05659aab5ad441192867d7b09aaa8584c962cc9fe020c93e7e16b83e5b"
                                      "2ab8d12f49cd75cffe2b279943b2d31397b510cf50ff0a923318bfb442c46fcad5cd4d"
                                      "83ec027bd0c4803548a8304dca0a91d764d2b82573f695f60c4b77ea9b9bd239caf741"
                                      "a5a54ec7adfb3f5a04072ca2414f90fed8cd92c8494ddada9716a350fccc1190db95c5"
                                      "88f67bb037e112246fb75a31d90be62e39213e96f35e8316cffe51e3f905e9514c7890"
                                      "a2cfcc321b809f4b5e51a608f371e7a928cc28291bd5a72115830bea19999b01bd2bae"
                                      "b0395e62ebbe6f917909f70154376ddb51dbec5f034e36d5dd46fac798aa526dd4a590"
                                      "6902fa3ab5819753d9076cdc61437d9b8ec1361b4c0dfff4641b114cf3e6889e1b58b9"
                                      "bbf86ac50ed58c6f23a0472a6b9c21763956c16d11da539922262e0911dfb4a4f8437a"
                                      "bdaf5faae74a82a50ae2f1ecb699dc40b8d89108ebdbf0f451701fe062fb7ffba4bede"
                                      "287c57eea4448af5e99d41c7d307d1f202af7f387f874342a29ccc9233a5c3bacfd754"
                                      "cb8d01eb11e2d43bfdc2828563088c17e618d413b0c3fa71666be5475a67a04803a868"
                                      "8bab9d038f6855537b4de42aaae1076066d00b23f4e1ea8fd228b87e3c7d3da2f42de4"
                                      "d143efd49f3b195c3240139452c70c41c05cedfac9ea8b891a372194d6aefd7de66179"
                                      "86914e2d394ce16307d3bbcb2f78b271e1bb19eba31c41d7f52d3f8530ebf0f0b44e3b"
                                      "f3421f96b9a70acc769bf4fd54e88fe6b1cf2b6287a7cf312bc788f93ba6018ad14154"
                                      "66fdbd2081734edc4580576ad943d3efa319f3e30c5908648342a4d0c431fc925a1791"
                                      "3c622b10d793dc76767b0a77120b7521915676bd2896edf6e3707a3d8279f06b87f806"
                                      "a88dee508cdb536e8539a384790399eaac7b3a24e3631614cacccb6e9329ca6de0a75e"
                                      "c4e3c1ead8c30e722c425e5c1c9e0678cfb4783f676b17587a504961c67ecdeb20c14f"
                                      "c6aefb398056c6cd28765a7157d6b24972dbea0b29fdec0f437a4ba69e4c6fad7159f3"
                                      "62d5eb4b76845faa63e02122ff37d80e5145ddada4faf20fdb7e313504734274307ad1"
                                      "1a81f83f54841a984fc116c69e91b404dc300e95921393b55a7c52d0454b76f27b170c"
                                      "7f217d0d2480b8980d63727f58c0da05ca9bf7e6c1283c986a305cd134b5604985d9f6"
                                      "c1abfc0c4415259dadc3a3cb69fbf42f7e3ee56dcc7afb0b9381128336ba44963f160c"
                                      "e4a246abba462ccb2bc18f63626412da3677676fffc5c0d8a85c8629068e4ef8683b09"
                                      "bf70537a812196eeb1389e274fc0209954e16fd950f9415252eeb63a08c296c42767da"
                                      "970dd56f80a65b36638c324f78725897b3c29b6f8485f4c0c184173ce1ac48e66ab770"
                                      "d4ac097033b0d8b58d6c900d473876b96e868bc3b3cdb392b3c616bb7cdbc71a4ddda4"
                                      "229ef57d7160dd78a7864fb379c4be2c019745de5885dd2d67a6d284fa63783d167e1a"
                                      "c18d5333f0cf5de0c303fb962f5774104d94398cb9f56b3738399de69df7db06ed32eb"
                                      "d6c12dd2d4ec809b745e6c5318486c583d810cd4f229fe848f8c6bbea34887b22eb368"
                                      "f01177182ac27fe93b44170869574e55e7ec9f729edbd11a2ed81cb52fa48d29bc80ac"
                                      "f232e75b75357c0191f442e878ae0be4bd763336ae338dafe3ea9e19174009d2373a4b"
                                      "bab948a84f2f8265171c31383f0691fd81ccd5aa4b3a6c851ddb8395320ecb56645c7c"
                                      "b14a099a2aa3e9775cf77579a27b1e1d1836e23cc2621c8d0a15a06c702007d97d3748"
                                      "c4f85389885d5534b58bec4c12bdb802e2bbb0836752c115a501b76268f561138838f0"
                                      "a16c25a168cd1f9cfebc821bc2e7daceb818537f94fe71f21430010f936f5042dc2b9a"
                                      "233c49c552db244fa54bd2868662a8f79645002897c6398a88f000a911dfcea622d6b2"
                                      "e7d88b510da0c52b269e2920245051328f6e1f8c761551c4ab25555d30e85e90ecf4b7"
                                      "4ba252587b24dfb787c4f3e01c0c41c830affede41be46e4de1fbbfd693c6f071bf804"
                                      "2a48e711b1e5bec8194708d6682d1b8bc1014b3b345b5de4dac73f1022c8f6fd661dd7"
                                      "fcc242fa17253aecf6a88ca4041f8cb8cdeedbd1aa1f315da1b15a8387327f5c6790a7"
                                      "60282c7d1e69305431b023686fc4ba676357f130fee85bda89e8b6f8de1cc31bd84255"
                                      "9908f7a78da9d8f21fd6e83f06fb327a4b8aafc94fef691c0fc5e104a74aaec8151068"
                                      "b640f6c4b739570026c08182e20a69bca2c19d52894d797ffb529eb5ae79a0830474ff"
                                      "bc983c59d6169ddd9051f503d78f397aeb273862be4f24bc9d2f4e1f113a31ac08bdb2"
                                      "4430b8a6f8a4ee95c0ca38bd707b1e5ae965a8258cae721bf5daff7fe5ef4f227fd7b4"
                                      "e2b805e171095c4458664c963b743eb05ef732a06889a6fc6792ba76157493b15a06fd"
                                      "531144545c0f45a4b6616d0f0cd6e36fe0be453dd8f09bb259128a2b5714cbd26cfedb"
                                      "7b27ecf3cca6563aa167953aae5ba390673c23e81c21a12969501aedcd53bf34994ef6"
                                      "590c8fa245bc67a4e23738a2d2ebd0066243f54ab9134174563631dcb97678355fab99"
                                      "cbf427b40ac552a04074923ba4ef6efe96a2f2d528ec552dded0d94eb2eef3eb5bb1ac"
                                      "f7cfc947bb07dc24260278e4640c4dceb2409971704ce38b7774ec2aaedae311d8fcd8"
                                      "5db07e7369382ae6ee4e35206f80c343d421ae59559c83439909cef11ffe98d9dea82d"
                                      "a1281a231fd4e497849ce8bad4c4698d9afd65e8d98825c1459e12abb310ca9dcf2b73"
                                      "f50dde50bce21f912c338a706f0e4b79aa983f293a4656bb3e503c3f556338eca99754"
                                      "b72ca0be2521486e5ddf1d0981d166053ec25c0fa25797a92eddc7182d45a47d446d28"
                                      "4249a2fbb758622ffd24662d248ce0ef906f0170a1c0be6193ddd41ea21c09e072a7b5"
                                      "34af8b82acf00b70d4e23a1c67a2c941c36a1d7f9b70a45bec0b6a883218e765db9c1c"
                                      "c6fcabdef7438871fe2d0d5821784d6ca8dc792ce4f600547085fab1b7d8c733b687f3"
                                      "4404625d580fa799c5a87892d6c28b741a7624c9024b40e2abb51378f9dbb593e59d19"
                                      "ab18d63e0db8dea9818254122a191a5ead9da0cd96806675f795bcef516acd50b8d8db"
                                      "5a33d8ccf46298e6d863cfd78cf54df893ded6d2e48b30e29bf77b99efcec1a764d1ce"
                                      "79417c420045e6e4b596ea39dafa845602497df2d3234bbf0bde33fbc1c2b041ee7918"
                                      "a62bc17d01bc64d18ace6a4ea7fd8d150219ed16df",
                       "adf2ebb0c337c89334fe8580b53dae70b25d00a7" } }
};

class Sha1Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha1Test, digest_generation_test)
{
    const auto [plaintext, digest]       = GetParam().second;
    auto                     digest_size = ALC_DIGEST_LEN_160 / 8;
    std::unique_ptr<IDigest> digest_obj  = std::make_unique<Sha1>();
    ASSERT_NE(nullptr, digest_obj);
    vector<Uint8>     hash(digest_size);
    std::stringstream ss;

    digest_obj->init();
    auto plaintext_hex = parseHexStrToBin(plaintext);
    ASSERT_EQ(digest_obj->update(&plaintext_hex[0], plaintext_hex.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(digest_obj->finalize(hash.data(), digest_size), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < digest_size; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();

    EXPECT_EQ(hash_string, digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha1Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha1Test::ParamType>& info)
        -> const std::string { return info.param.first; });

} // namespace