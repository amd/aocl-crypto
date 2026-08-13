/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

#include "alcp/ec.h"
#include "alcp/ecdh.h"

namespace {

constexpr Uint64 X25519KeySize = 32;
constexpr Uint64 P256KeySize   = 32;

constexpr Uint64 X25519PubKeySize = 32;
constexpr Uint64 P256PubKeySize   = 64;

/* the curve base point; every u-coordinate except zero is accepted */
constexpr Uint8 cX25519PeerPubKey[X25519PubKeySize] = { 9 };

/* a point that really is on P-256, so that a refused derivation can only be
 * down to the state of the object and not to the peer key */
constexpr Uint8 cP256PeerPubKey[P256PubKeySize] = {
    // X
    0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32,
    0xca, 0x65, 0x64, 0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d,
    0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
    // Y
    0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20,
    0xba, 0x5c, 0x51, 0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40,
    0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
};

/* a valid scalar on both curves, and a byte pattern distinctive enough to be
 * searched for in the caller's context buffer */
constexpr Uint8 cPrivateKey[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static_assert(sizeof(cPrivateKey) == X25519KeySize
                  && sizeof(cPrivateKey) == P256KeySize,
              "one private key is shared by the tests of both curves");

std::vector<size_t>
privateKeyOffsetsIn(const std::vector<Uint8>& rContext)
{
    std::vector<size_t> offsets;
    auto                search_begin = rContext.begin();

    while (search_begin != rContext.end()) {
        const auto match = std::search(search_begin,
                                       rContext.end(),
                                       std::begin(cPrivateKey),
                                       std::end(cPrivateKey));
        if (match == rContext.end()) {
            break;
        }

        offsets.push_back(static_cast<size_t>(match - rContext.begin()));
        search_begin = match + sizeof(cPrivateKey);
    }

    return offsets;
}

bool
privateKeyClearedAt(const std::vector<Uint8>& rContext,
                    const std::vector<size_t>& offsets)
{
    return std::all_of(offsets.begin(), offsets.end(), [&](size_t offset) {
        return std::all_of(rContext.begin() + offset,
                           rContext.begin() + offset + sizeof(cPrivateKey),
                           [](Uint8 byte) { return byte == 0; });
    });
}

TEST(EcCapiNullGuardTest, FinishNullHandle)
{
    alcp_ec_finish(nullptr);
    SUCCEED();
}

TEST(EcCapiNullGuardTest, NullContext)
{
    alc_ec_handle_t handle{};

    alcp_ec_finish(&handle);
    SUCCEED();
}

TEST(EcCapiNullGuardTest, SupportedNullInfo)
{
    EXPECT_NE(alcp_ec_supported(nullptr), ALC_ERROR_NONE);
}

TEST(EcCapiNullGuardTest, TeardownAfterFailedRequest)
{
    alc_ec_info_t info{};
    info.ecCurveId     = ALCP_EC_MAX;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;

    alc_ec_handle_t handle{};
    handle.context = std::malloc(alcp_ec_context_size(&info));
    ASSERT_NE(handle.context, nullptr);
    ASSERT_NE(alcp_ec_request(&info, &handle), ALC_ERROR_NONE);

    alcp_ec_finish(&handle);
    alcp_ec_finish(&handle);
    std::free(handle.context);
    SUCCEED();
}

class EcCapiLifecycleTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_info.ecCurveId     = ALCP_EC_CURVE25519;
        m_info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
        m_info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;

        m_handle.context = std::malloc(alcp_ec_context_size(&m_info));
        ASSERT_NE(m_handle.context, nullptr);
        ASSERT_EQ(alcp_ec_request(&m_info, &m_handle), ALC_ERROR_NONE);
    }

    void TearDown() override { std::free(m_handle.context); }

    alc_ec_info_t   m_info{};
    alc_ec_handle_t m_handle{};
};

TEST_F(EcCapiLifecycleTest, FinishLiveHandle)
{
    alcp_ec_finish(&m_handle);
    SUCCEED();
}

TEST_F(EcCapiLifecycleTest, DoubleFinish)
{
    alcp_ec_finish(&m_handle);
    alcp_ec_finish(&m_handle);
    SUCCEED();
}

TEST_F(EcCapiLifecycleTest, GetPublicKeyAfterFinish)
{
    Uint8 priv_key[X25519KeySize]{};
    Uint8 pub_key[X25519KeySize]{};

    alcp_ec_finish(&m_handle);

    /* the lengths are valid, so only the finished context can be rejected */
    EXPECT_EQ(
        alcp_ec_get_publickey(
            &m_handle, pub_key, sizeof(pub_key), priv_key, sizeof(priv_key)),
        ALC_ERROR_INVALID_DATA);
}

TEST(EcCapiP256LifecycleTest, DoubleFinish)
{
    alc_ec_info_t info{};
    info.ecCurveId     = ALCP_EC_SECP256R1;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;

    alc_ec_handle_t handle{};
    handle.context = std::malloc(alcp_ec_context_size(&info));
    ASSERT_NE(handle.context, nullptr);
    ASSERT_EQ(alcp_ec_request(&info, &handle), ALC_ERROR_NONE);

    Uint8 priv_key[P256KeySize]{};
    priv_key[P256KeySize - 1] = 1;
    ASSERT_EQ(alcp_ec_set_privatekey(&handle, priv_key, sizeof(priv_key)),
              ALC_ERROR_NONE);

    /* the context guard stops the second teardown before it reaches the
     * backend, so the key handles are released exactly once */
    alcp_ec_finish(&handle);
    alcp_ec_finish(&handle);
    std::free(handle.context);
    SUCCEED();
}

struct CurveParam
{
    const char*       name;
    alc_ec_curve_id   curveId;
    alc_ec_curve_type curveType;
    Uint64            keySize;
    const Uint8*      pPeerPubKey;
    Uint64            peerPubKeyLen;
};

class EcCapiCurveTest : public ::testing::TestWithParam<CurveParam>
{
  protected:
    void SetUp() override
    {
        const CurveParam& curve = GetParam();

        m_info.ecCurveId     = curve.curveId;
        m_info.ecCurveType   = curve.curveType;
        m_info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;

        /* zeroed, not merely allocated: the key-wipe test searches the whole
         * buffer, including the padding the library never writes */
        m_context.assign(alcp_ec_context_size(&m_info), 0);
        m_handle.context = m_context.data();
        ASSERT_EQ(alcp_ec_request(&m_info, &m_handle), ALC_ERROR_NONE);
    }

    /* idempotent through the context guard, so a test may also finish early */
    void TearDown() override { alcp_ec_finish(&m_handle); }

    alc_ec_info_t      m_info{};
    alc_ec_handle_t    m_handle{};
    std::vector<Uint8> m_context;
};

INSTANTIATE_TEST_SUITE_P(
    Curves,
    EcCapiCurveTest,
    ::testing::Values(CurveParam{ "x25519",
                                  ALCP_EC_CURVE25519,
                                  ALCP_EC_CURVE_TYPE_MONTGOMERY,
                                  X25519KeySize,
                                  cX25519PeerPubKey,
                                  X25519PubKeySize },
                      CurveParam{ "p256",
                                  ALCP_EC_SECP256R1,
                                  ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS,
                                  P256KeySize,
                                  cP256PeerPubKey,
                                  P256PubKeySize }),
    [](const ::testing::TestParamInfo<CurveParam>& tpInfo) {
        return std::string(tpInfo.param.name);
    });

TEST_P(EcCapiCurveTest, SecretKeyRefusedWithoutPrivateKey)
{
    const CurveParam& curve = GetParam();

    std::vector<Uint8> secret_key(curve.keySize, 0xa5);
    const auto         untouched_secret = secret_key;
    Uint64             secret_key_len = 0;

    /* every length is valid, so the missing private key is the only thing
     * left to reject */
    EXPECT_EQ(alcp_ec_get_secretkey(&m_handle,
                                    &secret_key[0],
                                    secret_key.size(),
                                    curve.pPeerPubKey,
                                    curve.peerPubKeyLen,
                                    &secret_key_len),
              ALC_ERROR_GENERIC);
    EXPECT_EQ(secret_key_len, 0U);
    EXPECT_EQ(secret_key, untouched_secret);
}

TEST_P(EcCapiCurveTest, PrivateKeyIsClearedByFinish)
{
    ASSERT_EQ(
        alcp_ec_set_privatekey(&m_handle, cPrivateKey, sizeof(cPrivateKey)),
        ALC_ERROR_NONE);

    /* the curve object is placement-constructed inside the caller's context
     * buffer, so the key it stores is reachable from here */
    const auto key_offsets = privateKeyOffsetsIn(m_context);
    ASSERT_FALSE(key_offsets.empty());

    alcp_ec_finish(&m_handle);

    EXPECT_TRUE(privateKeyClearedAt(m_context, key_offsets));
}

} // namespace
