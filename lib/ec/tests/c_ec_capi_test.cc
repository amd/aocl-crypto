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

#include <cstdlib>

#include "alcp/ec.h"
#include "alcp/ecdh.h"

namespace {

constexpr Uint64 X25519KeySize = 32;
constexpr Uint64 P256KeySize   = 32;

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

    /* the key P256 holds is freed but not nulled, so a second teardown of the
     * same backend is a double free */
    alcp_ec_finish(&handle);
    alcp_ec_finish(&handle);
    std::free(handle.context);
    SUCCEED();
}

} // namespace
