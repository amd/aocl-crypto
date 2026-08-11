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

#include "alcp/rng.h"

#include "gtest/gtest.h"

#include <vector>

/*
 * The RNG module draws from the operating system entropy source, so it has no
 * known answer to test against. These cases cover the public lifecycle, its
 * argument validation, and the output properties that must hold for any
 * correct generator.
 */

namespace {

constexpr Uint64 cBufferSize = 64;

alc_rng_info_t
osUniformRngInfo()
{
    alc_rng_info_t rng_info{};
    rng_info.ri_type    = ALC_RNG_TYPE_DISCRETE;
    rng_info.ri_source  = ALC_RNG_SOURCE_OS;
    rng_info.ri_distrib = ALC_RNG_DISTRIB_UNIFORM;
    return rng_info;
}

class RngSessionTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_rng_info = osUniformRngInfo();
        ASSERT_EQ(ALC_ERROR_NONE, alcp_rng_supported(&m_rng_info));

        const Uint64 context_size = alcp_rng_context_size(&m_rng_info);
        ASSERT_GT(context_size, 0U);

        m_context.resize(context_size);
        m_handle.rh_context = m_context.data();
        ASSERT_EQ(ALC_ERROR_NONE, alcp_rng_request(&m_rng_info, &m_handle));
    }

    void TearDown() override
    {
        EXPECT_EQ(ALC_ERROR_NONE, alcp_rng_finish(&m_handle));
    }

    alc_rng_info_t     m_rng_info{};
    alc_rng_handle_t   m_handle{};
    std::vector<Uint8> m_context;
};

TEST_F(RngSessionTest, FillsOutputBuffer)
{
    std::vector<Uint8> buffer(cBufferSize, 0);

    EXPECT_EQ(ALC_ERROR_NONE,
              alcp_rng_gen_random(&m_handle, buffer.data(), buffer.size()));

    /* An all-zero draw this wide is not credible from a working generator. */
    EXPECT_NE(std::vector<Uint8>(cBufferSize, 0), buffer);
}

TEST_F(RngSessionTest, SuccessiveDrawsDiffer)
{
    std::vector<Uint8> first(cBufferSize, 0);
    std::vector<Uint8> second(cBufferSize, 0);

    ASSERT_EQ(ALC_ERROR_NONE,
              alcp_rng_gen_random(&m_handle, first.data(), first.size()));
    ASSERT_EQ(ALC_ERROR_NONE,
              alcp_rng_gen_random(&m_handle, second.data(), second.size()));

    EXPECT_NE(first, second);
}

TEST_F(RngSessionTest, RejectsZeroLengthOutput)
{
    std::vector<Uint8> buffer(cBufferSize, 0);

    EXPECT_NE(ALC_ERROR_NONE, alcp_rng_gen_random(&m_handle, buffer.data(), 0));
}

TEST_F(RngSessionTest, RejectsNullOutputBuffer)
{
    EXPECT_NE(ALC_ERROR_NONE,
              alcp_rng_gen_random(&m_handle, nullptr, cBufferSize));
}

TEST(RngRequestTest, RejectsNullInfo)
{
    EXPECT_NE(ALC_ERROR_NONE, alcp_rng_supported(nullptr));
}

TEST(RngRequestTest, RejectsUnknownDistribution)
{
    alc_rng_info_t rng_info = osUniformRngInfo();
    rng_info.ri_distrib     = ALC_RNG_DISTRIB_UNKNOWN;

    EXPECT_NE(ALC_ERROR_NONE, alcp_rng_supported(&rng_info));
}

TEST(RngRequestTest, RejectsNullHandle)
{
    alc_rng_info_t rng_info = osUniformRngInfo();

    EXPECT_NE(ALC_ERROR_NONE, alcp_rng_request(&rng_info, nullptr));
}

} // namespace
