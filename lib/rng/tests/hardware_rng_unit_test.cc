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

#include "../../rng/include/hardware_rng.hh"
#include "alcp/base.hh"
#include "alcp/utils/cpuid.hh"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <set>
#include <vector>

using alcp::rng::HardwareRng;
using alcp::utils::CpuId;

namespace {

constexpr Uint8  cFill       = 0xCC;
constexpr size_t cGuardBytes = 8;

/*
 * A single trial cannot tell "RDRAND wrote this byte" from "RDRAND happened to
 * write back the fill value", which is a 1-in-256 event. Counting how many
 * distinct values a byte takes over several trials removes that ambiguity: a
 * byte that is never written keeps the fill on every trial and yields exactly
 * one value.
 */
constexpr int cTrials = 16;

void
expectEveryByteRandomized(Uint8* output, size_t length)
{
    HardwareRng rng;

    std::vector<std::set<Uint8>> observed(length);

    for (int trial = 0; trial < cTrials; trial++) {
        std::fill_n(output, length + cGuardBytes, cFill);

        EXPECT_EQ(rng.randomize(output, length), ALC_ERROR_NONE);

        for (size_t i = 0; i < length; i++) {
            observed[i].insert(output[i]);
        }
        for (size_t i = 0; i < cGuardBytes; i++) {
            ASSERT_EQ(output[length + i], cFill)
                << "wrote past the requested length " << length;
        }
    }

    for (size_t i = 0; i < length; i++) {
        EXPECT_GT(observed[i].size(), 1U)
            << "byte " << i << " of a " << length
            << " byte request never changed over " << cTrials << " calls";
    }
}

void
expectEveryByteRandomized(size_t length)
{
    std::vector<Uint8> buffer(length + cGuardBytes);
    expectEveryByteRandomized(buffer.data(), length);
}

class HardwareRngTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        if (!CpuId::cpuHasRdRand()) {
            GTEST_SKIP() << "RDRAND not available on this CPU";
        }
    }
};

TEST_F(HardwareRngTest, OddLengthRandomizesEveryByte)
{
    for (size_t length : { 1U, 3U, 5U, 7U, 15U, 33U, 65U }) {
        expectEveryByteRandomized(length);
    }
}

TEST_F(HardwareRngTest, EvenLengthRandomizesEveryByte)
{
    for (size_t length : { 2U, 4U, 8U, 16U, 32U, 64U }) {
        expectEveryByteRandomized(length);
    }
}

/*
 * The public C API accepts any Uint8 pointer, so the output buffer is not
 * guaranteed to be suitably aligned for a wider store.
 */
TEST_F(HardwareRngTest, UnalignedOutputRandomizesEveryByte)
{
    for (size_t length : { 1U, 2U, 3U, 16U, 33U }) {
        std::vector<Uint8> buffer(length + cGuardBytes + 1);
        Uint8*             unaligned = buffer.data() + 1;

        ASSERT_NE(reinterpret_cast<uintptr_t>(unaligned) % sizeof(Uint16), 0U);
        expectEveryByteRandomized(unaligned, length);
    }
}

TEST_F(HardwareRngTest, ZeroLengthSucceeds)
{
    HardwareRng rng;
    Uint8       output[cGuardBytes];

    std::fill_n(output, cGuardBytes, cFill);
    EXPECT_EQ(rng.randomize(output, 0), ALC_ERROR_NONE);
    for (size_t i = 0; i < cGuardBytes; i++) {
        EXPECT_EQ(output[i], cFill);
    }
}

} // namespace
