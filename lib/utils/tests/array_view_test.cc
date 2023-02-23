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

#include "alcp/utils/array_view.hh"

#include "gtest/gtest.h"

namespace {

using namespace std;
using namespace alcp;

TEST(ArrayView, nullpointer_access)
{
    void*  p    = nullptr;
    size_t size = 0;

    auto x = [=]() {
        ArrayView<Uint8> av{ p, size };
        av[0] = 1;
    };

#ifdef WIN32
    ASSERT_EXIT(x(), ::testing::ExitedWithCode(1), ".*");
#else
    ASSERT_EXIT(x(), ::testing::KilledBySignal(SIGSEGV), ".*");
#endif
}

TEST(ArrayView, assignment_reuse)
{
    auto   p    = new Uint8[10];
    size_t size = 10;

    std::memset(p, 0, 10 * sizeof(Uint8));

    auto x = [=]() {
        ArrayView<Uint8> av{ p, size };
        av[9] = 1;
    };

    x();

    EXPECT_EQ(p[9], 1);
}

TEST(ArrayView, access_as)
{
    constexpr size_t size = 20;
    Uint8            p[size]{
                   0,
    };

    // std::memset(p, 0, 20 * sizeof(Uint8));

    auto x = [&]() {
        ArrayView<Uint32> av{ p, size / 4 };
        av[1] = 0x01abcdef;
    };

    x();

    EXPECT_EQ((int)p[4], (int)0xef);
    EXPECT_EQ((int)p[5], (int)0xcd);
    EXPECT_EQ((int)p[6], (int)0xab);
    EXPECT_EQ((int)p[8], (int)0x0);
}

TEST(ArrayView, access_as_heap)
{
    constexpr size_t size = 20;
    auto             p    = new Uint8[size];

    std::memset(p, 0, size * sizeof(Uint8));

    auto x = [&]() {
        ArrayView<Uint32> av{ p, size / 4 };
        av[0] = 0x01abcdef;
    };

    x();

    EXPECT_EQ((int)p[0], (int)0xef);
    EXPECT_EQ((int)p[1], (int)0xcd);
    EXPECT_EQ((int)p[2], (int)0xab);
}

} // namespace
