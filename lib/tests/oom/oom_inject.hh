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

/*
 * A global operator new that can be made to fail on a chosen allocation.
 *
 * Replacing operator new in a test executable interposes for libalcp.so too, so
 * one of the library's own allocations can be failed on demand. Two properties
 * are checked at once, because the throwing forms here do throw: the library
 * must report the failure, and no exception may leave an extern "C" entry
 * point.
 *
 * Only the scalar forms are replaced. libstdc++ implements the array and
 * nothrow forms in terms of them, and its operator delete frees with free(),
 * which is compatible with the malloc used here.
 *
 * This header defines the replacements, so exactly one translation unit per
 * executable may include it, and that executable must not be built with
 * ALCP_SANITIZE=ON, which has interceptors of its own, nor run under Valgrind,
 * which redirects operator new to its own allocator in every object and so
 * never reaches the replacement.
 *
 * Linux only, on two counts: std::aligned_alloc is absent from the Microsoft
 * C++ library, and on Windows a replacement in the executable does not
 * interpose for a DLL that links its own runtime.
 */

#pragma once

#include <cstdlib>
#include <new>
#include <vector>

#include <gtest/gtest.h>

#include "alcp/error.h"

namespace alcp::testing::oom {

// -1 disarms. Otherwise the allocation that brings the counter to zero fails.
inline thread_local long g_countdown = -1;
inline thread_local bool g_fired     = false;

inline bool
should_fail()
{
    if (g_countdown < 0) {
        return false;
    }
    if (g_countdown-- == 0) {
        return g_fired = true;
    }
    return false;
}

inline void*
aligned(std::size_t size, std::size_t alignment)
{
    // aligned_alloc requires a size that is a multiple of the alignment
    const std::size_t rounded = (size + alignment - 1) & ~(alignment - 1);
    return std::aligned_alloc(alignment, rounded != 0 ? rounded : alignment);
}

struct Outcome
{
    alc_error_t err;
    bool        threw;
    bool        fired;
};

// Runs one call with the nth allocation failing. The window has to be this
// tight because gtest allocates freely, so nothing that can allocate may run
// while armed.
template<typename Fn>
Outcome
under_oom(long nth, Fn&& call)
{
    Outcome outcome{ ALC_ERROR_NONE, false, false };
    g_fired     = false;
    g_countdown = nth;
    try {
        outcome.err = call();
    } catch (...) {
        outcome.threw = true;
    }
    g_countdown   = -1;
    outcome.fired = g_fired;
    return outcome;
}

// A sweep that reaches this has not covered every allocation on the path, so
// the tests assert they stopped before it rather than silently testing less.
constexpr long MaxProbes = 32;

// Fails each of the first allocations of a request in turn. The context is
// allocated and the handle released outside the armed window.
template<typename Request, typename Finish>
void
probe_request(Uint64 contextSize, Request&& request, Finish&& finish)
{
    bool failure_reported = false;
    long nth              = 0;

    for (; nth < MaxProbes; nth++) {
        SCOPED_TRACE(nth);
        std::vector<Uint8> context(contextSize);

        auto out = under_oom(nth, [&] { return request(context.data()); });
        finish(context.data());

        ASSERT_FALSE(out.threw) << "an exception escaped the C API";
        if (out.err != ALC_ERROR_NONE) {
            failure_reported = true;
            EXPECT_EQ(out.err, ALC_ERROR_NO_MEMORY);
        }
        if (!out.fired) {
            break; // fewer allocations than this, so every one was probed
        }
    }

    EXPECT_LT(nth, MaxProbes) << "the sweep ran out of probes";
    EXPECT_TRUE(failure_reported) << "no failure was reported, nothing tested";
}

} // namespace alcp::testing::oom

void*
operator new(std::size_t size)
{
    void* p = alcp::testing::oom::should_fail()
                  ? nullptr
                  : std::malloc(size != 0 ? size : 1);
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    return p;
}

void*
operator new(std::size_t size, const std::nothrow_t&) noexcept
{
    return alcp::testing::oom::should_fail()
               ? nullptr
               : std::malloc(size != 0 ? size : 1);
}

void*
operator new(std::size_t size, std::align_val_t align)
{
    void* p = alcp::testing::oom::should_fail()
                  ? nullptr
                  : alcp::testing::oom::aligned(
                      size, static_cast<std::size_t>(align));
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    return p;
}

void*
operator new(std::size_t      size,
             std::align_val_t align,
             const std::nothrow_t&) noexcept
{
    return alcp::testing::oom::should_fail()
               ? nullptr
               : alcp::testing::oom::aligned(size,
                                             static_cast<std::size_t>(align));
}

// The injector is process wide, so every executable proves it works before
// relying on it.
TEST(OomInjector, FailsTheRequestedAllocation)
{
    using alcp::testing::oom::under_oom;

    auto nothrow_alloc = under_oom(0, [] {
        void* p = ::operator new(16, std::nothrow);
        if (p == nullptr) {
            return ALC_ERROR_NO_MEMORY;
        }
        ::operator delete(p);
        return ALC_ERROR_NONE;
    });
    EXPECT_EQ(nothrow_alloc.err, ALC_ERROR_NO_MEMORY);
    EXPECT_FALSE(nothrow_alloc.threw);

    auto throwing_alloc = under_oom(0, [] {
        ::operator delete(::operator new(16));
        return ALC_ERROR_NONE;
    });
    EXPECT_TRUE(throwing_alloc.threw);

    void* p = ::operator new(16, std::nothrow); // disarmed again
    EXPECT_NE(p, nullptr);
    ::operator delete(p);
}
