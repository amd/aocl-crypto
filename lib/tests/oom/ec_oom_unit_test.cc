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
 * Allocation-failure tests for the EC C API.
 *
 * EC builds its backend inside the caller's context, so a supported curve
 * allocates nothing. What allocates is its error reporting, because a Status
 * holds its message on the heap, which is where an exception used to escape the
 * C boundary.
 */

#include <vector>

#include <gtest/gtest.h>

#include "alcp/ec.h"
#include "alcp/ecdh.h"

#include "oom_inject.hh"

namespace {

using alcp::testing::oom::MaxProbes;
using alcp::testing::oom::under_oom;

alc_ec_info_t
info(alc_ec_curve_id curve)
{
    alc_ec_info_t ec_info{};
    ec_info.ecCurveId     = curve;
    ec_info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    ec_info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    return ec_info;
}

// An unimplemented curve is reported through a Status, whose message is the
// allocation being failed here.
TEST(EcOom, UnimplementedCurveIsReported)
{
    alc_ec_info_t good_info = info(ALCP_EC_CURVE25519);
    alc_ec_info_t bad_info  = info(ALCP_EC_MAX);
    bool          probed    = false;
    long          nth       = 0;

    for (; nth < MaxProbes; nth++) {
        SCOPED_TRACE(nth);
        std::vector<Uint8> context(alcp_ec_context_size(&good_info));
        alc_ec_handle_t    handle{};
        handle.context = reinterpret_cast<alc_ec_context_p>(context.data());

        auto out =
            under_oom(nth, [&] { return alcp_ec_request(&bad_info, &handle); });
        alcp_ec_finish(&handle);

        ASSERT_FALSE(out.threw) << "an exception escaped alcp_ec_request";
        EXPECT_NE(out.err, ALC_ERROR_NONE)
            << "an unimplemented curve was built";
        if (!out.fired) {
            break; // fewer allocations than this, so every one was probed
        }
        probed = true;
    }

    EXPECT_LT(nth, MaxProbes) << "the sweep ran out of probes";
    EXPECT_TRUE(probed) << "no allocation was failed, nothing tested";
}

} // namespace
