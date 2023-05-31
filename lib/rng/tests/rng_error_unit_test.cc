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
 */

#include "alcp/base.hh"
#include "alcp/rng.hh"
#include "gtest/gtest.h"
#include <iostream>

using namespace alcp;
using namespace rng;

TEST(ErrorTestRng, NoEntropy)
{
    String expected_message = "ALCP ERROR : Internal Error : Rng : Not Enough "
                              "Entropy : Specific Error Message";

    Status s   = StatusOk();
    auto   sts = rng::status::NoEntropy("Specific Error Message");
    EXPECT_EQ(expected_message, sts.message());
    s.update(sts);
    EXPECT_EQ(expected_message, s.message());
}

TEST(ErrorTestRng, NotPermitted)
{
    String expected_message = "ALCP ERROR : Invalid Argument : Rng : Not "
                              "Permitted : Specific Error Message";

    Status s   = StatusOk();
    auto   sts = rng::status::NotPermitted("Specific Error Message");
    EXPECT_EQ(expected_message, sts.message());
    s.update(sts);
    EXPECT_EQ(expected_message, s.message());
}

TEST(ErrorTestRng, NoEntropySource)
{
    String expected_message = "ALCP ERROR : Not Available : Rng : Entropy "
                              "source not defined : Specific Error Message";

    Status s   = StatusOk();
    auto   sts = rng::status::NoEntropySource("Specific Error Message");
    EXPECT_EQ(expected_message, sts.message());
    s.update(sts);
    EXPECT_EQ(expected_message, s.message());
}