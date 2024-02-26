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

#include "gtest/gtest.h"

namespace {
using namespace alcp;
using namespace alcp::base;
using namespace alcp::base::status;

static Status
returnOkStatus()
{
    return StatusOk();
}

TEST(StatusTest, Equality)
{
    Status s = StatusOk();

    Status q = returnOkStatus();

    EXPECT_EQ(s, q);
}

TEST(StatusTest, OkStatus)
{
    Status s = StatusOk();

    EXPECT_TRUE(s.ok());
}

TEST(StatusTest, InternalError)
{
    String str{ "Testing Internal Error" };
    Status s = InternalError(str);

    EXPECT_FALSE(s.ok());
    EXPECT_EQ(s.code(), ErrorCode::eInternal);

    auto n = s.message().find(str);
    EXPECT_TRUE(n != std::string::npos);
}

TEST(StatusTest, UnknownError)
{
    String str{ "Testing Unknown Error" };
    Status s = status::Unknown(str);

    EXPECT_FALSE(s.ok());
    EXPECT_EQ(s.code(), ErrorCode::eUnknown);

    auto n = s.message().find(str);
    EXPECT_TRUE(n != std::string::npos);
}

TEST(StatusTest, InvalidArgument)
{
    String str{ "Testing Invalid Arugument Error" };
    Status s = status::InvalidArgument(str);

    EXPECT_FALSE(s.ok());
    EXPECT_EQ(s.code(), ErrorCode::eInvalidArgument);

    auto n = s.message().find(str);
    EXPECT_TRUE(n != std::string::npos);
}

TEST(StatusTest, AlreadyExists)
{
    String str{ "Testing Already Exists" };
    Status s = status::AlreadyExists(str);

    EXPECT_FALSE(s.ok());
    EXPECT_EQ(s.code(), ErrorCode::eExists);

    auto n = s.message().find(str);
    EXPECT_TRUE(n != std::string::npos);
}

TEST(StatusTest, NotFound)
{
    String str{ "Testing Not Found" };
    Status s = status::NotFound(str);

    EXPECT_FALSE(s.ok());
    EXPECT_EQ(s.code(), ErrorCode::eNotFound);

    auto n = s.message().find(str);
    EXPECT_TRUE(n != std::string::npos);
}

TEST(StatusTest, NotAvailable)
{
    String str{ "Testing Not Available Error" };
    Status s = status::NotAvailable(str);

    EXPECT_FALSE(s.ok());
    EXPECT_EQ(s.code(), ErrorCode::eNotAvailable);

    auto n = s.message().find(str);
    EXPECT_TRUE(n != std::string::npos);
}

} // namespace
