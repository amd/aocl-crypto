/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include <string_view>

#include "exception.hh"
#include "sourcelocation.hh"

namespace alcp {

#if defined(DEBUG) || defined(ALCP_DEBUG)
// FIXME: default enabled now
#define ALCP_USE_ASSERTIONS 1
#endif

#if defined(ALCP_USE_ASSERTIONS)
static constexpr bool AssertionsBuild = true;
#else
static constexpr bool AssertionsBuild = false;
#endif

/**
 * @brief Assert using exceptions
 *
 * @tparam T Assert condition
 * @tparam E Exception to raise when assertion condition fails
 * @param assrt     is of type T
 * @param s         Source code location to print FILE:LINE:FUNCTION
 */
template<typename T, typename E = FatalErrorException>
inline void
Assert(T&& assrt, std::string_view s, const SourceLocation& loc)
{
    if constexpr (AssertionsBuild) {
        if (!assrt) {
            E throwing{ loc, string{ s } };
            throw throwing;
        }
    }
}

#if defined(ALCP_USE_ASSERTIONS)

#define ALCP_ASSERT(cond, msg)                                                      \
    alcp::Assert(cond, std::string_view(msg), ALCP_SOURCE_LOCATION())

#else

#define ALCP_ASSERT(cond, msg)              \
    do {                                    \
    } while(0)

#endif // if ALCP_USE_ASSERTIONS

} // namespace alcp
