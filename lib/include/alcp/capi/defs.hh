/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#pragma once

#include "alcp/base.hh"

#define ALCP_BAD_PTR_ERR_RET(ptr, err)                                         \
    do {                                                                       \
        using namespace alcp::base;                                            \
        if (nullptr == ptr) {                                                  \
            auto e = GenericError{ eInvalidArgument };                         \
            return (alc_error_t)e.code();                                      \
        }                                                                      \
    } while (0)

#define ALCP_ZERO_LEN_ERR_RET(len, err)                                        \
    do {                                                                       \
        using namespace alcp::base;                                            \
        if (0 == len) {                                                        \
            auto e = GenericError{ eInvalidArgument };                         \
            return (alc_error_t)e.code();                                      \
        }                                                                      \
    } while (0)

#if defined(ALCP_BUILD_OS_WINDOWS)
#if defined(VC)
#define ALCP_BUILD_COMPILER_IS_VC 1
#elif defined(__clang__)
#define ALCP_BUILD_COMPILER_IS_CLANG 1
#else
#warning "Unkown compiler"
#endif

#elif defined(ALCP_BUILD_OS_LINUX)
#if defined(__GNUC__)
#define ALCP_BUILD_COMPILER_IS_GCC 1
#elif defined(__clang__)
#define ALCP_BUILD_COMPILER_IS_CLANG 1
#else
#warning "Unkown compiler"
#endif
#endif

#if defined(ALCP_BUILD_OS_WINDOWS)
#define ALCP_ALIGN(x) __declspec align((x))
#elif defined(ALCP_BUILD_OS_LINUX)
#if defined(__cplusplus)
#define ALCP_ALIGN(x) alignas(x)
#else
#define ALCP_ALIGN(x) __attribute__((aligned((x))))
#endif
#else
#define ALCP_ALIGN(x)
#endif
