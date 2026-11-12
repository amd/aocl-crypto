/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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
#include "alcp/error.h"

#include <new>

#define LOG_INFO (1)
#define LOG_DBG  (2)
#define LOG_ERR  (3)

/* add more logging levels here, and deeper level details */
#define ALCP_DEBUG_LOG(log_level, ...)                                         \
    do {                                                                       \
        printf("\t%s\t", __FUNCTION__);                                        \
        if (log_level >= LOG_DBG) {                                            \
            __VA_OPT__(printf(__VA_ARGS__));                                   \
        }                                                                      \
        printf("\n");                                                          \
    } while (0)

// Branch prediction hints for likely/unlikely paths
#if defined(__GNUC__) || defined(__clang__)
#define ALCP_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ALCP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define ALCP_LIKELY(x)   (x)
#define ALCP_UNLIKELY(x) (x)
#endif

// Original macro - used for non-critical paths where null is possible
#define ALCP_BAD_PTR_ERR_RET(ptr)                                              \
    if (nullptr == ptr) {                                                      \
        return ALC_ERROR_INVALID_DATA;                                         \
    }

// Optimized macro with branch prediction hint - null is UNLIKELY
// Use in hot paths where ptr should almost never be null
#define ALCP_BAD_PTR_ERR_RET_UNLIKELY(ptr)                                     \
    if (ALCP_UNLIKELY(nullptr == ptr)) {                                       \
        return ALC_ERROR_INVALID_DATA;                                         \
    }

// Consolidated null check for multiple pointers in hot path
// Combines checks to reduce branch overhead
#define ALCP_BAD_PTR2_ERR_RET(ptr1, ptr2)                                      \
    if (ALCP_UNLIKELY(nullptr == ptr1 || nullptr == ptr2)) {                   \
        return ALC_ERROR_INVALID_DATA;                                         \
    }

#define ALCP_BAD_PTR3_ERR_RET(ptr1, ptr2, ptr3)                                \
    if (ALCP_UNLIKELY(nullptr == ptr1 || nullptr == ptr2 ||                    \
                      nullptr == ptr3)) {                                      \
        return ALC_ERROR_INVALID_DATA;                                         \
    }

#define ALCP_BAD_PTR4_ERR_RET(ptr1, ptr2, ptr3, ptr4)                          \
    if (ALCP_UNLIKELY(nullptr == ptr1 || nullptr == ptr2 ||                    \
                      nullptr == ptr3 || nullptr == ptr4)) {                   \
        return ALC_ERROR_INVALID_DATA;                                         \
    }

#define ALCP_BAD_PTR5_ERR_RET(ptr1, ptr2, ptr3, ptr4, ptr5)                    \
    if (ALCP_UNLIKELY(nullptr == ptr1 || nullptr == ptr2 ||                    \
                      nullptr == ptr3 || nullptr == ptr4 ||                    \
                      nullptr == ptr5)) {                                      \
        return ALC_ERROR_INVALID_DATA;                                         \
    }

#define ALCP_ZERO_LEN_ERR_RET(len)                                             \
    if (0 == len) {                                                            \
        return ALC_ERROR_INVALID_SIZE;                                         \
    }

// Optimized length check with branch prediction
#define ALCP_ZERO_LEN_ERR_RET_UNLIKELY(len)                                    \
    if (ALCP_UNLIKELY(0 == len)) {                                             \
        return ALC_ERROR_INVALID_SIZE;                                         \
    }

/*
 * A C++ exception crossing an extern "C" boundary is undefined behaviour, so
 * every entry point ends in one of these handlers.
 */
namespace alcp {
/* Call only from a catch handler; classifies the in-flight exception. */
inline alc_error_t
currentExceptionToError()
{
    try {
        throw;
    } catch (const std::bad_alloc&) {
        return ALC_ERROR_NO_MEMORY;
    } catch (...) {
        return ALC_ERROR_GENERIC;
    }
}
} // namespace alcp

#define ALCP_CATCH_ERR_RET                                                     \
    catch (...) { return alcp::currentExceptionToError(); }

#define ALCP_CATCH_IGNORE                                                      \
    catch (...) {}

/* FIXME, use this in future */
#define ALCP_GENERIC_ERR_CHECK(param)                                          \
    do {                                                                       \
        if constexpr (std::is_pointer_v<decltype(param)>) {                    \
            if (nullptr == param) {                                            \
                return ALC_ERROR_INVALID_DATA;                                 \
            }                                                                  \
        } else if constexpr (std::is_integral_v<decltype(param)>) {            \
            if (0 == param) {                                                  \
                return ALC_ERROR_INVALID_SIZE;                                 \
            }                                                                  \
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
