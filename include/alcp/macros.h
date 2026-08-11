/*
 * Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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

#ifndef _ALCP_MACROS_H_
#define _ALCP_MACROS_H_ 2

#ifdef __cplusplus
#define EXTERN_C_BEGIN                                                         \
    extern "C"                                                                 \
    {
#define EXTERN_C_END }

#define EXTERN_C extern "C"
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif

/**
 * dllexport helps to explicitly export symbols on Windows.
 * Therefore, any new API's must first be declared with ALCP_API_EXPORT to load
 * on Windows.
 */
#ifdef WIN32
#define ALCP_API_EXPORT __declspec(dllexport)
#elif defined(__clang__)
#define ALCP_API_EXPORT __attribute__((visibility("default")))
#elif defined(__GNUC__)
#define ALCP_API_EXPORT __attribute__((visibility("default")))
#else
#define ALCP_API_EXPORT
#endif

#ifdef ALCP_INTERNAL_CPP_EXPORTS_ENABLED
#define ALCP_INTERNAL_CPP_EXPORT ALCP_API_EXPORT
#if defined(__clang__) && !defined(WIN32)
#define ALCP_EXPLICIT_TEMPLATE_EXPORT __attribute__((visibility("default")))
#else
#define ALCP_EXPLICIT_TEMPLATE_EXPORT
#endif
#else
#define ALCP_INTERNAL_CPP_EXPORT
#define ALCP_EXPLICIT_TEMPLATE_EXPORT
#endif

#define UNREF(x) (void)(x)
#endif /* _ALCP_MACROS_H_ */
