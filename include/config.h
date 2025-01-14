/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
// config.h is cmake generated, please modify config.h.in instead.
#ifndef _INCLUDE_CONFIG_H
#define _INCLUDE_CONFIG_H 2

#define ALCP_CONFIG_LITTLE_ENDIAN

// CPU Identification
#define ALCP_ENABLE_AOCL_UTILS

// ALCP Release Version
#define AOCL_RELEASE_VERSION "5.0.0"
#define ALCP_RELEASE_VERSION_STRING "AOCL-Crypto 5.0.0 Build 20241010"

// ALCP Build environment
#define ALCP_BUILD_ENV "GCC_v11.4.0_Ubuntu_22.04"

// ALCP lib path
#define ALCP_LIB_OUTPUT_FILE_NAME_STRING                                  \
    "/projects/crypto/1/pjayaraj/OpenSourceCrypto/OSE/aocl-crypto/build/libalcp.so"

// Compiler Detection
/* #undef COMPILER_IS_CLANG */
#define COMPILER_IS_GCC
/* #undef COMPILER_IS_MSVC */

// OS Identification
#define ALCP_BUILD_OS_LINUX
/* #undef ALCP_BUILD_OS_WINDOWS */

// OpenSSL Overrides
#define ALCP_BIGNUM_USE_OPENSSL 1

// CPU Identification
#define ALCP_DISABLE_ASSEMBLY 0
/* #undef ALCP_CPUID_FORCE */
/* #undef ALCP_CPUID_DISABLE_AVX512 */
/* #undef ALCP_CPUID_DISABLE_AVX2 */
/* #undef ALCP_CPUID_DISABLE_AESNI */
/* #undef ALCP_CPUID_DISABLE_VAES */
/* #undef ALCP_CPUID_DISABLE_SHANI */
/* #undef ALCP_CPUID_DISABLE_RAND */
/* #undef ALCP_CPUID_DISABLE_AVX */
/* #undef ALCP_CPUID_DISABLE_BMI2 */
/* #undef ALCP_CPUID_DISABLE_ADX */
/* #undef ALCP_CPUID_FORCE_ZEN */
/* #undef ALCP_CPUID_FORCE_ZEN2 */
/* #undef ALCP_CPUID_FORCE_ZEN3 */
/* #undef ALCP_CPUID_FORCE_ZEN4 */
/* #undef ALCP_CPUID_FORCE_ZEN5 */

#endif /* _INCLUDE_CONFIG_H */
