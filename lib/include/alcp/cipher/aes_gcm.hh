/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"

#include "alcp/cipher/aes.hh"

#include "alcp/cipher/cipher_wrapper.hh"

#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher {

#define MAX_NUM_512_BLKS 8

#define UNROLL_2 _Pragma("GCC unroll 2")
#define UNROLL_8 _Pragma("GCC unroll 8")
#define UNROLL_4 _Pragma("GCC unroll 4")

/*
 * @brief        AES Encryption in GCM(Galois Counter mode)
 * @note
 */

class ALCP_API_EXPORT Gcm : public Aes
{
  public:
    __m128i m_reverse_mask_128; // local
    Uint64  m_dataLen;          // g_ctx

  public:
    Gcm()
        : Aes()
    {
        // default ivLength is 12 bytes or 96bits
        m_ivLen   = 12;
        m_dataLen = 0;
        m_reverse_mask_128 =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    }

    ~Gcm() {}
};

class ALCP_API_EXPORT GcmAuth
{
  public:
    __m128i m_tag_128;           // g_ctx
    Uint64  m_tagLen;            // g_ctx
    Uint64  m_additionalDataLen; // g_ctx
    __attribute__((aligned(64)))
    Uint64 m_hashSubkeyTable[MAX_NUM_512_BLKS * 8]; // g_ctx

    GcmAuthData m_gcmAuthData;

  public:
    GcmAuth()
    {
        m_tag_128           = _mm_setzero_si128();
        m_tagLen            = 0;
        m_additionalDataLen = 0;

        // gcmAuthData
        m_gcmAuthData.m_hash_subKey_128         = _mm_setzero_si128(); // local?
        m_gcmAuthData.m_gHash_128               = _mm_setzero_si128(); // g_ctx
        m_gcmAuthData.m_counter_128             = _mm_setzero_si128(); // g_ctx
        m_gcmAuthData.m_num_512blks_precomputed = 0;                   // g_ctx
        m_gcmAuthData.m_num_256blks_precomputed = 0;                   // g_ctx
    }
    ~GcmAuth()
    {
        memset(m_hashSubkeyTable, 0, sizeof(Uint64) * MAX_NUM_512_BLKS * 8);
    }
};

// Macro to generate authentication class, first is used for gcm and to be
// extended to other AEAD classes
#define AEAD_AUTH_CLASS_GEN(CHILD_NEW, PARENT1, PARENT2)                       \
    class ALCP_API_EXPORT CHILD_NEW                                            \
        : public PARENT1                                                       \
        , public PARENT2                                                       \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(){};                                                         \
        ~CHILD_NEW() {}                                                        \
                                                                               \
        alc_error_t getTag(Uint8* pOutput, Uint64 tagLen);                     \
        alc_error_t init(const Uint8* pKey,                                    \
                         Uint64       keyLen,                                  \
                         const Uint8* pIv,                                     \
                         Uint64       ivLen);                                        \
        alc_error_t setAad(const Uint8* pInput, Uint64 aadLen);                \
    };

AEAD_AUTH_CLASS_GEN(GcmGhash, Gcm, GcmAuth)

namespace vaes512 {
    AEAD_CLASS_GEN(GcmAEAD128, public GcmGhash)
    AEAD_CLASS_GEN(GcmAEAD192, public GcmGhash)
    AEAD_CLASS_GEN(GcmAEAD256, public GcmGhash)
} // namespace vaes512

namespace vaes {
    AEAD_CLASS_GEN(GcmAEAD128, public GcmGhash)
    AEAD_CLASS_GEN(GcmAEAD192, public GcmGhash)
    AEAD_CLASS_GEN(GcmAEAD256, public GcmGhash)
} // namespace vaes

namespace aesni {
    AEAD_CLASS_GEN(GcmAEAD128, public GcmGhash)
    AEAD_CLASS_GEN(GcmAEAD192, public GcmGhash)
    AEAD_CLASS_GEN(GcmAEAD256, public GcmGhash)
} // namespace aesni

} // namespace alcp::cipher
