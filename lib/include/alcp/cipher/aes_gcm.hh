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

#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher {

#define UNROLL_2 _Pragma("GCC unroll 2")
#define UNROLL_8 _Pragma("GCC unroll 8")
#define UNROLL_4 _Pragma("GCC unroll 4")

typedef struct _alc_gcm_local_data
{
    // gcm specific params
    Int32 m_num_512blks_precomputed;
    Int32 m_num_256blks_precomputed;

    __m128i m_hash_subKey_128;
    __m128i m_gHash_128;
    __m128i m_counter_128;

    __m128i m_reverse_mask_128;

} alc_gcm_local_data_t;

/*
 * @brief        AES Encryption in GCM(Galois Counter mode)
 * @note
 */

class ALCP_API_EXPORT Gcm : public Aes
{
  public:
    alc_gcm_local_data_t m_gcm_local_data;

  public:
    Gcm()
        : Aes()
    {
        // default ivLength is 12 bytes or 96bits
        m_cipherData.m_ivLen = 12;

        // cipher ctx
        m_cipherData.m_tag_128 = _mm_setzero_si128();

        // gcm local ctx
        m_gcm_local_data.m_hash_subKey_128 = _mm_setzero_si128();
        m_gcm_local_data.m_gHash_128       = _mm_setzero_si128();
        m_gcm_local_data.m_counter_128     = _mm_setzero_si128();

        m_gcm_local_data.m_num_512blks_precomputed = 0;
        m_gcm_local_data.m_num_256blks_precomputed = 0;

        m_gcm_local_data.m_reverse_mask_128 =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    }

    ~Gcm()
    {
        memset(m_cipherData.m_gcm.m_hashSubkeyTable,
               0,
               sizeof(Uint64) * MAX_NUM_512_BLKS * 8);
    }
};

AEAD_AUTH_CLASS_GEN(GcmGhash, Gcm)

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
