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

    Uint64* m_pHashSubkeyTable_global;

    __m128i m_tag_128;
    Uint64  m_additionalDataLen;

    _alc_cipher_gcm_data_t m_gcm;

} alc_gcm_local_data_t;

/*
 * @brief        AES Encryption in GCM(Galois Counter mode)
 * @note
 */

class ALCP_API_EXPORT Gcm : public Aes
{
  protected:
    alc_gcm_local_data_t m_gcm_local_data;

  public:
    Gcm(alc_cipher_data_t* ctx)
        : Aes(ctx)
    {
        // default ivLength is 12 bytes or 96bits
        m_ivLen_aes = 12;

        m_gcm_local_data.m_num_512blks_precomputed = 0;
        m_gcm_local_data.m_num_256blks_precomputed = 0;

        m_gcm_local_data.m_hash_subKey_128 = _mm_setzero_si128();
        m_gcm_local_data.m_gHash_128       = _mm_setzero_si128();
        m_gcm_local_data.m_counter_128     = _mm_setzero_si128();

        m_gcm_local_data.m_reverse_mask_128 =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        // global precomputed hashtable pointer
        m_gcm_local_data.m_pHashSubkeyTable_global =
            m_gcm_local_data.m_gcm.m_hashSubkeyTable;

        m_gcm_local_data.m_tag_128           = _mm_setzero_si128();
        m_gcm_local_data.m_additionalDataLen = 0;
    }

    ~Gcm()
    {
        // clear precomputed hashtable
        memset(m_gcm_local_data.m_pHashSubkeyTable_global,
               0,
               sizeof(Uint64) * MAX_NUM_512_BLKS * 8);
    }
};

AEAD_AUTH_CLASS_GEN(GcmGhash, Gcm)

namespace vaes512 {
    AES_CLASS_GEN(GcmAEAD128, GcmGhash)
    AES_CLASS_GEN(GcmAEAD192, GcmGhash)
    AES_CLASS_GEN(GcmAEAD256, GcmGhash)
} // namespace vaes512

namespace vaes {
    AES_CLASS_GEN(GcmAEAD128, GcmGhash)
    AES_CLASS_GEN(GcmAEAD192, GcmGhash)
    AES_CLASS_GEN(GcmAEAD256, GcmGhash)
} // namespace vaes

namespace aesni {
    AES_CLASS_GEN(GcmAEAD128, GcmGhash)
    AES_CLASS_GEN(GcmAEAD192, GcmGhash)
    AES_CLASS_GEN(GcmAEAD256, GcmGhash)
} // namespace aesni

} // namespace alcp::cipher
