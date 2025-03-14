/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher/cipher_common.hh"

#include <cstdint>
#include <immintrin.h>

#ifdef GCM_ALWAYS_COMPUTE
// 1: always compute, 0: compute, store and load from table
#define ALWAYS_COMPUTE 1
#else
#define ALWAYS_COMPUTE 0
#endif

/*
- Always compute without storage works well for real-world application where
init is called for every update call.
- OpenSSL speed uses single init and multiple update calls.
   - In such cases, it is better to store the precomputed table and load from
the table.
- By choosing always compute without storing, we are favoring real-world
application instead of OpenSSL speed or internal MicroBenchmark
*/

namespace alcp::cipher {

/*
 * @brief        AES Encryption in GCM(Galois Counter mode)
 * @note
 */

#define ALCP_GCM_TAG_MAX_SIZE 16
#define MAX_NUM_512_BLKS      8

typedef struct _alc_cipher_gcm_key_data
{
    __attribute__((aligned(64))) Uint64 m_hashSubkeyTable[MAX_NUM_512_BLKS * 8];

} _alc_cipher_gcm_key_data_t;

typedef struct _alc_gcm_ctx
{
    // gcm specific params
    Int32  m_num_512blks_precomputed;
    Int32  m_num_256blks_precomputed;
    Uint64 m_update_counter = 0;

    __m128i m_hash_subKey_128;
    __m128i m_gHash_128;
    __m128i m_counter_128;
    __m128i m_reverse_mask_128;
    __m128i m_tag_128;
    Uint64  m_additionalDataLen;
#if !ALWAYS_COMPUTE
    _alc_cipher_gcm_key_data_t m_gcm_key_data{};
    Uint64*                    m_pHashSubkeyTable_precomputed = nullptr;
#endif
} alc_gcm_ctx_t;
class ALCP_API_EXPORT Gcm
    : public Aes
    , public virtual iCipher
{
  protected:
    alc_gcm_ctx_t m_gcm_ctx;

  public:
    Gcm(Uint32 keyLen_in_bytes)
        : Aes(keyLen_in_bytes)
    {
        setMode(CipherMode::eAesGCM);
        // default ivLength is 12 bytes or 96bits
        m_ivLen_aes = 12;

        m_gcm_ctx.m_num_512blks_precomputed = 0;
        m_gcm_ctx.m_num_256blks_precomputed = 0;
        m_gcm_ctx.m_update_counter          = 0;

        m_gcm_ctx.m_hash_subKey_128 = _mm_setzero_si128();
        m_gcm_ctx.m_gHash_128       = _mm_setzero_si128();
        m_gcm_ctx.m_counter_128     = _mm_setzero_si128();

        m_gcm_ctx.m_reverse_mask_128 =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
#if !ALWAYS_COMPUTE
        // global precomputed hashtable pointer
        m_gcm_ctx.m_pHashSubkeyTable_precomputed =
            m_gcm_ctx.m_gcm_key_data.m_hashSubkeyTable;
#endif
        m_gcm_ctx.m_tag_128           = _mm_setzero_si128();
        m_gcm_ctx.m_additionalDataLen = 0;
    }

    ~Gcm()
    {
#if !ALWAYS_COMPUTE
        // clear precomputed hashtable
        if (m_gcm_ctx.m_pHashSubkeyTable_precomputed != nullptr) {
            memset(m_gcm_ctx.m_pHashSubkeyTable_precomputed,
                   0,
                   sizeof(Uint64) * MAX_NUM_512_BLKS * 8);
        }
#endif
    }

    void setTable(alc_cipher_state_t* pCipherState)
    {
#if !ALWAYS_COMPUTE
        if (pCipherState != nullptr) {
            // printf("setTable\n");
            m_gcm_ctx.m_pHashSubkeyTable_precomputed =
                pCipherState->alcp_precomputed_table;
        }
#endif
    }

    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override;
};

// GCM authentication class
class ALCP_API_EXPORT GcmAuth
    : public Gcm
    , public virtual iCipherAuth
{
  public:
    GcmAuth(Uint32 keyLen_in_bytes)
        : Gcm(keyLen_in_bytes)
    {}
    ~GcmAuth() {}

    alc_error_t setAad(const Uint8* pInput, Uint64 aadLen) override;
    alc_error_t getTag(Uint8* pTag, Uint64 tagLen) override;
    alc_error_t setTagLength(Uint64 tagLen) override;
};

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
class GcmT
    : public GcmAuth
    , public virtual iCipherAead
{
  public:
    GcmT()
        : GcmAuth((static_cast<Uint32>(keyLenBits)) / 8)
    {}

    GcmT(alc_cipher_state_t* pCipherState)
        : GcmAuth((static_cast<Uint32>(keyLenBits)) / 8)
    {
        setTable(pCipherState);
    }

    ~GcmT() = default;

  public:
    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len) override;
    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len) override;
    alc_error_t finish(const void*) override { return ALC_ERROR_NONE; }
};

} // namespace alcp::cipher
