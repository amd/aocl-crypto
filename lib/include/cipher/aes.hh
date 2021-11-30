/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#ifndef _CIPHER_AES_HH_
#define _CIPHER_AES_HH_ 2

#pragma GCC target("avx,avx2,vaes,fma")

#include <array>
#include <cstdint>
#include <functional>

#include "alcp/cipher.h"

#include "algorithm.hh"
#include "cipher.hh"
#include "error.hh"

namespace alcp::cipher {

typedef std::function<bool(const uint8_t*, uint8_t*, uint8_t*) const> Funcs;

class Rijndael
    : public BlockCipher
    , public Algorithm
{
  protected:
    cipher::Context m_ctx;
    uint64_t        m_nrounds;
    uint64_t        m_key_size;

  protected:
    Rijndael() {}
    virtual ~Rijndael() {}
};

/*
 * \brief       AES (Advanced Encryption Standard)
 *
 * \notes       AES is currently same as Rijndael, This may be renamed to
 *              other as well in the future.
 *
 */
class Aes : public Rijndael
{
  public:
    Aes() {}

    virtual ~Aes() {}

  protected:
    alc_aes_mode_t m_mode;
};

/*
 * \brief        AES Encryption in CFB(Cipher Feedback mode)
 * \notes        TODO: Move this to a aes_cbc.hh or other for now we are
 * good to go here
 */
class Cfb final
    : public Aes
    , public CipherAlgorithm
{
  public:
    Cfb() {}
    ~Cfb() {}

  public:
    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual uint64_t getContextSize(const alc_cipher_info_p pCipherInfo,
                                    alc_error_t&            err) final;
    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_p pCipherInfo,
                             alc_error_t&            err) final;

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint8_t*       pKey,
                                uint64_t       len) final;
};

class AesBuilder
{
  public:
    static Aes* Build(alc_cipher_info_p pCipherInfo, alc_error_t& err)
    {
        Aes* aes = nullptr;

        switch (pCipherInfo->mode_data.aes.mode) {
            case ALC_AES_MODE_CFB:
                auto cfb_algo = new Cfb();
                cfb_algo->isSupported(pCipherInfo, err);
                if (Error::isError(err)) {
                    delete cfb_algo;
                }
                aes = cfb_algo;
                break;
        }
        return aes;
    }
};

namespace aesni {
    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           uint8_t*       pKey,
                           int            nRounds,
                           const uint8_t* pIv);

} // namespace aesni

namespace aesni {

#include <immintrin.h>

    static inline __m256i amd_mm256_broadcast_i64x2(const __m128i* rkey)
    {
        const uint64_t* key64 = (const uint64_t*)rkey;
        return _mm256_set_epi64x(key64[1], key64[0], key64[1], key64[0]);
    }

    /* One block at a time */
    static inline void AESEncrypt(__m256i*       blk0,
                                  const __m128i* rkey, /* Round key */
                                  int            nrounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rkey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rkey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);

        rKey0 = amd_mm256_broadcast_i64x2(&rkey[2]);

        for (nr = 1, rkey++; nr < nrounds; nr += 2, rkey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rkey[2]);
            b0    = _mm256_aesenc_epi128(b0, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rkey[3]);
        }

        b0    = _mm256_aesenc_epi128(b0, rKey1);
        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* Two blocks at a time */
    static void AESEncrypt(__m256i*       blk0,
                           __m256i*       blk1,
                           const __m128i* rkey, /* Round key */
                           int            nrounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rkey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rkey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rkey[2]);

        for (nr = 1, rkey++; nr < nrounds; nr += 2, rkey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rkey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rkey[3]);
        }

        b0 = _mm256_aesenc_epi128(b0, rKey1);
        b1 = _mm256_aesenc_epi128(b1, rKey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* Three blocks at a time */
    static void AESEncrypt(__m256i*       blk0,
                           __m256i*       blk1,
                           __m256i*       blk2,
                           const __m128i* rkey, /* Round keys */
                           int            nrounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rkey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rkey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rkey[2]);

        for (nr = 1, rkey++; nr < nrounds; nr += 2, rkey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            b2    = _mm256_aesenc_epi128(b2, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rkey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            b2    = _mm256_aesenc_epi128(b2, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rkey[3]);
        }

        b0 = _mm256_aesenc_epi128(b0, rKey1);
        b1 = _mm256_aesenc_epi128(b1, rKey1);
        b2 = _mm256_aesenc_epi128(b2, rKey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rKey0);
        *blk2 = _mm256_aesenclast_epi128(b2, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* 4 blocks at a time */
    static void AESEncrypt(__m256i*       blk0,
                           __m256i*       blk1,
                           __m256i*       blk2,
                           __m256i*       blk3,
                           const __m128i* rkey, /* Round keys */
                           int            nrounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rkey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rkey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
        __m256i b3 = _mm256_xor_si256(*blk3, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rkey[2]);

        for (nr = 1, rkey++; nr < nrounds; nr += 2, rkey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            b2    = _mm256_aesenc_epi128(b2, rKey1);
            b3    = _mm256_aesenc_epi128(b3, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rkey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            b2    = _mm256_aesenc_epi128(b2, rKey0);
            b3    = _mm256_aesenc_epi128(b3, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rkey[3]);
        }

        b0 = _mm256_aesenc_epi128(b0, rKey1);
        b1 = _mm256_aesenc_epi128(b1, rKey1);
        b2 = _mm256_aesenc_epi128(b2, rKey1);
        b3 = _mm256_aesenc_epi128(b3, rKey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rKey0);
        *blk2 = _mm256_aesenclast_epi128(b2, rKey0);
        *blk3 = _mm256_aesenclast_epi128(b3, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    namespace experimantal {
        static void AESEncrypt(__m256i*       blk0,
                               __m256i*       blk1,
                               __m256i*       blk2,
                               __m256i*       blk3,
                               const __m128i* rkey, /* Round keys */
                               int            nrounds)
        {
            int nr;

            __m256i rKey0 = amd_mm256_broadcast_i64x2(&rkey[0]);

            __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
            __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
            __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
            __m256i b3 = _mm256_xor_si256(*blk3, rKey0);
            rKey0      = amd_mm256_broadcast_i64x2(&rkey[1]);

            for (nr = 1, rkey++; nr < nrounds; nr++, rkey++) {
                b0    = _mm256_aesenc_epi128(b0, rKey0);
                b1    = _mm256_aesenc_epi128(b1, rKey0);
                b2    = _mm256_aesenc_epi128(b2, rKey0);
                b3    = _mm256_aesenc_epi128(b3, rKey0);
                rKey0 = amd_mm256_broadcast_i64x2(&rkey[2]);
            }

            *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
            *blk1 = _mm256_aesenclast_epi128(b1, rKey0);
            *blk2 = _mm256_aesenclast_epi128(b2, rKey0);
            *blk3 = _mm256_aesenclast_epi128(b3, rKey0);

            rKey0 = _mm256_setzero_si256();
        }
    } // namespace experimantal

} // namespace aesni

} // namespace alcp::cipher

#endif /* _CIPHER_AES_H_ */
