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

namespace aesni {
    alc_error_t GenRoundKeys(uint8_t* key, uint8_t* userKey);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

} // namespace aesni

class Rijndael : public BlockCipher
//, public Algorithm
{
  public:
    static int constexpr cAlignment     = 16;
    static int constexpr cAlignmentWord = cAlignment / 4;

    static int constexpr cMaxKeySize      = 256;
    static int constexpr cMaxKeySizeBytes = cMaxKeySize / 8;

    /* Message size, key size, etc */
    enum BlockSize
    {
        eBits128 = 128,
        eBits192 = 192,
        eBits256 = 256,

        eBytes128 = eBits128 / 8,
        eBytes192 = eBits192 / 8,
        eBytes256 = eBits256 / 8,

        eWords128 = eBytes128 / 4,
        eWords192 = eBytes192 / 4,
        eWords256 = eBytes256 / 4,
    };

    constexpr int BitsToBytes(int cBits) { return cBits / 8; }
    constexpr int BitsToWord(int cBits) { return cBits / 32; }
    constexpr int BytesToWord(int cBytes) { return cBytes / 4; }

  public:
    uint64_t       getRounds() { return m_nrounds; }
    uint64_t       getKeySize() { return m_key_size; }
    const uint8_t* getKey() { return m_key; }

  protected:
    Rijndael() {}
    Rijndael(uint8_t* userKey) { genRoundKeys(userKey); }
    virtual ~Rijndael() {}

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)
  protected:
    uint8_t  m_key[RIJ_SIZE_ALIGNED(cMaxKeySizeBytes)];
    uint64_t m_nrounds;
    uint64_t m_key_size;

  private:
    void genRoundKeys(uint8_t* userKey)
    {
        if (isAesniAvailable()) {
            aesni::GenRoundKeys(m_key, userKey);
            return;
        }
        /* Default Key expansion */
    }
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
    Aes(const alc_aes_info_t& aesInfo)
        : m_mode{ aesInfo.mode }
    {}

  protected:
    Aes() {}
    virtual ~Aes() {}

  protected:
    alc_aes_mode_t m_mode;
};

/*
 * \brief        AES Encryption in CFB(Cipher Feedback mode)
 * \notes        TODO: Move this to a aes_cbc.hh or other
 */
class Cfb final : public Aes
{
  public:
    Cfb(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo)
    {
        /* TODO: Populate IV */
        // memcpy(m_iv, pAesInfo, 256);
    }

    ~Cfb() {}

  public:
    static bool isSupported(const alc_aes_info_t& cipherInfo,
                            const alc_key_info_t& keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo,
                             alc_error_t&             err) override
    {
        Error::setDetail(err, ALC_ERROR_NOT_SUPPORTED);

        if (cipherInfo.cipher_type == ALC_CIPHER_TYPE_AES) {
            if (cipherInfo.mode_data.aes.mode == ALC_AES_MODE_CFB) {
                Error::setDetail(err, ALC_ERROR_NONE);
                return true;
            }
        }

        return false;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual alc_error_t encrypt(const uint8_t* pPlainText,
                                uint8_t*       pCipherText,
                                uint64_t       len,
                                const uint8_t* pKey,
                                const uint8_t* pIv) const final
    {
        alc_error_t err = ALC_ERROR_NONE;

        // TODO: Check for CPUID before dispatching
        if (Cipher::isAesniAvailable()) {
            // dispatch to VAESNI
        }

        // dispatch to REF

        return err;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint64_t       len,
                                const uint8_t* pKey,
                                const uint8_t* pIv) const final
    {
        alc_error_t err = ALC_ERROR_NONE;

        // TODO: Check for CPUID before dispatching
        if (Cipher::isAesniAvailable()) {
            // dispatch to VAESNI
            err = aesni::DecryptCfb(
                pCipherText, pPlainText, len, pKey, m_nrounds, pIv);

            return err;
        }

        // dispatch to REF

        return err;
    }

  private:
    Cfb() = default;

  private:
    uint8_t m_iv[256]; /* Initialization Vector */
};

class AesBuilder
{
  public:
    static Cipher* Build(const alc_aes_info_t& aesInfo,
                         const alc_key_info_t& keyInfo,
                         alc_cipher_handle_p   pCipherHandle,
                         alc_error_t&          err);
};

class CipherBuilder
{
  public:
    static Cipher* Build(const alc_cipher_info_t& cipherInfo,
                         alc_cipher_handle_p      pCipherHandle,
                         alc_error_t&             err);
};

namespace aesni {

#include <immintrin.h>

    static inline __m256i amd_mm256_broadcast_i64x2(const __m128i* rKey)
    {
        const uint64_t* key64 = (const uint64_t*)rKey;
        return _mm256_set_epi64x(key64[1], key64[0], key64[1], key64[0]);
    }

    /* One block at a time */
    static inline void AESEncrypt(__m256i*       blk0,
                                  const __m128i* rKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);

        rKey0 = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);
            b0    = _mm256_aesenc_epi128(b0, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
        }

        b0    = _mm256_aesenc_epi128(b0, rKey1);
        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* Two blocks at a time */
    static void AESEncrypt(__m256i*       blk0,
                           __m256i*       blk1,
                           const __m128i* rKey, /* Round key */
                           int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
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
                           const __m128i* rKey, /* Round keys */
                           int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            b2    = _mm256_aesenc_epi128(b2, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            b2    = _mm256_aesenc_epi128(b2, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
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
                           const __m128i* rKey, /* Round keys */
                           int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
        __m256i b3 = _mm256_xor_si256(*blk3, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            b2    = _mm256_aesenc_epi128(b2, rKey1);
            b3    = _mm256_aesenc_epi128(b3, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            b2    = _mm256_aesenc_epi128(b2, rKey0);
            b3    = _mm256_aesenc_epi128(b3, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
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
                               const __m128i* rKey, /* Round keys */
                               int            nRounds)
        {
            int nr;

            __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);

            __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
            __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
            __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
            __m256i b3 = _mm256_xor_si256(*blk3, rKey0);
            rKey0      = amd_mm256_broadcast_i64x2(&rKey[1]);

            for (nr = 1, rKey++; nr < nRounds; nr++, rKey++) {
                b0    = _mm256_aesenc_epi128(b0, rKey0);
                b1    = _mm256_aesenc_epi128(b1, rKey0);
                b2    = _mm256_aesenc_epi128(b2, rKey0);
                b3    = _mm256_aesenc_epi128(b3, rKey0);
                rKey0 = amd_mm256_broadcast_i64x2(&rKey[2]);
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
