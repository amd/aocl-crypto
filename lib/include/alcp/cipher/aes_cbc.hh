/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/cipher.h"
#include "alcp/cipher.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/cipher/rijndael.hh"
#include "alcp/utils/bits.hh"
#include "alcp/utils/cpuid.hh"

#include <immintrin.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;

namespace alcp::cipher {

/*
 * @brief        AES Encryption in CBC(Cipher block chaining)
 */
template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          int          nRounds,
                          const Uint8* pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          int          nRounds,
                          const Uint8* pIv)>
class ALCP_API_EXPORT Cbc final
    : public ICipher
    , public Aes
{
  public:
    explicit Cbc(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    explicit Cbc(const Uint8* pKey, const Uint32 keyLen)
        : Aes(pKey, keyLen)
    {}

    Cbc() {}

    ~Cbc() {}

    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    static bool isSupported(const Uint32 keyLen)
    {
        if ((keyLen == ALC_KEY_LEN_128) || (keyLen == ALC_KEY_LEN_192)
            || (keyLen == ALC_KEY_LEN_256)) {
            return true;
        }
        return false;
    }

    /**
     * @brief   CBC Encrypt Operation
     * @note
     * @param   pPlainText      Pointer to output buffer
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * @brief   CBC Decrypt Operation
     * @note
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;
};

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          int          nRounds,
                          const Uint8* pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          int          nRounds,
                          const Uint8* pIv)>
alc_error_t
Cbc<FEnc, FDec>::decrypt(const Uint8* pCipherText,
                         Uint8*       pPlainText,
                         Uint64       len,
                         const Uint8* pIv) const
{
#if 0
    alc_error_t err = ALC_ERROR_NONE;
    if (CpuId::cpuHasAvx512(utils::AVX512_F)
        && CpuId::cpuHasAvx512(utils::AVX512_DQ)
        && CpuId::cpuHasAvx512(utils::AVX512_BW)) {
        err = vaes512::DecryptCbcAvx512(
            pCipherText, pPlainText, len, getDecryptKeys(), getRounds(), pIv);

        return err;
    }
    if (CpuId::cpuHasVaes()) {
        err = vaes::DecryptCbc(
            pCipherText, pPlainText, len, getDecryptKeys(), getRounds(), pIv);

        return err;
    }
    if (CpuId::cpuHasAesni()) {
        err = aesni::DecryptCbc(
            pCipherText, pPlainText, len, getDecryptKeys(), getRounds(), pIv);
        return err;
    }
    return err;
#endif
    return FDec(
        pCipherText, pPlainText, len, getDecryptKeys(), getRounds(), pIv);
    // dispatch to REF
}

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          int          nRounds,
                          const Uint8* pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          int          nRounds,
                          const Uint8* pIv)>
alc_error_t
Cbc<FEnc, FDec>::encrypt(const Uint8* pPlainText,
                         Uint8*       pCipherText,
                         Uint64       len,
                         const Uint8* pIv) const
{
#if 0
    alc_error_t err = ALC_ERROR_NONE;
// Only AESNI possible as CBC Encrypt is a strictly serial algorithm
    if (CpuId::cpuHasAesni()) {
        err = aesni::EncryptCbc(
            pPlainText, pCipherText, len, getEncryptKeys(), getRounds(), pIv);

        return err;
    }
    // dispatch to REF
    return err;
#endif
    return FEnc(
        pPlainText, pCipherText, len, getEncryptKeys(), getRounds(), pIv);
}
} // namespace alcp::cipher