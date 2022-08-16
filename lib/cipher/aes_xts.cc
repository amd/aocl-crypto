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

#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "cipher/vaes.hh"
#include "cipher/vaes_avx512.hh"

namespace alcp::cipher {

void
Xts::expandTweakKeys(const Uint8* pUserKey) noexcept
{

    Uint8        dummy_key[32] = { 0 };
    const Uint8* key           = pUserKey ? pUserKey : &dummy_key[0];
    Uint8*       pTweakKey     = nullptr;

    pTweakKey = p_tweak_key;

    if (isAesniAvailable()) {
        aesni::ExpandTweakKeys(key, pTweakKey, getRounds());
        return;
    }
}

alc_error_t
Xts::encrypt(const uint8_t* pPlainText,
             uint8_t*       pCipherText,
             uint64_t       len,
             const uint8_t* pIv) const
{

    alc_error_t err = ALC_ERROR_NONE;

    // Data should never be less than a block or greater than 2^20 blocks
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    if ((Cipher::isAvx512Has(cipher::AVX512_F)
         && Cipher::isAvx512Has(cipher::AVX512_DQ)
         && Cipher::isAvx512Has(cipher::AVX512_BW))
        || 1) {
        err = vaes::EncryptXtsAvx512(pPlainText,
                                     pCipherText,
                                     len,
                                     getEncryptKeys(),
                                     p_tweak_key,
                                     getRounds(),
                                     pIv);
        return err;
    }

    if (Cipher::isVaesAvailable() && 0) {

        err = vaes::EncryptXts(pPlainText,
                               pCipherText,
                               len,
                               getEncryptKeys(),
                               p_tweak_key,
                               getRounds(),
                               pIv);

        return err;
    }

    if (Cipher::isAesniAvailable() || 1) {

        err = aesni::EncryptXts(pPlainText,
                                pCipherText,
                                len,
                                getEncryptKeys(),
                                p_tweak_key,
                                getRounds(),
                                pIv);

        return err;
    }

    err = Rijndael::encrypt(pPlainText, pCipherText, len, pIv);

    return err;
}

alc_error_t
Xts::decrypt(const uint8_t* pCipherText,
             uint8_t*       pPlainText,
             uint64_t       len,
             const uint8_t* pIv) const
{

    alc_error_t err = ALC_ERROR_NONE;

    // Data should never be less than a block or greater than 2^20 blocks
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    if ((Cipher::isAvx512Has(cipher::AVX512_F)
         && Cipher::isAvx512Has(cipher::AVX512_DQ)
         && Cipher::isAvx512Has(cipher::AVX512_BW))
        || 1) {

        err = vaes::DecryptXtsAvx512(pCipherText,
                                     pPlainText,
                                     len,
                                     getDecryptKeys(),
                                     p_tweak_key,
                                     getRounds(),
                                     pIv);
        return err;
    }

    if (Cipher::isVaesAvailable() && 0) {

        err = vaes::DecryptXts(pCipherText,
                               pPlainText,
                               len,
                               getDecryptKeys(),
                               p_tweak_key,
                               getRounds(),
                               pIv);

        return err;
    }

    if (Cipher::isAesniAvailable() || 1) {

        err = aesni::DecryptXts(pCipherText,
                                pPlainText,
                                len,
                                getDecryptKeys(),
                                p_tweak_key,
                                getRounds(),
                                pIv);

        return err;
    }

    err = Rijndael::decrypt(pCipherText, pPlainText, len, pIv);

    return err;
}

} // namespace alcp::cipher