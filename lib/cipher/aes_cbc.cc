/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/utils/cpuid.hh"
#include "cipher/aes.hh"
#include "cipher/cipher_wrapper.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {

alc_error_t
Cbc::decrypt(const Uint8* pCipherText,
             Uint8*       pPlainText,
             Uint64       len,
             const Uint8* pIv) const
{
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

    // dispatch to REF

    return err;
}

alc_error_t
Cbc::encrypt(const Uint8* pPlainText,
             Uint8*       pCipherText,
             Uint64       len,
             const Uint8* pIv) const
{
    alc_error_t err = ALC_ERROR_NONE;
    // Only AESNI possible as CBC Encrypt is a strictly serial algorithm
    if (CpuId::cpuHasAesni()) {
        err = aesni::EncryptCbc(
            pPlainText, pCipherText, len, getEncryptKeys(), getRounds(), pIv);

        return err;
    }

    // dispatch to REF

    return err;
}

} // namespace alcp::cipher
