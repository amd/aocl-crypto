/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#include "cipher/aes_cfb.hh"
#include "cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {
alc_error_t
Cfb::decrypt(const Uint8* pCipherText,
             Uint8*       pPlainText,
             Uint64       len,
             const Uint8* pIv) const
{
    alc_error_t  err = ALC_ERROR_NONE;
    if (CpuId::cpuHasAvx512(utils::AVX512_F)
        && CpuId::cpuHasAvx512(utils::AVX512_DQ)
        && CpuId::cpuHasAvx512(utils::AVX512_BW)) {
        err = vaes512::DecryptCfbAvx512(
            pCipherText, pPlainText, len, getEncryptKeys(), getRounds(), pIv);
        return err;
    }
    if (CpuId::cpuHasVaes()) {
        err = vaes::DecryptCfb(
            pCipherText, pPlainText, len, getEncryptKeys(), getRounds(), pIv);

        return err;
    }
    if (CpuId::cpuHasAesni()) {
        err = aesni::DecryptCfb(
            pCipherText, pPlainText, len, getEncryptKeys(), getRounds(), pIv);

        return err;
    }

    err = Rijndael::decrypt(pCipherText, pPlainText, len, pIv);

    return err;
}

alc_error_t
Cfb::encrypt(const Uint8* pPlainText,
             Uint8*       pCipherText,
             Uint64       len,
             const Uint8* pIv) const
{
    alc_error_t  err = ALC_ERROR_NONE;

    if (CpuId::cpuHasAesni()) {
        err = aesni::EncryptCfb(
            pPlainText, pCipherText, len, getEncryptKeys(), getRounds(), pIv);

        return err;
    }

    auto n_words = len / Rijndael::cBlockSizeWord;
    auto src     = reinterpret_cast<const Uint32*>(pPlainText);
    auto dst     = reinterpret_cast<Uint32*>(pCipherText);

    Uint32 iv32[4];
    utils::CopyBytes(iv32, pIv, sizeof(iv32));

    while (n_words >= 4) {

        Uint32 out[4];

        utils::CopyBytes(out, iv32, sizeof(out));

        Rijndael::encryptBlock(out, getEncryptKeys(), getRounds());

        for (int i = 0; i < 4; i++)
            out[i] ^= src[i];

        utils::CopyBytes(dst, out, sizeof(out));

        utils::CopyBytes(iv32, out, sizeof(out));

        src += 4;
        dst += 4;
        n_words -= 4;
    }

    // err = Rijndael::encrypt(pPlainText, pCipherText, len, pIv);

    return err;
}

} // namespace alcp::cipher
