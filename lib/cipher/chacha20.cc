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

#include "alcp/cipher/chacha20.hh"
#include "chacha20_inplace.cc.inc"

namespace alcp::cipher::chacha20 {
using utils::CpuId;

alc_error_t
ChaCha20::validateKey(const Uint8* key, Uint64 keylen)
{
    return ValidateKey(key, keylen);
}

alc_error_t
ChaCha20::validateIv(const Uint8 iv[], Uint64 iVlen)
{
    return ValidateIv(iv, iVlen);
}

alc_error_t
ChaCha20::setKey(const Uint8 key[], Uint64 keylen)
{
    alc_error_t err = this->validateKey(key, keylen);
    if (alcp_is_error(err)) {
        return err;
    }
    memcpy(m_key, key, keylen);
    return ALC_ERROR_NONE;
}

alc_error_t
ChaCha20::setIv(const Uint8 iv[], Uint64 ivlen)
{
    alc_error_t err = this->validateIv(iv, ivlen);
    if (alcp_is_error(err)) {
        return err;
    }
    memcpy(m_iv, iv, ivlen);
    return ALC_ERROR_NONE;
}

alc_error_t
ChaCha20::processInput(const Uint8 plaintext[],
                       Uint64      plaintextLength,
                       Uint8       ciphertext[]) const
{
    static bool is_avx512 = CpuId::cpuHasAvx512(utils::AVX512_F)
                            && CpuId::cpuHasAvx512(utils::AVX512_DQ)
                            && CpuId::cpuHasAvx512(utils::AVX512_BW);
    if (is_avx512) {

        return zen4::ProcessInput(m_key,
                                  cMKeylen,
                                  m_iv,
                                  cMIvlen,
                                  plaintext,
                                  plaintextLength,
                                  ciphertext);
    } else {

        return ProcessInput(m_key,
                            cMKeylen,
                            m_iv,
                            cMIvlen,
                            plaintext,
                            plaintextLength,
                            ciphertext);
    }
}

} // namespace alcp::cipher::chacha20
