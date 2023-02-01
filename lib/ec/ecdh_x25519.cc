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

#include "ec/ecdh.hh"
#include <string.h>

static constexpr Uint32 MaxKeySize                     = 32;
static const Uint8      x25519_basepoint_9[MaxKeySize] = { 9 };

EcX25519::EcX25519()
{
    m_pPrivKey.resize(MaxKeySize);
}

alc_error_t
EcX25519::GeneratePublicKey(Uint8* pPublicKey, const Uint8* pPrivKey)
{
    alc_error_t err = ALC_ERROR_NONE;
    std::copy(pPrivKey, pPrivKey + MaxKeySize, m_pPrivKey.begin());
#if ALCP_X25519_ADDED
    alcpScalarMulX25519(pPublicKey, pPrivKey, x25519_basepoint_9);
#endif
    return err;
}

alc_error_t
EcX25519 ::ComputeSecretKey(Uint8*       pSecretKey,
                            const Uint8* pPublicKey,
                            Uint64*      pKeyLength)
{
    alc_error_t err = ALC_ERROR_NONE;

    err = ValidatePublicKey(pPublicKey, MaxKeySize);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

#if ALCP_X25519_ADDED
    alcpScalarMulX25519(pSecretKey, m_pPrivKey, pPublicKey);
#endif
    *pKeyLength = 32;
    return err;
}

alc_error_t
EcX25519::ValidatePublicKey(const Uint8* pPublicKey, Uint64 pKeyLength)
{
    if (pKeyLength != MaxKeySize) {
        return ALC_ERROR_INVALID_SIZE;
    }

    static const Uint8 all_zero[MaxKeySize] = { 0 };

    return memcmp(all_zero, pPublicKey, MaxKeySize) ? ALC_ERROR_NONE
                                                    : ALC_ERROR_NOT_PERMITTED;
}

void
EcX25519 ::reset()
{
    std::fill(m_pPrivKey.begin(), m_pPrivKey.end(), 0);
}

Uint64
EcX25519 ::getKeySize()
{
    return MaxKeySize;
}
