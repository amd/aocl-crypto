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

static const Uint8 x25519_basepoint_9[32] = { 9 };

alc_error_t
EcX25519::GeneratePublicKey(Uint8* pPublicKey, const Uint8* pPrivKey)
{
    alc_error_t err = ALC_ERROR_NONE;

    m_pPrivKey = pPrivKey;
#if ALCP_X25519_ADDED
    alcpScalarMulX25519(pPublicKey, m_pPrivKey, x25519_basepoint_9);
#endif
    return err;
}

alc_error_t
EcX25519 ::ComputeSecretKey(Uint8*       pSecretKey,
                            const Uint8* pPublicKey,
                            Uint64*      pKeyLength)
{
    alc_error_t err = ALC_ERROR_NONE;

#if ALCP_X25519_ADDED
    alcpScalarMulX25519(pSecretKey, m_pPrivKey, pPublicKey);
#endif
    *pKeyLength = 32;
    return err;
}

void
EcX25519 ::finish()
{}

void
EcX25519 ::reset()
{}

Uint64
EcX25519 ::getKeySize()
{
    // FIXME: add key size based on EC type
    return 32;
}
