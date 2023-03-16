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
#pragma once

#include "alcp/cipher.h"

#include "alcp/cipher.hh"

#include <functional>

namespace alcp::cipher {

struct Context
{
    void* m_cipher;

    alc_error_t (*decrypt)(const void*  rCipher,
                           const Uint8* pSrc,
                           Uint8*       pDst,
                           Uint64       len,
                           const Uint8* pIv);

    alc_error_t (*encrypt)(const void*  rCipher,
                           const Uint8* pSrt,
                           Uint8*       pDrc,
                           Uint64       len,
                           const Uint8* pIv);

    alc_error_t (*decryptUpdate)(void*        rCipher,
                                 const Uint8* pSrc,
                                 Uint8*       pDst,
                                 Uint64       len,
                                 const Uint8* pIv);

    alc_error_t (*encryptUpdate)(void*        rCipher,
                                 const Uint8* pSrc,
                                 Uint8*       pDst,
                                 Uint64       len,
                                 const Uint8* pIv);

    alc_error_t (*setIv)(void* rCipher, Uint64 len, const Uint8* pIv);

    alc_error_t (*setAad)(void* rCipher, const Uint8* pAad, Uint64 len);

    alc_error_t (*getTag)(void* rCipher, Uint8* pTag, Uint64 len);

    alc_error_t (*setTagLength)(void* rCipher, Uint64 len);

    alc_error_t (*finish)(const void*);
};

} // namespace alcp::cipher
