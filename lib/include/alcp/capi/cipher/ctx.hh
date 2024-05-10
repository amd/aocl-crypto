/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

typedef struct Context
{
    void* m_cipher = nullptr;

    alc_cipher_data_t m_alcp_cipher_data;

    // sw methods
    alc_error_t (*decrypt)(void*        ctx,
                           const Uint8* pSrc,
                           Uint8*       pDst,
                           Uint64       len);

    alc_error_t (*encrypt)(void*        ctx,
                           const Uint8* pSrt,
                           Uint8*       pDrc,
                           Uint64       len);

    alc_error_t (*encryptBlocksXts)(void*        ctx,
                                    const Uint8* pSrt,
                                    Uint8*       pDrc,
                                    Uint64       currPlainTextLen,
                                    Uint64       startBlockNum);

    alc_error_t (*decryptBlocksXts)(void*        ctx,
                                    const Uint8* pSrt,
                                    Uint8*       pDrc,
                                    Uint64       currCipherTextLen,
                                    Uint64       startBlockNum);

    alc_error_t (*decryptUpdate)(void*        ctx,
                                 const Uint8* pSrc,
                                 Uint8*       pDst,
                                 Uint64       len);

    alc_error_t (*encryptUpdate)(void*        ctx,
                                 const Uint8* pSrc,
                                 Uint8*       pDst,

                                 Uint64 len){ nullptr };

    alc_error_t (*init)(void*        ctx,
                        const Uint8* pKey,
                        Uint64       keyLen,
                        const Uint8* pIv,
                        Uint64       ivLen);

    alc_error_t (*setAad)(void* ctx, const Uint8* pAad, Uint64 aadLen);

    alc_error_t (*getTag)(void* ctx, Uint8* pTag, Uint64 tagLen);

    alc_error_t (*setTagLength)(void* ctx, Uint64 tagLen);

    alc_error_t (*finish)(const void*);

    Status status{ StatusOk() };
} alcp_cipher_ctx_t;

} // namespace alcp::cipher
