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
#include "alcp/cipher.h"
#include "alcp/macros.h"

#include "modulemanager.hh"

EXTERN_C_BEGIN

alc_error_t
alcp_cipher_supported(const alc_cipher_info_t* cinfo)
{
    /* TODO: Check for pointer validity */
    return ModuleManager::getInstance().isSupported(cinfo);
}

alc_error_t
alcp_cipher_ctx_size(const alc_cipher_info_t* cinfo)
{}

alc_error_t
alcp_cipher_request(const alc_cipher_info_t* cinfo, alc_ctx_t** ctx)
{
    ModuleManager& mm  = ModuleManager::getInstance();
    alc_error_t    err = ALC_ERROR_NONE;

    /* TODO: Check for pointer validity */
    err = mm.request(cinfo, ctx);

    return err;
}

alc_error_t
alcp_cipher_encrypt(const alc_ctx_t*        ctx,
                    uint8_t*                plantxt,
                    uint64_t                len,
                    uint8_t*                ciphertxt,
                    alc_cipher_mode_data_t* data)
{
    alc_error_t err = ALC_ERROR_NONE;
    /* TODO: Check for pointer validity */
    return err;
}

alc_error_t
alcp_cipher_decrypt(const alc_ctx_t*        ctx,
                    uint8_t*                plantxt,
                    uint64_t                len,
                    uint8_t*                ciphertxt,
                    alc_cipher_mode_data_t* data)
{
    alc_error_t err = ALC_ERROR_NONE;
    /* TODO: Check for pointer validity */
    return err;
}

EXTERN_C_END
