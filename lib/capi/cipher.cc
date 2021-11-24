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

#include "error.hh"

#include "module.hh"
#include "modulemanager.hh"

using namespace alcp;

EXTERN_C_BEGIN

alc_error_t
alcp_cipher_supported(const alc_cipher_info_t* cinfo)
{
    auto err = new Error(ALC_ERROR_NONE);

    /* TODO: Check for pointer validity */
    auto ret = ModuleManager::getInstance().isSupported(cinfo, *err);

    if (!ret) {
        // e->setDetail();
    }

    return err->getCValue();
}

uint64_t
alcp_cipher_ctx_size(const alc_cipher_info_t* cinfo)
{
    auto err = new Error(ALC_ERROR_NONE);
    /* TODO: Check for pointer validity */
    return 100;
}

alc_error_t
alcp_cipher_request(const alc_cipher_info_t* cinfo, alc_cipher_ctx_t* ctx)
{
    ModuleManager& mm = ModuleManager::getInstance();

    auto err = new Error(ALC_ERROR_NONE);

    /* TODO: Check for pointer validity */

    /* TODO: Check if pointer is already allocated, instantiated object
     * if so, we are called from normal path
     * if not, we are most likely called from IPP-CP compatibility layer
     */

    auto ret = mm.requestModule(cinfo, ctx, *err);

    if (!ret) {
        // return e.setDetail();
    }

    return err->getCValue();
}

alc_error_t
alcp_cipher_encrypt(const alc_cipher_ctx_t* ctx,
                    const uint8_t*          plaintxt,
                    uint8_t*                ciphertxt,
                    uint64_t                len)
{
    auto err = new Error(ALC_ERROR_NONE);
    /* TODO: Check for pointer validity */
    return err->getCValue();
}

alc_error_t
alcp_cipher_decrypt(const alc_cipher_ctx_t* ctx,
                    const uint8_t*          ciphertxt,
                    uint8_t*                plaintxt,
                    uint64_t                len)
{
    auto err = new Error(ALC_ERROR_NONE);
    /* TODO: Check for pointer validity */
    return err->getCValue();
}

/**
 * \brief
 * \notes
 * \params
 */
void
alcp_cipher_finish(const alc_cipher_ctx_t* ctx)
{}

EXTERN_C_END
