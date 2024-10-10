/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "aes/ipp_aes_init_common.hh"

IppStatus
ippsAES_GCMGetSize(int* pSize)
{
    printMsg("GCM GetSize");
    // Size of the context is the wrapper context size with alcp context size
    *pSize = sizeof(ipp_wrp_aes_aead_ctx) + alcp_cipher_aead_context_size();
    printMsg("GCM GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsAES_GCMInit(const Ipp8u*      pKey,
                int               keyLen,
                IppsAES_GCMState* pState,
                int               ctxSize)
{
    printMsg("GCM Init");

    std::stringstream ss;
    ss << "KeyLength:" << keyLen;
    printMsg(ss.str());

    // Cast the context into the correct data type
    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);
    alc_error_t err = ALC_ERROR_NONE;

    // Calculate the pointer of the alcp cipher context
    Uint8* alcp_ctx =
        reinterpret_cast<Uint8*>(pState) + sizeof(ipp_wrp_aes_aead_ctx);
    context_aead->handle.ch_context = alcp_ctx;

    // Wipe the alcp context
    std::fill(alcp_ctx, alcp_ctx + alcp_cipher_aead_context_size(), 0);

    // Request for the GCM Cipher
    err = alcp_cipher_aead_request(
        ALC_AES_MODE_GCM, keyLen * 8, &(context_aead->handle));
    if (alcp_is_error(err)) {
        printErr("Unable to request");
        return ippStsErr;
    }

    // Initialize the context with the key
    err = alcp_cipher_aead_init(
        &(context_aead->handle), pKey, keyLen * 8, nullptr, 0);
    if (alcp_is_error(err)) {
        printMsg("GCM: Error Initializing with Key!");
    }

    printMsg("GCM Init End");
    return ippStsNoErr;
}