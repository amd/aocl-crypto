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

#include "aes/ipp_aes_init_common.hh"

IppStatus
ippsAES_GCMGetSize(int* pSize)
{
    printMsg("GCM GetSize");
    *pSize = sizeof(ipp_wrp_aes_aead_ctx);
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
    ipp_wrp_aes_ctx* context_dec =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->decrypt_ctx);
    ipp_wrp_aes_ctx* context_enc =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->encrypt_ctx);
    if (pKey != nullptr) {
        context_dec->cinfo.ci_type              = ALC_CIPHER_TYPE_AES;
        context_dec->cinfo.ci_key_info.type     = ALC_KEY_TYPE_SYMMETRIC;
        context_dec->cinfo.ci_key_info.fmt      = ALC_KEY_FMT_RAW;
        context_dec->cinfo.ci_key_info.key      = (Uint8*)pKey;
        context_dec->cinfo.ci_key_info.len      = keyLen * 8;
        context_dec->cinfo.ci_algo_info.ai_mode = ALC_AES_MODE_GCM;
        context_dec->handle.ch_context          = nullptr;
        context_enc->cinfo                      = context_dec->cinfo;
        context_enc->handle.ch_context          = nullptr;
    } else {
        if (context_dec->handle.ch_context != nullptr) {
            alcp_cipher_finish(&(context_dec->handle));
            free(context_dec->handle.ch_context);
            context_dec->handle.ch_context = nullptr;
        }
        if (context_enc->handle.ch_context != nullptr) {
            alcp_cipher_finish(&(context_enc->handle));
            free(context_enc->handle.ch_context);
            context_enc->handle.ch_context = nullptr;
        }
    }
    printMsg("GCM Init End");
    return ippStsNoErr;
}