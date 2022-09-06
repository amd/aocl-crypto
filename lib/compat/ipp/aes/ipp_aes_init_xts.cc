/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "ipp_aes_init_common.hh"

IppStatus
ippsAES_XTSGetSize(int* pSize)
{
    printMsg("XTS GetSize");
    *pSize = sizeof(ipp_wrp_aes_xts_ctx);
    printMsg("XTS GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsAES_XTSInit(const Ipp8u*     pKey,
                int              keyLen,
                int              duBitsize,
                IppsAES_XTSSpec* pCtx,
                int              ctxSize)
{
    printMsg("XTS Init");
    std::stringstream ss;
    ss << "KeyLength:" << keyLen;
    printMsg(ss.str());
    ipp_wrp_aes_ctx* context_dec =
        &((reinterpret_cast<ipp_wrp_aes_xts_ctx*>(pCtx))->decrypt_ctx);
    ipp_wrp_aes_ctx* context_enc =
        &((reinterpret_cast<ipp_wrp_aes_xts_ctx*>(pCtx))->encrypt_ctx);
    alc_key_info_t* tkey =
        &((reinterpret_cast<ipp_wrp_aes_xts_ctx*>(pCtx))->tweak_key);
    Uint8* tweak = ((reinterpret_cast<ipp_wrp_aes_xts_ctx*>(pCtx))->tkey);
    Uint8* key   = ((reinterpret_cast<ipp_wrp_aes_xts_ctx*>(pCtx))->key);
    if (pKey != nullptr) {

        // FIXME: This is not needed but test framework is insane as of now.
        memcpy(tweak, ((Uint8*)pKey) + (keyLen / (8 * 2)), (keyLen / (8 * 2)));
        memcpy(key, ((Uint8*)pKey), (keyLen / (8 * 2)));

        alc_key_info_t kinfo;
        kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
        kinfo.fmt  = ALC_KEY_FMT_RAW;
        kinfo.len  = keyLen / 2;
        kinfo.key  = tweak;
        *tkey      = kinfo;

        context_dec->cinfo.ci_type              = ALC_CIPHER_TYPE_AES;
        context_dec->cinfo.ci_key_info.type     = ALC_KEY_TYPE_SYMMETRIC;
        context_dec->cinfo.ci_key_info.fmt      = ALC_KEY_FMT_RAW;
        context_dec->cinfo.ci_key_info.key      = key;
        context_dec->cinfo.ci_key_info.len      = keyLen / 2;
        context_dec->cinfo.ci_algo_info.ai_mode = ALC_AES_MODE_XTS;
        context_dec->cinfo.ci_algo_info.ai_xts.xi_tweak_key = tkey;
        context_dec->handle.ch_context                      = nullptr;

        context_enc->cinfo             = context_dec->cinfo;
        context_enc->handle.ch_context = nullptr;
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
    printMsg("XTS Init End");
    return ippStsNoErr;
}