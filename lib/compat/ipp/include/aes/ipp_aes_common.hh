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

#pragma once

#include "common/context.hh"
#include "common/debug.hh"
#include "common/error.hh"
#include <alcp/alcp.h>
#include <alcp/types.h>
#include <iostream>
#include <ippcp.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Encrypt Decrypt Common Function for CBC,CTR,CFB,OFB and XTS
 *
 * @param pSrc            Source (Ciphertext during dec else Plaintext)
 * @param pDst            Destination (Plaintext during dec else Ciphertext)
 * @param len             Length of Source
 * @param pCtx            Context of Wrapper
 * @param pCtrValue       Counter/IV value
 * @param ctrNumBitSize   Unused, ignore
 * @param mode            ALCP Mode
 * @param enc             True means encrypt mode
 * @return IppStatus      NotSupported,Error
 */
inline IppStatus
alcp_encdecAES(const Ipp8u*       pSrc,
               Ipp8u*             pDst,
               int                len,
               const IppsAESSpec* pCtx,
               const Ipp8u*       pCtrValue,
               int                ctrNumBitSize,
               alc_cipher_mode_t  mode,
               bool               enc)
{
    // Should replace below with something better as it does discard const
    ipp_wrp_aes_ctx* context = (ipp_wrp_aes_ctx*)(pCtx);
    alc_error_t      err;
    const int        err_size = 256;
    Uint8            err_buf[err_size];

    /* Continue initialization as we didnt have iv in initialization function
       if we already have context then it's already good, we can take it as
       already initialized. */

    if (context->handle.ch_context == nullptr) {
        context->cinfo.ci_type              = ALC_CIPHER_TYPE_AES;
        context->cinfo.ci_algo_info.ai_mode = mode;
        context->cinfo.ci_algo_info.ai_iv   = (Uint8*)pCtrValue;

        // context->cinfo = cinfo;
        err = alcp_cipher_supported(&(context->cinfo));
        if (alcp_is_error(err)) {
            printErr("not supported");
            alcp_error_str(err, err_buf, err_size);
            return ippStsNotSupportedModeErr;
        }
        context->handle.ch_context =
            malloc(alcp_cipher_context_size(&(context->cinfo)));

// TODO: Debug statements, remove once done.
// Leaving debug statements here as XTS testing framework needs to be debugged.
#ifdef DEBUG
        if (mode == ALC_AES_MODE_XTS) {
            std::cout << "MODE:XTS" << std::endl;
            std::cout << "KEY:"
                      << parseBytesToHexStr(context->cinfo.ci_key_info.key,
                                            (context->cinfo.ci_key_info.len)
                                                / 8)
                      << std::endl;
            std::cout << "KEYLen:" << context->cinfo.ci_key_info.len / 8
                      << std::endl;
            std::cout
                << "TKEY:"
                << parseBytesToHexStr(
                       context->cinfo.ci_algo_info.ai_xts.xi_tweak_key->key,
                       (context->cinfo.ci_algo_info.ai_xts.xi_tweak_key->len)
                           / 8)
                << std::endl;
            std::cout << "KEYLen:"
                      << context->cinfo.ci_algo_info.ai_xts.xi_tweak_key->len
                             / 8
                      << std::endl;
            std::cout << "IV:"
                      << parseBytesToHexStr(context->cinfo.ci_algo_info.ai_iv,
                                            16)
                      << std::endl;
            std::cout << "INLEN:" << len << std::endl;
            std::cout << "IN:"
                      << parseBytesToHexStr(
                             reinterpret_cast<const Uint8*>(pSrc), len)
                      << std::endl;
        }
#endif
        err = alcp_cipher_request(&(context->cinfo), &(context->handle));
        if (alcp_is_error(err)) {
            printErr("unable to request");
            alcp_error_str(err, err_buf, err_size);
            free(context->handle.ch_context);
            context->handle.ch_context = nullptr;
            return ippStsErr;
        }
    }

    // Do the actual decryption
    if (enc) {
        // err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
        err = alcp_cipher_encrypt(&(context->handle),
                                  reinterpret_cast<const Uint8*>(pSrc),
                                  reinterpret_cast<Uint8*>(pDst),
                                  len,
                                  reinterpret_cast<const Uint8*>(pCtrValue));
    } else {
        err = alcp_cipher_decrypt(&(context->handle),
                                  reinterpret_cast<const Uint8*>(pSrc),
                                  reinterpret_cast<Uint8*>(pDst),
                                  len,
                                  reinterpret_cast<const Uint8*>(pCtrValue));
    }
#ifdef DEBUG
    if (mode == ALC_AES_MODE_XTS) {
        std::cout << "OUT:"
                  << parseBytesToHexStr(reinterpret_cast<const Uint8*>(pDst),
                                        len)
                  << std::endl;
    }
#endif
    // Messup ciphertext to test wrapper
    // *(reinterpret_cast<Uint8*>(pDst)) = 0x00;

    if (alcp_is_error(err)) {
        printErr("Unable decrypt");
        alcp_error_str(err, err_buf, err_size);
        return ippStsUnderRunErr;
    }
    printMsg("Decrypt succeeded");
#ifdef DEBUG
    if (mode == ALC_AES_MODE_XTS) {
        std::cout << std::endl;
    }
#endif
    /*At this point it should be supported and alcp context should exist*/
    return ippStsNoErr;
}