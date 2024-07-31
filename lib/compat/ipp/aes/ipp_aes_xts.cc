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

#include "aes/ipp_aes_common.hh"

IppStatus
ippsAES_XTSEncrypt(const Ipp8u*           pSrc,
                   Ipp8u*                 pDst,
                   int                    bitSizeLen,
                   const IppsAES_XTSSpec* pCtx,
                   const Ipp8u*           pTweak,
                   int                    startCipherBlkNo)
{
    printMsg("ippsAESEncryptXTS_Direct Start");
    ipp_wrp_aes_ctx* context_cipher =
        &(((ipp_wrp_aes_xts_ctx*)(pCtx))->cipher_ctx);
    return alcp_encdecAES(pSrc,
                          pDst,
                          bitSizeLen / 8,
                          (IppsAESSpec*)context_cipher,
                          pTweak,
                          startCipherBlkNo,
                          ALC_AES_MODE_XTS,
                          true);
    printMsg("ippsAESEncryptXTS_Direct End");
}

IppStatus
ippsAES_XTSDecrypt(const Ipp8u*           pSrc,
                   Ipp8u*                 pDst,
                   int                    bitSizeLen,
                   const IppsAES_XTSSpec* pCtx,
                   const Ipp8u*           pTweak,
                   int                    startCipherBlkNo)
{
    printMsg("ippsAES_XTSDecrypt Start");
    ipp_wrp_aes_ctx* context_cipher =
        &(((ipp_wrp_aes_xts_ctx*)(pCtx))->cipher_ctx);
    return alcp_encdecAES(pSrc,
                          pDst,
                          bitSizeLen / 8,
                          (IppsAESSpec*)context_cipher,
                          pTweak,
                          startCipherBlkNo,
                          ALC_AES_MODE_XTS,
                          false);
    printMsg("ippsAES_XTSDecrypt End");
}

inline IppStatus
alcp_initXTSDirect(alc_cipher_handle_t& handle,
                   const Ipp8u*         pKey,
                   int                  keyBitSize,
                   const Ipp8u*         pTweakPT)
{

    constexpr unsigned int iv_len   = 16;
    Uint32                 key_size = static_cast<Uint32>(
        keyBitSize / 2); // casting to prevent narrowing conversion
                                         // from int to Uint32 warning
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    handle.ch_context = malloc(alcp_cipher_context_size());
    if (!handle.ch_context)
        return ippStsErr;

    err = alcp_cipher_segment_request(ALC_AES_MODE_XTS, key_size, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    // xts init
    err = alcp_cipher_segment_init(&handle, pKey, key_size, pTweakPT, iv_len);
    if (alcp_is_error(err)) {
        printf("Error: unable to init\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    return ippStsNoErr;
}

inline void
alcp_finalizeXTSDirect(alc_cipher_handle_t& handle)
{
    alcp_cipher_segment_finish(&handle);
    free(handle.ch_context);
    handle.ch_context = nullptr;
}

IppStatus
ippsAESEncryptXTS_Direct(const Ipp8u* pSrc,
                         Ipp8u*       pDst,
                         int          encBitSize,
                         int          aesBlkNo,
                         const Ipp8u* pTweakPT,
                         const Ipp8u* pKey,
                         int          keyBitSize,
                         int          dataUnitBitSize)
{

    printMsg("ippsAESEncryptXTS_Direct : START");
    alc_cipher_handle_t handle;
    alc_error_t         err;
    const int           err_size = 256;
    Uint8               err_buf[err_size];
    IppStatus status = alcp_initXTSDirect(handle, pKey, keyBitSize, pTweakPT);
    if (status != 0) {
        return status;
    }
    err = alcp_cipher_segment_encrypt_xts(
        &handle, pSrc, pDst, encBitSize / 8, aesBlkNo);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    alcp_finalizeXTSDirect(handle);
    printMsg("ippsAESEncryptXTS_Direct : END");
    return status;
}

IppStatus
ippsAESDecryptXTS_Direct(const Ipp8u* pSrc,
                         Ipp8u*       pDst,
                         int          encBitSize,
                         int          aesBlkNo,
                         const Ipp8u* pTweakPT,
                         const Ipp8u* pKey,
                         int          keyBitSize,
                         int          dataUnitBitSize)
{
    printMsg("ippsAESDecryptXTS_Direct : START");

    alc_cipher_handle_t handle;
    alc_error_t         err;
    const int           err_size = 256;
    Uint8               err_buf[err_size];
    IppStatus status = alcp_initXTSDirect(handle, pKey, keyBitSize, pTweakPT);
    if (status != 0) {
        return status;
    }
    err = alcp_cipher_segment_decrypt_xts(
        &handle, pSrc, pDst, encBitSize / 8, aesBlkNo);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    alcp_finalizeXTSDirect(handle);
    printMsg("ippsAESDecryptXTS_Direct : END");

    return status;
}