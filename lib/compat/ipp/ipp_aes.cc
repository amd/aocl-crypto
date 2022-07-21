#include "context.hh"
#include "error.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <ippcp.h>
#include <stdint.h>
#include <string.h>

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
    ipp_wrp_ctx* context = (ipp_wrp_ctx*)(pCtx);
    alc_error_t  err;
    const int    err_size = 256;
    uint8_t      err_buf[err_size];

    /* Continue initialization as we didnt have iv in initialization function
       if we already have context then it's already good, we can take it as
       already initialized. */

    if (context->handle.ch_context == nullptr) {
        // alc_cipher_info_t cinfo = {
        //     .ci_type = ALC_CIPHER_TYPE_AES,
        //     /* No padding, Not Implemented yet*/
        //     //.pad     = ALC_CIPHER_PADDING_NONE,
        //     .ci_algo_info   = {
        //         .ai_mode = mode,
        //         .ai_iv   = (uint8_t*)pCtrValue,
        //     },
        // };
        context->cinfo.ci_type              = ALC_CIPHER_TYPE_AES;
        context->cinfo.ci_algo_info.ai_mode = mode;
        context->cinfo.ci_algo_info.ai_iv   = (uint8_t*)pCtrValue;

        // context->cinfo = cinfo;
        err = alcp_cipher_supported(&(context->cinfo));
        if (alcp_is_error(err)) {
            printErr("not supported");
            alcp_error_str(err, err_buf, err_size);
            return ippStsNotSupportedModeErr;
        }
        context->handle.ch_context =
            malloc(alcp_cipher_context_size(&(context->cinfo)));
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
        err = alcp_cipher_encrypt(&(context->handle),
                                  reinterpret_cast<const uint8_t*>(pSrc),
                                  reinterpret_cast<uint8_t*>(pDst),
                                  len,
                                  reinterpret_cast<const uint8_t*>(pCtrValue));
    } else {
        err = alcp_cipher_decrypt(&(context->handle),
                                  reinterpret_cast<const uint8_t*>(pSrc),
                                  reinterpret_cast<uint8_t*>(pDst),
                                  len,
                                  reinterpret_cast<const uint8_t*>(pCtrValue));
    }

    // Messup ciphertext to test wrapper
    // *(reinterpret_cast<uint8_t*>(pDst)) = 0x00;

    if (alcp_is_error(err)) {
        printErr("Unable decrypt");
        alcp_error_str(err, err_buf, err_size);
        return ippStsUnderRunErr;
    }

    printMsg("Decrypt succeeded");

    /*At this point it should be supported and alcp context should exist*/
    return ippStsNoErr;
}

// CTR Mode

IppStatus
ippsAESDecryptCTR(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  const IppsAESSpec* pCtx,
                  Ipp8u*             pCtrValue,
                  int                ctrNumBitSize)
{

    printMsg("CTR-MODE DEC");
    return alcp_encdecAES(pSrc,
                          pDst,
                          len,
                          pCtx,
                          pCtrValue,
                          ctrNumBitSize,
                          ALC_AES_MODE_CTR,
                          false);
}

IppStatus
ippsAESEncryptCTR(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  const IppsAESSpec* pCtx,
                  Ipp8u*             pCtrValue,
                  int                ctrNumBitSize)
{
    printMsg("CTR-MODE ENC");
    return alcp_encdecAES(pSrc,
                          pDst,
                          len,
                          pCtx,
                          pCtrValue,
                          ctrNumBitSize,
                          ALC_AES_MODE_CTR,
                          true);
}

// CFB Mode

IppStatus
ippsAESDecryptCFB(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  int                cfbBlkSize,
                  const IppsAESSpec* pCtx,
                  const Ipp8u*       pIV)
{
    printMsg("CFB-MODE DEC");
    return alcp_encdecAES(
        pSrc, pDst, len, pCtx, pIV, cfbBlkSize, ALC_AES_MODE_CFB, false);
}

IppStatus
ippsAESEncryptCFB(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  int                cfbBlkSize,
                  const IppsAESSpec* pCtx,
                  const Ipp8u*       pIV)
{
    printMsg("CFB-MODE ENC");
    return alcp_encdecAES(
        pSrc, pDst, len, pCtx, pIV, cfbBlkSize, ALC_AES_MODE_CFB, true);
}

// CBC Mode
IppStatus
ippsAESDecryptCBC(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  const IppsAESSpec* pCtx,
                  const Ipp8u*       pIV)
{
    printMsg("CBC-MODE DEC");
    return alcp_encdecAES(
        pSrc, pDst, len, pCtx, pIV, 0, ALC_AES_MODE_CBC, false);
}

IppStatus
ippsAESEncryptCBC(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  const IppsAESSpec* pCtx,
                  const Ipp8u*       pIV)
{
    printMsg("CBC-MODE ENC");
    return alcp_encdecAES(
        pSrc, pDst, len, pCtx, pIV, 0, ALC_AES_MODE_CBC, true);
}

// OFB Mode

IppStatus
ippsAESDecryptOFB(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  int                ofbBlkSize,
                  const IppsAESSpec* pCtx,
                  Ipp8u*             pIV)
{
    printMsg("OFB-MODE DEC");
    return alcp_encdecAES(
        pSrc, pDst, len, pCtx, pIV, ofbBlkSize, ALC_AES_MODE_OFB, false);
}

IppStatus
ippsAESEncryptOFB(const Ipp8u*       pSrc,
                  Ipp8u*             pDst,
                  int                len,
                  int                ofbBlkSize,
                  const IppsAESSpec* pCtx,
                  Ipp8u*             pIV)
{
    printMsg("OFB-MODE ENC");
    return alcp_encdecAES(
        pSrc, pDst, len, pCtx, pIV, ofbBlkSize, ALC_AES_MODE_OFB, true);
}