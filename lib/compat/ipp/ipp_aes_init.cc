#include "context.hh"
#include "error.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <ippcp.h>
#include <sstream>
#include <stdint.h>
#include <string.h>

IppStatus
ippsAESGetSize(int* pSize)
{
    printMsg("GetSize");
    *pSize = sizeof(ipp_wrp_ctx);
    printMsg("GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsAESInit(const Ipp8u* pKey, int keyLen, IppsAESSpec* pCtx, int ctxSize)
{
    printMsg("Init");
    std::stringstream ss;
    ss << "KeyLength:" << keyLen;
    printMsg(ss.str());
    ipp_wrp_ctx* context = reinterpret_cast<ipp_wrp_ctx*>(pCtx);
    if (pKey != nullptr) {
        // context->key           = std::vector<uint8_t>(pKey, pKey + keyLen);
        context->cinfo.ci_type          = ALC_CIPHER_TYPE_AES;
        context->cinfo.ci_key_info.type = ALC_KEY_TYPE_SYMMETRIC;
        context->cinfo.ci_key_info.fmt  = ALC_KEY_FMT_RAW;
        context->cinfo.ci_key_info.key  = (uint8_t*)pKey;
        context->cinfo.ci_key_info.len  = keyLen * 8;
        context->handle.ch_context      = nullptr;
    } else {
        if (context->handle.ch_context != nullptr) {
            alcp_cipher_finish(&(context->handle));
            free(context->handle.ch_context);
            context->handle.ch_context = nullptr;
            context->key               = std::vector<uint8_t>(0, 0);
        }
    }
    printMsg("Init End");
    return ippStsNoErr;
}