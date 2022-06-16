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

#include "ipp_base.hh"

namespace alcp::testing {

IPPCipherBase::IPPCipherBase(const alc_aes_mode_t mode, const uint8_t* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

IPPCipherBase::IPPCipherBase(const alc_aes_mode_t mode,
                             const uint8_t*       iv,
                             const uint8_t*       key,
                             const uint32_t       key_len)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_key{ key }
    , m_key_len{ key_len }
{
    if (m_mode == ALC_AES_MODE_GCM) {
        ippsAES_GCMGetSize(&m_ctxSize);
        m_ctx_gcm = (IppsAES_GCMState*)(new Ipp8u[m_ctxSize]);
        ippsAES_GCMInit(key, key_len / 8, m_ctx_gcm, m_ctxSize);
    } else {
        ippsAESGetSize(&m_ctxSize);
        m_ctx = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
        ippsAESInit(key, key_len / 8, m_ctx, m_ctxSize);
    }
}

IPPCipherBase::~IPPCipherBase()
{
    if (m_ctx != nullptr) {
        delete[](Ipp8u*) m_ctx;
    }
    if (m_ctx_gcm != nullptr) {
        delete[](Ipp8u*) m_ctx_gcm;
    }
}
bool
IPPCipherBase::init(const uint8_t* iv,
                    const uint8_t* key,
                    const uint32_t key_len)
{
    m_iv = iv;
    return init(key, key_len);
}

bool
IPPCipherBase::init(const uint8_t* key, const uint32_t key_len)
{
    if (m_mode == ALC_AES_MODE_GCM) {
        ippsAES_GCMGetSize(&m_ctxSize);
        if (m_ctx_gcm != nullptr) {
            delete[](Ipp8u*) m_ctx_gcm;
        }
        m_ctx_gcm = (IppsAES_GCMState*)(new Ipp8u[m_ctxSize]);
        ippsAES_GCMInit(key, key_len / 8, m_ctx_gcm, m_ctxSize);
    } else {
        ippsAESGetSize(&m_ctxSize);
        if (m_ctx != nullptr) {
            delete[](Ipp8u*) m_ctx;
        }
        m_ctx = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
        ippsAESInit(key, key_len / 8, m_ctx, m_ctxSize);
    }
    return true;
}

bool
IPPCipherBase::alcpModeToFuncCall(const uint8_t* in,
                                  uint8_t*       out,
                                  size_t         len,
                                  bool           enc)
{
    IppStatus status = ippStsNoErr;
    uint8_t   iv[16];
    memcpy(iv, m_iv, 16);
    switch (m_mode) {
        case ALC_AES_MODE_CBC:
            if (enc) {
                status = ippsAESEncryptCBC(in, out, len, m_ctx, iv);
            } else {
                status = ippsAESDecryptCBC(in, out, len, m_ctx, iv);
            }
            break;
        case ALC_AES_MODE_CFB:
            if (enc) {
                status = ippsAESEncryptCFB(in, out, len, 16, m_ctx, iv);
            } else {
                status = ippsAESDecryptCFB(in, out, len, 16, m_ctx, iv);
            }
            break;
        case ALC_AES_MODE_OFB:
            if (enc) {
                status = ippsAESEncryptOFB(in, out, len, 16, m_ctx, iv);
            } else {
                status = ippsAESDecryptOFB(in, out, len, 16, m_ctx, iv);
            }
            break;
        case ALC_AES_MODE_CTR:
            if (enc) {
                status = ippsAESEncryptCTR(in, out, len, m_ctx, iv, 128);
            } else {
                status = ippsAESDecryptCTR(in, out, len, m_ctx, iv, 128);
            }
            break;
        default:
            return false;
    }
    if (status != ippStsNoErr)
        return false;
    else
        return true;
}

bool
IPPCipherBase::alcpGCMModeToFuncCall(alcp_data_ex_t data, bool enc)
{
    if (enc) {
        ippsAES_GCMStart(m_iv, data.ivl, data.ad, data.adl, m_ctx_gcm);
        ippsAES_GCMEncrypt(data.in, data.out, data.inl, m_ctx_gcm);
        ippsAES_GCMGetTag(data.tag, data.tagl, m_ctx_gcm);
    } else {
        uint8_t tagbuff[data.tagl];
        ippsAES_GCMStart(m_iv, data.ivl, data.ad, data.adl, m_ctx_gcm);
        ippsAES_GCMDecrypt(data.in, data.out, data.inl, m_ctx_gcm);
        ippsAES_GCMGetTag(tagbuff, data.tagl, m_ctx_gcm);
        // ippsAES_GCMReset(m_ctx_gcm);
        // Tag verification
        for (int i = 0; i < data.tagl; i++) {
            if (tagbuff[i] != data.tag[i]) {
                return false;
            }
        }
    }
    return true;
}

bool
IPPCipherBase::encrypt(const uint8_t* plaintxt, size_t len, uint8_t* ciphertxt)
{
    return alcpModeToFuncCall(plaintxt, ciphertxt, len, true);
}

bool
IPPCipherBase::encrypt(alcp_data_ex_t data)
{
    if (m_mode == ALC_AES_MODE_GCM) {
        return alcpGCMModeToFuncCall(data, true);
    } else {
        return alcpModeToFuncCall(data.in, data.out, data.inl, true);
    }
    return true;
}

bool
IPPCipherBase::decrypt(const uint8_t* ciphertxt, size_t len, uint8_t* plaintxt)
{
    return alcpModeToFuncCall(ciphertxt, plaintxt, len, false);
}
bool
IPPCipherBase::decrypt(alcp_data_ex_t data)
{
    if (m_mode == ALC_AES_MODE_GCM) {
        return alcpGCMModeToFuncCall(data, false);
    } else {
        return alcpModeToFuncCall(data.in, data.out, data.inl, false);
    }
    return true;
}

void
IPPCipherBase::reset()
{
    if (m_mode == ALC_AES_MODE_GCM) {
        IppStatus ippsAES_GCMReset(IppsAES_GCMState * pState);
        ippsAES_GCMInit(m_key, m_key_len / 8, m_ctx_gcm, m_ctxSize);
    }
    return;
}

} // namespace alcp::testing