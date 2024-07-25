/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "cipher/ipp_cipher.hh"

namespace alcp::testing {

void
IPPCipherBase::PrintErrors(IppStatus status)
{
    std::cout << "IPP Error: " << status << std::endl;
}

IPPCipherBase::IPPCipherBase(const _alc_cipher_type  cIpherType,
                             const alc_cipher_mode_t cMode,
                             const Uint8*            iv)
    : m_mode{ cMode }
    , m_iv{ iv }
{
}

IPPCipherBase::IPPCipherBase(const _alc_cipher_type  cIpherType,
                             const alc_cipher_mode_t cMode,
                             const Uint8*            iv,
                             const Uint32            cIvLen,
                             const Uint8*            key,
                             const Uint32            cKeyLen,
                             const Uint8*            tkey,
                             const Uint64            cBlockSize)
    : m_mode{ cMode }
    , m_iv{ iv }
    , m_tkey{ tkey }
    , m_block_size{ cBlockSize }
{
    init(key, cKeyLen);
}

IPPCipherBase::~IPPCipherBase()
{
    if (m_ctx != nullptr) {
        delete[] (Ipp8u*)m_ctx;
    }
    if (m_ctx_gcm != nullptr) {
        delete[] (Ipp8u*)m_ctx_gcm;
    }
    if (m_ctx_ccm != nullptr) {
        delete[] (Ipp8u*)m_ctx_ccm;
    }
    if (m_ctx_xts != nullptr) {
        delete[] (Ipp8u*)m_ctx_xts;
    }
}

bool
IPPCipherBase::init(const Uint8* iv,
                    const Uint32 cIvLen,
                    const Uint8* key,
                    const Uint32 cKeyLen,
                    const Uint8* tkey,
                    const Uint64 cBlockSize)
{
    m_iv         = iv;
    m_tkey       = tkey;
    m_key        = key;
    m_block_size = cBlockSize;
    return init(key, cKeyLen);
}

bool
IPPCipherBase::init(const Uint8* key, const Uint32 cKeyLen)
{
    IppStatus status = ippStsNoErr;
    m_key            = key;
    m_key_len        = cKeyLen;
    switch (m_mode) {
        case ALC_AES_MODE_XTS:
            /* add key with tkey for */
            memcpy(m_key_final, m_key, cKeyLen / 8);
            memcpy(m_key_final + cKeyLen / 8, m_tkey, cKeyLen / 8);
            m_key  = m_key_final;
            status = ippsAES_XTSGetSize(&m_ctxSize);
            if (m_ctx_xts != nullptr) {
                delete[] (Ipp8u*)m_ctx_xts;
            }
            m_ctx_xts = (IppsAES_XTSSpec*)(new Ipp8u[m_ctxSize]);

            /* for xts, pass the key concatenated with tkey */
            status = ippsAES_XTSInit(m_key,
                                     (cKeyLen / 8) * 16,
                                     m_block_size * 8,
                                     m_ctx_xts,
                                     m_ctxSize);
            break;
        default:
            status = ippsAESGetSize(&m_ctxSize);
            if (m_ctx != nullptr) {
                delete[] (Ipp8u*)m_ctx;
            }
            m_ctx  = (IppsAESSpec*)(new Ipp8u[m_ctxSize]);
            status = ippsAESInit(key, cKeyLen / 8, m_ctx, m_ctxSize);
            break;
    }

    if (status != ippStsNoErr) {
        std::cout << "Error code: " << status << " from IPP Init" << std::endl;
        return false;
    }
    return true;
}

bool
IPPCipherBase::alcpModeToFuncCall(const Uint8* in,
                                  Uint8*       out,
                                  size_t       len,
                                  bool         enc)
{
    IppStatus status = ippStsNoErr;
    Uint8     iv[16];
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
        case ALC_AES_MODE_XTS:
            if (enc) {
                status = ippsAES_XTSEncrypt(in, out, len * 8, m_ctx_xts, iv, 0);
            } else {
                status = ippsAES_XTSDecrypt(in, out, len * 8, m_ctx_xts, iv, 0);
            }
            break;
        default:
            break;
    }
    if (status != ippStsNoErr) {
        std::cout << "Error code: " << status << " from IPP enc/dec"
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPCipherBase::encrypt(const Uint8* plaintxt, size_t len, Uint8* ciphertxt)
{
    return alcpModeToFuncCall(plaintxt, ciphertxt, len, true);
}

bool
IPPCipherBase::encrypt(alcp_dc_ex_t& data)
{
    bool retval = false;
    retval      = alcpModeToFuncCall(data.m_in, data.m_out, data.m_inl, true);
    return retval;
}

bool
IPPCipherBase::decrypt(const Uint8* ciphertxt, size_t len, Uint8* plaintxt)
{
    return alcpModeToFuncCall(ciphertxt, plaintxt, len, false);
}

bool
IPPCipherBase::decrypt(alcp_dc_ex_t& data)
{
    bool retval = false;
    retval      = alcpModeToFuncCall(data.m_in, data.m_out, data.m_inl, false);
    return retval;
}

bool
IPPCipherBase::reset()
{
    return true;
}

} // namespace alcp::testing
