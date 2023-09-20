/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "cipher/ipp_cipher_aead.hh"

namespace alcp::testing {

void
IPPCipherAeadBase::PrintErrors(IppStatus status)
{
    std::cout << "IPP Error: " << status << std::endl;
}

IPPCipherAeadBase::IPPCipherAeadBase(const _alc_cipher_type  cipher_type,
                                     const alc_cipher_mode_t mode,
                                     const Uint8*            iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

IPPCipherAeadBase::IPPCipherAeadBase(const _alc_cipher_type  cipher_type,
                                     const alc_cipher_mode_t mode,
                                     const Uint8*            iv,
                                     const Uint32            iv_len,
                                     const Uint8*            key,
                                     const Uint32            key_len,
                                     const Uint8*            tkey,
                                     const Uint64            block_size)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_tkey{ tkey }
    , m_block_size{ block_size }
{
    init(key, key_len);
}

IPPCipherAeadBase::IPPCipherAeadBase(const _alc_cipher_type  cipher_type,
                                     const alc_cipher_mode_t mode,
                                     const Uint8*            iv,
                                     const Uint8*            key,
                                     const Uint32            key_len)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_key{ key }
    , m_key_len{ key_len }
{
    IppStatus status = ippStsNoErr;
    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            status = ippsAES_GCMGetSize(&m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
            }
            m_ctx_gcm = (IppsAES_GCMState*)(new Ipp8u[m_ctxSize]);
            status    = ippsAES_GCMInit(key, key_len / 8, m_ctx_gcm, m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
            }
            break;
        case ALC_AES_MODE_CCM:
            status = ippsAES_CCMGetSize(&m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
            }
            m_ctx_ccm = (IppsAES_CCMState*)(new Ipp8u[m_ctxSize]);
            status    = ippsAES_CCMInit(key, key_len / 8, m_ctx_ccm, m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
            }
            break;
        case ALC_AES_MODE_SIV:
            break;
        default: // Should not come here
            break;
    }
}

IPPCipherAeadBase::~IPPCipherAeadBase()
{
    if (m_ctx != nullptr) {
        delete[](Ipp8u*) m_ctx;
    }
    if (m_ctx_gcm != nullptr) {
        delete[](Ipp8u*) m_ctx_gcm;
    }
    if (m_ctx_ccm != nullptr) {
        delete[](Ipp8u*) m_ctx_ccm;
    }
    if (m_ctx_xts != nullptr) {
        delete[](Ipp8u*) m_ctx_xts;
    }
}

bool
IPPCipherAeadBase::init(const Uint8* iv,
                        const Uint32 iv_len,
                        const Uint8* key,
                        const Uint32 key_len)
{
    m_iv = iv;
    return init(key, key_len);
}

bool
IPPCipherAeadBase::init(const Uint8* iv,
                        const Uint32 iv_len,
                        const Uint8* key,
                        const Uint32 key_len,
                        const Uint8* tkey,
                        const Uint64 block_size)
{
    m_iv         = iv;
    m_tkey       = tkey;
    m_key        = key;
    m_block_size = block_size;
    return init(key, key_len);
}

bool
IPPCipherAeadBase::init(const Uint8* iv, const Uint8* key, const Uint32 key_len)
{
    m_iv = iv;
    return init(key, key_len);
}

bool
IPPCipherAeadBase::init(const Uint8* key, const Uint32 key_len)
{
    IppStatus status = ippStsNoErr;
    m_key            = key;
    m_key_len        = key_len;
    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            status = ippsAES_GCMGetSize(&m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
                return false;
            }
            if (m_ctx_gcm != nullptr) {
                delete[](Ipp8u*) m_ctx_gcm;
            }
            m_ctx_gcm = (IppsAES_GCMState*)(new Ipp8u[m_ctxSize]);
            status    = ippsAES_GCMInit(key, key_len / 8, m_ctx_gcm, m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
                return false;
            }
            break;

        case ALC_AES_MODE_CCM:
            status = ippsAES_CCMGetSize(&m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
                return false;
            }
            if (m_ctx_ccm != nullptr) {
                delete[](Ipp8u*) m_ctx_ccm;
            }
            m_ctx_ccm = (IppsAES_CCMState*)(new Ipp8u[m_ctxSize]);
            status    = ippsAES_CCMInit(key, key_len / 8, m_ctx_ccm, m_ctxSize);
            if (status != 0) {
                PrintErrors(status);
                return false;
            }
            break;

        case ALC_AES_MODE_SIV:
            break;

        default: // Should not come here
            return false;
    }

    if (status != ippStsNoErr) {
        std::cout << "Error code: " << status << " from IPP Init" << std::endl;
        return false;
    } else
        return true;
}

bool
IPPCipherAeadBase::alcpGCMModeToFuncCall(alcp_dca_ex_t data, bool enc)
{
    IppStatus status = ippStsNoErr;
    if (enc) {
        status = ippsAES_GCMStart(
            m_iv, data.m_ivl, data.m_ad, data.m_adl, m_ctx_gcm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status =
            ippsAES_GCMEncrypt(data.m_in, data.m_out, data.m_inl, m_ctx_gcm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_GCMGetTag(data.m_tag, data.m_tagl, m_ctx_gcm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
    } else {
        Uint8 tagbuff[data.m_tagl];
        status = ippsAES_GCMStart(
            m_iv, data.m_ivl, data.m_ad, data.m_adl, m_ctx_gcm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status =
            ippsAES_GCMDecrypt(data.m_in, data.m_out, data.m_inl, m_ctx_gcm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_GCMGetTag(tagbuff, data.m_tagl, m_ctx_gcm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        // Tag verification
        /* do only if tag contains valid data */
        if (data.m_isTagValid
            && std::memcmp(tagbuff, data.m_tag, data.m_tagl) != 0) {
            printf("IPP:GCM:Tag verification failed\n");
            return false;
        }
    }
    return true;
}

bool
IPPCipherAeadBase::alcpCCMModeToFuncCall(alcp_dca_ex_t data, bool enc)
{
    IppStatus status = ippStsNoErr;
    Ipp8u     Temp   = 0;
    if (enc) {
        status = ippsAES_CCMMessageLen(data.m_inl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_CCMTagLen(data.m_tagl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_CCMStart(
            m_iv, data.m_ivl, data.m_ad, data.m_adl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }

        /* FIXME: Hack for test data when PT is NULL */
        if (data.m_inl == 0) {
            data.m_out = &Temp;
            data.m_in  = data.m_out;
        }
        status =
            ippsAES_CCMEncrypt(data.m_in, data.m_out, data.m_inl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_CCMGetTag(data.m_tag, data.m_tagl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
    } else {
        status = ippsAES_CCMMessageLen(data.m_inl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_CCMTagLen(data.m_tagl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_CCMStart(
            m_iv, data.m_ivl, data.m_ad, data.m_adl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }

        /* FIXME: Hack for test data when PT is NULL */
        if (data.m_inl == 0) {
            data.m_out = &Temp;
            data.m_in  = data.m_out;
        }
        status =
            ippsAES_CCMDecrypt(data.m_in, data.m_out, data.m_inl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        status = ippsAES_CCMGetTag(data.m_tagBuff, data.m_tagl, m_ctx_ccm);
        if (status != 0) {
            PrintErrors(status);
            return false;
        }
        // Tag verification
        if (std::memcmp(data.m_tagBuff, data.m_tag, data.m_tagl) != 0) {
            return false;
        }
    }
    return true;
}

bool
IPPCipherAeadBase::alcpSIVModeToFuncCall(alcp_dca_ex_t data, bool enc)
{
    Ipp8u* ad_ptr_list[]  = { (Ipp8u*)data.m_ad, (Ipp8u*)data.m_in };
    int    ad_size_list[] = { (int)data.m_adl, (int)data.m_inl };
    if (enc) {
        int ret = ippsAES_SIVEncrypt(data.m_in,
                                     data.m_out,
                                     data.m_inl,
                                     data.m_tag,
                                     m_key,
                                     data.m_tkey,
                                     m_key_len / 8,
                                     (const Ipp8u**)ad_ptr_list,
                                     ad_size_list,
                                     (sizeof(ad_ptr_list) / sizeof(void*) - 1));
        switch (ret) {
            case ippStsNoErr:
                // utils::printErrors("No error", __FILE__, __LINE__);
                break;
            case ippStsNullPtrErr:
                utils::printErrors("Null PTR", __FILE__, __LINE__);
                return false;
            case ippStsLengthErr:
                utils::printErrors("Length Error", __FILE__, __LINE__);
                return false;
            default:
                utils::printErrors("Unknown Error", __FILE__, __LINE__);
                return false;
        }
        return true;
    } else {
        int    authRes           = 0;
        Ipp8u* ad_ptr_list_dec[] = { (Ipp8u*)data.m_ad, (Ipp8u*)data.m_in };
        Ipp8u* ad_ptr_list_s2v[] = { (Ipp8u*)data.m_ad, (Ipp8u*)data.m_out };
        int    ad_size_list[]    = { (int)data.m_adl, (int)data.m_inl };
        int    ret               = ippsAES_SIVDecrypt(data.m_in,
                                     data.m_out,
                                     data.m_inl,
                                     &authRes,
                                     m_key,
                                     data.m_tkey,
                                     m_key_len / 8,
                                     (const Ipp8u**)ad_ptr_list_dec,
                                     ad_size_list,
                                     (sizeof(ad_ptr_list) / sizeof(void*) - 1),
                                     data.m_tag);
        switch (ret) {
            case ippStsNoErr:
                // utils::printErrors("No error", __FILE__, __LINE__);
                break;
            case ippStsNullPtrErr:
                utils::printErrors("Null PTR", __FILE__, __LINE__);
                return false;
            case ippStsLengthErr:
                utils::printErrors("Length Error", __FILE__, __LINE__);
                return false;
            default:
                utils::printErrors("Unknown Error", __FILE__, __LINE__);
                return false;
        }
        return authRes;
    }
}

bool
IPPCipherAeadBase::encrypt(const Uint8* plaintxt, size_t len, Uint8* ciphertxt)
{
    return false;
}

bool
IPPCipherAeadBase::encrypt(alcp_dc_ex_t& data_in)
{
    alcp_dca_ex_t data   = *reinterpret_cast<alcp_dca_ex_t*>(&data_in);
    bool          retval = false;
    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            retval = alcpGCMModeToFuncCall(data, true);
            break;
        case ALC_AES_MODE_CCM:
            retval = alcpCCMModeToFuncCall(data, true);
            break;
        case ALC_AES_MODE_SIV:
            retval = alcpSIVModeToFuncCall(data, true);
            break;
        default: // Should not come here
            return false;
    }
    return retval;
}

bool
IPPCipherAeadBase::decrypt(const Uint8* ciphertxt, size_t len, Uint8* plaintxt)
{
    return false;
}

bool
IPPCipherAeadBase::decrypt(alcp_dc_ex_t& data_in)
{
    alcp_dca_ex_t data   = *reinterpret_cast<alcp_dca_ex_t*>(&data_in);
    bool          retval = false;
    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            retval = alcpGCMModeToFuncCall(data, false);
            break;
        case ALC_AES_MODE_CCM:
            retval = alcpCCMModeToFuncCall(data, false);
            break;
        case ALC_AES_MODE_SIV:
            retval = alcpSIVModeToFuncCall(data, false);
            break;
        default: // Should not come here
            return false;
    }
    return retval;
}

bool
IPPCipherAeadBase::reset()
{
    return true;
}

} // namespace alcp::testing
