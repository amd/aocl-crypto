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

#include "cipher_experimental/ipp_cipher_gcm.hh"
#include <iostream>
#include <memory>

namespace alcp::testing::cipher::gcm {

template<bool encryptor>
bool
IppGcmCipher<encryptor>::init(alc_test_init_data_p data)
{
    alc_test_gcm_init_data_p data_gcm =
        reinterpret_cast<alc_test_gcm_init_data_p>(data);
    IppStatus status = ippStsNoErr;
    int       ctx_size;
    status = ippsAES_GCMGetSize(&ctx_size);
    if (status != 0) {
        return false;
    }
    if (m_ctx_gcm == nullptr) {
        m_ctx_gcm = (IppsAES_GCMState*)(new Ipp8u[ctx_size]);
    } else {
        // Context not finalized!
        return 0;
    }
    status = ippsAES_GCMInit(
        data_gcm->m_key, data_gcm->m_key_len, m_ctx_gcm, ctx_size);
    if (status != 0) {
        return false;
    }
    status = ippsAES_GCMStart(data_gcm->m_iv,
                              data_gcm->m_iv_len,
                              data_gcm->m_aad,
                              data_gcm->m_aad_len,
                              m_ctx_gcm);
    if (status != 0) {
        return false;
    }
    return true;
}

template<bool encryptor>
bool
IppGcmCipher<encryptor>::update(alc_test_update_data_p data)
{
    alc_test_gcm_update_data_p p_gcm_update_data =
        reinterpret_cast<alc_test_gcm_update_data_p>(data);
    IppStatus status = ippStsNoErr;
    if constexpr (encryptor) {
        status = ippsAES_GCMEncrypt(p_gcm_update_data->m_input,
                                    p_gcm_update_data->m_output,
                                    p_gcm_update_data->m_input_len,
                                    m_ctx_gcm);
    } else {
        status = ippsAES_GCMDecrypt(p_gcm_update_data->m_input,
                                    p_gcm_update_data->m_output,
                                    p_gcm_update_data->m_input_len,
                                    m_ctx_gcm);
    }
    if (status != 0) {
        return false;
    }
    return true;
}

template<bool encryptor>
bool
IppGcmCipher<encryptor>::finalize(alc_test_finalize_data_p data)
{
    alc_test_gcm_finalize_data_p p_gcm_finalize_data =
        reinterpret_cast<alc_test_gcm_finalize_data_p>(data);
    IppStatus status = ippStsNoErr;
    status           = ippsAES_GCMGetTag(
        p_gcm_finalize_data->m_tag, p_gcm_finalize_data->m_tag_len, m_ctx_gcm);
    if (status != 0) {
        return false;
    }
    if (m_ctx_gcm != nullptr) {
        delete[] (Ipp8u*)m_ctx_gcm;
        m_ctx_gcm = nullptr;
    }
    return true;
}

template class IppGcmCipher<true>;
template class IppGcmCipher<false>;

} // namespace alcp::testing::cipher::gcm
