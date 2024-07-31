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

#include "cipher_experimental/alc_cipher_gcm.hh"

namespace alcp::testing::cipher::gcm {
template<bool encryptor>
bool
AlcpGcmCipher<encryptor>::init(alc_test_init_data_p data)
{
    alc_test_gcm_init_data_p data_gcm =
        reinterpret_cast<alc_test_gcm_init_data_p>(data);
    alc_error_t err = ALC_ERROR_NONE;

    m_handle.ch_context = malloc(alcp_cipher_aead_context_size());
    if (!m_handle.ch_context)
        return false;

    err = alcp_cipher_aead_request(
        ALC_AES_MODE_GCM, (data_gcm->m_key_len) * 8, &m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        return false;
    }

    // GCM init
    err = alcp_cipher_aead_init(&m_handle,
                                data_gcm->m_key,
                                data_gcm->m_key_len * 8,
                                data_gcm->m_iv,
                                data_gcm->m_iv_len);
    if (alcp_is_error(err)) {
        printf("Error: GCM encrypt init failure!\n");
        return false;
    }

    if (data_gcm->m_aad_len > 0) {
        // Additional Data
        err = alcp_cipher_aead_set_aad(
            &m_handle, data_gcm->m_aad, data_gcm->m_aad_len);
        if (alcp_is_error(err)) {
            printf("Error: unable gcm add data processing \n");
            return false;
        }
    }

    return true;
};

template<bool encryptor>
bool
AlcpGcmCipher<encryptor>::update(alc_test_update_data_p data)
{
    alc_test_gcm_update_data_p p_gcm_update_data =
        reinterpret_cast<alc_test_gcm_update_data_p>(data);
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    if constexpr (encryptor == true) {
        err = alcp_cipher_aead_encrypt(&m_handle,
                                       p_gcm_update_data->m_input,
                                       p_gcm_update_data->m_output,
                                       p_gcm_update_data->m_input_len);
        if (alcp_is_error(err)) {
            printf("Error: unable encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
    } else {
        err = alcp_cipher_aead_decrypt(&m_handle,
                                       p_gcm_update_data->m_input,
                                       p_gcm_update_data->m_output,
                                       p_gcm_update_data->m_input_len);
        if (alcp_is_error(err)) {
            printf("Error: unable decrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
    }
    return true;
};
template<bool encryptor>
bool
AlcpGcmCipher<encryptor>::finalize(alc_test_finalize_data_p data)
{
    alc_test_gcm_finalize_data_p p_gcm_finalize_data =
        reinterpret_cast<alc_test_gcm_finalize_data_p>(data);
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    err = alcp_cipher_aead_get_tag(
        &m_handle, p_gcm_finalize_data->m_tag, p_gcm_finalize_data->m_tag_len);
    if (alcp_is_error(err)) {
        printf(
            "Error: unable getting tag, possible tag mismatch if decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    alcp_cipher_aead_finish(&m_handle);
    if (m_handle.ch_context != nullptr) {
        free(m_handle.ch_context);
        m_handle.ch_context = nullptr;
    }
    return true;
};

template class AlcpGcmCipher<true>;
template class AlcpGcmCipher<false>;
} // namespace alcp::testing::cipher::gcm
