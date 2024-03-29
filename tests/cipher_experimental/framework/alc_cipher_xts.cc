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

#include "cipher_experimental/alc_cipher_xts.hh"

namespace alcp::testing::cipher::xts {
template<bool encryptor>
bool
AlcpXtsCipher<encryptor>::init(alc_test_init_data_p data)
{
    alc_test_xts_init_data_p data_xts =
        reinterpret_cast<alc_test_xts_init_data_p>(data);
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .len     = (data_xts->m_key_len)*8,
            .key     = data_xts->m_key,
        },
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_XTS,
           .ai_iv   = data_xts->m_iv,
        },
    };

    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    m_handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    if (!m_handle.ch_context)
        return false;

    err = alcp_cipher_request(&cinfo, &m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }

    // xts init
    err = alcp_cipher_set_iv(&m_handle, data_xts->m_iv_len, data_xts->m_iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to set iv\n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    return true;
};

template<bool encryptor>
bool
AlcpXtsCipher<encryptor>::update(alc_test_update_data_p data)
{
    alc_test_xts_update_data_p p_xts_update_data =
        reinterpret_cast<alc_test_xts_update_data_p>(data);
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    if constexpr (encryptor == true) {
        err = alcp_cipher_blocks_encrypt(&m_handle,
                                         p_xts_update_data->m_input,
                                         p_xts_update_data->m_output,
                                         p_xts_update_data->m_input_len,
                                         p_xts_update_data->m_aes_block_id);
        if (alcp_is_error(err)) {
            printf("Error: unable encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
    } else {
        err = alcp_cipher_blocks_decrypt(&m_handle,
                                         p_xts_update_data->m_input,
                                         p_xts_update_data->m_output,
                                         p_xts_update_data->m_input_len,
                                         p_xts_update_data->m_aes_block_id);
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
AlcpXtsCipher<encryptor>::finalize(alc_test_finalize_data_p data)
{
    alc_test_xts_finalize_data_p p_xts_finalize_data =
        reinterpret_cast<alc_test_xts_finalize_data_p>(data);
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    alcp_cipher_finish(&m_handle);
    if (m_handle.ch_context != nullptr) {
        free(m_handle.ch_context);
        m_handle.ch_context = nullptr;
    }
    return true;
};

template class AlcpXtsCipher<true>;
template class AlcpXtsCipher<false>;
} // namespace alcp::testing::cipher::xts
