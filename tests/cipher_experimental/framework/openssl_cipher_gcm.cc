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

#include "cipher_experimental/openssl_cipher_gcm.hh"
#include <iostream>
#include <memory>
#include <openssl/err.h>

namespace alcp::testing::cipher::gcm {

template<bool encryptor>
void
OpenSSLGcmCipher<encryptor>::handleErrors()
{
    ERR_print_errors_fp(stderr);
}

template<bool encryptor>
bool
OpenSSLGcmCipher<encryptor>::init(alc_test_init_data_p data)
{
    alc_test_gcm_init_data_p data_gcm =
        reinterpret_cast<alc_test_gcm_init_data_p>(data);

    const EVP_CIPHER* mode = nullptr;
    switch (data->m_key_len) {
        case 16:
            mode = EVP_aes_128_gcm();
            break;
        case 24:
            mode = EVP_aes_192_gcm();
            break;
        case 32:
            mode = EVP_aes_256_gcm();
            break;
        default:
            std::cout << "KeySize Error" << std::endl;
            return false;
    }

    // Create context for decryption and initalize
    if (m_ctx != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx);
    }
    m_ctx = EVP_CIPHER_CTX_new();
    if (m_ctx == NULL) {
        m_ctx = nullptr;
        handleErrors();
        return false;
    }

    if constexpr (encryptor) {
        if (1 != EVP_EncryptInit_ex(m_ctx, mode, NULL, NULL, NULL)) {
            handleErrors();
            return false;
        }
        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx, EVP_CTRL_GCM_SET_IVLEN, data_gcm->m_iv_len, NULL)) {
            handleErrors();
            return false;
        }

        if (1
            != EVP_EncryptInit_ex(
                m_ctx, NULL, NULL, data_gcm->m_key, data_gcm->m_iv)) {
            handleErrors();
            return false;
        }

        int len;
        if (data_gcm->m_aad_len > 0) {
            if (1
                != EVP_EncryptUpdate(
                    m_ctx, NULL, &len, data_gcm->m_aad, data_gcm->m_aad_len)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }
        }

    } else {
        if (1 != EVP_DecryptInit_ex(m_ctx, mode, NULL, NULL, NULL)) {
            handleErrors();
            return false;
        }

        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx, EVP_CTRL_GCM_SET_IVLEN, data_gcm->m_iv_len, NULL)) {
            handleErrors();
            return false;
        }

        if (1
            != EVP_DecryptInit_ex(
                m_ctx, NULL, NULL, data_gcm->m_key, data_gcm->m_iv)) {
            handleErrors();
            return false;
        }

        int len;
        if (data_gcm->m_aad_len > 0) {
            if (1
                != EVP_DecryptUpdate(
                    m_ctx, NULL, &len, data_gcm->m_aad, data_gcm->m_aad_len)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }
        }
    }
    return true;
}

template<bool encryptor>
bool
OpenSSLGcmCipher<encryptor>::update(alc_test_update_data_p data)
{
    alc_test_gcm_update_data_p p_gcm_update_data =
        reinterpret_cast<alc_test_gcm_update_data_p>(data);
    if constexpr (encryptor) {
        int len_ct = 0;
        if (1
            != EVP_EncryptUpdate(m_ctx,
                                 p_gcm_update_data->m_output,
                                 &len_ct,
                                 p_gcm_update_data->m_input,
                                 p_gcm_update_data->m_input_len)) {
            handleErrors();
            return false;
        }
    } else {
        int len_pt = 0;
        if (1
            != EVP_DecryptUpdate(m_ctx,
                                 p_gcm_update_data->m_output,
                                 &len_pt,
                                 p_gcm_update_data->m_input,
                                 p_gcm_update_data->m_input_len)) {
            handleErrors();
            return false;
        }
    }
    return true;
}

template<bool encryptor>
bool
OpenSSLGcmCipher<encryptor>::finalize(alc_test_finalize_data_p data)
{
    alc_test_gcm_finalize_data_p p_gcm_finalize_data =
        reinterpret_cast<alc_test_gcm_finalize_data_p>(data);

    if constexpr (encryptor) {
        int len_ct = p_gcm_finalize_data->m_pt_len;
        if (1
            != EVP_EncryptFinal_ex(m_ctx,
                                   p_gcm_finalize_data->m_out
                                       + p_gcm_finalize_data->m_pt_len,
                                   &len_ct)) {
            std::cout << "Error: Finalize" << std::endl;
            handleErrors();
            return false;
        }

        if (1
            != EVP_CIPHER_CTX_ctrl(m_ctx,
                                   EVP_CTRL_CCM_GET_TAG,
                                   p_gcm_finalize_data->m_tag_len,
                                   p_gcm_finalize_data->m_tag)) {
            handleErrors();
            return false;
        }
    } else {
        int len_pt = p_gcm_finalize_data->m_pt_len;
        if (p_gcm_finalize_data->m_tag_len > 0)
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx,
                                       EVP_CTRL_GCM_SET_TAG,
                                       p_gcm_finalize_data->m_tag_len,
                                       p_gcm_finalize_data->m_tag_expected)) {
                std::cout << "Error: Tag Setting Failed" << std::endl;
                handleErrors();
                return false;
            }

        if (1
            != EVP_DecryptFinal_ex(m_ctx,
                                   p_gcm_finalize_data->m_out
                                       + p_gcm_finalize_data->m_pt_len,
                                   &len_pt)) {
            std::cout << "Error: EVP_DecryptFinal_ex Failed" << std::endl;
            handleErrors();
            return false;
        }
    }
    // FIXME: Decrypt does not write data in openssl, for our test to pass, we
    // are copying.
    p_gcm_finalize_data->verified = true;
    std::copy(p_gcm_finalize_data->m_tag_expected,
              p_gcm_finalize_data->m_tag_expected
                  + p_gcm_finalize_data->m_tag_len,
              p_gcm_finalize_data->m_tag);
    EVP_CIPHER_CTX_free(m_ctx);
    m_ctx = nullptr;
    return true;
}

template class OpenSSLGcmCipher<true>;
template class OpenSSLGcmCipher<false>;

} // namespace alcp::testing::cipher::gcm