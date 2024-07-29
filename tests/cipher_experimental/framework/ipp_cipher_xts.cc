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

#include "cipher_experimental/ipp_cipher_xts.hh"
#include <iostream>
#include <memory>

namespace alcp::testing::cipher::xts {

template<bool encryptor>
bool
IppXtsCipher<encryptor>::init(alc_test_init_data_p data)
{
    alc_test_xts_init_data_p data_xts =
        reinterpret_cast<alc_test_xts_init_data_p>(data);
    m_pIv    = data_xts->m_iv;
    m_ivLen  = data_xts->m_iv_len;
    m_pKey   = data_xts->m_key;
    m_keyLen = data_xts->m_key_len;
    return true;
}

template<bool encryptor>
bool
IppXtsCipher<encryptor>::update(alc_test_update_data_p data)
{
    alc_test_xts_update_data_p p_xts_update_data =
        reinterpret_cast<alc_test_xts_update_data_p>(data);
    IppStatus status = ippStsNoErr;
    if constexpr (encryptor) {
#if 0
    int       firstDataLenInBlks = 8;
        status =
            ippsAESEncryptXTS_Direct(p_xts_update_data->m_input,
                                     p_xts_update_data->m_output,
                                     firstDataLenInBlks * 128,
                                     p_xts_update_data->m_aes_block_id,
                                     m_pIv,
                                     m_pKey,
                                     m_keyLen * 8 * 2,
                                     p_xts_update_data->m_total_input_len * 8);
        status = ippsAESEncryptXTS_Direct(
            p_xts_update_data->m_input + (firstDataLenInBlks * 16),
            p_xts_update_data->m_output + (firstDataLenInBlks * 16),
            (p_xts_update_data->m_input_len - (firstDataLenInBlks * 16)) * 8,
            p_xts_update_data->m_aes_block_id + firstDataLenInBlks,
            m_pIv,
            m_pKey,
            m_keyLen * 8 * 2,
            p_xts_update_data->m_total_input_len * 8);
        }
#else
        status =
            ippsAESEncryptXTS_Direct(p_xts_update_data->m_input,
                                     p_xts_update_data->m_output,
                                     p_xts_update_data->m_input_len * 8,
                                     p_xts_update_data->m_aes_block_id,
                                     m_pIv,
                                     m_pKey,
                                     m_keyLen * 8 * 2,
                                     p_xts_update_data->m_total_input_len * 8);
#endif
    } else {
        status =
            ippsAESDecryptXTS_Direct(p_xts_update_data->m_input,
                                     p_xts_update_data->m_output,
                                     p_xts_update_data->m_input_len * 8,
                                     p_xts_update_data->m_aes_block_id,
                                     m_pIv,
                                     m_pKey,
                                     m_keyLen * 8 * 2,
                                     p_xts_update_data->m_total_input_len * 8);
    }
    if (status != 0) {
        std::cout << __FILE__ << ":" << __LINE__
                  << " IPP_ERROR_STATUS:" << status << std::endl;
        return false;
    }
    return true;
}

template<bool encryptor>
bool
IppXtsCipher<encryptor>::finalize(alc_test_finalize_data_p data)
{
    return true;
}

template class IppXtsCipher<true>;
template class IppXtsCipher<false>;

} // namespace alcp::testing::cipher::xts
