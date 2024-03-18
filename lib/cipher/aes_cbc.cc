/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes.hh"
//
#include "alcp/cipher/aes_cbc.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {

namespace vaes512 {
    CRYPT_WRAPPER_FUNC(
        Cbc128, encrypt, aesni::EncryptCbc128, m_cipher_key_data.m_enc_key, 10)
    CRYPT_WRAPPER_FUNC(
        Cbc192, encrypt, aesni::EncryptCbc192, m_cipher_key_data.m_enc_key, 12)
    CRYPT_WRAPPER_FUNC(
        Cbc256, encrypt, aesni::EncryptCbc256, m_cipher_key_data.m_enc_key, 14)

    CRYPT_WRAPPER_FUNC(
        Cbc128, decrypt, DecryptCbc128, m_cipher_key_data.m_dec_key, 10)
    CRYPT_WRAPPER_FUNC(
        Cbc192, decrypt, DecryptCbc192, m_cipher_key_data.m_dec_key, 12)
    CRYPT_WRAPPER_FUNC(
        Cbc256, decrypt, DecryptCbc256, m_cipher_key_data.m_dec_key, 14)
} // namespace vaes512

namespace vaes {
    CRYPT_WRAPPER_FUNC(
        Cbc128, encrypt, aesni::EncryptCbc128, m_cipher_key_data.m_enc_key, 10)
    CRYPT_WRAPPER_FUNC(
        Cbc192, encrypt, aesni::EncryptCbc192, m_cipher_key_data.m_enc_key, 12)
    CRYPT_WRAPPER_FUNC(
        Cbc256, encrypt, aesni::EncryptCbc256, m_cipher_key_data.m_enc_key, 14)

    CRYPT_WRAPPER_FUNC(
        Cbc128, decrypt, DecryptCbc128, m_cipher_key_data.m_dec_key, 10)
    CRYPT_WRAPPER_FUNC(
        Cbc192, decrypt, DecryptCbc192, m_cipher_key_data.m_dec_key, 12)
    CRYPT_WRAPPER_FUNC(
        Cbc256, decrypt, DecryptCbc256, m_cipher_key_data.m_dec_key, 14)
} // namespace vaes

namespace aesni {
    CRYPT_WRAPPER_FUNC(
        Cbc128, encrypt, EncryptCbc128, m_cipher_key_data.m_enc_key, 10)
    CRYPT_WRAPPER_FUNC(
        Cbc192, encrypt, EncryptCbc192, m_cipher_key_data.m_enc_key, 12)
    CRYPT_WRAPPER_FUNC(
        Cbc256, encrypt, EncryptCbc256, m_cipher_key_data.m_enc_key, 14)

    CRYPT_WRAPPER_FUNC(
        Cbc128, decrypt, DecryptCbc128, m_cipher_key_data.m_dec_key, 10)
    CRYPT_WRAPPER_FUNC(
        Cbc192, decrypt, DecryptCbc192, m_cipher_key_data.m_dec_key, 12)
    CRYPT_WRAPPER_FUNC(
        Cbc256, decrypt, DecryptCbc256, m_cipher_key_data.m_dec_key, 14)
} // namespace aesni

} // namespace alcp::cipher