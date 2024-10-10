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
#include "alcp/cipher/aes_cfb.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {

// cfb uses encKey for both encrypt and decrypt
// vaes512 member functions
CRYPT_WRAPPER_FUNC(vaes512,
                   Cfb128,
                   encrypt,
                   aesni::EncryptCfb128,
                   m_cipher_key_data.m_enc_key,
                   10,
                   ALCP_ENC)
CRYPT_WRAPPER_FUNC(vaes512,
                   Cfb192,
                   encrypt,
                   aesni::EncryptCfb192,
                   m_cipher_key_data.m_enc_key,
                   12,
                   ALCP_ENC)
CRYPT_WRAPPER_FUNC(vaes512,
                   Cfb256,
                   encrypt,
                   aesni::EncryptCfb256,
                   m_cipher_key_data.m_enc_key,
                   14,
                   ALCP_ENC)

CRYPT_WRAPPER_FUNC(vaes512,
                   Cfb128,
                   decrypt,
                   vaes512::DecryptCfb128,
                   m_cipher_key_data.m_enc_key,
                   10,
                   ALCP_DEC)
CRYPT_WRAPPER_FUNC(vaes512,
                   Cfb192,
                   decrypt,
                   vaes512::DecryptCfb192,
                   m_cipher_key_data.m_enc_key,
                   12,
                   ALCP_DEC)
CRYPT_WRAPPER_FUNC(vaes512,
                   Cfb256,
                   decrypt,
                   vaes512::DecryptCfb256,
                   m_cipher_key_data.m_enc_key,
                   14,
                   ALCP_DEC)

// vaes member functions
CRYPT_WRAPPER_FUNC(vaes,
                   Cfb128,
                   encrypt,
                   aesni::EncryptCfb128,
                   m_cipher_key_data.m_enc_key,
                   10,
                   ALCP_ENC)
CRYPT_WRAPPER_FUNC(vaes,
                   Cfb192,
                   encrypt,
                   aesni::EncryptCfb192,
                   m_cipher_key_data.m_enc_key,
                   12,
                   ALCP_ENC)
CRYPT_WRAPPER_FUNC(vaes,
                   Cfb256,
                   encrypt,
                   aesni::EncryptCfb256,
                   m_cipher_key_data.m_enc_key,
                   14,
                   ALCP_ENC)

CRYPT_WRAPPER_FUNC(vaes,
                   Cfb128,
                   decrypt,
                   vaes::DecryptCfb128,
                   m_cipher_key_data.m_enc_key,
                   10,
                   ALCP_DEC)
CRYPT_WRAPPER_FUNC(vaes,
                   Cfb192,
                   decrypt,
                   vaes::DecryptCfb192,
                   m_cipher_key_data.m_enc_key,
                   12,
                   ALCP_DEC)
CRYPT_WRAPPER_FUNC(vaes,
                   Cfb256,
                   decrypt,
                   vaes::DecryptCfb256,
                   m_cipher_key_data.m_enc_key,
                   14,
                   ALCP_DEC)

// aesni member functions
CRYPT_WRAPPER_FUNC(aesni,
                   Cfb128,
                   encrypt,
                   aesni::EncryptCfb128,
                   m_cipher_key_data.m_enc_key,
                   10,
                   ALCP_ENC)
CRYPT_WRAPPER_FUNC(aesni,
                   Cfb192,
                   encrypt,
                   aesni::EncryptCfb192,
                   m_cipher_key_data.m_enc_key,
                   12,
                   ALCP_ENC)
CRYPT_WRAPPER_FUNC(aesni,
                   Cfb256,
                   encrypt,
                   aesni::EncryptCfb256,
                   m_cipher_key_data.m_enc_key,
                   14,
                   ALCP_ENC)

CRYPT_WRAPPER_FUNC(aesni,
                   Cfb128,
                   decrypt,
                   aesni::DecryptCfb128,
                   m_cipher_key_data.m_enc_key,
                   10,
                   ALCP_DEC)
CRYPT_WRAPPER_FUNC(aesni,
                   Cfb192,
                   decrypt,
                   aesni::DecryptCfb192,
                   m_cipher_key_data.m_enc_key,
                   12,
                   ALCP_DEC)
CRYPT_WRAPPER_FUNC(aesni,
                   Cfb256,
                   decrypt,
                   aesni::DecryptCfb256,
                   m_cipher_key_data.m_enc_key,
                   14,
                   ALCP_DEC)

} // namespace alcp::cipher