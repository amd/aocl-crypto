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
#pragma once
#include "alcp/alcp.h"
#include "file.hh"
#include "utils.hh"
#include <alcp/rsa.h>
#include <cstring>
#include <iostream>
#include <map>
#include <stdio.h>
#include <string>
#include <vector>

namespace alcp::testing {

#define ALCP_TEST_RSA_PADDING_OAEP 1
#define ALCP_TEST_RSA_PADDING_PKCS 2
#define ALCP_TEST_RSA_PADDING_PSS  3
#define ALCP_TEST_RSA_NO_PADDING   0

#define ALCP_TEST_RSA_ALGO_SIGN_VERIFY 4
#define ALCP_TEST_RSA_ALGO_ENC_DEC     5

typedef struct _alcp_rsa_data
{
    const Uint8* m_msg     = nullptr;
    Uint64       m_msg_len = 0;
    Uint64       m_key_len = 0;

    Uint8* m_encrypted_data = nullptr;
    Uint8* m_decrypted_data = nullptr;

    Uint8* m_pub_key_mod = nullptr;

    Uint8* m_pseed      = nullptr;
    Uint8* m_label      = nullptr;
    Uint64 m_label_size = 0;

    /* for signing and verification*/
    Uint8* m_digest        = nullptr;
    Uint64 m_digest_len    = 0;
    Uint8* m_signature     = nullptr;
    Uint64 m_signature_len = 0;
    Uint8* m_salt          = nullptr;
    Uint64 m_salt_len      = 0;
    bool   m_check         = false;

    /* for pkcs encrypt decrypt */
    Uint8* m_random_pad     = nullptr;
    Uint64 m_random_pad_len = 0;
} alcp_rsa_data_t;

class RsaBase
{
  public:
    alc_digest_info_t m_digest_info{};
    alc_digest_info_t m_mgf_info{};
    int               m_padding_mode                             = 0;
    std::string       m_rsa_algo                                 = "";
    Uint64            m_key_len                                  = 0;
    Uint64            m_hash_len                                 = 0;
    virtual bool      init()                                     = 0;
    virtual bool      reset()                                    = 0;
    virtual bool      SetPublicKey(const alcp_rsa_data_t& data)  = 0;
    virtual bool      SetPrivateKey(const alcp_rsa_data_t& data) = 0;
    virtual int       EncryptPubKey(const alcp_rsa_data_t& data) = 0;
    virtual int       DecryptPvtKey(const alcp_rsa_data_t& data) = 0;
    virtual bool      ValidateKeys()                             = 0;
    virtual bool      DigestSign(const alcp_rsa_data_t& data)    = 0;
    virtual bool      DigestVerify(const alcp_rsa_data_t& data)  = 0;
    virtual bool      Sign(const alcp_rsa_data_t& data)          = 0;
    virtual bool      Verify(const alcp_rsa_data_t& data)        = 0;
};
} // namespace alcp::testing
