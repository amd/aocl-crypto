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

/* C/C++ Headers */
#include <cstring>
#include <iostream>
#include <stdio.h>
#include <string.h>
// OpenSSL headers
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "digest.hh"

namespace alcp::testing {
class OpenSSLDigestBase : public DigestBase
{
    EVP_MD_CTX*       m_handle     = nullptr;
    EVP_MD_CTX*       m_handle_dup = nullptr;
    alc_digest_info_t m_info{};
    Uint8*            m_message    = nullptr;
    Uint8*            m_digest     = nullptr;
    Uint8*            m_digest_dup = nullptr;
    Int64             m_digest_len = 0;
    const EVP_MD*     m_md_type    = nullptr;

  public:
    // Class contructor and destructor
    /**
     * @brief Creates a digest base of type openssl with alcp_digest_info_t
     * provided
     *
     * @param info Information of which digest to use and what length.
     */
    OpenSSLDigestBase(const alc_digest_info_t& info);
    ~OpenSSLDigestBase();

    // All inits
    bool init(const alc_digest_info_t& info, Int64 digest_len);
    bool init();

    bool context_copy();
    bool digest_update(const alcp_digest_data_t& data);
    bool digest_finalize(const alcp_digest_data_t& data);
    bool digest_squeeze(const alcp_digest_data_t& data);
    void reset();
};

} // namespace alcp::testing