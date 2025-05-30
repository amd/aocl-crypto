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

#include "alcp/digest/sha1.hh"
#include <iostream>
#include <openssl/err.h>

namespace alcp::digest {

Sha1::Sha1()
{
    m_block_len  = ALC_DIGEST_BLOCK_SIZE_SHA1 / 8;
    m_digest_len = ALC_DIGEST_LEN_160 / 8;
    m_ctx        = EVP_MD_CTX_new();
    m_md         = EVP_MD_fetch(NULL, "SHA-1", "provider=default");
}

void
Sha1::init()
{
    if (EVP_DigestInit(m_ctx, m_md) != 1) {
        std::cout << "SHA1: Error code in EVP_DigestInit: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return;
    }
}

alc_error_t
Sha1::update(const Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (EVP_DigestUpdate(m_ctx, pBuf, size) != 1) {
        err = ALC_ERROR_EXISTS;
    }

    return err;
}

alc_error_t
Sha1::finalize(Uint8* pBuf, Uint64 size)
{
    if (size != (160 / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
    alc_error_t  err         = ALC_ERROR_NONE;
    unsigned int output_size = 0;
    if (EVP_DigestFinal_ex(m_ctx, pBuf, &output_size) != 1) {
        err = ALC_ERROR_EXISTS;
    }
    assert(size == output_size);

    return err;
}

Sha1::~Sha1()
{
    if (m_ctx != nullptr) {
        EVP_MD_CTX_free(m_ctx);
    }
    if (m_md != nullptr) {
        EVP_MD_free(m_md);
    }
}

Sha1::Sha1(const Sha1& src)
{
    m_digest_len = src.m_digest_len;
    m_block_len  = src.m_block_len;
    if (m_md) {
        EVP_MD_free(m_md);
    }
    m_md = EVP_MD_fetch(NULL, "SHA-1", "provider=default");
    if (m_ctx) {
        EVP_MD_CTX_free(m_ctx);
    }
    m_ctx = EVP_MD_CTX_new();

    EVP_MD_CTX_copy(m_ctx, src.m_ctx);
}

} // namespace alcp::digest