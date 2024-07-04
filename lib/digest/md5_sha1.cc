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

#include "alcp/digest/md5_sha1.hh"
#include <iostream>
#include <openssl/err.h>

namespace alcp::digest {

MD5_SHA1::MD5_SHA1()
{
    m_block_len  = ALC_DIGEST_BLOCK_SIZE_MD5_SHA1 / 8;
    m_digest_len = ALC_DIGEST_LEN_288 / 8;
}

void
MD5_SHA1::init()
{
    m_md5.init();
    m_sha1.init();
}

alc_error_t
MD5_SHA1::update(const Uint8* pBuf, Uint64 size)
{
    if (m_md5.update(pBuf, size)) {
        return ALC_ERROR_EXISTS;
    }
    return m_sha1.update(pBuf, size);
}

alc_error_t
MD5_SHA1::finalize(Uint8* pBuf, Uint64 size)
{
    if (size != (ALC_DIGEST_LEN_288 / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (m_md5.finalize(pBuf, (ALC_DIGEST_LEN_128 / 8))) {
        return ALC_ERROR_EXISTS;
    }
    return m_sha1.finalize(pBuf + (ALC_DIGEST_LEN_128 / 8),
                           (ALC_DIGEST_LEN_160 / 8));
}

MD5_SHA1::~MD5_SHA1() {}

MD5_SHA1::MD5_SHA1(const MD5_SHA1& src)
    : m_sha1{ src.m_sha1 }
    , m_md5{ src.m_md5 }
{
    m_digest_len = src.m_digest_len;
    m_block_len  = src.m_block_len;
}

} // namespace alcp::digest