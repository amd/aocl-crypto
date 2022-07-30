/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "digest/alc_base.hh"
#include "digest/base.hh"

namespace alcp::testing {

static uint8_t size_[4096] = { 0 };

AlcpDigestBase::AlcpDigestBase(_alc_sha2_mode   mode,
                               _alc_digest_type type,
                               _alc_digest_len  sha_len)
    : m_mode{ mode }
    , m_type{ type }
    , m_sha_len{ sha_len }
{
    init();
}

bool
AlcpDigestBase::init()
{
    alc_error_t err;
    alc_digest_info_t dinfo = {
        .dt_type = m_type,
        .dt_len = m_sha_len,
        .dt_mode = {.dm_sha2 = m_mode,},
    };

    m_handle          = new alc_digest_handle_t;
    m_handle->context = &size_[0];

    err = alcp_digest_request(&dinfo, m_handle);
    if (alcp_is_error(err)) {
        printf("Error!\n");
        return false;
    }
    return true;
}

bool
AlcpDigestBase::init(_alc_sha2_mode   mode,
                     _alc_digest_type type,
                     _alc_digest_len  sha_len)
{
    this->m_mode    = mode;
    this->m_type    = type;
    this->m_sha_len = sha_len;
    return init();
}

AlcpDigestBase::~AlcpDigestBase()
{
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        delete m_handle;
    }
}

alc_error_t
AlcpDigestBase::digest_function(const uint8_t* pSrc,
                                size_t         src_size,
                                uint8_t*       pOutput,
                                uint64_t       out_size)
{
    alc_error_t err;
    err = alcp_digest_update(m_handle, pSrc, src_size);
    if (alcp_is_error(err)) {
        printf("Digest update failed\n");
        return err;
    }

    alcp_digest_finalize(m_handle, NULL, 0);
    if (alcp_is_error(err)) {
        printf("Digest finalize failed\n");
        return err;
    }

    err = alcp_digest_copy(m_handle, pOutput, out_size);
    if (alcp_is_error(err)) {
        printf("Digest copy failed\n");
        return err;
    }
    return err;
}

void
AlcpDigestBase::reset()
{
    alcp_digest_reset(m_handle);
}
/* Hash value to string */
void
AlcpDigestBase::hash_to_string(char*          output_string,
                               const uint8_t* hash,
                               int            sha_len)
{
    for (int i = 0; i < sha_len / 8; i++) {
        output_string += sprintf(output_string, "%02x", hash[i]);
    }
    output_string[(sha_len / 8) * 2 + 1] = '\0';
}

} // namespace alcp::testing
