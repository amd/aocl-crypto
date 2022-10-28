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

#include "alcp/digest.h"
#include "digest/base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <malloc.h>
#include <vector>

#pragma once

namespace alcp::testing {
class AlcpDigestBase : public DigestBase
{
    alc_digest_handle_t* m_handle;
    _alc_sha2_mode       m_mode;
    _alc_digest_type     m_type;
    _alc_digest_len      m_sha_len;
    Uint8*               m_message;
    Uint8*               m_digest;

  public:
    AlcpDigestBase(_alc_sha2_mode   mode,
                   _alc_digest_type type,
                   _alc_digest_len  sha_len);

    bool init(_alc_sha2_mode   mode,
              _alc_digest_type type,
              _alc_digest_len  sha_len);

    bool init();

    ~AlcpDigestBase();

    alc_error_t digest_function(const Uint8* src,
                                size_t       src_size,
                                Uint8*       output,
                                Uint64       out_size);
    /* Resets the context back to initial condition, reuse context */
    void reset();
    /* Hash value to string */
    void hash_to_string(char* output_string, const Uint8* hash, int sha_len);
};

/* SHA3 */
class AlcpDigestBaseSHA3 : public DigestBaseSHA3
{
    alc_digest_handle_t* m_handle;
    _alc_sha3_mode       m_mode;
    _alc_digest_type     m_type;
    _alc_digest_len      m_sha_len;
    Uint8*               m_message;
    Uint8*               m_digest;

  public:
    AlcpDigestBaseSHA3(_alc_sha3_mode   mode,
                   _alc_digest_type type,
                   _alc_digest_len  sha_len);

    bool init(_alc_sha3_mode   mode,
              _alc_digest_type type,
              _alc_digest_len  sha_len);

    bool init();

    ~AlcpDigestBaseSHA3();

    alc_error_t digest_function(const Uint8* src,
                                size_t       src_size,
                                Uint8*       output,
                                Uint64       out_size);
    /* Resets the context back to initial condition, reuse context */
    void reset();
    /* Hash value to string */
    void hash_to_string(char* output_string, const Uint8* hash, int sha_len);
};


} // namespace alcp::testing
