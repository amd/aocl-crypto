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
#pragma once

#include "base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <ippcp.h>
#include <stdio.h>
#include <string.h>

namespace alcp::bench {
class IPPDigestBase : public DigestBase
{
    IppsHashState*   m_handle = nullptr;
    _alc_sha2_mode   m_mode;
    _alc_digest_type m_type;
    _alc_digest_len  m_sha_len;
    uint8_t*         m_message;
    uint8_t*         m_digest;

  public:
    IPPDigestBase(_alc_sha2_mode   mode,
                  _alc_digest_type type,
                  _alc_digest_len  sha_len);
    ~IPPDigestBase();
    bool init();
    bool init(_alc_sha2_mode   mode,
              _alc_digest_type type,
              _alc_digest_len  sha_len);

    alc_error_t digest_function(const uint8_t* src,
                                uint64_t       src_size,
                                uint8_t*       output,
                                uint64_t       out_size);
    void hash_to_string(char* output_string, const uint8_t* hash, int sha_len);
};
} // namespace alcp::bench