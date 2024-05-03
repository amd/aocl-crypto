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

#include "alcp/alcp.h"
#include "alcp/digest.h"
#include "digest/digest.hh"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <malloc.h>
#include <vector>
#pragma once

namespace alcp::testing {
class AlcpDigestBase : public DigestBase
{
    alc_digest_handle_t* m_handle = {};
    /* duplicate context created from m_handle */
    alc_digest_handle_t* m_handle_dup = {};
    alc_digest_info_t    m_info       = {};
    Uint8*               m_message    = {};
    Uint8*               m_digest     = {};
    /* Digest output which would be squeezed out
                                     of the duplicate context */
    Uint8* m_digest_dup_ctx = {};
    /* for Sha3 shake variants */
    Int64 m_digest_len = {};
    void* m_context    = {};

  public:
    AlcpDigestBase(const alc_digest_info_t& info);

    bool init(const alc_digest_info_t& info, Int64 digest_len);

    bool init();

    ~AlcpDigestBase();

    /* copies ctx from main m_handle to duplicate handle m_handle_dup
     */
    bool context_copy();

    bool digest_update(const alcp_digest_data_t& data);

    bool digest_finalize(const alcp_digest_data_t& data);

    bool digest_squeeze(const alcp_digest_data_t& data);

    /* Resets the context back to initial condition, reuse context */
    void reset();
};

} // namespace alcp::testing
