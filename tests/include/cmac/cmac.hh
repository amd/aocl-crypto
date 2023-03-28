/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
#include <map>
#include <vector>

namespace alcp::testing {

struct alcp_cmac_data_t
{
    Uint8* m_msg      = nullptr;
    Uint64 m_msg_len  = 0;
    Uint8* m_key      = nullptr;
    Uint64 m_key_len  = 0;
    Uint8* m_cmac     = nullptr;
    Uint64 m_cmac_len = 0;
};

/* add mapping for HMAC mode and length */
extern std::map<alc_digest_len_t, alc_sha2_mode_t> sha2_mode_len_map;

class CmacBase
{
  public:
    virtual bool init(const alc_mac_info_t& info, std::vector<Uint8>& Key) = 0;
    virtual bool init()                                                    = 0;
    virtual bool cmacFunction(const alcp_cmac_data_t& data)                = 0;
    virtual bool reset()                                                   = 0;
};

} // namespace alcp::testing
