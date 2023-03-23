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
#include <alcp/ec.h>
#include <alcp/ecdh.h>
#include <iostream>
#include <map>
#include <stdio.h>
#include <string>
#include <vector>

namespace alcp::testing {

struct alcp_ecdh_data_t
{
    Uint8* m_Peer1_PvtKey       = nullptr;
    Uint8* m_Peer2_PvtKey       = nullptr;
    Uint64 m_Peer1_PvtKeyLen    = 0;
    Uint64 m_Peer2_PvtKeyLen    = 0;
    Uint8* m_Peer1_PubKey       = nullptr;
    Uint8* m_Peer2_PubKey       = nullptr;
    Uint64 m_Peer1_PubKeyLen    = 0;
    Uint64 m_Peer2_PubKeyLen    = 0;
    Uint8* m_Peer1_SecretKey    = nullptr;
    Uint8* m_Peer2_SecretKey    = nullptr;
    Uint64 m_Peer1_SecretKeyLen = 0;
    Uint64 m_Peer2_SecretKeyLen = 0;
};

class EcdhBase
{
  public:
    virtual bool init(const alc_ec_info_t&    info,
                      const alcp_ecdh_data_t& data)               = 0;
    virtual bool GeneratePublicKeys(const alcp_ecdh_data_t& data) = 0;
    virtual bool ComputeSecretKeys(const alcp_ecdh_data_t& data)  = 0;
    virtual bool reset()                                          = 0;
};
} // namespace alcp::testing
