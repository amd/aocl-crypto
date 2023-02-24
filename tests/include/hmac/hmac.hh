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
#include "base_common.hh"
#include <alcp/alcp.h>
#include <map>
#include <vector>

namespace alcp::testing {

/**
 *  HMAC data which are input to the algorithm
 */
struct alcp_hmac_data_in_t
{
    // Input message to generate authentication token on.
    const Uint8* m_msg;
    // Length of the input message
    Uint64 m_msg_len;
    // Key used to create the authentication token
    const Uint8* m_key;
    // Length of the Key
    Uint64 m_key_len;
};

/**
 *  HMAC data which are output to the algorithm
 */
struct alcp_hmac_data_out_t
{
    // Output authentication token.
    Uint8* m_hmac;
    // Length of the authentication token.
    Uint64 m_hmac_len;
};
/**
 *  Hmac test data.
 *
 *  in and out should be populated for KAT.
 *  in should should only be populated for CrossTest.
 */
struct alcp_hmac_data_t
{
    // Input Data into the algorithm.
    alcp_hmac_data_in_t in;
    // Output Data from the algorithm.
    alcp_hmac_data_out_t out;

    alcp_hmac_data_t() // Initialize in, out all values to null/0
        : in{}
        , out{}
    {}
};

/* add mapping for HMAC mode and length */
extern std::map<alc_digest_len_t, alc_sha2_mode_t> sha2_mode_len_map;

class DataSet : private File
{
  private:
    std::string        line = "", m_filename = "";
    std::vector<Uint8> Message, Key, Hmac;
    // First line is skipped, linenum starts from 1
    int lineno = 1;

  public:
    // Treats file as CSV, skips first line
    DataSet(const std::string filename);
    // Read without condition
    bool readMsgKeyHmac();
    // To print which line in dataset failed
    int getLineNumber();
    /* fetch Message / Digest */
    std::vector<Uint8> getMessage();
    std::vector<Uint8> getKey();
    std::vector<Uint8> getHmac();
};
class HmacBase
{
  public:
    virtual bool init(const alc_mac_info_t& info, std::vector<Uint8>& Key) = 0;
    virtual bool init()                                                    = 0;
    virtual bool Hmac_function(const alcp_hmac_data_t& data)               = 0;
    virtual bool reset()                                                   = 0;
};

} // namespace alcp::testing
