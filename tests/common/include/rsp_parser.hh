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

/* C/C++ Headers */
#include <bits/stdc++.h>

/* ALCP Headers */
#include "file.hh"
#include "utils.hh"

namespace alcp::testing {
using utils::parseHexStrToBin;

typedef std::unordered_map<String, String> param_map_t;

// A Generic DataSet
class CRspParser final : private File
{
  private:
    String              m_input_rsp_file  = {};
    String              m_lineBuf      = {};   // Buffer to a line in RSP file
    size_t              m_paramPerTC  = 0;  // Number of parameters per TC
    std::vector<String> m_names     = {};   // Keys (CSV header items)
    param_map_t         m_data_map= {};   // Parameters stored as key-value pair
    // Linenum starts from 0
    Uint m_lineno = 0;   // Line Count

  public:
    CRspParser(const String&);

    bool init();
    bool skipRSPHeader();
    String FetchTCfromRSP();
    void removeSpaces(String& str);
    bool readNextTC();
    void StoreTCinUMap(StringView);
    int isSubstring(StringView deststr, StringView srcstr);

    std::vector<Uint8> getVect(StringView cName);
    Uint64 getLenBytes(StringView cName);
    String adjustKeyNames(String cName);
    Uint getLineNumber();

    bool m_file_exists = {};
};

} // namespace alcp::testing
