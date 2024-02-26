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
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

/* ALCP Headers */
#include "../../../lib/include/alcp/types.hh"
#include "file.hh"
#include "utils.hh"

namespace alcp::testing {
using utils::parseHexStrToBin;

typedef std::tuple<String, String> data_elm_t;
typedef std::vector<data_elm_t>    data_vect_t;

// Better version of DataSet, which is generic so that we can remove duplicate
// code
class Csv final : private File
{
  private:
    String              m_filename  = {};
    String              m_line      = {};
    std::vector<String> m_names     = {};
    data_vect_t         m_data_vect = {};
    // First line is skipped, linenum starts from 1
    int m_lineno = 1;

    std::vector<String> parseCsv() const;

    bool genericParse();

  public:
    // FIXME: Names can be captured from Header of CSV itself (Future
    // Improvement)
    Csv(String filename);

    bool readNext();

    String getStr(const String cName);

    // Be very careful with this, as if its not a hexstring, it will return
    // zeros.
    std::vector<Uint8> getVect(const String cName);

    int getLineNumber();

    bool m_file_exists = {};
};

} // namespace alcp::testing
