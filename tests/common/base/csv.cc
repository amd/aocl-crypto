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

#include "csv.hh"

namespace alcp::testing {

// FIXME: Names can be captured from Header of CSV itself (Future
// Improvement)
Csv::Csv(String filename)
    : File(filename)
{
    m_filename    = filename;
    m_file_exists = checkFileExists();
    if (!m_file_exists) {
        utils::printErrors("File doesnt exist: " + m_filename);
        return;
    }
    m_line  = readLine(); // Read header out
    m_names = parseCsv(); // Parse the header into items
    return;
}

// m_line.split(",")
std::vector<String>
Csv::parseCsv() const
{
    int                 curr_pos = 0;
    std::vector<String> out      = {};
    while (true) {
        const int cPos  = m_line.find(',', curr_pos);
        String    found = {};

        if (cPos == -1) {
            found = m_line.substr(curr_pos);
        } else {
            found = m_line.substr(curr_pos, cPos - curr_pos);
        }
        out.push_back(found);

        if (cPos == -1) {
            break; // Terminating condition.. Line end
        }
        curr_pos = cPos + 1;
    }
    return out;
}

String
Csv::getStr(const String cName)
{
    // Linear Search
    for (Uint64 i = 0; i < m_data_vect.size(); i++) {
        String id;
        String value;
        std::tie(id, value) = m_data_vect.at(i);
        if (id == cName) {
            return value;
        }
    }
    return String();
}

// Be very careful with this, as if its not a hexstring, it will return
// zeros.
std::vector<Uint8>
Csv::getVect(const String cName)
{
    String value = getStr(cName);
    return parseHexStrToBin(value);
}

int
Csv::getLineNumber()
{
    return m_lineno;
}

// FIXME: Simplify with parseCsv function
bool
Csv::genericParse()
{
    std::vector<String> out = {};

    out = parseCsv();

    if (m_names.size() != out.size()) {
        return false; // Field sizes mismatch
    }
    for (size_t i = 0; i < m_names.size(); i++) {
        m_data_vect.push_back(data_elm_t(m_names.at(i), out[i]));
    }

    return true;
}

bool
Csv::readNext()
{
    m_data_vect.clear();
    if (!checkFileExists()) {
        std::cout << "File doesnt exist: " << m_filename << std::endl;
        return false;
    }
    bool search_lines = true;
    while (search_lines) {
        m_line = readLine();
        // Any way the line is read so increment
        m_lineno++;
        if (m_line.empty() || m_line == "\n") {
            return false;
        }
        for (Uint64 i = 0; i < m_line.size(); i++) {
            const char cS = m_line.at(i);
            // Search until we hit a non "#" char which is not a space
            if (cS == ' ' || cS == '\t') {
                continue;
            } else if (cS != '#') { // Line is not a comment
                search_lines = false;
                break;
            }
        }
    }
    return genericParse();
}

} // namespace alcp::testing