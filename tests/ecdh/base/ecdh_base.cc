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

#include "ecdh/ecdh_base.hh"
#include <iostream>
#include <sstream>
#ifdef __linux__
#include <unistd.h>
#else
#include <direct.h>
#include <io.h>
#endif

namespace alcp::testing {

DataSet::DataSet(const std::string filename)
    : File(filename)
{
    m_filename = filename;
    line       = readLine(); // Read header out
    return;
}

bool
DataSet::readEcdhTestData()
{
    if (!CheckFileExists()) {
        std::cout << "File doesnt exist: " << m_filename << std::endl;
        return false;
    }
    line = readLine();
    if (line.empty() || line == "\n") {
        return false;
    }
    int pos1 = line.find(","); // End of Peer1Pvtkey
    int pos2 = line.find(",", pos1 + 1);
    int pos3 = line.find(",", pos2 + 1);
    int pos4 = line.find(",", pos3 + 1);
    int pos5 = line.find(",", pos4 + 1);
    if ((pos1 == -1) || (pos2 == -1) || (pos3 == -1) || (pos4 == -1)) {
        std::cout << "Error in parsing csv: " << m_filename << std::endl;
        return false;
    }

    m_Peer1_PvtKey = parseHexStrToBin(line.substr(0, pos1));
    m_Peer2_PvtKey = parseHexStrToBin(line.substr(pos1 + 1, pos2 - pos1 - 1));
    m_Peer1_PubKey = parseHexStrToBin(line.substr(pos2 + 1, pos3 - pos2 - 1));
    m_Peer2_PubKey = parseHexStrToBin(line.substr(pos3 + 1, pos4 - pos3 - 1));
    m_Peer1_SecretKey =
        parseHexStrToBin(line.substr(pos4 + 1, pos5 - pos4 - 1));
    m_Peer2_SecretKey = parseHexStrToBin(line.substr(pos5 + 1));

    lineno++;
    return true;
}

int
DataSet::getLineNumber()
{
    return lineno;
}

/* to read test data params */
std::vector<Uint8>
DataSet::getPeer1PvtKey()
{
    return m_Peer1_PvtKey;
}

std::vector<Uint8>
DataSet::getPeer2PvtKey()
{
    return m_Peer2_PvtKey;
}

std::vector<Uint8>
DataSet::getPeer1PubKey()
{
    return m_Peer1_PubKey;
}

std::vector<Uint8>
DataSet::getPeer2PubKey()
{
    return m_Peer2_PubKey;
}

std::vector<Uint8>
DataSet::getPeer1SecretKey()
{
    return m_Peer1_SecretKey;
}

std::vector<Uint8>
DataSet::getPeer2SecretKey()
{
    return m_Peer2_SecretKey;
}

} // namespace alcp::testing
