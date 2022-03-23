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

#include "base.hh"
#include <iostream>

namespace alcp::bench {

/* Class File procedures */
File::File(const std::string fileName)
{
    file.open(fileName, std::ios::in);
    if (file.is_open()) {
        fileExists = true;
    } else {
        fileExists = false;
    }
    return;
}

std::string
File::readWord()
{
    std::string buff;
    file >> buff;
    return buff;
}

std::string
File::readLine()
{
    std::string buff;
    std::getline(file, buff);
    return buff;
}

std::string
File::readLineCharByChar()
{
    std::string buff;
    while (!file.eof()) {
        char s = file.get();
        if (s != '\n')
            buff += s;
        else
            break;
    }
    return buff;
}

char*
File::readChar(const int n)
{
    // TODO: Deallocation in the calling function.
    char* c_buff = new char[n];
    file.read(c_buff, n);
    return c_buff;
}

/**
 * @brief Construct a new Data Set:: Data Set object
 *
 * @param filename
 */
DataSet::DataSet(const std::string filename)
    : File(filename)
{
    line = readLine(); // Read header out
    return;
}

bool
DataSet::readMsgDigest()
{
#if 1
    line = readLine();
#else
    // Reference slower implementation
    line = readLineCharByChar();
    // std::cout << line << std::endl;
#endif
    if (line.empty() || line == "\n") {
        return false;
    }
    int pos1 = line.find(","); // End of Msg
    if ((pos1 == -1)) {
        printf("Error in parsing csv\n");
        return false;
    }
    std::string          messageStr = line.substr(0, pos1);
    std::vector<uint8_t> messageVect(messageStr.c_str(),
                                     (messageStr.c_str() + messageStr.size()));
    Message = messageVect;
    Digest  = parseHexStrToBin(line.substr(pos1 + 1));
    lineno++;
    return true;
}

uint8_t
DataSet::parseHexToNum(const unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

std::vector<uint8_t>
DataSet::parseHexStrToBin(const std::string in)
{
    std::vector<uint8_t> vector;
    int                  len = in.size();
    int                  ind = 0;

    for (int i = 0; i < len; i += 2) {
        uint8_t val =
            parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
        vector.push_back(val);
        ind += 2;
    }
    return vector;
}

std::string
DataSet::parseBytesToHexStr(const uint8_t* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int charRep;
        charRep = bytes[i];
        // Convert int to hex
        ss << std::hex << charRep;
    }
    return ss.str();
}

int
DataSet::getLineNumber()
{
    return lineno;
}

std::vector<uint8_t>
DataSet::getMessage()
{
    return Message;
}

std::vector<uint8_t>
DataSet::getDigest()
{
    return Digest;
}

} // namespace alcp::bench
