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

#include "utils.hh"

namespace alcp::testing::utils {

// Some important functions which don't belong to a class
void
printErrors(std::string in)
{
    if (isatty(fileno(stderr))) {
        // stdout is a real terminal, safe to output color
        std::cerr << RED_BOLD << in << RESET << std::endl;

    } else {
        // stdout is a pseudo terminal, unsafe to output color
        std::cerr << in << std::endl;
    }
}
void
printErrors(std::string in, std::string file, int lineno)
{
    if (isatty(fileno(stderr))) {
        // stdout is a real terminal, safe to output color
        std::cerr << RED_BOLD << file << ":" << lineno << ":" << in << RESET
                  << std::endl;

    } else {
        // stdout is a pseudo terminal, unsafe to output color
        std::cerr << in << std::endl;
    }
}
std::vector<Uint8>
parseHexStrToBin(const std::string in)
{
    std::vector<Uint8> vector;
    int                len = in.size();
    int                ind = 0;
    
    if (in == "0")
        vector.push_back(Uint8(0));
    else 
        for (int i = 0; i < len; i += 2) {
            Uint8 val =
                parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
            vector.push_back(val);
            ind += 2;
        }
    return vector;
}
std::string
parseBytesToHexStr(const Uint8* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        // Convert int to hex
        il << std::hex << charRep;
        std::string ilStr = il.str();
        // 01 will be 0x1 so we need to make it 0x01
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    return ss.str();
}
Uint8
parseHexToNum(const unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

Uint64
parseStrToUint64(const std::string str)
{
    return std::stoull(str);
}

bool
isPathExist(const std::string dir)
{
    struct stat buffer;
    if (stat(dir.c_str(), &buffer) == 0) {
        return true;
    } else {
        return false;
    }
}

void
Hash_to_string(char* output_string, const Uint8* hash, int sha_len)
{
    for (int i = 0; i < sha_len / 8; i++) {
        output_string += sprintf(output_string, "%02x", hash[i]);
    }
    output_string[(sha_len / 8) * 2 + 1] = '\0';
}

} // namespace alcp::testing::utils