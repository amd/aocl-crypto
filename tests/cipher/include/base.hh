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
#pragma once
#include <fstream>
#include <sstream>
#include <vector>

namespace alcp::testing {
class File
{
  private:
    std::fstream file;
    bool         fileExists;

  public:
    // Opens File as ASCII Text File
    File(std::string fileName);
    // Read file word by word excludes newlines and spaces
    std::string readWord();
    // Read file line by line
    std::string readLine();
    // Reads a line by reading char by char
    std::string readLineCharByChar();
    // Read file n char
    char* readChar(int n);
    // Rewind file to initial position
    void rewind();
};

class DataSet : private File
{
  private:
    std::string          line = "";
    std::vector<uint8_t> pt, iv, key, ct;
    // First line is skipped, linenum starts from 1
    int lineno = 1;

  public:
    // Treats file as CSV, skips first line
    DataSet(std::string filename);
    // Read without condition
    bool readPtIvKeyCt();
    // Read only specified key size
    bool readPtIvKeyCt(int keybits);
    // Convert a hex char to number;
    uint8_t parseHexToNum(unsigned char c);
    // Parse hexString to binary
    std::vector<uint8_t> parseHexStrToBin(std::string in);
    std::string          parseBytesToHexStr(uint8_t* bytes, int length);
    // To print which line in dataset failed
    int getLineNumber();
    // Return private data plain text
    std::vector<uint8_t> getPt();
    // Return private data initialization vector
    std::vector<uint8_t> getIv();
    // Return private data key
    std::vector<uint8_t> getKey();
    // Return private data cipher text
    std::vector<uint8_t> getCt();
};
} // namespace alcp::testing
