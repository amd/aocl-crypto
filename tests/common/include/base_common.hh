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

#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <vector>

namespace alcp::testing {
class File
{
  private:
    std::fstream m_file;
    bool         m_fileExists;

  public:
    // Opens File as Bin/ASCII File with write support.
    File(std::string fileName, bool binary, bool write);
    // Opens File as ASCII Text File
    File(std::string fileName);
    ~File();
    // Read file word by word excludes newlines and spaces
    std::string readWord();
    // Read file line by line
    std::string readLine();
    // Write a line to the file
    bool writeLine(std::string buff);
    // Reads a line by reading char by char
    std::string readLineCharByChar();
    // Read file n bytes from a file
    char* readChar(size_t n);
    // Reads a set of bytes
    bool readBytes(size_t n, uint8_t* buffer);
    // Writes a set of bytes
    bool writeBytes(size_t n, const uint8_t* buffer);
    // Rewind file to initial position
    void rewind();
    // seekG
    void seek(long pos);
    // tell
    long tell();
    void flush();
};

/* Some functions which don't belong to any class but is common */
void
printErrors(std::string in);
std::vector<uint8_t>
parseHexStrToBin(const std::string in);
std::string
parseBytesToHexStr(const uint8_t* bytes, const int length);
uint8_t
parseHexToNum(const unsigned char c);
bool
isPathExist(const std::string dir);
} // namespace alcp::testing