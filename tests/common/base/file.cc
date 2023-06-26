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

#include "file.hh"

namespace alcp::testing {
/* Class File procedures */
File::File(const std::string fileName, bool binary, bool write)
{
    if (binary && write) { // Binary write
        m_file.open(fileName, std::ios::out | std::ios::binary);
    } else if ((!write) && binary) { // Read Binary
        m_file.open(fileName, std::ios::in | std::ios::binary);
    } else if (write) { // Write
        m_file.open(fileName, std::ios::out);
    } else { // Read
        m_file.open(fileName, std::ios::in);
    }
    if (m_file.is_open()) { // In read mode, this means file did exist
        m_fileExists = true;
    } else {
        m_fileExists = false;
    }
    m_fileEOF = false;
    return;
}

File::File(const std::string fileName)
{
    m_file.open(fileName, std::ios::in);
    if (m_file.is_open()) {
        m_fileExists = true;
    } else {
        m_fileExists = false;
    }
    m_fileEOF = false;
    return;
}

File::~File()
{
    m_file.flush();
    m_file.close();
}

bool
File::CheckFileExists()
{
    return m_fileExists;
}

std::string
File::readWord()
{
    std::string buff;
    m_file >> buff;
    return buff;
}

std::string
File::readLine()
{
    std::string buff;
    std::getline(m_file, buff);
    return buff;
}

bool
File::writeLine(std::string buff)
{
    m_file << buff << "\n";
    return true;
}

std::string
File::readLineCharByChar()
{
    std::string buff;
    while (!m_file.eof()) {
        char s = m_file.get();
        if (s != '\n')
            buff += s;
        else
            break;
    }
    return buff;
}

bool
File::readBytes(size_t n, Uint8* buffer)
{
    m_file.read(reinterpret_cast<char*>(buffer), n);
    return true;
}

bool
File::writeBytes(size_t n, const Uint8* buffer)
{
    m_file.write(reinterpret_cast<const char*>(buffer), n);
    return true;
}

char*
File::readChar(size_t n)
{
    // TODO: Deallocation in the calling function.
    char* c_buff = new char[n];
    m_file.read(c_buff, n);
    return c_buff;
}

void
File::seek(long position)
{
    m_file.seekg(position, std::ios::beg);
}

long
File::tell()
{
    return m_file.tellg();
}

void
File::flush()
{
    m_file.flush();
}

} // namespace alcp::testing