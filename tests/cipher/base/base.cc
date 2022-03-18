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
#ifdef USE_IPP
#include "ipp_base.hh"
#endif
#include <iostream>

namespace alcp::testing {

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

// Class Data
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
DataSet::readPtIvKeyCt(size_t keybits)
{
    while (true) {
        if (readPtIvKeyCt() == false)
            return false;
        else if (m_key.size() * 8 == keybits)
            return true;
    }
}
bool
DataSet::readPtIvKeyCt()
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
    int pos1 = line.find(",");           // End of Plain Text (PT)
    int pos2 = line.find(",", pos1 + 1); // End of IV
    int pos3 = line.find(",", pos2 + 1); // End of Key
    if ((pos1 == -1) || (pos2 == -1) || (pos3 == -1)) {
        return false;
    }
    m_pt  = parseHexStrToBin(line.substr(0, pos1));
    m_iv  = parseHexStrToBin(line.substr(pos1 + 1, pos2 - pos1 - 1));
    m_key = parseHexStrToBin(line.substr(pos2 + 1, pos3 - pos2 - 1));
    m_ct  = parseHexStrToBin(line.substr(pos3 + 1));
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
            parseHexToNum(in.at(ind + 1)) << 4 | parseHexToNum(in.at(ind));
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
DataSet::getPt()
{
    return m_pt;
}

std::vector<uint8_t>
DataSet::getIv()
{
    return m_iv;
}

std::vector<uint8_t>
DataSet::getKey()
{
    return m_key;
}

std::vector<uint8_t>
DataSet::getCt()
{
    return m_ct;
}

// CipherTesting class functions
CipherTesting::CipherTesting(CipherBase* impl)
{
    setcb(impl);
}
std::vector<uint8_t>
CipherTesting::testingEncrypt(const std::vector<uint8_t> plaintext,
                              const std::vector<uint8_t> key,
                              const std::vector<uint8_t> iv)
{
    if (cb != nullptr) {
        if (cb->init(&iv[0], &key[0], key.size() * 8)) {
            uint8_t ciphertext[plaintext.size()];
            cb->encrypt(&(plaintext[0]), plaintext.size(), ciphertext);
            std::vector<uint8_t> vt =
                std::vector<uint8_t>(ciphertext, ciphertext + plaintext.size());
            return vt;
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return {};
}

std::vector<uint8_t>
CipherTesting::testingDecrypt(const std::vector<uint8_t> ciphertext,
                              const std::vector<uint8_t> key,
                              const std::vector<uint8_t> iv)
{
    if (cb != nullptr) {
        if (cb->init(&iv[0], &key[0], key.size() * 8)) {
            uint8_t plaintext[ciphertext.size()];
            cb->decrypt(&ciphertext[0], ciphertext.size(), plaintext);
            std::vector<uint8_t> vt =
                std::vector<uint8_t>(plaintext, plaintext + ciphertext.size());
            return vt;
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return {};
}
void
CipherTesting::setcb(CipherBase* impl)
{
    cb = impl;
}

} // namespace alcp::testing