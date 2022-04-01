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
#include "colors.hh"
#include <sstream>
#include <unistd.h>
#ifdef USE_IPP
#include "ipp_base.hh"
#endif

namespace alcp::testing {

/* Class File procedures */
File::File(const std::string fileName, bool binary, bool write)
{
    if (binary && write) { // Binary write
        m_file.open(fileName, std::ios::out | std::ios::binary);
    } else if (binary) { // Binary read
        m_file.open(fileName, std::ios::binary);
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
    return;
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
File::readBytes(size_t n, uint8_t* buffer)
{
    m_file.read(reinterpret_cast<char*>(buffer), n);
    return true;
}

bool
File::writeBytes(size_t n, const uint8_t* buffer)
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

size_t
File::tell()
{
    return m_file.tellg();
}

// Class FlightRecorder
FlightRecorder::FlightRecorder()
{
    m_blackbox_bin = new File("crosstest_blackbox.bin", true, true);
    m_log          = new File("crosstest.log", true, true);
}

FlightRecorder::FlightRecorder(std::string str_mode)
{
    m_blackbox_bin =
        new File("crosstest_" + str_mode + "_blackbox.bin", true, true);
    m_log = new File("crosstest_" + str_mode + ".log", true, true);
}

void
FlightRecorder::startEvent()
{
    m_start_time         = time(0);
    m_blackbox_start_pos = m_blackbox_bin->tell();
}

void
FlightRecorder::endEvent()
{
    m_end_time         = time(0);
    m_blackbox_end_pos = m_blackbox_bin->tell();
}

void
FlightRecorder::setEvent(std::vector<uint8_t> key,
                         std::vector<uint8_t> iv,
                         std::vector<uint8_t> data,
                         record_t             rec)
{
    setKey(key);
    setIv(iv);
    setData(data);
    setRecType(rec);
}

void
FlightRecorder::setKey(std::vector<uint8_t> key)
{
    m_key = key;
}

void
FlightRecorder::setIv(std::vector<uint8_t> iv)
{
    m_iv = iv;
}

void
FlightRecorder::setData(std::vector<uint8_t> data)
{
    m_data = data;
}

void
FlightRecorder::setRecType(record_t rec)
{
    m_rec_type = rec;
}

void
FlightRecorder::writeBackBox()
{
    m_blackbox_bin->writeBytes(m_iv.size(), &(m_iv[0]));
    m_blackbox_bin->writeBytes(m_key.size(), &(m_key[0]));
    m_blackbox_bin->writeBytes(m_data.size(), &(m_data[0]));
}

void
FlightRecorder::writeLog()
{
    /*
       Format of the log file is
       start_time, end_time, blackbox_start, blackbox_end, record_type,
       key_size, data_size # TODO FAILED/SUCCESS record
    */
    std::stringstream ss;
    ss << m_start_time << ",";
    ss << m_end_time << ",";
    ss << m_blackbox_start_pos << ",";
    ss << m_blackbox_end_pos << ",";
    ss << m_rec_type << ",";
    ss << m_key.size() << ",";
    ss << m_data.size();
    m_log->writeLine(ss.str());
}

// Class DataSet
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
            // For very large sizes, dynamic is better.
            uint8_t* ciphertext = new uint8_t[plaintext.size()];
            cb->encrypt(&(plaintext[0]), plaintext.size(), ciphertext);
            std::vector<uint8_t> vt =
                std::vector<uint8_t>(ciphertext, ciphertext + plaintext.size());
            delete[] ciphertext;
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
            // For very large sizes, dynamic is better.
            uint8_t* plaintext = new uint8_t[ciphertext.size()];
            cb->decrypt(&ciphertext[0], ciphertext.size(), plaintext);
            std::vector<uint8_t> vt =
                std::vector<uint8_t>(plaintext, plaintext + ciphertext.size());
            delete[] plaintext;
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
std::vector<uint8_t>
parseHexStrToBin(const std::string in)
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
parseBytesToHexStr(const uint8_t* bytes, const int length)
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
uint8_t
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

} // namespace alcp::testing