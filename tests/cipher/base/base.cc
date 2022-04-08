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

File::~File()
{
    m_file.flush();
    m_file.close();
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

// Class ExecRecPlay - FlightRecorder/FlightReplay
ExecRecPlay::ExecRecPlay()
{
    init("", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode)
{
    init(str_mode, false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode, bool playback)
{
    init(str_mode, playback);
}

ExecRecPlay::~ExecRecPlay()
{
    if (m_blackbox_bin != nullptr) {
        delete m_blackbox_bin;
        m_blackbox_bin = nullptr;
    }
    if (m_log != nullptr) {
        delete m_log;
        m_log = nullptr;
    }
}

void
ExecRecPlay::init(std::string str_mode, bool playback)
{
    if (!playback) { // Record
        // Binary File, need to open binary
        m_blackbox_bin =
            new File("crosstest_" + str_mode + "_blackbox.bin", true, true);
        // ASCII File, need to open as ASCII
        if (m_blackbox_bin == nullptr) {
            std::cout << "base.cc: Blackbox creation failure" << std::endl;
        }
        m_log = new File("crosstest_" + str_mode + ".log", false, true);
        if (m_log == nullptr) {
            std::cout << "base.cc: Log creation failure" << std::endl;
        }
    } else { // Playback
        // Binary File, need to open binary
        m_blackbox_bin =
            new File("crosstest_" + str_mode + "_blackbox.bin", true, false);
        // ASCII File, need to open as ASCII
        m_log = new File("crosstest_" + str_mode + ".log", false, false);
    }
}

bool
ExecRecPlay::rewindLog()
{
    if (m_log != nullptr) {
        m_log->seek(0);
        return 1; // No Error
    }
    return 0; // There is Error
}

bool
ExecRecPlay::nextLog() // Parser
{
    int comma[6]; // There are 6 comma and 7 values
    m_prev_log_point = m_log->tell();
    std::string line = m_log->readLine();
    if (line.size() == 0) { // Enof of File condition
        return false;
    }
    // Locate all comma
    comma[0] = line.find(",");
    comma[1] = line.find(",", comma[0] + 1);
    comma[2] = line.find(",", comma[1] + 1);
    comma[3] = line.find(",", comma[2] + 1);
    comma[4] = line.find(",", comma[3] + 1);
    comma[5] = line.find(",", comma[4] + 1);

    // Extract the data from the current log
    m_start_time = stol(line.substr(0, comma[0]));
    m_end_time   = stol(line.substr(comma[0] + 1, comma[1] - comma[0] - 1));
    m_byte_start = stol(line.substr(comma[1] + 1, comma[2] - comma[1] - 1));
    m_byte_end   = stol(line.substr(comma[2] + 1, comma[3] - comma[2] - 1));
    m_rec_t      = stol(line.substr(comma[3] + 1, comma[4] - comma[3] - 1));
    m_key_size   = stol(line.substr(comma[4] + 1, comma[5] - comma[4] - 1));
    m_data_size  = stol(line.substr(comma[5] + 1));

#if 0 // Enable for Debug
    std::cout << "start_time->" << start_time << " "
              << "end_time->" << end_time << " "
              << "byte_start->" << byte_start << " "
              << "byte_end->" << byte_end << " "
              << "rec_dec->" << rec_dec << " "
              << "key_size->" << key_size << " "
              << "data_size->" << data_size << std::endl;
#endif
    return true;
}

bool
ExecRecPlay::fastForward(record_t rec)
{

    while (nextLog()) {
        if (m_rec_t == rec) {
            break;
        }
    }
    m_log->seek(m_prev_log_point);
}

bool
ExecRecPlay::getValues(std::vector<uint8_t>* key,
                       std::vector<uint8_t>* iv,
                       std::vector<uint8_t>* data)
{
    uint8_t* buffer = new uint8_t[m_byte_end - m_byte_start];
    // uint8_t  buffer[m_byte_end - m_byte_start];
    m_blackbox_bin->seek(m_byte_start);
    if (m_blackbox_bin->readBytes(m_byte_end - m_byte_start, buffer)) {
        *iv   = std::vector<uint8_t>(buffer, buffer + 16);
        *key  = std::vector<uint8_t>(buffer + 16, buffer + 16 + m_key_size);
        *data = std::vector<uint8_t>(buffer + 16 + m_key_size,
                                     buffer + m_byte_end - m_byte_start);
#if 0
        std::cout << "IV:" << parseBytesToHexStr(&((*iv)[0]), iv->size())
                  << std::endl;
        std::cout << "KEY:" << parseBytesToHexStr(&((*key)[0]), key->size())
                  << std::endl;
        std::cout << "DATA:" << parseBytesToHexStr(&((*data)[0]), data->size())
                  << std::endl;
        std::cout << "END:" << m_byte_end << "\tSTART:" << m_byte_start
                  << std::endl;
#endif
    }
    if (buffer) {
        delete[] buffer;
    }
}

bool
ExecRecPlay::playbackLocateEvent(record_t rec)
{
    rewindLog();
    fastForward(rec);
    // Write a parser and locate the recorder..
}

void
ExecRecPlay::startRecEvent()
{
    m_start_time         = time(0);
    m_blackbox_start_pos = m_blackbox_bin->tell();
}

void
ExecRecPlay::endRecEvent()
{
    m_end_time         = time(0);
    m_blackbox_end_pos = m_blackbox_bin->tell();
}

void
ExecRecPlay::setRecEvent(std::vector<uint8_t> key,
                         std::vector<uint8_t> iv,
                         std::vector<uint8_t> data,
                         record_t             rec)
{
    setRecKey(key);
    setRecIv(iv);
    setRecData(data);
    setRecType(rec);
}

void
ExecRecPlay::setRecKey(std::vector<uint8_t> key)
{
    m_key = key;
}

void
ExecRecPlay::setRecIv(std::vector<uint8_t> iv)
{
    m_iv = iv;
}

void
ExecRecPlay::setRecData(std::vector<uint8_t> data)
{
    m_data = data;
}

void
ExecRecPlay::setRecType(record_t rec)
{
    m_rec_type = rec;
}

void
ExecRecPlay::dumpBlackBox()
{
    m_blackbox_bin->writeBytes(m_iv.size(), &(m_iv[0]));
    m_blackbox_bin->writeBytes(m_key.size(), &(m_key[0]));
    m_blackbox_bin->writeBytes(m_data.size(), &(m_data[0]));
    m_blackbox_bin->flush();
}

void
ExecRecPlay::dumpLog()
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
    m_log->flush();
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