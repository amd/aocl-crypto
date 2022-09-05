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

#include "cipher/base.hh"
#include <sstream>
#ifdef USE_IPP
#include "cipher/ipp_base.hh"
#endif

namespace alcp::testing {

// Class ExecRecPlay - FlightRecorder/FlightReplay
ExecRecPlay::ExecRecPlay()
{
    init("", "cipher_test_data", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode)
{
    init(str_mode, "cipher_test_data", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode, bool playback)
{
    init(str_mode, "cipher_test_data", playback);
}

ExecRecPlay::ExecRecPlay(std::string str_mode,
                         std::string dir_name,
                         bool        playback)
{
    init(str_mode, dir_name, playback);
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
ExecRecPlay::init(std::string str_mode, std::string dir_name, bool playback)
{
    if (!isPathExist(dir_name)) {
        mkdir(dir_name.c_str(), 0755);
    }
    if (!playback) { // Record
        // Binary File, need to open binary
        m_blackbox_bin = new File(
            dir_name + "/crosstest_" + str_mode + "_blackbox.bin", true, true);
        // ASCII File, need to open as ASCII
        if (m_blackbox_bin == nullptr) {
            std::cout << "base.cc: Blackbox creation failure" << std::endl;
        }
        m_log =
            new File(dir_name + "/crosstest_" + str_mode + ".log", false, true);
        if (m_log == nullptr) {
            std::cout << "base.cc: Log creation failure" << std::endl;
        }
    } else { // Playback
        // Binary File, need to open binary
        m_blackbox_bin = new File(
            dir_name + "/crosstest_" + str_mode + "_blackbox.bin", true, false);
        // ASCII File, need to open as ASCII
        m_log = new File(
            dir_name + "/crosstest_" + str_mode + ".log", false, false);
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
    bool ret = false;
    while (nextLog()) {
        if (m_rec_t == rec) {
            ret = true;
            break;
        }
    }
    m_log->seek(m_prev_log_point);
    return ret;
}

bool
ExecRecPlay::getValues(std::vector<uint8_t>* key,
                       std::vector<uint8_t>* iv,
                       std::vector<uint8_t>* data)
{
    bool ret = false;
    if ((m_byte_end - m_byte_start) <= 0) {
        std::stringstream ss;
        ss << "Error: Cannot allocate -ve memory m_byte_end:" << m_byte_end
           << " ";
        ss << "m_byte_start:" << m_byte_start;
        throw ss.str();
    }
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
        ret = true;
    }
    if (buffer) {
        delete[] buffer;
    }
    return ret;
}

bool
ExecRecPlay::playbackLocateEvent(record_t rec)
{
    rewindLog();
    return fastForward(rec);
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

bool
DataSet::readPtIvKeyCtAddTag(size_t keybits)
{
    while (true) {
        if (readPtIvKeyCtAddTag() == false)
            return false;
        else if (m_key.size() * 8 == keybits)
            return true;
    }
}

bool
DataSet::readPtIvKeyCtAddTag()
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
    int pos4 = line.find(",", pos3 + 1); // End of CT
    int pos5 = line.find(",", pos4 + 1); // End of additional data
    if ((pos1 == -1) || (pos2 == -1) || (pos3 == -1)) {
        return false;
    }

    m_pt  = parseHexStrToBin(line.substr(0, pos1));
    m_iv  = parseHexStrToBin(line.substr(pos1 + 1, pos2 - pos1 - 1));
    m_key = parseHexStrToBin(line.substr(pos2 + 1, pos3 - pos2 - 1));
    m_ct  = parseHexStrToBin(line.substr(pos3 + 1, pos4 - pos3 - 1));
    m_add = parseHexStrToBin(line.substr(pos4 + 1, pos5 - pos4 - 1));
    m_tag = parseHexStrToBin(line.substr(pos5 + 1));

    lineno++;
    return true;
}

bool
DataSet::readPtIvKeyCtTKey(size_t keybits)
{
    while (true) {
        if (readPtIvKeyCtTKey() == false)
            return false;
        else if (m_key.size() * 8 == keybits)
            return true;
    }
}

bool
DataSet::readPtIvKeyCtTKey()
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
    int pos4 = line.find(",", pos3 + 1); // End of CT
    if ((pos1 == -1) || (pos2 == -1) || (pos3 == -1) || (pos4 == -1)) {
        return false;
    }

    m_pt   = parseHexStrToBin(line.substr(0, pos1));
    m_iv   = parseHexStrToBin(line.substr(pos1 + 1, pos2 - pos1 - 1));
    m_key  = parseHexStrToBin(line.substr(pos2 + 1, pos3 - pos2 - 1));
    m_ct   = parseHexStrToBin(line.substr(pos3 + 1, pos4 - pos3 - 1));
    m_tkey = parseHexStrToBin(line.substr(pos4 + 1));

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

std::vector<uint8_t>
DataSet::getAdd()
{
    return m_add;
}

std::vector<uint8_t>
DataSet::getTag()
{
    return m_tag;
}

/*for aes xtr*/
std::vector<uint8_t>
DataSet::getTKey()
{
    return m_tkey;
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

bool
CipherTesting::testingEncrypt(alcp_data_ex_t             data,
                              const std::vector<uint8_t> key)
{
    if (cb != nullptr) {
        if (cb->init(data.iv,
                     data.ivl,
                     &(key[0]),
                     key.size() * 8,
                     data.tkey,
                     data.block_size)) {
            // For very large sizes, dynamic is better.
            return cb->encrypt(data);
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return false;
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

bool
CipherTesting::testingDecrypt(alcp_data_ex_t             data,
                              const std::vector<uint8_t> key)
{
    if (cb != nullptr) {
        if (cb->init(data.iv,
                     data.ivl,
                     &(key[0]),
                     key.size() * 8,
                     data.tkey,
                     data.block_size)) {
            return cb->decrypt(data);
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return false;
}

void
CipherTesting::setcb(CipherBase* impl)
{
    cb = impl;
}

} // namespace alcp::testing
