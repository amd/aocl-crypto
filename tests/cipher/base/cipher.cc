/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "cipher/cipher.hh"
#include "alcp/alcp.h"
#include <sstream>
#ifdef USE_IPP
#include "cipher/ipp_cipher.hh"
#endif
#ifdef WIN32
#include <direct.h>
#endif

namespace alcp::testing {

/* to check if cipher type is non-AES
 TO DO: Update this when we have more non-AES types */
bool
isNonAESCipherType(_alc_cipher_type cipher_type)
{
    return cipher_type != ALC_CIPHER_TYPE_AES;
}

/**
 * returns respective string based on AES modes
 */
std::string
GetModeSTR(alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_ECB:
            return "ECB";
        case ALC_AES_MODE_CBC:
            return "CBC";
        case ALC_AES_MODE_OFB:
            return "OFB";
        case ALC_AES_MODE_CTR:
            return "CTR";
        case ALC_AES_MODE_CFB:
            return "CFB";
        case ALC_AES_MODE_XTS:
            return "XTS";
        case ALC_AES_MODE_GCM:
            return "GCM";
        case ALC_AES_MODE_CCM:
            return "CCM";
        case ALC_AES_MODE_SIV:
            return "SIV";
        case ALC_CHACHA20:
            return "Chacha20";
        case ALC_CHACHA20_POLY1305:
            return "chacha20-poly1305";
        default:
            return "";
    }
}

/** check if cipher mode is AEAD **/
bool
CheckCipherIsAEAD(alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_ECB:
        case ALC_AES_MODE_CBC:
        case ALC_AES_MODE_OFB:
        case ALC_AES_MODE_CTR:
        case ALC_AES_MODE_CFB:
        case ALC_AES_MODE_XTS:
        case ALC_CHACHA20:
            return false;
        case ALC_AES_MODE_GCM:
        case ALC_AES_MODE_CCM:
        case ALC_AES_MODE_SIV:
        case ALC_CHACHA20_POLY1305:
            return true;
        default:
            return false;
    }
    return false;
}

// Class ExecRecPlay - FlightRecorder/FlightReplay
ExecRecPlay::ExecRecPlay()
{
    init("", "cipher_test_data", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode)
{
    init(std::move(str_mode), "cipher_test_data", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode, bool playback)
{
    init(std::move(str_mode), "cipher_test_data", playback);
}

ExecRecPlay::ExecRecPlay(std::string str_mode,
                         std::string dir_name,
                         bool        playback)
{
    init(std::move(str_mode), std::move(dir_name), playback);
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
    int retval = 0;
    if (!isPathExist(dir_name)) {
#ifdef __linux__
        retval = mkdir(dir_name.c_str(), 0755);
#elif WIN32
        retval = _mkdir(dir_name.c_str());
#endif
    }
    if (retval != 0) {
        std::cout << "Blackbox creation failure" << std::endl;
        return;
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
ExecRecPlay::getValues(std::vector<Uint8>* key,
                       std::vector<Uint8>* iv,
                       std::vector<Uint8>* data)
{
    bool ret = false;
    if ((m_byte_end - m_byte_start) <= 0) {
        std::stringstream ss;
        ss << "Error: Cannot allocate -ve memory m_byte_end:" << m_byte_end
           << " ";
        ss << "m_byte_start:" << m_byte_start;
        throw ss.str();
    }
    Uint8* buffer = new Uint8[m_byte_end - m_byte_start];
    // Uint8  buffer[m_byte_end - m_byte_start];
    m_blackbox_bin->seek(m_byte_start);
    if (m_blackbox_bin->readBytes(m_byte_end - m_byte_start, buffer)) {
        *iv   = std::vector<Uint8>(buffer, buffer + 16);
        *key  = std::vector<Uint8>(buffer + 16, buffer + 16 + m_key_size);
        *data = std::vector<Uint8>(buffer + 16 + m_key_size,
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
ExecRecPlay::setRecEvent(std::vector<Uint8> key,
                         std::vector<Uint8> iv,
                         std::vector<Uint8> data,
                         record_t           rec)
{
    setRecKey(std::move(key));
    setRecIv(std::move(iv));
    setRecData(std::move(data));
    setRecType(rec);
}

void
ExecRecPlay::setRecKey(std::vector<Uint8> key)
{
    m_key = std::move(key);
}

void
ExecRecPlay::setRecIv(std::vector<Uint8> iv)
{
    m_iv = std::move(iv);
}

void
ExecRecPlay::setRecData(std::vector<Uint8> data)
{
    m_data = std::move(data);
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

// CipherTesting class functions
CipherTesting::CipherTesting(CipherBase* impl)
{
    setcb(impl);
}

bool
CipherTesting::testingEncrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key)
{
    if (cb != nullptr) {
        if (cb->init(data.m_iv,
                     data.m_ivl,
                     &(key[0]),
                     key.size() * 8,
                     data.m_tkey,
                     data.m_block_size)) {
            // For very large sizes, dynamic is better.
            return cb->encrypt(data);
        } else {
            std::cout << "Test: Cipher: Encrypt: Failure in Init" << std::endl;
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return false;
}

bool
CipherTesting::testingDecrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key)
{
    if (cb != nullptr) {
        if (cb->init(data.m_iv,
                     data.m_ivl,
                     &(key[0]),
                     key.size() * 8,
                     data.m_tkey,
                     data.m_block_size)) {
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

bool
CipherAeadBase::isAead(const alc_cipher_mode_t& mode)
{
    switch (mode) {
        case ALC_AES_MODE_GCM:
        case ALC_AES_MODE_SIV:
        case ALC_AES_MODE_CCM:
        case ALC_CHACHA20_POLY1305:
            return true;
        default:
            return false;
    }
}

} // namespace alcp::testing
