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

#include "digest/base.hh"
#include <iostream>
#include <sstream>
#include <unistd.h>

namespace alcp::testing {

// Class ExecRecPlay - FlightRecorder/FlightReplay
ExecRecPlay::ExecRecPlay()
{
    init("", "digest_test_data", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode)
{
    init(str_mode, "digest_test_data", false);
}

ExecRecPlay::ExecRecPlay(std::string str_mode, bool playback)
{
    init(str_mode, "digest_test_data", playback);
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

    // Extract the data from the current log
    m_start_time = stol(line.substr(0, comma[0]));
    m_end_time   = stol(line.substr(comma[0] + 1, comma[1] - comma[0] - 1));
    m_byte_start = stol(line.substr(comma[1] + 1, comma[2] - comma[1] - 1));
    m_byte_end   = stol(line.substr(comma[2] + 1, comma[3] - comma[2] - 1));
    m_rec_t      = stol(line.substr(comma[3] + 1, comma[4] - comma[3] - 1));
    m_data_size  = stol(line.substr(comma[4] + 1));

#if 0 // Enable for Debug
    std::cout << "start_time->" << start_time << " "
              << "end_time->" << end_time << " "
              << "byte_start->" << byte_start << " "
              << "byte_end->" << byte_end << " "
              << "rec_dec->" << rec_dec << " "
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
ExecRecPlay::getValues(std::vector<uint8_t>* data)
{
    bool     ret    = false;
    uint8_t* buffer = new uint8_t[m_byte_end - m_byte_start];
    m_blackbox_bin->seek(m_byte_start);
    if (m_blackbox_bin->readBytes(m_byte_end - m_byte_start, buffer)) {
        *data =
            std::vector<uint8_t>(buffer, buffer + m_byte_end - m_byte_start);
#if 0
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
ExecRecPlay::setRecEvent(std::vector<uint8_t> data, record_t rec)
{
    setRecData(data);
    setRecType(rec);
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
    m_blackbox_bin->writeBytes(m_data.size(), &(m_data[0]));
    m_blackbox_bin->flush();
}

void
ExecRecPlay::dumpLog()
{
    /*
       Format of the log file is
       start_time, end_time, blackbox_start, blackbox_end, record_type,
       data_size # TODO FAILED/SUCCESS record
    */
    std::stringstream ss;
    ss << m_start_time << ",";
    ss << m_end_time << ",";
    ss << m_blackbox_start_pos << ",";
    ss << m_blackbox_end_pos << ",";
    ss << m_rec_type << ",";
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
} // namespace alcp::testing
