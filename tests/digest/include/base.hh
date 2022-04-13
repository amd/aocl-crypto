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
#include "base_common.hh"
#include <alcp/alcp.h>
#include <vector>

namespace alcp::testing {

typedef enum
{
    SHA2_224 = 0,
    SHA2_256,
    SHA2_384,
    SHA2_512,
} record_t;

class ExecRecPlay
{
  private:
    File*                m_blackbox_bin = nullptr;
    File*                m_log          = nullptr;
    time_t               m_start_time;
    time_t               m_end_time;
    std::size_t          m_blackbox_start_pos = 0;
    std::size_t          m_blackbox_end_pos   = 0;
    record_t             m_rec_type;
    std::vector<uint8_t> m_data;
    std::string          m_str_mode = "";
    long                 m_byte_start, m_byte_end, m_rec_t, m_data_size;
    long                 m_prev_log_point;

  public:
    // Create new files for writing
    ExecRecPlay();                     // Default Record Mode
    ExecRecPlay(std::string str_mode); // Default Record Mode
    ExecRecPlay(std::string str_mode, bool playback);
    ExecRecPlay(std::string str_mode, std::string dir_name, bool playback);

    // Destructor, free and clear pointers
    ~ExecRecPlay();

    void init(std::string str_mode, std::string dir_name, bool playback);

    // Rewind log pointer
    bool rewindLog();
    bool nextLog();
    bool fastForward(record_t rec);
    bool getValues(std::vector<uint8_t>* data);

    bool playbackLocateEvent(record_t rec);

    // Start a new event, so initalize new entry.
    void startRecEvent();

    // End the event, so record end time.
    void endRecEvent();

    /**
     * @brief Set everything generated during test
     *
     * @param key - 128/192/256 bit KEY
     * @param iv - 128 bit IV
     * @param data - PlainText/CipherText
     * @param rec - Test type, BIG_ENC,SMALL_ENC etc..
     */
    void setRecEvent(std::vector<uint8_t> data, record_t rec);

    // Sets the Data in the event
    void setRecData(std::vector<uint8_t> data);

    // Set Test type, BIG_ENC,SMALL_ENC etc..
    void setRecType(record_t rec);

    // Write to backbox, write binary data, not the actual log
    void dumpBlackBox();

    // Write to event log, csv file about the event
    void dumpLog();
};
class DataSet : private File
{
  private:
    std::string          line = "";
    std::vector<uint8_t> Digest, Message;
    // First line is skipped, linenum starts from 1
    int lineno = 1;

  public:
    // Treats file as CSV, skips first line
    DataSet(const std::string filename);
    // Read without condition
    bool readMsgDigest();
    // To print which line in dataset failed
    int getLineNumber();
    /* fetch Message / Digest */
    std::vector<uint8_t> getMessage();
    std::vector<uint8_t> getDigest();
};
class DigestBase
{
  public:
    virtual bool        init(_alc_sha2_mode   mode,
                             _alc_digest_type type,
                             _alc_digest_len  sha_len)      = 0;
    virtual bool        init()                             = 0;
    virtual alc_error_t digest_function(const uint8_t* src,
                                        uint64_t       src_size,
                                        uint8_t*       output,
                                        uint64_t       out_size) = 0;
    virtual void        hash_to_string(char*          output_string,
                                       const uint8_t* hash,
                                       int            sha_len)        = 0;
    virtual void        reset()                            = 0;
};

} // namespace alcp::testing
