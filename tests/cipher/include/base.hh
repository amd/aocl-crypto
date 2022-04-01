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
#include "alcp/alcp.h"
#include <fstream>
#include <iostream>
#include <vector>

namespace alcp::testing {

typedef enum
{
    SMALL_DEC = 0,
    SMALL_ENC,
    BIG_DEC,
    BIG_ENC,
} record_t;

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
    // Read file word by word excludes newlines and spaces
    std::string readWord();
    // Read file line by line
    std::string readLine();
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
    size_t tell();
};

class FlightRecorder
{
  private:
    File*                m_blackbox_bin = nullptr;
    File*                m_log          = nullptr;
    time_t               m_start_time;
    time_t               m_end_time;
    std::size_t          m_blackbox_start_pos = 0;
    std::size_t          m_blackbox_end_pos   = 0;
    record_t             m_rec_type;
    std::vector<uint8_t> m_key;
    std::vector<uint8_t> m_iv;
    std::vector<uint8_t> m_data;
    std::string          m_str_mode = "";

  public:
    // Create new files for writing
    FlightRecorder();
    FlightRecorder(std::string str_mode);

    // Start a new event, so initalize new entry.
    void startEvent();

    // End the event, so record end time.
    void endEvent();

    /**
     * @brief Set everything generated during test
     *
     * @param key - 128/192/256 bit KEY
     * @param iv - 128 bit IV
     * @param data - PlainText/CipherText
     * @param rec - Test type, BIG_ENC,SMALL_ENC etc..
     */
    void setEvent(std::vector<uint8_t> key,
                  std::vector<uint8_t> iv,
                  std::vector<uint8_t> data,
                  record_t             rec);

    // Sets the Key of the event
    void setKey(std::vector<uint8_t> key);

    // Sets the IV of the event
    void setIv(std::vector<uint8_t> iv);

    // Sets the Data in the event
    void setData(std::vector<uint8_t> data);

    // Set Test type, BIG_ENC,SMALL_ENC etc..
    void setRecType(record_t rec);

    // Write to backbox, write binary data, not the actual log
    void writeBackBox();

    // Write to event log, csv file about the event
    void writeLog();
};

class DataSet : private File
{
  private:
    std::string          line = "";
    std::vector<uint8_t> m_pt, m_iv, m_key, m_ct;
    // First line is skipped, linenum starts from 1
    int lineno = 1;

  public:
    // Treats file as CSV, skips first line
    DataSet(const std::string filename);
    // Read without condition
    bool readPtIvKeyCt();
    // Read only specified key size
    bool readPtIvKeyCt(size_t keybits);
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

/**
 * @brief CipherBase is a wrapper for which library to use
 *
 */
class CipherBase
{
  public:
    virtual bool init(const uint8_t* iv,
                      const uint8_t* key,
                      const uint32_t key_len)                     = 0;
    virtual bool init(const uint8_t* key, const uint32_t key_len) = 0;
    virtual bool encrypt(const uint8_t* plaintxt,
                         size_t         len,
                         uint8_t*       ciphertxt)                      = 0;
    virtual bool decrypt(const uint8_t* ciphertxt,
                         size_t         len,
                         uint8_t*       plaintxt)                       = 0;
};

class CipherTesting
{
  private:
    CipherBase* cb = nullptr;

  public:
    CipherTesting() {}
    CipherTesting(CipherBase* impl);
    std::vector<uint8_t> testingEncrypt(const std::vector<uint8_t> plaintext,
                                        const std::vector<uint8_t> key,
                                        const std::vector<uint8_t> iv);
    std::vector<uint8_t> testingDecrypt(const std::vector<uint8_t> ciphertext,
                                        const std::vector<uint8_t> key,
                                        const std::vector<uint8_t> iv);
    void                 setcb(CipherBase* impl);
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
} // namespace alcp::testing
