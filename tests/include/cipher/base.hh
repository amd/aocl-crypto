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
#include "base_common.hh"
#include <cstring>
#include <iostream>
#include <vector>

namespace alcp::testing {

struct alcp_data_ex_t
{
    const Uint8* in;
    Uint64       inl;
    Uint8*       out;
    Uint64       outl;
    const Uint8* iv;
    Uint64       ivl;
    const Uint8* ad;
    Uint64       adl;
    Uint8*       tag; // Probably const but openssl expects non const
    Uint64       tagl;
    Uint8*       tkey;  // tweak key
    Uint64       tkeyl; // tweak key len
    Uint64       block_size;
    // Initialize everything to 0
    alcp_data_ex_t()
    {
        in         = nullptr;
        inl        = 0;
        out        = nullptr;
        outl       = 0;
        iv         = nullptr;
        ivl        = 0;
        ad         = nullptr;
        adl        = 0;
        tag        = nullptr;
        tagl       = 0;
        tkey       = nullptr;
        tkey       = 0;
        block_size = 0;
    }
};

typedef enum
{
    SMALL_DEC = 0,
    SMALL_ENC,
    BIG_DEC,
    BIG_ENC,
} record_t;

class ExecRecPlay
{
  private:
    File*              m_blackbox_bin = nullptr;
    File*              m_log          = nullptr;
    time_t             m_start_time;
    time_t             m_end_time;
    std::size_t        m_blackbox_start_pos = 0;
    std::size_t        m_blackbox_end_pos   = 0;
    record_t           m_rec_type;
    std::vector<Uint8> m_key;
    std::vector<Uint8> m_iv;
    std::vector<Uint8> m_data;
    std::string        m_str_mode = "";
    long m_byte_start = 0, m_byte_end = 0, m_rec_t = 0, m_key_size = 0,
         m_data_size = 0;
    long m_prev_log_point;

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
    bool getValues(std::vector<Uint8>* key,
                   std::vector<Uint8>* iv,
                   std::vector<Uint8>* data);

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
    void setRecEvent(std::vector<Uint8> key,
                     std::vector<Uint8> iv,
                     std::vector<Uint8> data,
                     record_t           rec);

    // Sets the Key of the event
    void setRecKey(std::vector<Uint8> key);

    // Sets the IV of the event
    void setRecIv(std::vector<Uint8> iv);

    // Sets the Data in the event
    void setRecData(std::vector<Uint8> data);

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
    std::string        line = "";
    std::vector<Uint8> m_pt, m_iv, m_key, m_ct, m_add, m_tag, m_tkey;
    // First line is skipped, linenum starts from 1
    int lineno = 1;

  public:
    // Treats file as CSV, skips first line
    DataSet(const std::string filename);
    // Read without condition
    bool readPtIvKeyCt();
    bool readPtIvKeyCtAddTag();
    bool readPtIvKeyCtTKey();

    // Read only specified key size
    bool readPtIvKeyCt(size_t keybits);
    bool readPtIvKeyCtAddTag(size_t keybits);
    bool readPtIvKeyCtTKey(size_t keybits);
    // To print which line in dataset failed
    int getLineNumber();
    // Return private data plain text
    std::vector<Uint8> getPt();
    // Return private data initialization vector
    std::vector<Uint8> getIv();
    // Return private data key
    std::vector<Uint8> getKey();
    // Return private data cipher text
    std::vector<Uint8> getCt();
    // Return private data additional data
    std::vector<Uint8> getAdd();
    // Return private data tag
    std::vector<Uint8> getTag();
    // return tweak key
    std::vector<Uint8> getTKey();
};

/**
 * @brief CipherBase is a wrapper for which library to use
 *
 */
class CipherBase
{
  public:
    virtual bool init(const Uint8* iv,
                      const Uint32 iv_len,
                      const Uint8* key,
                      const Uint32 key_len)                   = 0;
    virtual bool init(const Uint8* iv,
                      const Uint8* key,
                      const Uint32 key_len)                   = 0;
    virtual bool init(const Uint8* key, const Uint32 key_len) = 0;
    virtual bool init(const Uint8* iv,
                      const Uint32 iv_len,
                      const Uint8* key,
                      const Uint32 key_len,
                      const Uint8* tkey,
                      const Uint64 block_size)                = 0;
    virtual bool encrypt(const Uint8* plaintxt,
                         size_t       len,
                         Uint8*       ciphertxt)                    = 0;
    virtual bool encrypt(alcp_data_ex_t data)                 = 0;
    virtual bool decrypt(const Uint8* ciphertxt,
                         size_t       len,
                         Uint8*       plaintxt)                     = 0;
    virtual bool decrypt(alcp_data_ex_t data)                 = 0;
    virtual void reset()                                      = 0;
    virtual ~CipherBase(){};
};

class CipherTesting
{
  private:
    CipherBase* cb = nullptr;

  public:
    CipherTesting() {}
    CipherTesting(CipherBase* impl);
    /**
     * @brief Encrypts the data and returns the vector.
     *
     * @param plaintext - Data to encrypt.
     * @param key - Key for ecryption.
     * @param iv - IV for encryption.
     * @return std::vector<Uint8>
     */
    std::vector<Uint8> testingEncrypt(const std::vector<Uint8> plaintext,
                                      const std::vector<Uint8> key,
                                      const std::vector<Uint8> iv);
    /**
     * @brief Encrypts data and puts in data.out, expects data.out to already
     * have valid memory pointer with appropriate size
     *
     * @param data - Everything that should go in or out of the cipher except
     * the key
     * @param key - Key used to encrypt, should be std::vector
     * @return true
     * @return false
     */
    bool testingEncrypt(alcp_data_ex_t data, const std::vector<Uint8> key);
    /**
     * @brief Decrypts the data and returns the vector.
     *
     * @param ciphertext - Data to decrypt.
     * @param key - Key used for encryption of ciphertext.
     * @param iv  - IV used for encryption.
     * @return std::vector<Uint8>
     */
    std::vector<Uint8> testingDecrypt(const std::vector<Uint8> ciphertext,
                                      const std::vector<Uint8> key,
                                      const std::vector<Uint8> iv);
    /**
     * @brief Decrypts data and puts in data.out, expects data.out to already
     * have valid memory point with appropriate size
     *
     * @param data - Everything that should go in or out of the cipher expect
     * the key
     * @param key - Key ysed to decrypt, should be std::vector
     * @return true
     * @return false
     */
    bool testingDecrypt(alcp_data_ex_t data, const std::vector<Uint8> key);
    /**
     * @brief Set CipherBase pimpl
     *
     * @param impl - Object of class extended from CipherBase
     */
    void setcb(CipherBase* impl);
};
} // namespace alcp::testing
