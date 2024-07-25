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
#pragma once
#include "alcp/alcp.h"
#include "file.hh"
#include "utils.hh"
#include <cstring>
#include <iostream>
#include <vector>

namespace alcp::testing {
using alcp::testing::utils::isPathExist;
using alcp::testing::utils::parseHexStrToBin;

/* to check cipher type is AES */
bool
isNonAESCipherType(_alc_cipher_type cipher_type);

/* to check if cipher mode is AEAD */
bool
CheckCipherIsAEAD(alc_cipher_mode_t mode);

/* to get cipher mode as a string */
std::string
GetModeSTR(alc_cipher_mode_t mode);

// alcp_data_cipher_ex_t
struct alcp_dc_ex_t
{
    const Uint8* m_in;
    Uint64       m_inl;
    Uint8*       m_out;
    Uint64       m_outl;
    const Uint8* m_iv;
    Uint64       m_ivl;
    Uint8*       m_tkey;  // tweak key
    Uint64       m_tkeyl; // tweak key len
    Uint64       m_block_size;
    // Initialize everything to 0
    alcp_dc_ex_t()
    {
        m_in         = {};
        m_inl        = {};
        m_out        = {};
        m_outl       = {};
        m_iv         = {};
        m_ivl        = {};
        m_tkey       = {};
        m_tkeyl      = {};
        m_block_size = {};
    }
};
// alcp_data_cipher_aead_ex_t
struct alcp_dca_ex_t : public alcp_dc_ex_t
{
    const Uint8* m_ad;
    Uint64       m_adl;
    Uint8*       m_tag; // Probably const but openssl expects non const
    Uint64       m_tagl;
    bool         m_isTagValid;

    Uint8* m_tagBuff; // Place to store tag buffer
    // Initialize everything to 0
    alcp_dca_ex_t()
        : alcp_dc_ex_t::alcp_dc_ex_t()
    {
        m_ad         = {};
        m_adl        = {};
        m_tag        = {};
        m_tagl       = {};
        m_tagBuff    = {};
        m_isTagValid = true;
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
    time_t             m_start_time{};
    time_t             m_end_time{};
    std::size_t        m_blackbox_start_pos = 0;
    std::size_t        m_blackbox_end_pos   = 0;
    record_t           m_rec_type{};
    std::vector<Uint8> m_key{};
    std::vector<Uint8> m_iv{};
    std::vector<Uint8> m_data{};
    std::string        m_str_mode = "";
    long m_byte_start = 0, m_byte_end = 0, m_rec_t = 0, m_key_size = 0,
         m_data_size      = 0;
    long m_prev_log_point = 0;

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
                      const Uint32 key_len,
                      const Uint8* tkey,
                      const Uint64 block_size)                = 0;
    virtual bool init(const Uint8* key, const Uint32 key_len) = 0;
    virtual bool encrypt(alcp_dc_ex_t& data)                  = 0;
    virtual bool decrypt(alcp_dc_ex_t& data)                  = 0;
    virtual bool reset()                                      = 0;
    virtual ~CipherBase()                                     = default;
};

class CipherAeadBase : public CipherBase
{
  public:
    virtual ~CipherAeadBase() = default;
    static bool isAead(const alc_cipher_mode_t& mode);
};

class CipherTesting
{
  private:
    CipherBase* cb = nullptr;

  public:
    CipherTesting() {}
    CipherTesting(CipherBase* impl);
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
    bool testingEncrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key);

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
    bool testingDecrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key);
    /**
     * @brief Set CipherBase pimpl
     *
     * @param impl - Object of class extended from CipherBase
     */
    void setcb(CipherBase* impl);
};

} // namespace alcp::testing
