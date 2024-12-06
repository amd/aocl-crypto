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
isNonAESCipherType(alc_cipher_mode_t mode);

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

    const Uint8* m_ad;
    Uint64       m_adl;
    Uint8*       m_tag; // Probably const but openssl expects non const
    Uint64       m_tagl;
    bool         m_isTagValid;

    Uint8* m_tagBuff; // Place to store tag buffer
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
