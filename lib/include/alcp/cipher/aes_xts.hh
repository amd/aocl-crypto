/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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

#include <cstdint>

#include "alcp/error.h"

#include "alcp/base/error.hh"
#include "alcp/cipher/cipher_common.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/constants.hh"
#include "alcp/utils/copy.hh"

namespace alcp::cipher {

// XTS-specific data (IV is stored in IvManager)
typedef struct _alc_cipher_xts_data
{
    __attribute__((aligned(64))) Uint8 m_tweak_block[16];
    Uint8 m_tweak_round_key[(RIJ_SIZE_ALIGNED(32) * (16))];
    Int64 m_aes_block_id;

} _alc_cipher_xts_data_t;

/*
 * @brief        AES Encryption in XTS(XEX Tweakable Block Ciphertext
 * Stealing Mode)
 *
 * Uses composition for state, key (with Rijndael), and IV management.
 * KeyManager inherits from Rijndael and handles key expansion internally.
 */
class ALCP_INTERNAL_CPP_EXPORT Xts
{
  protected:
    // Composed components
    StateManager m_stateManager;
    KeyManager   m_keyManager;
    IvManager    m_ivManager;

  public:
    // XTS-specific data
    _alc_cipher_xts_data_t m_xts;

    Xts(Uint32 keyLen_in_bytes, CipherMode mode)
        : m_keyManager(keyLen_in_bytes)
        , m_ivManager(16, 16) // XTS uses fixed 16-byte IV
    {
        m_xts.m_aes_block_id = -1;
        memset(m_xts.m_tweak_round_key, 0, sizeof(m_xts.m_tweak_round_key));
    };
    
    ~Xts()
    { // clear keys
        memset(m_xts.m_tweak_round_key, 0, sizeof(m_xts.m_tweak_round_key));
    }
    
    virtual alc_error_t init(const Uint8* pKey,
                             Uint64       keyLen,
                             const Uint8* pIv,
                             Uint64       ivLen);


    void tweakBlockSet(Uint64 aesBlockId);

  private:
    // functions unique to Xts class
    void        expandTweakKeys(const Uint8* pUserKey, int len);
    alc_error_t setIv(const Uint8* pIv, const Uint64 ivLen);
};

static inline Uint8
GetSbox(Uint8 offset, bool use_invsbox = false)
{
    return utils::GetSbox(offset, use_invsbox);
}

template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
class XtsT
    : public Xts
    , public iCipher
{
  public:
    XtsT()
        : Xts((static_cast<Uint32>(keyLenBits)) / 8, CipherMode::eAesXTS)
    {
    }
    ~XtsT() = default;

  public:
    // iCipher methods - delegate init to base class
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override
    {
        return Xts::init(pKey, keyLen, pIv, ivLen);
    }
    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        Uint64*      outlen) override;
    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        Uint64*      outlen) override;
    alc_error_t finish() override { return ALC_ERROR_NONE; }
    alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) override
    {
        return ALC_ERROR_NOT_SUPPORTED;
    }
};

/* XTS Block cipher with segmented capability */
template<CipherKeyLen keyLenBits, utils::CpuArchLevel arch>
class XtsBlockT
    : public Xts
    , public iCipherSegment
{
  public:
    XtsBlockT()
        : Xts((static_cast<Uint32>(keyLenBits)) / 8, CipherMode::eAesXTS)
    {
    }
    ~XtsBlockT() = default;

  public:
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override
    {
        return Xts::init(pKey, keyLen, pIv, ivLen);
    }
    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        Uint64*      outlen) override;
    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        Uint64*      outlen) override;

    // Segmented capability methods
    alc_error_t encryptSegment(const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       currSrcLen,
                               Uint64       startBlockNum) override;
    alc_error_t decryptSegment(const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       currSrcLen,
                               Uint64       startBlockNum) override;

    alc_error_t finish() override { return ALC_ERROR_NONE; }
    alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) override
    {
        return ALC_ERROR_NOT_SUPPORTED;
    }
};

} // namespace alcp::cipher
