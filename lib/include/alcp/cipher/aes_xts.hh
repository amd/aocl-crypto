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

#include <cstdint>

#include "alcp/error.h"

#include "alcp/base/error.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/constants.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;
namespace alcp::cipher {

// FIXME: _alc_cipher_xts_data structure needs further refinement.
typedef struct _alc_cipher_xts_data
{
    __attribute__((aligned(64))) Uint8 m_iv_xts[16];
    __attribute__((aligned(64))) Uint8 m_tweak_block[16];
    Uint8  m_tweak_round_key[(RIJ_SIZE_ALIGNED(32) * (16))];
    Uint8* m_pTweak_key; // this pointer can be removed.
    Int64  m_aes_block_id;

} _alc_cipher_xts_data_t;

/*
 * @brief        AES Encryption in XTS(XEX Tweakable Block Ciphertext
 * Stealing Mode)
 */
class ALCP_API_EXPORT Xts
    : public Aes
    , public virtual iCipher
{
  public:
    Uint8* m_pIv_xts;
    Uint32 m_iv_xts_size          = 0;
    Uint8* m_ptweak_round_key     = NULL;
    Uint32 m_tweak_round_key_size = 0;

    _alc_cipher_xts_data_t m_xts;

    Xts(Uint32 keyLen_in_bytes)
        : Aes(keyLen_in_bytes)
    {
        setMode(ALC_AES_MODE_CTR);
        m_ivLen_max = 16;
        m_ivLen_min = 16;

        m_pIv_xts     = m_xts.m_iv_xts;
        m_iv_xts_size = sizeof(m_xts.m_iv_xts);

        m_ptweak_round_key     = m_xts.m_tweak_round_key;
        m_tweak_round_key_size = sizeof(m_xts.m_tweak_round_key);

        Aes::setMode(ALC_AES_MODE_XTS);
        m_xts.m_aes_block_id = -1;
        memset(m_xts.m_iv_xts, 0, m_iv_xts_size);
        memset(m_ptweak_round_key, 0, m_tweak_round_key_size);
    };
    ~Xts()
    { // clear keys
        memset(m_pIv_xts, 0, m_iv_xts_size);
        memset(m_ptweak_round_key, 0, m_tweak_round_key_size);
    }
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override;

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

/* iCipher classes */
// vaes512 classes
CIPHER_CLASS_GEN_N(vaes512, Xts128, Xts, virtual iCipher, 128 / 8)
CIPHER_CLASS_GEN_N(vaes512, Xts256, Xts, virtual iCipher, 256 / 8)

// vaes classes
CIPHER_CLASS_GEN_N(vaes, Xts128, Xts, virtual iCipher, 128 / 8)
CIPHER_CLASS_GEN_N(vaes, Xts256, Xts, virtual iCipher, 256 / 8)

// aesni classes
CIPHER_CLASS_GEN_N(aesni, Xts128, Xts, virtual iCipher, 128 / 8)
CIPHER_CLASS_GEN_N(aesni, Xts256, Xts, virtual iCipher, 256 / 8)

/* iCipherSeg classes */
// vaes512 classes
CIPHERBLOCKS_CLASS_GEN_N(vaes512, XtsBlock128, Xts, virtual iCipherSeg, 128 / 8)
CIPHERBLOCKS_CLASS_GEN_N(vaes512, XtsBlock256, Xts, virtual iCipherSeg, 256 / 8)

// vaes classes
CIPHERBLOCKS_CLASS_GEN_N(vaes, XtsBlock128, Xts, virtual iCipherSeg, 128 / 8)
CIPHERBLOCKS_CLASS_GEN_N(vaes, XtsBlock256, Xts, virtual iCipherSeg, 256 / 8)

// aesni classes
CIPHERBLOCKS_CLASS_GEN_N(aesni, XtsBlock128, Xts, virtual iCipherSeg, 128 / 8)
CIPHERBLOCKS_CLASS_GEN_N(aesni, XtsBlock256, Xts, virtual iCipherSeg, 256 / 8)

} // namespace alcp::cipher
