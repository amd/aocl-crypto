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

/*
 * @brief        AES Encryption in XTS(XEX Tweakable Block Ciphertext
 * Stealing Mode)
 */
class ALCP_API_EXPORT Xts : public Aes
{
  public:
    alignas(64) mutable Uint8 m_iv[16]                              = {};
    alignas(64) mutable Uint8 m_tweak_block[16]                     = {};
    Uint8          m_tweak_round_key[(RIJ_SIZE_ALIGNED(32) * (16))] = {};
    Uint8*         m_pTweak_key                                     = nullptr;
    mutable Uint64 m_aes_block_id = static_cast<Uint64>(-1);

  public:
    Xts() { Aes::setMode(ALC_AES_MODE_XTS); };
    ~Xts(){};

    // functions unique to Xts class
    void expandTweakKeys(const Uint8* pUserKey, int len);
    void tweakBlockSet(Uint64 aesBlockId);

    // overriden functions
    alc_error_t init(const Uint8* pKey,
                     const Uint64 keyLen,
                     const Uint8* pIv,
                     const Uint64 ivLen);

    alc_error_t setIv(const Uint8* pIv, const Uint64 ivLen);
};

static inline Uint8
GetSbox(Uint8 offset, bool use_invsbox = false)
{
    return utils::GetSbox(offset, use_invsbox);
}

#define AES_XTS_CLASS_GEN(CHILD_NEW, PARENT1, PARENT2)                         \
    class ALCP_API_EXPORT CHILD_NEW                                            \
        : PARENT1                                                              \
        , PARENT2                                                              \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(){};                                                         \
        ~CHILD_NEW(){};                                                        \
                                                                               \
      public:                                                                  \
        virtual alc_error_t encrypt(const Uint8* pPlainText,                   \
                                    Uint8*       pCipherText,                  \
                                    Uint64       len) const final;                   \
                                                                               \
        virtual alc_error_t decrypt(const Uint8* pCipherText,                  \
                                    Uint8*       pPlainText,                   \
                                    Uint64       len) const final;                   \
                                                                               \
        Status encryptBlocks(const Uint8* pSrc,                                \
                             Uint8*       pDest,                               \
                             Uint64       currSrcLen,                          \
                             Uint64       startBlockNum);                            \
                                                                               \
        Status decryptBlocks(const Uint8* pSrc,                                \
                             Uint8*       pDest,                               \
                             Uint64       currSrcLen,                          \
                             Uint64       startBlockNum);                            \
    };

namespace vaes512 {
    AES_XTS_CLASS_GEN(Xts128, public Xts, public ICipher)
    AES_XTS_CLASS_GEN(Xts256, public Xts, public ICipher)
} // namespace vaes512

namespace vaes {
    AES_XTS_CLASS_GEN(Xts128, public Xts, public ICipher)
    AES_XTS_CLASS_GEN(Xts256, public Xts, public ICipher)
} // namespace vaes

namespace aesni {
    AES_XTS_CLASS_GEN(Xts128, public Xts, public ICipher)
    AES_XTS_CLASS_GEN(Xts256, public Xts, public ICipher)
} // namespace aesni

} // namespace alcp::cipher
