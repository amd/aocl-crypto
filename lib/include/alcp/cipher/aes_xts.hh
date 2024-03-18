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
    Uint8* m_pIv_xts;
    Uint32 m_iv_xts_size          = 0;
    Uint8* m_ptweak_round_key     = NULL;
    Uint32 m_tweak_round_key_size = 0;

    Xts(alc_cipher_data_t* ctx)
        : Aes(ctx)
    {
        m_pIv_xts     = ctx->m_xts.m_iv_xts;
        m_iv_xts_size = sizeof(ctx->m_xts.m_iv_xts);

        m_ptweak_round_key     = ctx->m_xts.m_tweak_round_key;
        m_tweak_round_key_size = sizeof(ctx->m_xts.m_tweak_round_key);

        Aes::setMode(ALC_AES_MODE_XTS);
        ctx->m_xts.m_aes_block_id = -1;
        memset(ctx->m_xts.m_iv_xts, 0, m_iv_xts_size);
        memset(m_ptweak_round_key, 0, m_tweak_round_key_size);
    };
    ~Xts()
    {
        // clear keys
        memset(m_pIv_xts, 0, m_iv_xts_size);
        memset(m_ptweak_round_key, 0, m_tweak_round_key_size);
    };

    // functions unique to Xts class
    void expandTweakKeys(alc_cipher_data_t* ctx,
                         const Uint8*       pUserKey,
                         int                len);
    void tweakBlockSet(alc_cipher_data_t* ctx, Uint64 aesBlockId);

    // overriden functions
    alc_error_t init(alc_cipher_data_t* ctx,
                     const Uint8*       pKey,
                     const Uint64       keyLen,
                     const Uint8*       pIv,
                     const Uint64       ivLen);

    alc_error_t setIv(alc_cipher_data_t* ctx,
                      const Uint8*       pIv,
                      const Uint64       ivLen);
};

static inline Uint8
GetSbox(Uint8 offset, bool use_invsbox = false)
{
    return utils::GetSbox(offset, use_invsbox);
}

#define AES_XTS_CLASS_GEN(CHILD_NEW, PARENT)                                   \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT                            \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx)                                      \
            : PARENT(ctx){};                                                   \
        ~CHILD_NEW(){};                                                        \
                                                                               \
      public:                                                                  \
        alc_error_t encrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pPlainText,                     \
                            Uint8*             pCipherText,                    \
                            Uint64             len);                                       \
                                                                               \
        alc_error_t decrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pCipherText,                    \
                            Uint8*             pPlainText,                     \
                            Uint64             len);                                       \
                                                                               \
        Status encryptBlocksXts(alc_cipher_data_t* ctx,                        \
                                const Uint8*       pSrc,                       \
                                Uint8*             pDest,                      \
                                Uint64             currSrcLen,                 \
                                Uint64             startBlockNum);                         \
                                                                               \
        Status decryptBlocksXts(alc_cipher_data_t* ctx,                        \
                                const Uint8*       pSrc,                       \
                                Uint8*             pDest,                      \
                                Uint64             currSrcLen,                 \
                                Uint64             startBlockNum);                         \
    };

namespace vaes512 {
    AES_XTS_CLASS_GEN(Xts128, Xts)
    AES_XTS_CLASS_GEN(Xts256, Xts)
} // namespace vaes512

namespace vaes {
    AES_XTS_CLASS_GEN(Xts128, Xts)
    AES_XTS_CLASS_GEN(Xts256, Xts)
} // namespace vaes

namespace aesni {
    AES_XTS_CLASS_GEN(Xts128, Xts)
    AES_XTS_CLASS_GEN(Xts256, Xts)
} // namespace aesni

} // namespace alcp::cipher
