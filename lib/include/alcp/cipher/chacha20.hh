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

#include "alcp/base.hh"
#include "alcp/cipher.h"
#include "alcp/cipher/cipher_common.hh"

namespace alcp::cipher {
using utils::CpuArchLevel;

static constexpr Uint32 Chacha20Constants[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

#define CHACHA20_BLOCK_SIZE 64

/**
 * @brief ChaCha20 base class with composition-based state management
 *
 * Uses StateManager, KeyManager, and IvManager components for state tracking.
 */
class ChaCha20
{
  protected:
    // Composed components
    StateManager m_stateManager;
    KeyManager   m_keyManager;
    IvManager    m_ivManager;

    static constexpr Uint64 cMKeylen    = 256 / 8;
    static constexpr Uint64 cMIvlen     = (128 / 8);
    static constexpr int    cMBlockSize = CHACHA20_BLOCK_SIZE;

  public:
    ChaCha20()
        : m_keyManager(cMKeylen)
        , m_ivManager(cMIvlen, cMIvlen) // ChaCha20 uses fixed 16-byte IV (nonce + counter)
    {
    }

    alc_error_t setKey(const Uint8 key[], Uint64 keylen);
    alc_error_t setIv(const Uint8 iv[], Uint64 ivlen);

    // Accessors for key/IV data (for encryption operations)
    const Uint8* getKey() const { return m_keyManager.getOriginalKey(); }
    Uint8*       getIv() { return m_ivManager.getIv(); }
    const Uint8* getIv() const { return m_ivManager.getIv(); }

  private:
    static alc_error_t validateKey(const Uint8* key, Uint64 keylen);
    static alc_error_t validateIv(const Uint8 iv[], Uint64 iVlen);

  public:
    virtual alc_error_t init(const Uint8* pKey,
                             const Uint64 keyLen,
                             const Uint8* pIv,
                             const Uint64 ivLen);
};

/**
 * @brief ChaCha20-256 cipher template
 *
 * Template class for ChaCha20 with 256-bit key support.
 * Uses composition for state management via ChaCha20 base.
 *
 * Template parameters:
 * - arch: CPU architecture features (eVaes512 or eReference)
 */
template<CpuArchLevel arch>
class ChaCha256T
    : public ChaCha20
    , public iCipher
{
  public:
    ChaCha256T() = default;
    ~ChaCha256T() = default;

  public:
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override
    {
        return ChaCha20::init(pKey, keyLen, pIv, ivLen);
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
        return ALC_ERROR_NONE;
    }
};

// Backward compatibility type aliases
namespace vaes512 {
    using ChaCha256 = ChaCha256T<CpuArchLevel::eZen4>;
} // namespace vaes512

namespace avx2 {
    using ChaCha256 = ChaCha256T<CpuArchLevel::eZen>;
} // namespace avx2

namespace ref {
    using ChaCha256 = ChaCha256T<CpuArchLevel::eReference>;
} // namespace ref

} // namespace alcp::cipher
