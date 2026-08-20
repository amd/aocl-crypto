/*
 * Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/cipher_common.hh"
#include "alcp/mac/poly1305.hh"

namespace alcp::cipher {

// These will be used to store the length of the ciphertext
union len_input_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

union len_aad_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

using utils::CpuArchLevel;

/**
 * @brief Unified ChaCha20-Poly1305 template class
 *
 * Inherits from ChaCha256T which provides StateManager, KeyManager, and IvManager
 * components via the ChaCha20 base class.
 *
 * Template parameters:
 * - arch: CPU architecture level (eZen4 or eReference)
 */
template<CpuArchLevel arch>
class ALCP_API_EXPORT ChaChPolyT
    : public ChaCha256T<arch>
    , public alcp::mac::poly1305::Poly1305<arch>
    , public iCipherAead
{
  protected:
    static constexpr Uint8            m_zero_padding[16]{};
    static constexpr Uint32           cChaChaBlockSize = CHACHA20_BLOCK_SIZE;
    static constexpr Uint32           cKsBatchBytes = 4 * cChaChaBlockSize;
    len_input_processed               m_len_input_processed{};
    len_aad_processed                 m_len_aad_processed{};
    // Keystream cache state:
    //
    // The cache serves two call patterns:
    //
    // 1. Single-shot or first short update:
    //    Generate only the number of 64-byte ChaCha20 blocks needed for
    //    this update. This avoids producing a full 256-byte batch when
    //    the caller may immediately finalize and discard the unused
    //    keystream.
    //
    // 2. Multi-update streaming:
    //    Once an operation has already produced message keystream, refill
    //    the cache with one full 4-block kernel batch. Later short updates
    //    can then drain the cached bytes without re-entering the ChaCha20
    //    kernel.
    //
    // Because those two paths can fill different amounts of the same buffer,
    // the cache tracks both:
    //
    //   m_keystreamValid:  number of bytes in m_keystreamBuffer that contain
    //                      real, usable ChaCha20 keystream.
    //   m_keystreamOffset: index of the next unread byte inside that valid
    //                      range.
    //
    // The currently cached bytes are:
    //   m_keystreamBuffer[m_keystreamOffset ... m_keystreamValid)
    alignas(64) Uint8                 m_keystreamBuffer[cKsBatchBytes]{};
    Uint32                            m_keystreamOffset = 0;
    Uint32                            m_keystreamValid  = 0;
    Uint32                            m_chacha20Counter = 1;
    bool                              m_aadPadded       = false;

    alc_error_t setIvInternal(const Uint8* iv, Uint64 ivLen);
    alc_error_t initPoly1305Key();
    alc_error_t padAadToBlockBoundary();
    void        setChaChaCounter(Uint32 counter);
    template<bool isDecrypt>
    alc_error_t cryptAndAuth(const Uint8* inputBuffer,
                             Uint8*       outputBuffer,
                             Uint64       bufferLength,
                             Uint64*      outlen);

  public:
    ChaChPolyT() = default;
    ~ChaChPolyT() = default;

  public:
    // iCipherAead auth methods
    alc_error_t setAad(const Uint8* pInput, Uint64 aadLen) override;
    alc_error_t setTagLength(Uint64 tagLength) override;
    alc_error_t getTag(Uint8* pOutput, Uint64 tagLen) override;

    // iCipher methods
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override;
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

template<CpuArchLevel arch>
using ChaChaPoly = ChaChPolyT<arch>;

namespace vaes512 {
    using ChaChaPoly256 = ChaChPolyT<CpuArchLevel::eZen4>;
    using ChaChaPoly = ChaChaPoly256;
} // namespace vaes512

namespace ref {
    using ChaChaPoly256 = ChaChPolyT<CpuArchLevel::eReference>;
    using ChaChaPoly = ChaChaPoly256;
} // namespace ref

} // namespace alcp::cipher
