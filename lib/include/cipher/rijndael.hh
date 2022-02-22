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

#include <cstdalign>
#include <cstdint>
#include <map>

#include "alcp/cipher.h"

//#include "algorithm.hh"
#include "cipher.hh"
#include "types.hh"
#include "utils/bits.hh"

namespace alcp::cipher {

class Rijndael : public alcp::BlockCipher
//, public Algorithm
{
  public:
    static uint32 constexpr cAlignment     = 16;
    static uint32 constexpr cAlignmentWord = cAlignment / utils::BytesPerWord;

    static uint32 constexpr cMinKeySizeBits = 128;
    static uint32 constexpr cMaxKeySizeBits = 256;
    static uint32 constexpr cMinKeySize = cMinKeySizeBits / utils::BitsPerByte;
    static uint32 constexpr cMaxKeySize = cMaxKeySizeBits / utils::BitsPerByte;

    static uint32 constexpr cBlockSizeBits = 128;
    static uint32 constexpr cBlockSize = cBlockSizeBits / utils::BitsPerByte;
    static uint32 constexpr cBlockSizeWord = cBlockSize / utils::BytesPerWord;

    static uint32 constexpr cMaxRounds = 14;

  private:
    // non-movable:
    Rijndael(Rijndael&& rhs) noexcept;
    Rijndael& operator=(Rijndael&& rhs) noexcept;

    // and non-copyable
    Rijndael(const Rijndael& rhs);
    Rijndael& operator=(const Rijndael& rhs);

  public:
    /**
     * FIPS-197 compatible getters
     */
    /* Nk - number of words in key128/key192/key256 */
    uint32 getNk() const;

    /* Nr - Number of rounds */
    uint32 getNr() const;

    /* Nb - No of words in a block (block is always 128-bits) */
    uint32 getNb() const { return cBlockSizeWord; };

  public:
    uint32       getRounds() const;
    uint32       getKeySize() const;
    const uint8* getEncryptKeys() const;
    const uint8* getDecryptKeys() const;

    virtual void setKey(const uint8* pUserKey, uint64 len);
    virtual void setEncryptKey(const uint8* pEncKey, uint64 len);
    virtual void setDecryptKey(const uint8* pDecKey, uint64 len);

  protected:
    Rijndael();
    explicit Rijndael(const alc_key_info_t& rKeyInfo);
    virtual ~Rijndael();

  private:
    class Impl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace alcp::cipher
