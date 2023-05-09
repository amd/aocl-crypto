/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher.h"

#include "alcp/base.hh"
#include "alcp/cipher.hh"
#include "alcp/utils/bits.hh"

#include <memory>

namespace alcp::cipher {
using Status = alcp::base::Status;

class ALCP_API_EXPORT Rijndael
    : public alcp::ICipher
    , protected Cipher
{

  public:
    static Uint32 constexpr cAlignment     = 16;
    static Uint32 constexpr cAlignmentWord = cAlignment / utils::BytesPerWord;

    static Uint32 constexpr cMinKeySizeBits = 128;
    static Uint32 constexpr cMaxKeySizeBits = 256;
    static Uint32 constexpr cMinKeySize = cMinKeySizeBits / utils::BitsPerByte;
    static Uint32 constexpr cMaxKeySize = cMaxKeySizeBits / utils::BitsPerByte;

    static Uint32 constexpr cBlockSizeBits = 128;
    static Uint32 constexpr cBlockSize = cBlockSizeBits / utils::BitsPerByte;
    static Uint32 constexpr cBlockSizeWord = cBlockSize / utils::BytesPerWord;

    static Uint32 constexpr cMaxRounds = 14;

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
    Uint32 getNk() const;

    /* Nr - Number of rounds */
    Uint32 getNr() const;

    /* Nb - No of words in a block (block is always 128-bits) */
    Uint32 getNb() const { return cBlockSizeWord; };

  public:
    Uint32       getRounds() const;
    Uint32       getKeySize() const;
    const Uint8* getEncryptKeys() const;
    const Uint8* getDecryptKeys() const;

    virtual Status setKey(const Uint8* pUserKey, Uint64 len);

    virtual void setEncryptKey(const Uint8* pEncKey, Uint64 len);
    virtual void setDecryptKey(const Uint8* pDecKey, Uint64 len);

    virtual alc_error_t encrypt(const Uint8* pSrc,
                                Uint8*       pDst,
                                Uint64       len,
                                const Uint8* pIv) const override;

    void encryptBlock(Uint32 (&blk0)[4], const Uint8* pkey, int nr) const;

    void encryptBlock(Uint32 (*blk0)[4], const Uint8* pkey, int nr) const;

    virtual void AesDecrypt(Uint32* blk0, const Uint8* pkey, int nr) const;

    virtual alc_error_t decrypt(const Uint8* pSrc,
                                Uint8*       pDst,
                                Uint64       len,
                                const Uint8* pIv) const override;

  protected:
    Rijndael();
    explicit Rijndael(const alc_key_info_t& rKeyInfo);
    explicit Rijndael(const Uint8* pKey, const Uint32 keyLen);
    virtual ~Rijndael();

  private:
    class Impl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace alcp::cipher
