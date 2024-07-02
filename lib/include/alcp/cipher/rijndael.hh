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

#include "alcp/cipher.h"

#include "alcp/base.hh"
#include "alcp/utils/bits.hh"

#include <memory>

namespace alcp::cipher {
// using Status = alcp::base::Status;

// aes and Rijndael can be unified?

/* Message size, key size, etc */
enum BlockSize : Uint32
{
    eBits0   = 0,
    eBits128 = 128,
    eBits192 = 192,
    eBits256 = 256,
};

struct Params
{
    Uint32 Nk;
    Uint32 Nb;
    Uint32 Nr;
};

class ALCP_API_EXPORT Rijndael
{

  public:
    static Uint32 constexpr cAlignment     = 16;
    static Uint32 constexpr cAlignmentWord = cAlignment / utils::BytesPerWord;

    static Uint32 constexpr cMaxKeySizeBits = 256;
    static Uint32 constexpr cMaxKeySize = cMaxKeySizeBits / utils::BitsPerByte;

    static Uint32 constexpr cBlockSizeBits = 128;
    static Uint32 constexpr cBlockSize = cBlockSizeBits / utils::BitsPerByte;
    static Uint32 constexpr cBlockSizeWord = cBlockSize / utils::BytesPerWord;

    static Uint32 constexpr cMaxRounds = 14;

  private:
    __attribute__((aligned(64)))
    Uint8 m_round_key_enc[cMaxKeySize * (cMaxRounds + 2)] = {};
    __attribute__((aligned(64)))
    Uint8 m_round_key_dec[cMaxKeySize * (cMaxRounds + 2)] = {};

    Uint8* m_enc_key = NULL;
    Uint8* m_dec_key = NULL;

    Uint32    m_nrounds    = 0; /* no of rounds */
    Uint32    m_ncolumns   = 0; /* no of columns in matrix */
    Uint32    m_key_size   = 0; /* key size in bytes */
    BlockSize m_block_size = eBits0;

    // duplicate of aes, to be removed
    const Uint8* m_pKey_rij   = NULL; /* User input key*/
    Uint32       m_keyLen_rij = 0;    /* key len*/

  public:
    Rijndael() {}
    ~Rijndael();

    /**
     * FIPS-197 compatible getters
     */

    Uint32 getNk() const; /* Nk - number of words in key128/key192/key256 */
    Uint32 getNr() const; /* Nr - Number of rounds */
    Uint32 getNb()
        const /* Nb - No of words in a block (block is always 128-bits) */
    {
        return cBlockSizeWord;
    };

    void initRijndael(const Uint8* pKey, const Uint64 keyLen);
    void setEncryptKey(const Uint8* pEncKey, Uint64 len);
    void setDecryptKey(const Uint8* pDecKey, Uint64 len);

    // this should move to aes
    alc_error_t encrypt(const Uint8* pSrc, Uint8* pDst, Uint64 len) const;

    // this should move to aes
    alc_error_t decrypt(const Uint8* pSrc, Uint8* pDst, Uint64 len) const;

    void encryptBlock(Uint32 (&blk0)[4], const Uint8* pkey, int nr) const;
    void encryptBlock(Uint32 (*blk0)[4], const Uint8* pkey, int nr) const;
    void AESEncrypt(Uint32* blk0, const Uint8* pkey, int nr) const;
    void AesDecrypt(Uint32* blk0, const Uint8* pkey, int nr) const;

    void setKeyLen(Uint32 keyLen) { m_keyLen_rij = keyLen; }
    void setKey(const Uint8* pKey) { m_pKey_rij = pKey; }

    Uint32       getRounds() const { return m_nrounds; }
    Uint32       getKeySize() const { return m_key_size; }
    const Uint8* getEncryptKeys() const { return m_enc_key; }
    const Uint8* getDecryptKeys() const { return m_dec_key; }

    void setUp() { setKey(m_pKey_rij, m_keyLen_rij); }
    void setKey(const Uint8* key, int len);

  private:
    void expandKeys(const Uint8* pUserKey) noexcept;
    void addRoundKey(Uint8 state[][4], Uint8 k[][4]) noexcept;
};

} // namespace alcp::cipher
