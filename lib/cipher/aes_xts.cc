/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes.hh"
//
#include "alcp/cipher/aes_xts.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {

// over AES init, for tweakKey operation
alc_error_t
Xts::setIv(const Uint8* pIv, const Uint64 ivLen)
{
    Status s = StatusOk();
    utils::CopyBytes(m_iv, pIv, ivLen); // Keep a copy of iv

    // FIXME: In future we need to dispatch it correctly
    aesni::InitializeTweakBlock(pIv, m_tweak_block, m_pTweak_key, getRounds());

    m_aes_block_id = 0; // Initialized BlockId to 0

    return s.code();
}

alc_error_t
Xts::init(const Uint8* pKey,
          const Uint64 keyLen,
          const Uint8* pIv,
          const Uint64 ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pKey != NULL && keyLen != 0) {
        err = setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_pTweak_key = &m_tweak_round_key[0];
        expandTweakKeys(pKey + keyLen / 8, keyLen);

        m_isKeyset = true;
    }

    if (pIv != NULL && ivLen != 0) {
        err       = Xts::setIv(pIv, ivLen);
        m_isIvset = true;
    }

    if (!(m_isIvset && m_isKeyset)) {
        return ALC_ERROR_BAD_STATE; // FIXME: better error code?
    }

    return err;
}

void
Xts::tweakBlockSet(Uint64 aesBlockId)
{
    // FIXME: In future we need to dispatch it correctly
    // m_aes_block_id is the previous block id and aesBlockId is the target
    // block id.
    if (aesBlockId > m_aes_block_id) {
        aesni::TweakBlockCalculate(m_tweak_block, aesBlockId - m_aes_block_id);
    } else if (aesBlockId < m_aes_block_id) {
        aesni::InitializeTweakBlock(
            m_iv, m_tweak_block, m_pTweak_key, getRounds());
        aesni::TweakBlockCalculate(m_tweak_block, aesBlockId);
    }
    m_aes_block_id = aesBlockId;
}

void
Xts::expandTweakKeys(const Uint8* pKey, int len)
{
    using utils::GetByte, utils::MakeWord;
    Uint8 dummy_key[32] = { 0 };

    const Uint8* key = pKey ? pKey : &dummy_key[0];
    if (CpuId::cpuHasAesni()) {
        aesni::ExpandTweakKeys(key, m_pTweak_key, getRounds());
        return;
    }

    // Dispatch to Reference Algorithm

    Uint32 i;
    Uint32 nb = Rijndael::cBlockSizeWord, nr = getRounds(),
           nk          = len / utils::BitsPerByte / utils::BytesPerWord;
    const Uint32* rtbl = utils::s_round_constants;
    Uint32*       p_tweak_key32;

    p_tweak_key32 = reinterpret_cast<Uint32*>(m_pTweak_key);

    for (i = 0; i < nk; i++) {
        p_tweak_key32[i] = MakeWord(
            key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
    }

    for (i = nk; i < nb * (nr + 1); i++) {
        Uint32 temp = p_tweak_key32[i - 1];
        if (i % nk == 0) {
            temp = MakeWord((GetByte(temp, 1)),
                            (GetByte(temp, 2)),
                            (GetByte(temp, 3)),
                            (GetByte(temp, 0)));

            temp ^= *rtbl++;
        } else if (nk > 6 && (i % nk == 4)) {
            temp = MakeWord(GetSbox(GetByte(temp, 0)),
                            GetSbox(GetByte(temp, 1)),
                            GetSbox(GetByte(temp, 2)),
                            GetSbox(GetByte(temp, 3)));
        }

        p_tweak_key32[i] = p_tweak_key32[i - nk] ^ temp;
    }
}

#define CRYPT_BLOCKS_XTS_WRAPPER_FUNC(CLASS_NAME, WRAPPER_FUNC, FUNC_NAME)     \
    Status CLASS_NAME::WRAPPER_FUNC(                                           \
        const Uint8* pinput, Uint8* pOutput, Uint64 len, Uint64 startBlockNum) \
                                                                               \
    {                                                                          \
        Status s = StatusOk();                                                 \
        alcp::cipher::Xts::tweakBlockSet(startBlockNum);                       \
        alc_error_t err = FUNC_NAME(pinput, pOutput, len);                     \
                                                                               \
        if (alcp_is_error(err)) {                                              \
            s = alcp::base::status::InternalError("Encryption failed!");       \
        }                                                                      \
        return s;                                                              \
    }

namespace vaes512 {
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts128, encryptBlocks, encrypt)
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts256, encryptBlocks, encrypt)

    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts128, decryptBlocks, decrypt)
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts256, decryptBlocks, decrypt)
} // namespace vaes512

namespace vaes {
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts128, encryptBlocks, encrypt)
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts256, encryptBlocks, encrypt)

    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts128, decryptBlocks, decrypt)
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts256, decryptBlocks, decrypt)
} // namespace vaes

namespace aesni {
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts128, encryptBlocks, encrypt)
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts256, encryptBlocks, encrypt)

    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts128, decryptBlocks, decrypt)
    CRYPT_BLOCKS_XTS_WRAPPER_FUNC(Xts256, decryptBlocks, decrypt)
} // namespace aesni

// pIv arg to be removed and this is made same as other ciper wrapper func
// length check to be converted to generic function for all cipher modes
#define CRYPT_XTS_WRAPPER_FUNC(                                                \
    CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, PKEY, NUM_ROUNDS)                     \
    alc_error_t CLASS_NAME::WRAPPER_FUNC(                                      \
        const Uint8* pinput, Uint8* pOutput, Uint64 len) const                 \
    {                                                                          \
        alc_error_t err = ALC_ERROR_NONE;                                      \
                                                                               \
        if (len < 16 || len > (1 << 21)) {                                     \
            err = ALC_ERROR_INVALID_DATA;                                      \
            return err;                                                        \
        }                                                                      \
        Uint64 blocks_in = len / 16;                                           \
        err =                                                                  \
            FUNC_NAME(pinput, pOutput, len, PKEY, NUM_ROUNDS, m_tweak_block);  \
        m_aes_block_id += blocks_in;                                           \
        return err;                                                            \
    }

namespace vaes512 {
    CRYPT_XTS_WRAPPER_FUNC(Xts128, encrypt, EncryptXts128, m_enc_key, 10)
    CRYPT_XTS_WRAPPER_FUNC(Xts256, encrypt, EncryptXts256, m_enc_key, 14)

    CRYPT_XTS_WRAPPER_FUNC(Xts128, decrypt, DecryptXts128, m_dec_key, 10)
    CRYPT_XTS_WRAPPER_FUNC(Xts256, decrypt, DecryptXts256, m_dec_key, 14)
} // namespace vaes512

namespace vaes {
    CRYPT_XTS_WRAPPER_FUNC(Xts128, encrypt, EncryptXts128, m_enc_key, 10)
    CRYPT_XTS_WRAPPER_FUNC(Xts256, encrypt, EncryptXts256, m_enc_key, 14)

    CRYPT_XTS_WRAPPER_FUNC(Xts128, decrypt, DecryptXts128, m_dec_key, 10)
    CRYPT_XTS_WRAPPER_FUNC(Xts256, decrypt, DecryptXts256, m_dec_key, 14)
} // namespace vaes

namespace aesni {
    CRYPT_XTS_WRAPPER_FUNC(Xts128, encrypt, EncryptXts128, m_enc_key, 10)
    CRYPT_XTS_WRAPPER_FUNC(Xts256, encrypt, EncryptXts256, m_enc_key, 14)

    CRYPT_XTS_WRAPPER_FUNC(Xts128, decrypt, DecryptXts128, m_dec_key, 10)
    CRYPT_XTS_WRAPPER_FUNC(Xts256, decrypt, DecryptXts256, m_dec_key, 14)
} // namespace aesni

} // namespace alcp::cipher