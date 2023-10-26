/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_xts.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/constants.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#define GF_POLYNOMIAL 0x87

using alcp::utils::CpuId;

namespace alcp::cipher {

/*
 * @brief        AES Encryption in XTS(XEX Tweakable Block Ciphertext
 * Stealing Mode)
 */
template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
class ALCP_API_EXPORT Xts final : public Aes
{

  public:
    explicit Xts(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {

        p_tweak_key = &m_tweak_round_key[0];
        expandTweakKeys(aesInfo.ai_xts.xi_tweak_key->key,
                        aesInfo.ai_xts.xi_tweak_key->len);
    }

    explicit Xts(const Uint8* pKey, const Uint32 keyLen)
        : Aes(pKey, keyLen)
    {
        p_tweak_key = &m_tweak_round_key[0];
        expandTweakKeys(pKey + keyLen / 8, keyLen);
    }

    // Unoffical API, need to be replaced in future
    Status encryptBlocks(const Uint8* pSrc,
                         Uint8*       pDest,
                         Uint64       currSrcLen,
                         Uint64       startBlockNum);

    Status decryptBlocks(const Uint8* pSrc,
                         Uint8*       pDest,
                         Uint64       currSrcLen,
                         Uint64       startBlockNum);

    ~Xts() {}

  public:
    virtual alc_error_t setIv(Uint64 len, const Uint8* pIv);

    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    static bool isSupported(const Uint32 keyLen)
    {
        if ((keyLen == ALC_KEY_LEN_128) || (keyLen == ALC_KEY_LEN_256)) {
            return true;
        }
        return false;
    }

    /**
     * @brief   XTS Encrypt Operation
     * @note
     * @param   pPlainText      Pointer to output buffer
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) final;

    /**
     * @brief   XTS Decrypt Operation
     * @note
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) final;

    virtual void expandTweakKeys(const Uint8* pUserKey, int len);

  private:
    Xts() { p_tweak_key = &m_tweak_round_key[0]; };
    void tweakBlockSet(Uint64 aesBlockId);

  private:
    alignas(64) Uint8 m_iv[16];
    alignas(64) Uint8 m_tweak_block[16];
    Uint8  m_tweak_round_key[(RIJ_SIZE_ALIGNED(32) * (16))];
    Uint8* p_tweak_key = nullptr; /* Tweak key(for aes-xts mode): points to
                           offset in 'm_tweak_key' */
    Uint64 m_aes_block_id = static_cast<Uint64>(-1);
};

static inline Uint8
GetSbox(Uint8 offset, bool use_invsbox = false)
{
    return utils::GetSbox(offset, use_invsbox);
}
#if 0
static void
MultiplyAlphaByTwo(Uint32* alpha)
{
    unsigned long long res, carry;

    unsigned long long* tmp_tweak = (unsigned long long*)alpha;

    res   = (((long long)tmp_tweak[1]) >> 63) & GF_POLYNOMIAL;
    carry = (((long long)tmp_tweak[0]) >> 63) & 1;

    tmp_tweak[0] = ((tmp_tweak[0]) << 1) ^ res;
    tmp_tweak[1] = ((tmp_tweak[1]) << 1) | carry;
}
#endif

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
alc_error_t
Xts<FEnc, FDec>::setIv(Uint64 len, const Uint8* pIv)
{
    Status s = StatusOk();
    // std::cout << "HERE!" << std::endl;
    utils::CopyBytes(m_iv, pIv, len); // Keep a copy of iv

    // FIXME: In future we need to dispatch it correctly
    aesni::InitializeTweakBlock(m_iv, m_tweak_block, p_tweak_key, getRounds());

    m_aes_block_id = 0; // Initialized BlockId to 0

    return s.code();
}

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
void
Xts<FEnc, FDec>::expandTweakKeys(const Uint8* pUserKey, int len)
{
    using utils::GetByte, utils::MakeWord;
    Uint8 dummy_key[32] = { 0 };

    const Uint8* key = pUserKey ? pUserKey : &dummy_key[0];
    if (CpuId::cpuHasAesni()) {
        aesni::ExpandTweakKeys(key, p_tweak_key, getRounds());
        return;
    }

    // Dispatch to Reference Algorithm

    Uint32 i;
    Uint32 nb = Rijndael::cBlockSizeWord, nr = getRounds(),
           nk          = len / utils::BitsPerByte / utils::BytesPerWord;
    const Uint32* rtbl = utils::s_round_constants;
    Uint32*       p_tweak_key32;

    p_tweak_key32 = reinterpret_cast<Uint32*>(p_tweak_key);

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

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
Status
Xts<FEnc, FDec>::encryptBlocks(const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       currSrcLen,
                               Uint64       startBlockNum)
{
    Status s = StatusOk();
    tweakBlockSet(startBlockNum);
    alc_error_t err = encrypt(pSrc, pDest, currSrcLen, nullptr);
    if (alcp_is_error(err)) {
        s = alcp::base::status::InternalError("Encryption failed!");
    }
    return s;
}

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
Status
Xts<FEnc, FDec>::decryptBlocks(const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       currSrcLen,
                               Uint64       startBlockNum)
{
    Status s = StatusOk();
    tweakBlockSet(startBlockNum);
    alc_error_t err = decrypt(pSrc, pDest, currSrcLen, nullptr);
    if (alcp_is_error(err)) {
        s = alcp::base::status::InternalError("Decryption failed!");
    }
    return s;
}

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
void
Xts<FEnc, FDec>::tweakBlockSet(Uint64 aesBlockId)
{
    // FIXME: In future we need to dispatch it correctly
    if (aesBlockId > m_aes_block_id) {
        aesni::TweakBlockCalculate(m_tweak_block, aesBlockId - m_aes_block_id);
    } else if (aesBlockId < m_aes_block_id) {
        aesni::InitializeTweakBlock(
            m_iv, m_tweak_block, p_tweak_key, getRounds());
        aesni::TweakBlockCalculate(m_tweak_block, aesBlockId);
    }
    m_aes_block_id = aesBlockId;
}

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
alc_error_t
Xts<FEnc, FDec>::encrypt(const Uint8* pPlainText,
                         Uint8*       pCipherText,
                         Uint64       len,
                         const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    // Data should never be less than a block or greater than 2^20 blocks
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    Uint64 blocks_in = len / 16;

    err = FEnc(pPlainText,
               pCipherText,
               len,
               getEncryptKeys(),
               p_tweak_key,
               getRounds(),
               m_tweak_block);

    m_aes_block_id += blocks_in;

#if 0


    auto p_key128       = reinterpret_cast<const Uint8*>(getEncryptKeys());
    auto p_tweak_key128 = reinterpret_cast<const Uint8*>(p_tweak_key);
    auto p_src128       = reinterpret_cast<const Uint32*>(pPlainText);
    auto p_dest128      = reinterpret_cast<Uint32*>(pCipherText);
    auto p_iv128        = reinterpret_cast<const Uint32*>(pIv);

    Uint32 currentAlpha[4];
    utils::CopyBytes(currentAlpha, p_iv128, 16);

    auto n_words         = len / Rijndael::cBlockSizeWord;
    int  last_Round_Byte = len % Rijndael::cBlockSize;

    Rijndael::encryptBlock(currentAlpha, p_tweak_key128, getRounds());

    // blocks *= 4;

    while (n_words >= 4) {

        Uint32 tweaked_src_text_1[4];

        for (int i = 0; i < 4; i++)
            tweaked_src_text_1[i] = (currentAlpha[i] ^ p_src128[i]);

        Rijndael::encryptBlock(tweaked_src_text_1, p_key128, getRounds());

        for (int i = 0; i < 4; i++)
            tweaked_src_text_1[i] = (currentAlpha[i] ^ tweaked_src_text_1[i]);

        utils::CopyBytes(p_dest128, tweaked_src_text_1, Rijndael::cBlockSize);

        MultiplyAlphaByTwo(currentAlpha);

        n_words -= 4;
        p_src128 += 4;
        p_dest128 += 4;
    }

    auto p_dest8 = reinterpret_cast<Uint8*>(p_dest128);
    auto p_src8  = reinterpret_cast<const Uint8*>(p_src128);

    if (last_Round_Byte > 0) {

        Uint32 last_messgae_block[4];
        auto   p_last_messgae_block =
            reinterpret_cast<Uint8*>(last_messgae_block);

        utils::CopyBytes(p_last_messgae_block + last_Round_Byte,
                         p_dest8 - 16 + last_Round_Byte,
                         16 - last_Round_Byte);
        utils::CopyBytes(p_last_messgae_block, p_src8, last_Round_Byte);
        utils::CopyBytes(p_dest8, p_dest8 - 16, last_Round_Byte);

        // encrypting last message block
        for (int i = 0; i < 4; i++)
            last_messgae_block[i] = (currentAlpha[i] ^ last_messgae_block[i]);

        encryptBlock(last_messgae_block, p_key128, getRounds());

        for (int i = 0; i < 4; i++)
            last_messgae_block[i] = (currentAlpha[i] ^ last_messgae_block[i]);

        utils::CopyBytes((p_dest8 - 16), p_last_messgae_block, 16);
    }

#endif

    return err;
}

template<alc_error_t FEnc(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv),
         alc_error_t FDec(const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len,
                          const Uint8* pKey,
                          const Uint8* pTweakKey,
                          int          nRounds,
                          Uint8*       pIv)>
alc_error_t
Xts<FEnc, FDec>::decrypt(const Uint8* pCipherText,
                         Uint8*       pPlainText,
                         Uint64       len,
                         const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    // Data should never be less than a block or greater than 2^20 blocks
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    Uint64 blocks_in = len / 16;

    err = FDec(pCipherText,
               pPlainText,
               len,
               getDecryptKeys(),
               p_tweak_key,
               getRounds(),
               m_tweak_block);

    m_aes_block_id += blocks_in;

#if 0

    if (CpuId::cpuHasAvx512(utils::AVX512_F)
        && CpuId::cpuHasAvx512(utils::AVX512_DQ)
        && CpuId::cpuHasAvx512(utils::AVX512_BW)) {

        err = vaes512::DecryptXtsAvx512(pCipherText,
                                        pPlainText,
                                        len,
                                        getDecryptKeys(),
                                        p_tweak_key,
                                        getRounds(),
                                        pIv);
        return err;
    }

    if (CpuId::cpuHasVaes()) {

        err = vaes::DecryptXts(pCipherText,
                               pPlainText,
                               len,
                               getDecryptKeys(),
                               p_tweak_key,
                               getRounds(),
                               pIv);

        return err;
    }

    if (CpuId::cpuHasAesni()) {

        err = aesni::DecryptXts(pCipherText,
                                pPlainText,
                                len,
                                getDecryptKeys(),
                                p_tweak_key,
                                getRounds(),
                                pIv);

        return err;
    }

    auto p_key128       = reinterpret_cast<const Uint8*>(getDecryptKeys());
    auto p_tweak_key128 = reinterpret_cast<const Uint8*>(p_tweak_key);
    auto p_src128       = reinterpret_cast<const Uint32*>(pCipherText);
    auto p_dest128      = reinterpret_cast<Uint32*>(pPlainText);
    auto p_iv128        = reinterpret_cast<const Uint32*>(pIv);

    Uint32 currentAlpha[4];
    utils::CopyBytes(currentAlpha, p_iv128, 16);

    Uint64 blocks          = len / Rijndael::cBlockSize;
    int    last_Round_Byte = len % Rijndael::cBlockSize;

    Rijndael::encryptBlock(currentAlpha, p_tweak_key128, getRounds());
    blocks *= 4;

    Uint32 lastAlpha[4];

    while (blocks >= 4) {

        Uint32 tweaked_src_text_1[4];
        if (blocks == 4 && last_Round_Byte) {
            utils::CopyBytes(lastAlpha, currentAlpha, 16);
            MultiplyAlphaByTwo(currentAlpha);
        }
        for (int i = 0; i < 4; i++)
            tweaked_src_text_1[i] = (currentAlpha[i] ^ p_src128[i]);

        Rijndael::AesDecrypt(tweaked_src_text_1, p_key128, getRounds());

        for (int i = 0; i < 4; i++)
            tweaked_src_text_1[i] = (currentAlpha[i] ^ tweaked_src_text_1[i]);

        utils::CopyBytes(p_dest128, tweaked_src_text_1, 16);

        MultiplyAlphaByTwo(currentAlpha);

        blocks -= 4;
        p_src128 += 4;
        p_dest128 += 4;
    }

    auto p_dest8 = reinterpret_cast<Uint8*>(p_dest128);
    auto p_src8  = reinterpret_cast<const Uint8*>(p_src128);

    if (last_Round_Byte > 0) {

        Uint32 last_messgae_block[4];
        auto   p_last_messgae_block =
            reinterpret_cast<Uint8*>(last_messgae_block);

        utils::CopyBytes(p_last_messgae_block + last_Round_Byte,
                         p_dest8 - 16 + last_Round_Byte,
                         16 - last_Round_Byte);
        utils::CopyBytes(p_last_messgae_block, p_src8, last_Round_Byte);
        utils::CopyBytes(p_dest8, p_dest8 - 16, last_Round_Byte);

        // encrypting last message block
        for (int i = 0; i < 4; i++)
            last_messgae_block[i] = (lastAlpha[i] ^ last_messgae_block[i]);

        AesDecrypt(last_messgae_block, p_key128, getRounds());

        for (int i = 0; i < 4; i++)
            last_messgae_block[i] = (lastAlpha[i] ^ last_messgae_block[i]);

        utils::CopyBytes((p_dest8 - 16), p_last_messgae_block, 16);
    }

#endif

    return err;
}

} // namespace alcp::cipher
