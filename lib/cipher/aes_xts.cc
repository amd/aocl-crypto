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

#include "cipher/aes.hh"
#include "cipher/cipher_wrapper.hh"
#include "utils/constants.hh"
#include "utils/copy.hh"

#define GF_POLYNOMIAL 0x87

namespace alcp::cipher {

static Uint8
GetSbox(Uint8 offset, bool use_invsbox = false)
{
    return utils::GetSbox(offset, use_invsbox);
}

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

alc_error_t
Xts::setIv(Uint64 len, const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len != 16) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }
    return err;
}

void
Xts::expandTweakKeys(const Uint8* pUserKey, int len)
{

    using utils::GetByte, utils::MakeWord;
    Uint8 dummy_key[32] = { 0 };

    const Uint8* key = pUserKey ? pUserKey : &dummy_key[0];
    if (utils::Cpuid::cpuHasAesni()) {
        aesni::ExpandTweakKeys(key, p_tweak_key, getRounds());
        return;
    }

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
            temp = MakeWord(GetSbox(GetByte(temp, 1)),
                            GetSbox(GetByte(temp, 2)),
                            GetSbox(GetByte(temp, 3)),
                            GetSbox(GetByte(temp, 0)));

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

alc_error_t
Xts::encrypt(const Uint8* pPlainText,
             Uint8*       pCipherText,
             Uint64       len,
             const Uint8* pIv) const
{

    alc_error_t err = ALC_ERROR_NONE;

    // Data should never be less than a block or greater than 2^20 blocks
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    if (utils::Cpuid::cpuHasAvx512(utils::AVX512_F)
        && utils::Cpuid::cpuHasAvx512(utils::AVX512_DQ)
        && utils::Cpuid::cpuHasAvx512(utils::AVX512_BW)) {
        err = vaes512::EncryptXtsAvx512(pPlainText,
                                        pCipherText,
                                        len,
                                        getEncryptKeys(),
                                        p_tweak_key,
                                        getRounds(),
                                        pIv);
        return err;
    }

    if (utils::Cpuid::cpuHasVaes()) {

        err = vaes::EncryptXts(pPlainText,
                               pCipherText,
                               len,
                               getEncryptKeys(),
                               p_tweak_key,
                               getRounds(),
                               pIv);

        return err;
    }

    if (utils::Cpuid::cpuHasAesni()) {

        err = aesni::EncryptXts(pPlainText,
                                pCipherText,
                                len,
                                getEncryptKeys(),
                                p_tweak_key,
                                getRounds(),
                                pIv);

        return err;
    }

    auto p_key128       = reinterpret_cast<const Uint8*>(getEncryptKeys());
    auto p_tweak_key128 = reinterpret_cast<const Uint8*>(p_tweak_key);
    auto p_src128       = reinterpret_cast<const Uint32*>(pPlainText);
    auto p_dest128      = reinterpret_cast<Uint32*>(pCipherText);
    auto p_iv128        = reinterpret_cast<const Uint32*>(pIv);

    Uint32 currentAlpha[4];
    utils::CopyBytes(currentAlpha, p_iv128, 16);

    Uint64 blocks          = len / Rijndael::cBlockSize;
    int    last_Round_Byte = len % Rijndael::cBlockSize;

    Rijndael::AesEncrypt(currentAlpha, p_tweak_key128, getRounds());

    blocks *= 4;

    while (blocks >= 4) {

        Uint32 tweaked_src_text_1[4];

        for (int i = 0; i < 4; i++)
            tweaked_src_text_1[i] = (currentAlpha[i] ^ p_src128[i]);

        Rijndael::AesEncrypt(tweaked_src_text_1, p_key128, getRounds());

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
            last_messgae_block[i] = (currentAlpha[i] ^ last_messgae_block[i]);

        AesEncrypt(last_messgae_block, p_key128, getRounds());

        for (int i = 0; i < 4; i++)
            last_messgae_block[i] = (currentAlpha[i] ^ last_messgae_block[i]);

        utils::CopyBytes((p_dest8 - 16), p_last_messgae_block, 16);
    }

    return err;
}

alc_error_t
Xts::decrypt(const Uint8* pCipherText,
             Uint8*       pPlainText,
             Uint64       len,
             const Uint8* pIv) const
{

    alc_error_t err = ALC_ERROR_NONE;

    // Data should never be less than a block or greater than 2^20 blocks
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    if (utils::Cpuid::cpuHasAvx512(utils::AVX512_F)
        && utils::Cpuid::cpuHasAvx512(utils::AVX512_DQ)
        && utils::Cpuid::cpuHasAvx512(utils::AVX512_BW)) {

        err = vaes512::DecryptXtsAvx512(pCipherText,
                                        pPlainText,
                                        len,
                                        getDecryptKeys(),
                                        p_tweak_key,
                                        getRounds(),
                                        pIv);
        return err;
    }

    if (utils::Cpuid::cpuHasVaes()) {

        err = vaes::DecryptXts(pCipherText,
                               pPlainText,
                               len,
                               getDecryptKeys(),
                               p_tweak_key,
                               getRounds(),
                               pIv);

        return err;
    }

    if (utils::Cpuid::cpuHasAesni()) {

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

    Rijndael::AesEncrypt(currentAlpha, p_tweak_key128, getRounds());
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

    return err;
}

} // namespace alcp::cipher