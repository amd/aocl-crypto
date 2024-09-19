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
    alc_error_t err{ ALC_ERROR_NONE };
    utils::CopyBytes(m_xts.m_iv_xts, pIv, ivLen); // Keep a copy of iv

    // FIXME: In future we need to dispatch it correctly
    aesni::InitializeTweakBlock(
        pIv, m_xts.m_tweak_block, m_xts.m_pTweak_key, getRounds());

    m_xts.m_aes_block_id = 0; // Initialized BlockId to 0

    return err;
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

        m_xts.m_pTweak_key = &(m_xts.m_tweak_round_key[0]);
        expandTweakKeys(pKey + keyLen / 8, keyLen);

        m_isKeySet_aes = 1;
    }

    if (pIv != NULL && ivLen != 0) {
        err           = Xts::setIv(pIv, ivLen);
        m_ivState_aes = 1;
    }

    return err;
}

void
Xts::tweakBlockSet(Uint64 aesBlockId)
{
    // FIXME: In future we need to dispatch it correctly
    // m_cipher_key_data.m_xts.m_aes_block_id is the previous block id and
    // aesBlockId is the target block id.
    if ((Int64)aesBlockId > m_xts.m_aes_block_id) {
        aesni::TweakBlockCalculate(m_xts.m_tweak_block,
                                   aesBlockId - m_xts.m_aes_block_id);
    } else if ((Int64)aesBlockId < m_xts.m_aes_block_id) {
        aesni::InitializeTweakBlock(m_xts.m_iv_xts,
                                    m_xts.m_tweak_block,
                                    m_xts.m_pTweak_key,
                                    getRounds());
        aesni::TweakBlockCalculate(m_xts.m_tweak_block, aesBlockId);
    }
    m_xts.m_aes_block_id = aesBlockId;
}

void
Xts::expandTweakKeys(const Uint8* pKey, int len)
{
    using utils::GetByte, utils::MakeWord;
    Uint8 dummy_key[32] = { 0 };

    const Uint8* key = pKey ? pKey : &dummy_key[0];
    if (CpuId::cpuHasAesni()) {
        aesni::ExpandTweakKeys(key, m_xts.m_pTweak_key, getRounds());
        return;
    }

    // Dispatch to Reference Algorithm

    Uint32 i;
    Uint32 nb = Rijndael::cBlockSizeWord, nr = getRounds(),
           nk          = len / utils::BitsPerByte / utils::BytesPerWord;
    const Uint32* rtbl = utils::s_round_constants;
    Uint32*       p_tweak_key32;

    p_tweak_key32 = reinterpret_cast<Uint32*>(m_xts.m_pTweak_key);

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

/*******************************************/
/**     iCipher implementation of XTS     **/
/*******************************************/

// pIv arg to be removed and this is made same as other ciper wrapper func
// length check to be converted to generic function for all cipher modes
#define CRYPT_XTS_WRAPPER_FUNC(                                                        \
    NAMESPACE, CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, PKEY, NUM_ROUNDS)                  \
    alc_error_t CLASS_NAME##_##NAMESPACE::WRAPPER_FUNC(                                \
        const Uint8* pinput, Uint8* pOutput, Uint64 len)                               \
    {                                                                                  \
        alc_error_t err = ALC_ERROR_NONE;                                              \
                                                                                       \
        if (!(m_ivState_aes && m_isKeySet_aes)) {                                      \
            printf("\nError: Key or Iv not set \n");                                   \
            return ALC_ERROR_BAD_STATE;                                                \
        }                                                                              \
        if (len < 16 || len > (1 << 21)) {                                             \
            err = ALC_ERROR_INVALID_DATA;                                              \
            return err;                                                                \
        }                                                                              \
        Uint64 blocks_in = len / 16;                                                   \
        err              = NAMESPACE::FUNC_NAME(                                       \
            pinput, pOutput, len, PKEY, NUM_ROUNDS, m_xts.m_tweak_block); \
        m_xts.m_aes_block_id += blocks_in;                                             \
        return err;                                                                    \
    };

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tXts<keyLenBits, arch>::encrypt(const Uint8* pinput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    if constexpr ((keyLenBits != CipherKeyLen::eKey128Bit)
                  && (keyLenBits != CipherKeyLen::eKey256Bit)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    Uint64 blocks_in = len / 16;

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        err = vaes512::EncryptXts(pinput,
                                  pOutput,
                                  len,
                                  m_cipher_key_data.m_enc_key,
                                  getRounds(),
                                  m_xts.m_tweak_block);

    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        err = vaes::EncryptXts(pinput,
                               pOutput,
                               len,
                               m_cipher_key_data.m_enc_key,
                               getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::EncryptXts(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_xts.m_tweak_block);
    }
    m_xts.m_aes_block_id += blocks_in;
    return err;
};

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tXts<keyLenBits, arch>::decrypt(const Uint8* pinput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }

    if constexpr ((keyLenBits != CipherKeyLen::eKey128Bit)
                  && (keyLenBits != CipherKeyLen::eKey256Bit)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    Uint64 blocks_in = len / 16;
    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        err = vaes512::DecryptXts(pinput,
                                  pOutput,
                                  len,
                                  m_cipher_key_data.m_dec_key,
                                  getRounds(),
                                  m_xts.m_tweak_block);

    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        err = vaes::DecryptXts(pinput,
                               pOutput,
                               len,
                               m_cipher_key_data.m_dec_key,
                               getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::DecryptXts(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_dec_key,
                                getRounds(),
                                m_xts.m_tweak_block);
    }

    m_xts.m_aes_block_id += blocks_in;
    return err;
};

/*******************************************/
/** iCipher segment implementation of XTS **/
/*******************************************/

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tXtsBlock<keyLenBits, arch>::encrypt(const Uint8* pinput,
                                     Uint8*       pOutput,
                                     Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }
    Uint64 blocks_in = len / 16;

    if constexpr ((keyLenBits != CipherKeyLen::eKey128Bit)
                  && (keyLenBits != CipherKeyLen::eKey256Bit)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        err = vaes512::EncryptXts(pinput,
                                  pOutput,
                                  len,
                                  m_cipher_key_data.m_enc_key,
                                  getRounds(),
                                  m_xts.m_tweak_block);

    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        err = vaes::EncryptXts(pinput,
                               pOutput,
                               len,
                               m_cipher_key_data.m_enc_key,
                               getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::EncryptXts(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_enc_key,
                                getRounds(),
                                m_xts.m_tweak_block);
    }
    m_xts.m_aes_block_id += blocks_in;
    return err;
};

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tXtsBlock<keyLenBits, arch>::decrypt(const Uint8* pinput,
                                     Uint8*       pOutput,
                                     Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (len < 16 || len > (1 << 21)) {
        err = ALC_ERROR_INVALID_DATA;
        return err;
    }
    Uint64 blocks_in = len / 16;

    if constexpr ((keyLenBits != CipherKeyLen::eKey128Bit)
                  && (keyLenBits != CipherKeyLen::eKey256Bit)) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        err = vaes512::DecryptXts(pinput,
                                  pOutput,
                                  len,
                                  m_cipher_key_data.m_dec_key,
                                  getRounds(),
                                  m_xts.m_tweak_block);
    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        err = vaes::DecryptXts(pinput,
                               pOutput,
                               len,
                               m_cipher_key_data.m_dec_key,
                               getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::DecryptXts(pinput,
                                pOutput,
                                len,
                                m_cipher_key_data.m_dec_key,
                                getRounds(),
                                m_xts.m_tweak_block);
    }

    m_xts.m_aes_block_id += blocks_in;
    return err;
};

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tXtsBlock<keyLenBits, arch>::encryptSegment(const Uint8* pinput,
                                            Uint8*       pOutput,
                                            Uint64       len,
                                            Uint64       startBlockNum)
{
    alc_error_t err = ALC_ERROR_NONE;
    alcp::cipher::Xts::tweakBlockSet(startBlockNum);
    err = encrypt(pinput, pOutput, len);
    return err;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tXtsBlock<keyLenBits, arch>::decryptSegment(const Uint8* pinput,
                                            Uint8*       pOutput,
                                            Uint64       len,
                                            Uint64       startBlockNum)
{
    alc_error_t err = ALC_ERROR_NONE;
    alcp::cipher::Xts::tweakBlockSet(startBlockNum);
    err = decrypt(pinput, pOutput, len);
    return err;
}

template class tXts<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes512>;
template class tXts<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes512>;

template class tXts<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes256>;
template class tXts<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes256>;

template class tXts<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eAesni>;
template class tXts<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eAesni>;

template class tXtsBlock<alcp::cipher::CipherKeyLen::eKey128Bit,
                         CpuCipherFeatures::eVaes512>;
template class tXtsBlock<alcp::cipher::CipherKeyLen::eKey256Bit,
                         CpuCipherFeatures::eVaes512>;

template class tXtsBlock<alcp::cipher::CipherKeyLen::eKey128Bit,
                         CpuCipherFeatures::eVaes256>;
template class tXtsBlock<alcp::cipher::CipherKeyLen::eKey256Bit,
                         CpuCipherFeatures::eVaes256>;

template class tXtsBlock<alcp::cipher::CipherKeyLen::eKey128Bit,
                         CpuCipherFeatures::eAesni>;
template class tXtsBlock<alcp::cipher::CipherKeyLen::eKey256Bit,
                         CpuCipherFeatures::eAesni>;

} // namespace alcp::cipher