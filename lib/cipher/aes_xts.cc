/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes_xts.hh"
#include "alcp/cipher/cipher_wrapper.hh"

using alcp::utils::CpuId;
using alcp::utils::CpuArchLevel;
using alcp::utils::AlgorithmType;

namespace alcp::cipher {

// over AES init, for tweakKey operation
alc_error_t
Xts::setIv(const Uint8* pIv, const Uint64 ivLen)
{
    alc_error_t err{ ALC_ERROR_NONE };
    
    // Use IvManager for IV storage
    err = m_ivManager.setIv(pIv, ivLen);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // FIXME: In future we need to dispatch it correctly
    aesni::InitializeTweakBlock(
        pIv, m_xts.m_tweak_block, m_xts.m_tweak_round_key, m_keyManager.getRounds());

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

    // Validate and set key
    if (keyLen != 0 || pKey != nullptr) {
        // XTS supports only 128-bit and 256-bit keys. Reject anything else
        // here so the tweak-key pointer arithmetic below stays in bounds.
        if (keyLen != 128 && keyLen != 256) {
            return ALC_ERROR_INVALID_SIZE;
        }

        err = m_keyManager.setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        // Always expand tweak keys
        expandTweakKeys(pKey + keyLen / 8, keyLen);

        m_stateManager.onKeySet();
    }

    // Validate and set IV -- let IvManager reject null/bad length
    if (pIv == nullptr && ivLen != 0) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pIv != nullptr) {
        err = Xts::setIv(pIv, ivLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_stateManager.onIvSet();
    }

    return err;
}

void
Xts::tweakBlockSet(Uint64 aesBlockId)
{
    // FIXME: In future we need to dispatch it correctly
    // m_xts.m_aes_block_id is the previous block id and
    // aesBlockId is the target block id.
    if ((Int64)aesBlockId > m_xts.m_aes_block_id) {
        aesni::TweakBlockCalculate(m_xts.m_tweak_block,
                                   aesBlockId - m_xts.m_aes_block_id);
    } else if ((Int64)aesBlockId < m_xts.m_aes_block_id) {
        // Use IvManager for IV
        aesni::InitializeTweakBlock(m_ivManager.getIv(),
                                    m_xts.m_tweak_block,
                                    m_xts.m_tweak_round_key,
                                    m_keyManager.getRounds());
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
    // Use cached cipher feature for AESNI check
    static CpuArchLevel cipherFeature =
        CpuId::getCachedArchLevel(AlgorithmType::eCipher);
    if (cipherFeature >= CpuArchLevel::eZen) {
        aesni::ExpandTweakKeys(key, m_xts.m_tweak_round_key, m_keyManager.getRounds());
        return;
    }

    // Dispatch to Reference Algorithm

    Uint32 i;
    Uint32 nb = Rijndael::cBlockSizeWord, nr = m_keyManager.getRounds(),
           nk          = len / utils::BitsPerByte / utils::BytesPerWord;
    const Uint32* rtbl = utils::s_round_constants;
    Uint32*       p_tweak_key32;

    p_tweak_key32 = reinterpret_cast<Uint32*>(m_xts.m_tweak_round_key);

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

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
XtsT<keyLenBits, arch>::encrypt(const Uint8* pInput,
                                Uint8*       pOutput,
                                Uint64       len,
                                Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    if (!m_stateManager.isReady()) {
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

    if constexpr (arch == CpuArchLevel::eZen4) {
        err = vaes512::EncryptXts(pInput,
                                  pOutput,
                                  len,
                                  m_keyManager.getCipherKeyData().m_enc_key,
                                  m_keyManager.getRounds(),
                                  m_xts.m_tweak_block);

    } else if constexpr (arch == CpuArchLevel::eZen3) {
        err = vaes::EncryptXts(pInput,
                               pOutput,
                               len,
                               m_keyManager.getCipherKeyData().m_enc_key,
                               m_keyManager.getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuArchLevel::eZen) {
        err = aesni::EncryptXts(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_enc_key,
                                m_keyManager.getRounds(),
                                m_xts.m_tweak_block);
    }

    // XTS is a block-aligned mode: output length equals input length on success
    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }

    m_xts.m_aes_block_id += blocks_in;
    return err;
};

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
XtsT<keyLenBits, arch>::decrypt(const Uint8* pInput,
                                Uint8*       pOutput,
                                Uint64       len,
                                Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    if (!m_stateManager.isReady()) {
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
    if constexpr (arch == CpuArchLevel::eZen4) {
        err = vaes512::DecryptXts(pInput,
                                  pOutput,
                                  len,
                                  m_keyManager.getCipherKeyData().m_dec_key,
                                  m_keyManager.getRounds(),
                                  m_xts.m_tweak_block);

    } else if constexpr (arch == CpuArchLevel::eZen3) {
        err = vaes::DecryptXts(pInput,
                               pOutput,
                               len,
                               m_keyManager.getCipherKeyData().m_dec_key,
                               m_keyManager.getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuArchLevel::eZen) {
        err = aesni::DecryptXts(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_dec_key,
                                m_keyManager.getRounds(),
                                m_xts.m_tweak_block);
    }

    m_xts.m_aes_block_id += blocks_in;
    return err;
};

/*******************************************/
/** iCipher segment implementation of XTS **/
/*******************************************/

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
XtsBlockT<keyLenBits, arch>::decrypt(const Uint8* pInput,
                                     Uint8*       pOutput,
                                     Uint64       len,
                                     Uint64*      outlen)
{
    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    alc_error_t err = ALC_ERROR_NONE;
    if (!m_stateManager.isReady()) {
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

    if constexpr (arch == CpuArchLevel::eZen4) {
        err = vaes512::DecryptXts(pInput,
                                  pOutput,
                                  len,
                                  m_keyManager.getCipherKeyData().m_dec_key,
                                  m_keyManager.getRounds(),
                                  m_xts.m_tweak_block);
    } else if constexpr (arch == CpuArchLevel::eZen3) {
        err = vaes::DecryptXts(pInput,
                               pOutput,
                               len,
                               m_keyManager.getCipherKeyData().m_dec_key,
                               m_keyManager.getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuArchLevel::eZen) {
        err = aesni::DecryptXts(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_dec_key,
                                m_keyManager.getRounds(),
                                m_xts.m_tweak_block);
    }

    m_xts.m_aes_block_id += blocks_in;
    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }
    return err;
};

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
XtsBlockT<keyLenBits, arch>::encrypt(const Uint8* pInput,
                                     Uint8*       pOutput,
                                     Uint64       len,
                                     Uint64*      outlen)
{
    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;

    alc_error_t err = ALC_ERROR_NONE;
    if (!m_stateManager.isReady()) {
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

    if constexpr (arch == CpuArchLevel::eZen4) {
        err = vaes512::EncryptXts(pInput,
                                  pOutput,
                                  len,
                                  m_keyManager.getCipherKeyData().m_enc_key,
                                  m_keyManager.getRounds(),
                                  m_xts.m_tweak_block);

    } else if constexpr (arch == CpuArchLevel::eZen3) {
        err = vaes::EncryptXts(pInput,
                               pOutput,
                               len,
                               m_keyManager.getCipherKeyData().m_enc_key,
                               m_keyManager.getRounds(),
                               m_xts.m_tweak_block);
    } else if constexpr (arch == CpuArchLevel::eZen) {
        err = aesni::EncryptXts(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_enc_key,
                                m_keyManager.getRounds(),
                                m_xts.m_tweak_block);
    }
    m_xts.m_aes_block_id += blocks_in;
    if (err == ALC_ERROR_NONE) {
        *outlen = len;
    }
    return err;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
XtsBlockT<keyLenBits, arch>::encryptSegment(const Uint8* pInput,
                                            Uint8*       pOutput,
                                            Uint64       len,
                                            Uint64       startBlockNum)
{
    alc_error_t err = ALC_ERROR_NONE;
    Uint64      outlen;
    alcp::cipher::Xts::tweakBlockSet(startBlockNum);
    err = encrypt(pInput, pOutput, len, &outlen);
    return err;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
XtsBlockT<keyLenBits, arch>::decryptSegment(const Uint8* pInput,
                                            Uint8*       pOutput,
                                            Uint64       len,
                                            Uint64       startBlockNum)
{
    alc_error_t err = ALC_ERROR_NONE;
    Uint64      outlen;
    alcp::cipher::Xts::tweakBlockSet(startBlockNum);
    err = decrypt(pInput, pOutput, len, &outlen);
    return err;
}

template class XtsT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuArchLevel::eZen4>;
template class XtsT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuArchLevel::eZen4>;

template class XtsT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuArchLevel::eZen3>;
template class XtsT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuArchLevel::eZen3>;

template class XtsT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuArchLevel::eZen>;
template class XtsT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuArchLevel::eZen>;

template class XtsBlockT<alcp::cipher::CipherKeyLen::eKey128Bit,
                         CpuArchLevel::eZen4>;
template class XtsBlockT<alcp::cipher::CipherKeyLen::eKey256Bit,
                         CpuArchLevel::eZen4>;

template class XtsBlockT<alcp::cipher::CipherKeyLen::eKey128Bit,
                         CpuArchLevel::eZen3>;
template class XtsBlockT<alcp::cipher::CipherKeyLen::eKey256Bit,
                         CpuArchLevel::eZen3>;

template class XtsBlockT<alcp::cipher::CipherKeyLen::eKey128Bit,
                         CpuArchLevel::eZen>;
template class XtsBlockT<alcp::cipher::CipherKeyLen::eKey256Bit,
                         CpuArchLevel::eZen>;

} // namespace alcp::cipher
