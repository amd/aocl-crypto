/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

// CTR DRBG is implemented as per NIST.SP.800-90Ar1 and the algorithm
// steps are also shown as in the documentation as part of the code for future
// matching and references

#include "alcp/cipher/aesni.hh"
#include "alcp/rng/drbg_ctr.hh"
#include "alcp/utils/copy.hh"
#include <immintrin.h>

namespace alcp::rng::drbg::avx2 {

class EncryptAes : public cipher::Aes
{
  public:
    bool isSupported(const alc_cipher_info_t& cipherInfo) { return true; }
};

inline void
IncrementValue(__m128i& regValue)
{
    __m128i shuffle_mask =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    regValue = _mm_shuffle_epi8(regValue, shuffle_mask);
    __m128i one_reg_128 =
        _mm_setr_epi8(0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    regValue = regValue + one_reg_128;
    regValue = _mm_shuffle_epi8(regValue, shuffle_mask);
}

// CTR_DRBG_Update
void
CtrDrbgUpdate(const Uint8  pProvidedData[],
              const Uint64 cProvidedDataLen,
              Uint8*       key,
              Uint64       keyLen,
              Uint8*       value)
{
    Uint64 seed_length = keyLen + 16;

    static constexpr Uint64 cMaxSeedLength =
        384; // For key size 256 (Block Size + KeySize = 256+128=384)

    // temp = Null.
    Uint8  temp[cMaxSeedLength];
    Uint64 temp_size = 0;

    EncryptAes aes;
    aes.setKey(&key[0], keyLen * 8);
    Uint32  aes_rounds = aes.getRounds();
    auto    p_key      = reinterpret_cast<const __m128i*>(aes.getEncryptKeys());
    __m128i reg_value  = _mm_loadu_si128(reinterpret_cast<__m128i*>(value));

    // While (len (temp) < seedlen) do
    while (temp_size < seed_length) {
        // V = (V+1) mod 2^blocklen.
        IncrementValue(reg_value);

        // output_block = Block_Encrypt (Key, V).
        __m128i temp_reg_value = reg_value;
        alcp::cipher::aesni::AesEncrypt(
            &temp_reg_value, (const __m128i*)p_key, aes_rounds);
        // temp = temp || output_block.
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&temp[0] + temp_size),
                         temp_reg_value);
        temp_size += 16;
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&value[0]), reg_value);

    // temp = leftmost (temp, seedlen).
    assert(temp_size >= seed_length);
    temp_size = seed_length; // Meaning, only seed_length bytes are considered
                             // from here on. rest is discarded.

    assert(cProvidedDataLen == temp_size);

    // temp = temp ⊕ provided_data
    for (Uint64 i = 0; i < cProvidedDataLen; i++) {
        temp[i] = temp[i] ^ pProvidedData[i];
    }

    // Key = leftmost (temp, keylen).
    utils::CopyBytes(key, temp, keyLen);
    // V = rightmost (temp, blocklen).
    utils::CopyBytes(value, temp + temp_size - 16, 16);
}

// CTR_DRBG_Generate_algorithm
void
DrbgCtrGenerate(const Uint8  cAdditionalInput[],
                const Uint64 cAdditionalInputLen,
                Uint8        output[],
                const Uint64 cOutputLen,
                Uint8*       key,
                Uint64       keyLen,
                Uint8*       value,
                Uint64       valueLen,
                bool         useDf)
{
    Uint64 seed_length = keyLen + 16;

    // Fully create a zeroed out buffer of seed_length length
    static constexpr Uint64 cMaxSeedLength =
        384; // For key size 256 (Block Size + KeySize = 256+128=384)
    Uint8 additional_input_bits
        [cMaxSeedLength] = {}; // Allocating for max seedlength although the
                               // function should only consider seed_length
                               // bytes

    // If (additional_input ≠ Null), then
    if (cAdditionalInput != nullptr && cAdditionalInputLen != 0) {
        if (useDf) {
            alcp::rng::drbg::avx2::BlockCipherDf(cAdditionalInput,
                                                 cAdditionalInputLen * 8,
                                                 &additional_input_bits[0],
                                                 seed_length * 8,
                                                 keyLen);
        } else {
            // If (temp < seedlen), then  additional_input =
            // additional_input || 0 ^ (seedlen - temp)
            utils::CopyBytes(&additional_input_bits[0],
                             cAdditionalInput,
                             cAdditionalInputLen);
        }
        // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
        alcp::rng::drbg::avx2::CtrDrbgUpdate(
            &additional_input_bits[0], seed_length, &key[0], keyLen, &value[0]);
    }

    Uint64 inc = 0;

    // We wont create a temporary buffer as the FIPS algorithm suggests but
    // rather store the data directly to the output buffer of the encryption
    // While (len (temp) < requested_number_of_bits) do:
    __m128i    reg_value = _mm_loadu_si128(reinterpret_cast<__m128i*>(value));
    EncryptAes aes;
    aes.setKey(&key[0], keyLen * 8);
    Uint32 aes_rounds = aes.getRounds();
    auto   p_key      = reinterpret_cast<const __m128i*>(aes.getEncryptKeys());

    for (inc = 0; cOutputLen - inc >= 16; inc += 16) {
        // V = (V+1) mod 2^blocklen
        IncrementValue(reg_value);
        __m128i temp_reg_value = reg_value;
        // output_block = Block_Encrypt (Key, V)
        alcp::cipher::aesni::AesEncrypt(
            &temp_reg_value, (const __m128i*)p_key, aes_rounds);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + inc),
                         temp_reg_value);
    }

    if (cOutputLen - inc > 0) {
        IncrementValue(reg_value);
        Uint8   output_block[16];
        __m128i temp_reg_value = reg_value;
        alcp::cipher::aesni::AesEncrypt(
            &temp_reg_value, (const __m128i*)p_key, aes_rounds);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output_block),
                         temp_reg_value);
        utils::CopyBytes(output + inc, output_block, cOutputLen - inc);
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&value[0]), reg_value);

    // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
    alcp::rng::drbg::avx2::CtrDrbgUpdate(
        &additional_input_bits[0], seed_length, &key[0], keyLen, &value[0]);
}

// BCC (Key, data):
void
BCC(const Uint8* key,
    Uint64       keyLength,
    Uint8*       data,
    Uint64       dataLength,
    Uint8*       outputBlock)
{
    // chaining_value = 0^outlen.
    static constexpr int cOutlen = 16; // Block length in bytes
    assert(dataLength % cOutlen == 0);

    __m128i chaining_value_reg = _mm_setzero_si128();
    auto    n                  = dataLength / cOutlen; // number of blocks

    // Starting with the leftmost bits of data, split data into n blocks
    // ofencrypt_block outlen bits each, forming block1 to blockn. For i = 1 to
    // n do
    __m128i    data_reg;
    EncryptAes aes;
    aes.setKey(&key[0], keyLength * 8);
    Uint32 aes_rounds = aes.getRounds();
    auto   p_key      = reinterpret_cast<const __m128i*>(aes.getEncryptKeys());
    for (Uint64 i = 0; i < n; i++) {
        // input_block = chaining_value ⊕ blocki.
        data_reg =
            _mm_loadu_si128(reinterpret_cast<__m128i*>(data + i * cOutlen));
        chaining_value_reg = _mm_xor_si128(data_reg, chaining_value_reg);

        // chaining_value = Block_Encrypt (Key, input_block)
        alcp::cipher::aesni::AesEncrypt(
            &chaining_value_reg, (const __m128i*)p_key, aes_rounds);
    }
    // output_block = chaining_value.
    _mm_storeu_si128(reinterpret_cast<__m128i*>(outputBlock),
                     chaining_value_reg);
}

void
BlockCipherDf(const Uint8* inputString,
              Uint64       inputStringLength,
              Uint8*       requestedBits,
              Uint64       noOfBitsToReturn,
              Uint64       keylen)
{
    // If (number_of_bits_to_return > max_number_of_bits), then return an
    // ERROR_FLAG and a Null string.
    constexpr int cOutlen = 16;
    Int32         L = inputStringLength / 8; // Input string length in bytes
    Int32         N = noOfBitsToReturn / 8;  // no. of bits to return in bytes
    auto          s_size = sizeof(L) + sizeof(N) + L + 1;

    const Uint64 cNoOfBytesToReturn = noOfBitsToReturn / 8;

    if (s_size % cOutlen != 0) {
        s_size += (cOutlen - (s_size % cOutlen));
    }

    std::vector<Uint8> S(s_size);

    Uint8* p_s_8 = &S[0];
    for (size_t i = 0; i < sizeof(Int32); i++) {
        Uint8 t                      = (L & (0xff << i * 8)) >> (i * 8);
        p_s_8[sizeof(Int32) - i - 1] = t;
    }

    p_s_8 = p_s_8 + sizeof(Int32);
    for (size_t i = 0; i < sizeof(Int32); i++) {
        Uint8 t                      = (N & (0xff << i * 8)) >> (i * 8);
        p_s_8[sizeof(Int32) - i - 1] = t;
    }
    auto p_s_input_str = (&S[0]) + sizeof(L) + sizeof(N);
    memcpy(p_s_input_str, inputString, L);
    memset(p_s_input_str + L, 0x80, 1);

    // temp = the Null string.
    constexpr Uint64 cMaxTempSize = 32 + 16; // maxKeySize+Blocklen
    Uint8            temp[cMaxTempSize];
    Uint64           temp_size = 0;

    // i = 0
    Int32 i = 0;

    // K = leftmost (0x00010203...1D1E1F, keylen).
    static const Uint8 big_key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                     0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                     0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                     0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                                     0x1c, 0x1d, 0x1e, 0x1f };

    // While len (temp) < keylen + outlen, do
    while (temp_size < (keylen + cOutlen)) {
        // IV = i || 0^(outlen - len (i)); len(i) is fixed as 32 bits
        std::vector<Uint8> IV(cOutlen);
        auto               iv_8 = &IV[0];
        for (size_t j = 0; j < sizeof(Int32); j++) {
            Uint8 t                     = (i & (0xff << j * 8)) >> (j * 8);
            iv_8[sizeof(Int32) - j - 1] = t;
        }

        // temp = temp || BCC (K, (IV || S)).
        std::vector<Uint8> iv_concat_s(IV.size() + S.size());
        memcpy(&iv_concat_s[0], &IV[0], IV.size());
        memcpy(&iv_concat_s[0] + IV.size(), &S[0], S.size());

        BCC(big_key,
            keylen,
            &iv_concat_s[0],
            iv_concat_s.size(),
            &temp[0] + temp_size); // BCC (K, (IV || S)).
        temp_size += 16;
        i++;
    }

    EncryptAes aes;
    // K = leftmost (temp, keylen).
    aes.setKey(&temp[0], keylen * 8);
    Uint32 aes_rounds = aes.getRounds();
    auto   p_key      = reinterpret_cast<const __m128i*>(aes.getEncryptKeys());
    // X = select (temp, keylen+1, keylen+outlen).
    __m128i x_reg =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(&temp[0] + keylen));
    Uint64 inc = 0;
    for (inc = 0; cNoOfBytesToReturn - inc >= cOutlen; inc += cOutlen) {
        alcp::cipher::aesni::AesEncrypt(
            &x_reg, (const __m128i*)p_key, aes_rounds);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(requestedBits + inc),
                         x_reg);
    }
    if (cNoOfBytesToReturn - inc > 0) {
        Uint8 output_block[cOutlen];
        alcp::cipher::aesni::AesEncrypt(
            &x_reg, (const __m128i*)p_key, aes_rounds);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&output_block[0]), x_reg);
        utils::CopyBytes(
            requestedBits + inc, &output_block[0], cNoOfBytesToReturn - inc);
    }
}
} // namespace alcp::rng::drbg::avx2