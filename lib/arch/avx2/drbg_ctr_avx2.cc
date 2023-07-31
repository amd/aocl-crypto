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

// #define DEBUG 1
namespace alcp::rng::drbg::avx2 {

class EncryptAes : public cipher::Aes
{
  public:
    bool isSupported(const alc_cipher_info_t& cipherInfo) { return true; }
};

void
increment_value(Uint8* value)
{
    reg_128 shuffle_mask;
    shuffle_mask.reg =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    reg_128 v_reg_128;
    v_reg_128.reg = _mm_loadu_si128(reinterpret_cast<__m128i*>(&value[0]));
    v_reg_128.reg = _mm_shuffle_epi8(v_reg_128.reg, shuffle_mask.reg);
#ifdef DEBUG
    printf("CTR DRBG: Loaded data from value in register ");
    print(v_reg_128);
    printf("\n");
#endif
    reg_128 one_reg_128;
    one_reg_128.reg =
        _mm_setr_epi8(0x01, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0);
#ifdef DEBUG
    printf("one_reg value is ");
    print(one_reg_128);
    printf("\n");
#endif
    v_reg_128.reg = v_reg_128.reg + one_reg_128.reg;
#ifdef DEBUG
    printf("v_reg value after adding 1 ");
    print(v_reg_128);
    printf("\n");
#endif
    v_reg_128.reg = _mm_shuffle_epi8(v_reg_128.reg, shuffle_mask.reg);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&value[0]), v_reg_128.reg);
}

inline void
increment_value(reg_128& reg_value)
{
    reg_128 shuffle_mask;
    shuffle_mask.reg =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    reg_value.reg = _mm_shuffle_epi8(reg_value.reg, shuffle_mask.reg);
    reg_128 one_reg_128;
    one_reg_128.reg =
        _mm_setr_epi8(0x01, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    reg_value.reg = reg_value.reg + one_reg_128.reg;
    reg_value.reg = _mm_shuffle_epi8(reg_value.reg, shuffle_mask.reg);
}
void
encrypt_block(Uint8* input, const Uint8* key, Uint64 key_size, Uint8* output)
{
    EncryptAes aes;
    aes.setKey(&key[0], key_size * 8);
    reg_128 reg_input;
    reg_input.reg = _mm_loadu_si128(reinterpret_cast<__m128i*>(input));
    auto p_key    = reinterpret_cast<const __m128i*>(aes.getEncryptKeys());
    alcp::cipher::aesni::AesEncrypt(
        &reg_input.reg, (const __m128i*)p_key, aes.getRounds());
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output), reg_input.reg);
}

void
encrypt_block_reg(reg_128      reg_input,
                  const Uint8* key,
                  Uint64       key_size,
                  Uint8*       output)
{
    EncryptAes aes;
    aes.setKey(&key[0], key_size * 8);
    auto p_key = reinterpret_cast<const __m128i*>(aes.getEncryptKeys());
    alcp::cipher::aesni::AesEncrypt(
        &reg_input.reg, (const __m128i*)p_key, aes.getRounds());
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output), reg_input.reg);
}

// CTR_DRBG_Update
void
ctrDrbgUpdate(const Uint8  p_provided_data[],
              const Uint64 cProvidedDataLen,
              Uint8*       key,
              Uint64       key_len,
              Uint8*       value)
{
    Uint64 seed_length = key_len + 16;
#ifdef DEBUG
    printf("Inside DRBG Update:\n");
    std::cout << "Provided Data : "
              << parseBytesToHexStr(p_provided_data, cProvidedDataLen)
              << std::endl;
    printf("Provided Data Length : %ld\n", cProvidedDataLen);
    printf("Seed Length: %ld\n", seed_length);
#endif

    // temp = Null.

    static constexpr Uint64 cMaxSeedLength =
        384; // For key size 256 (Block Size + KeySize = 256+128=384)

    Uint8  temp[cMaxSeedLength];
    Uint64 temp_size = 0;

    reg_128 reg_value;
    reg_value.reg = _mm_loadu_si128(reinterpret_cast<__m128i*>(value));
    // While (len (temp) < seedlen) do
    while (temp_size < seed_length) {
#ifdef DEBUG
        printf("CTR DRBG Update: Temp Size %ld\n", temp.size());
        std::cout << "CTR DRBG Update: Value before incrementing : "
                  << parseBytesToHexStr(value, 16) << std::endl;
#endif
        // V = (V+1) mod 2blocklen.
        increment_value(reg_value);
#ifdef DEBUG
        std::cout << "CTR DRBG Update: Value after incrementing : "
                  << parseBytesToHexStr(value, 16) << std::endl;
#endif

#ifdef DEBUG
        printf("Encryption Details\n");
        std::cout << "Key : " << parseBytesToHexStr(key, key_len) << std::endl;
        std::cout << "Key Length : " << key_len << std::endl;
        std::cout << "Value : " << parseBytesToHexStr(value, 16) << std::endl;
#endif
        // output_block = Block_Encrypt (Key, V).
        // temp = temp || output_block.
        avx2::encrypt_block_reg(
            reg_value, &key[0], key_len, &temp[0] + temp_size);
        temp_size += 16;
#ifdef DEBUG
        printf("Update: Iteration End \n\n");
#endif
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&value[0]), reg_value.reg);

#ifdef DEBUG
    std::cout << "Temp after loop :  "
              << parseBytesToHexStr(&temp[0], temp.size()) << std::endl;

#endif
    // temp = leftmost (temp, seedlen).
    assert(temp_size >= seed_length);
    temp_size = seed_length; // Meaning, only seed_length bytes are considered
                             // from here on. rest is discarded.
#ifdef DEBUG
    std::cout << "leftmost (temp, seedlen) : "
              << parseBytesToHexStr(&temp[0], temp.size()) << std::endl;

#endif

    assert(seed_length == temp_size);
    assert(cProvidedDataLen == temp_size);

    // temp = temp ⊕ provided_data
    for (Uint64 i = 0; i < cProvidedDataLen; i++) {
        temp[i] = temp[i] ^ p_provided_data[i];
    }

#ifdef DEBUG
    std::cout << "Temp value after xor is : "
              << parseBytesToHexStr(&temp[0], temp.size()) << std::endl;
    std::cout << "Size of temp  is " << temp.size() << std::endl;
#endif
    // Key = leftmost (temp, keylen).
    utils::CopyBytes(key, temp, key_len);
#ifdef DEBUG
    std::cout << "Key = leftmost (temp, keylen). So Key = "
              << parseBytesToHexStr(key, key_len) << std::endl;
#endif
    // V = rightmost (temp, blocklen).
    utils::CopyBytes(value, temp + temp_size - 16, 16);
#ifdef DEBUG
    std::cout << "V = rightmost (temp, blocklen). So Value = "
              << parseBytesToHexStr(value, 16) << std::endl;

    printf("Exit DRBG Update:\n");
#endif
}

// CTR_DRBG_Generate_algorithm
void
DrbgCtrGenerate(const Uint8  cAdditionalInput[],
                const Uint64 cAdditionalInputLen,
                Uint8        output[],
                const Uint64 cOutputLen,
                Uint8*       key,
                Uint64       key_len,
                Uint8*       value,
                Uint64       value_len,
                bool         use_df)
{
    Uint64 seed_length = key_len + 16;

    // Fully create a zeroed out buffer of seed_length length
    static constexpr Uint64 cMaxSeedLength =
        384; // For key size 256 (Block Size + KeySize = 256+128=384)
    Uint8 additional_input_bits
        [cMaxSeedLength] = {}; // Allocating for max seedlength although the
                               // function should only consider seed_length
                               // bytes

    // If (additional_input ≠ Null), then
    if (cAdditionalInput != nullptr && cAdditionalInputLen != 0) {
        if (use_df) {
            alcp::rng::drbg::avx2::Block_Cipher_df(cAdditionalInput,
                                                   cAdditionalInputLen * 8,
                                                   &additional_input_bits[0],
                                                   seed_length * 8,
                                                   key_len);
        } else {
            // If (temp < seedlen), then  additional_input =
            // additional_input || 0 ^ (seedlen - temp)
            utils::CopyBytes(&additional_input_bits[0],
                             cAdditionalInput,
                             cAdditionalInputLen);
        }
        // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
        alcp::rng::drbg::avx2::ctrDrbgUpdate(&additional_input_bits[0],
                                             seed_length,
                                             &key[0],
                                             key_len,
                                             &value[0]);
    }

    Uint64 inc = 0;

    // We wont create a temporary buffer as the FIPS algorithm suggests but
    // rather store the data directly to the output buffer of the encryption
    // While (len (temp) < requested_number_of_bits) do:
    for (inc = 0; cOutputLen - inc >= 16; inc += 16) {
        // V = (V+1) mod 2^blocklen
        increment_value(value);
        // output_block = Block_Encrypt (Key, V)
        alcp::rng::drbg::avx2::encrypt_block(
            &value[0], &key[0], key_len, output + inc);
    }

    if (cOutputLen - inc > 0) {
        increment_value(value);
        Uint8 output_block[16];
        alcp::rng::drbg::avx2::encrypt_block(
            &value[0], &key[0], key_len, output_block);
        utils::CopyBytes(output + inc, output_block, cOutputLen - inc);
    }

    // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
    alcp::rng::drbg::avx2::ctrDrbgUpdate(
        &additional_input_bits[0], seed_length, &key[0], key_len, &value[0]);
}

void
do_xor(const Uint8* input1, const Uint8* input2, Uint8* output, Uint64 n)
{
    for (Uint64 i = 0; i < n; i++) {
        output[i] = input1[i] ^ input2[i];
    }
}

// BCC (Key, data):
void
BCC(Uint8* key,
    Uint64 key_length,
    Uint8* data,
    Uint64 data_length,
    Uint8* output_block)
{
    // chaining_value = 0^outlen.
    static constexpr int outlen = 16; // Block length in bytes
    assert(data_length % outlen == 0);
    Uint8 chaining_value[outlen] = {};
    // n = len (data)/outlen.
    auto n = data_length / outlen; // number of blocks

    // Starting with the leftmost bits of data, split data into n blocks
    // ofencrypt_block outlen bits each, forming block1 to blockn. For i = 1 to
    // n do
    Uint8 input_block[outlen] = {};
    for (Uint64 i = 0; i < n; i++) {
        // input_block = chaining_value ⊕ blocki.
        do_xor(chaining_value, data + i * outlen, input_block, 16);
        // chaining_value = Block_Encrypt (Key, input_block)
        encrypt_block(input_block, key, key_length, chaining_value);
    }
    // output_block = chaining_value.
    utils::CopyBytes(output_block, chaining_value, outlen);
}

void
Block_Cipher_df(const Uint8* input_string,
                Uint64       input_string_length,
                Uint8*       requested_bits,
                Uint64       no_of_bits_to_return,
                Uint64       keylen)
{
    // If (number_of_bits_to_return > max_number_of_bits), then return an
    // ERROR_FLAG and a Null string.
    constexpr int outlen = 16;
    Int32         L = input_string_length / 8; // Input string length in bytes
    Int32 N      = no_of_bits_to_return / 8;   // no. of bits to return in bytes
    auto  s_size = sizeof(L) + sizeof(N) + L + 1;

    const Uint64 no_of_bytes_to_return = no_of_bits_to_return / 8;

    if (s_size % outlen != 0) {
        s_size += (outlen - (s_size % outlen));
    }

    std::vector<Uint8> S(s_size, 0);

    Uint8* s_8 = &S[0];
    for (size_t i = 0; i < sizeof(Int32); i++) {
        Uint8 t                    = (L & (0xff << i * 8)) >> (i * 8);
        s_8[sizeof(Int32) - i - 1] = t;
    }

    s_8 = s_8 + sizeof(Int32);
    for (size_t i = 0; i < sizeof(Int32); i++) {
        Uint8 t                    = (N & (0xff << i * 8)) >> (i * 8);
        s_8[sizeof(Int32) - i - 1] = t;
    }

    memcpy((&S[0]) + sizeof(L) + sizeof(N), input_string, L);
    // S[2 + input_string_length + 1] = 0x80;
    memset((&S[0]) + sizeof(L) + sizeof(N) + L, 0x80, 1);

    // temp = the Null string.
    std::vector<Uint8> temp;

    // i = 0
    Int32 i = 0;

    // K = leftmost (0x00010203...1D1E1F, keylen).
    Uint8 bigKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    std::vector<Uint8> K(keylen);
    utils::CopyBytes(&K[0], bigKey, keylen);

    // While len (temp) < keylen + outlen, do
    while (temp.size() < (keylen + outlen)) {
        // IV = i || 0^(outlen - len (i)); len(i) is fixed as 32 bits
        std::vector<Uint8> IV(outlen, 0);
        auto               iv_8 = &IV[0];
        for (size_t j = 0; j < sizeof(Int32); j++) {
            Uint8 t                     = (i & (0xff << j * 8)) >> (j * 8);
            iv_8[sizeof(Int32) - j - 1] = t;
        }

        // temp = temp || BCC (K, (IV || S)).
        std::vector<Uint8> iv_concat_s(IV.size() + S.size());
        ;
        memcpy(&iv_concat_s[0], &IV[0], IV.size());
        memcpy(&iv_concat_s[0] + IV.size(), &S[0], S.size());

        std::vector<Uint8> output_block(outlen, 0);
        BCC(bigKey,
            keylen,
            &iv_concat_s[0],
            iv_concat_s.size(),
            &output_block[0]); // BCC (K, (IV || S)).

        temp.insert(temp.end(), output_block.begin(), output_block.end());
        i++;
    }

    // K = leftmost (temp, keylen).
    utils::CopyBytes(&K[0], &temp[0], keylen);
    // X = select (temp, keylen+1, keylen+outlen).
    std::vector<Uint8> X(outlen, 0);
    utils::CopyBytes(&X[0], &temp[0] + keylen, outlen);

    temp.clear();
    while (temp.size() < no_of_bytes_to_return) {
        encrypt_block(&X[0], &K[0], keylen, &X[0]);
        temp.insert(temp.end(), X.begin(), X.end());
    }
    utils::CopyBytes(requested_bits, &temp[0], no_of_bytes_to_return);
}
} // namespace alcp::rng::drbg::avx2