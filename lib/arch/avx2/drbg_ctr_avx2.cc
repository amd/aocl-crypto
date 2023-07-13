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
    std::vector<Uint8> temp;

    // While (len (temp) < seedlen) do
    while (temp.size() < seed_length) {
#ifdef DEBUG
        printf("CTR DRBG Update: Temp Size %ld\n", temp.size());
        std::cout << "CTR DRBG Update: Value before incrementing : "
                  << parseBytesToHexStr(value, 16) << std::endl;
#endif
        // V = (V+1) mod 2blocklen.
        increment_value(value);
#ifdef DEBUG
        std::cout << "CTR DRBG Update: Value after incrementing : "
                  << parseBytesToHexStr(value, 16) << std::endl;
#endif

        std::vector<Uint8> output_block(16, 0);
#ifdef DEBUG
        printf("Encryption Details\n");
        std::cout << "Key : " << parseBytesToHexStr(key, key_len) << std::endl;
        std::cout << "Key Length : " << key_len << std::endl;
        std::cout << "Value : " << parseBytesToHexStr(value, 16) << std::endl;
#endif
        // output_block = Block_Encrypt (Key, V).
        avx2::encrypt_block(&value[0], &key[0], key_len, &output_block[0]);
#ifdef DEBUG
        std::cout << "Output_block : "
                  << parseBytesToHexStr(&output_block[0], 16) << std::endl;
#endif
        // temp = temp || output_block.
        temp.insert(temp.end(), output_block.begin(), output_block.end());
#ifdef DEBUG
        printf("Update: Iteration End \n\n");
#endif
    }

#ifdef DEBUG
    std::cout << "Temp after loop :  "
              << parseBytesToHexStr(&temp[0], temp.size()) << std::endl;

#endif
    // temp = leftmost (temp, seedlen).
    temp = std::vector<Uint8>(temp.begin(), temp.begin() + seed_length);
#ifdef DEBUG
    std::cout << "leftmost (temp, seedlen) : "
              << parseBytesToHexStr(&temp[0], temp.size()) << std::endl;

#endif

    assert(seed_length == temp.size());
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
    utils::CopyBytes(key, &temp[0], key_len);
#ifdef DEBUG
    std::cout << "Key = leftmost (temp, keylen). So Key = "
              << parseBytesToHexStr(key, key_len) << std::endl;
#endif
    // V = rightmost (temp, blocklen).
    utils::CopyBytes(value, &temp[0] + temp.size() - 16, 16);
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
                Uint64       value_len)
{
    Uint64 seed_length = key_len + 16;

    // Fully create a zeroed out buffer of seed_length length
    Uint8 additional_input_bits[seed_length] = {};

    // If (additional_input ≠ Null), then
    if (cAdditionalInput != nullptr && cAdditionalInputLen != 0) {
        // f (temp < seedlen), then  additional_input =
        // additional_input || 0 ^ (seedlen - temp)
        utils::CopyBytes(
            additional_input_bits, cAdditionalInput, cAdditionalInputLen);
        // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
        alcp::rng::drbg::avx2::ctrDrbgUpdate(
            additional_input_bits, seed_length, &key[0], key_len, &value[0]);
    }

    // temp = Null.
    std::vector<Uint8> temp;

    std::vector<Uint8> output_block(16, 0);

    // While (len (temp) < requested_number_of_bits) do:
    while (temp.size() < cOutputLen) {
        // V = (V+1) mod 2^blocklen
        increment_value(value);
        // output_block = Block_Encrypt (Key, V)
        alcp::rng::drbg::avx2::encrypt_block(
            &value[0], &key[0], key_len, &output_block[0]);
        // emp = temp || output_block.
        temp.insert(temp.end(), output_block.begin(), output_block.end());
    }
    // returned_bits = leftmost (temp, requested_number_of_bits)
    utils::CopyBytes(output, &temp[0], cOutputLen);
    // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
    alcp::rng::drbg::avx2::ctrDrbgUpdate(
        additional_input_bits, seed_length, &key[0], key_len, &value[0]);
}

} // namespace alcp::rng::drbg::avx2