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

#include <complex.h>
#include <cstdint>
#include <cstdio>
#include <immintrin.h>
#include <vector>

#include "alcp/base.hh"
#include "alcp/base/error.hh"

#include "alcp/cipher/aesni.hh"
#include "alcp/types.hh"
#include "avx512.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

// Branch prediction hints (no-op on MSVC)
#if defined(__GNUC__) || defined(__clang__)
#define ALCP_EXPECT_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define ALCP_EXPECT_UNLIKELY(x) (x)
#endif

using namespace alcp;
using namespace alcp::base;
using namespace alcp::cipher;

// CFB Encryption: Ciphertext = Plaintext ⊕ Encrypt(IV)
// IV Update: Next_IV = Ciphertext (feedback from ciphertext)
namespace alcp::cipher::vaes512 {

/* @brief   Helper function to pack 4 lanes of IV data into a single __m512i
 * register for CFB mode encryption.
 *
 * @param   iv_block    Pointer to an array of 4 __m128i IVs.
 * @return  A __m512i register containing the packed IV data.
 */

static inline __m512i
pack_lanes_to_zmm(const __m128i** p_in_block, const __m128i* iv_block)
{
    __m512i zmm_val = _mm512_castsi128_si512(iv_block[0]);
    zmm_val         = _mm512_inserti32x4(zmm_val, iv_block[1], 1);
    zmm_val         = _mm512_inserti32x4(zmm_val, iv_block[2], 2);
    zmm_val         = _mm512_inserti32x4(zmm_val, iv_block[3], 3);
    return zmm_val;
}

/* @brief   Unpacks a __m512i register into 4 lanes of __m128i data and updates
 * the output pointers and IVs for CFB mode.
 *
 * @param   zmm_val     The __m512i register containing the encrypted IV data.
 * @param   p_out_block Pointer to an array of 4 pointers to __m128i output
 * blocks.
 * @param   iv_block    Pointer to an array of 4 __m128i IVs to be updated.
 * @param   p_in_block  Pointer to an array of 4 const __m128i input blocks.
 */

static inline void
unpack_zmm_to_lanes_and_update(const __m512i&  zmm_val,
                               __m128i**       p_out_block,
                               __m128i*        iv_block,
                               const __m128i** p_in_block)
{
    __m128i encrypted_iv0 = _mm512_extracti32x4_epi32(zmm_val, 0);
    __m128i encrypted_iv1 = _mm512_extracti32x4_epi32(zmm_val, 1);
    __m128i encrypted_iv2 = _mm512_extracti32x4_epi32(zmm_val, 2);
    __m128i encrypted_iv3 = _mm512_extracti32x4_epi32(zmm_val, 3);

    // XOR the encrypted IV with plaintext to get ciphertext
    __m128i ctext_lane0 =
        _mm_xor_si128(encrypted_iv0, _mm_loadu_si128(p_in_block[0]));
    __m128i ctext_lane1 =
        _mm_xor_si128(encrypted_iv1, _mm_loadu_si128(p_in_block[1]));
    __m128i ctext_lane2 =
        _mm_xor_si128(encrypted_iv2, _mm_loadu_si128(p_in_block[2]));
    __m128i ctext_lane3 =
        _mm_xor_si128(encrypted_iv3, _mm_loadu_si128(p_in_block[3]));

    _mm_storeu_si128(p_out_block[0], ctext_lane0);
    _mm_storeu_si128(p_out_block[1], ctext_lane1);
    _mm_storeu_si128(p_out_block[2], ctext_lane2);
    _mm_storeu_si128(p_out_block[3], ctext_lane3);

    _mm_storeu_si128(&iv_block[0], ctext_lane0);
    _mm_storeu_si128(&iv_block[1], ctext_lane1);
    _mm_storeu_si128(&iv_block[2], ctext_lane2);
    _mm_storeu_si128(&iv_block[3], ctext_lane3);

    (p_in_block[0])++;
    (p_in_block[1])++;
    (p_in_block[2])++;
    (p_in_block[3])++;

    (p_out_block[0])++;
    (p_out_block[1])++;
    (p_out_block[2])++;
    (p_out_block[3])++;
}

/* @brief Encrypts data in CFB mode using AES with AVX512 instructions.
 *
 * @param   pPlainText   Pointer to an array of pointers to plaintext
 * buffers.
 * @param   pCipherText  Pointer to an array of pointers to ciphertext
 * buffers.
 * @param   len          Length of the plaintext in bytes.
 * @param   pKey         Pointer to the encryption key.
 * @param   nRounds      Number of rounds for AES (10, 12, or 14).
 * @param   num_buffers  Number of buffers to process (1, 2, 4, 8, 16, 32, or
 * 64).
 * @param   pIv          Pointer to an array of pointers to IV buffers.
 * @return  ALC_ERROR_NONE on success, or an error code on failure.
 * Note: The function assumes that the input buffers are properly aligned and
 * sized. It also assumes that the input plaintext length is a multiple of the
 * block size (16 bytes). The function will process multiple buffers in parallel
 * using AVX512 instructions.
 */
alc_error_t
EncryptCfb(const Uint8** pPlainText,
           Uint8**       pCipherText,
           Uint64        len,
           const Uint8*  pKey,
           int           nRounds,
           int           num_buffers,
           Uint8**       pIv)
{
    Uint64      blocks = len / Rijndael::cBlockSize;
    alc_error_t err    = ALC_ERROR_NONE;

    if (ALCP_EXPECT_UNLIKELY(num_buffers == 0 || blocks == 0)) {
        return ALC_ERROR_NONE;
    }

    if (ALCP_EXPECT_UNLIKELY(nRounds != 10 && nRounds != 12 && nRounds != 14)) {
        return ALC_ERROR_INVALID_ARG; // Invalid number of rounds
    }

    // Use dynamic allocation to avoid template attribute warnings
    auto p_in_128_storage    = std::make_unique<const __m128i*[]>(num_buffers);
    auto p_out_128_storage   = std::make_unique<__m128i*[]>(num_buffers);
    auto current_ivs_storage = std::make_unique<__m128i[]>(num_buffers);
    const __m128i**   p_in_128    = p_in_128_storage.get();
    __m128i**         p_out_128   = p_out_128_storage.get();
    __m128i*          current_ivs = current_ivs_storage.get();
    auto              pkey128     = reinterpret_cast<const __m128i*>(pKey);
    alignas(64) sKeys keys{};

    for (int i = 0; i < num_buffers; i++) {
        p_in_128[i]  = reinterpret_cast<const __m128i*>(pPlainText[i]);
        p_out_128[i] = reinterpret_cast<__m128i*>(pCipherText[i]);
        //clang-format off
        current_ivs[i] =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv[i]));
        // clang-format on
    }

    switch (nRounds) {
        case 10:
            alcp_load_key_zmm_10rounds(pkey128, keys);
            break;
        case 12:
            alcp_load_key_zmm_12rounds(pkey128, keys);
            break;
        case 14:
            alcp_load_key_zmm_14rounds(pkey128, keys);
            break;
    }
    switch (num_buffers) {
        case 4:
            VAES512_ENCRYPT_SWITCH_ROUNDS(VAES512_ENCRYPT_BLOCK_LOOP_1, 1);
            break;
        case 8:
            VAES512_ENCRYPT_SWITCH_ROUNDS(VAES512_ENCRYPT_BLOCK_LOOP_2, 2);
            break;
        case 16:
            VAES512_ENCRYPT_SWITCH_ROUNDS(VAES512_ENCRYPT_BLOCK_LOOP_4, 4);
            break;
        case 32:
            VAES512_ENCRYPT_SWITCH_ROUNDS(VAES512_ENCRYPT_BLOCK_LOOP_8, 8);
            break;
        case 64:
            VAES512_ENCRYPT_SWITCH_ROUNDS(VAES512_ENCRYPT_BLOCK_LOOP_16, 16);
            break;
    }

        // Update final IVs in the caller's pIv array if AES_MULTI_UPDATE is
        // defined
#ifdef AES_MULTI_UPDATE
    for (int i = 0; i < num_buffers; i++) {
        // Store the last ciphertext block (now in current_ivs[i]) back
        // to pIv[i]
        _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv[i]), current_ivs[i]);
    }
#endif
    return err;
}

} // namespace alcp::cipher::vaes512
