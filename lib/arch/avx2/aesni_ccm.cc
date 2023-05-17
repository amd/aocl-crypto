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

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aesni.hh"

#include <immintrin.h>

#if 0
#define ENTER() printf("ENTER %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__)
#define EXIT()  printf("EXIT %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__)
#define EXITG() printf("EXIT %s %s:%d GOOD\n", __FUNCTION__, __FILE__, __LINE__)
#define EXITB() printf("EXIT %s %s:%d BAD\n", __FUNCTION__, __FILE__, __LINE__)
#else
#define ENTER()
#define EXIT()
#define EXITG()
#define EXITB()
#endif
namespace alcp::cipher::aesni { namespace ccm {

    void SetAad(ccm_data_t* ccm_data, const Uint8 paad[], size_t alen)
    {
        ENTER();
        __m128i p_blk0   = { 0 };
        __m128i aad_128  = { 0 };
        Uint8*  p_blk0_8 = reinterpret_cast<Uint8*>(&p_blk0);
        Uint64  i        = 0;

        if (alen == 0) {
            EXITB();
            return;
        }

        ccm_data->nonce[0] |= 0x40; /* set Adata flag */

        p_blk0 =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(ccm_data->nonce));

        // ccm_data->cmac should be inside p_blk0
        AesEncrypt(&p_blk0,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        ccm_data->blocks++;

        if (alen < (0x10000 - 0x100)) {
            // alen < (2^16 - 2^8)
            *(p_blk0_8 + 0) ^= static_cast<Uint8>(alen >> 8);
            *(p_blk0_8 + 1) ^= static_cast<Uint8>(alen);
            i = 2;
        } else if (sizeof(alen) == 8 && alen >= ((size_t)1 << 32)) {
            // alen > what 32 bits can hold.
            *(p_blk0_8 + 0) ^= 0xFF;
            *(p_blk0_8 + 1) ^= 0xFF;
            *(p_blk0_8 + 2) ^= static_cast<Uint8>(alen >> 56);
            *(p_blk0_8 + 3) ^= static_cast<Uint8>(alen >> 48);
            *(p_blk0_8 + 4) ^= static_cast<Uint8>(alen >> 40);
            *(p_blk0_8 + 5) ^= static_cast<Uint8>(alen >> 32);
            *(p_blk0_8 + 6) ^= static_cast<Uint8>(alen >> 24);
            *(p_blk0_8 + 7) ^= static_cast<Uint8>(alen >> 16);
            *(p_blk0_8 + 8) ^= static_cast<Uint8>(alen >> 8);
            *(p_blk0_8 + 9) ^= static_cast<Uint8>(alen);
            i = 10;
        } else {
            // alen is represented by 32 bits but larger than
            // what 16 bits can hold
            *(p_blk0_8 + 0) ^= 0xFF;
            *(p_blk0_8 + 1) ^= 0xFE;
            *(p_blk0_8 + 2) ^= static_cast<Uint8>(alen >> 24);
            *(p_blk0_8 + 3) ^= static_cast<Uint8>(alen >> 16);
            *(p_blk0_8 + 4) ^= static_cast<Uint8>(alen >> 8);
            *(p_blk0_8 + 5) ^= static_cast<Uint8>(alen);
            i = 6;
        }

        // i=2,6,10 to i=16 do the CBC operation
        for (; i < 16 && alen; ++i, ++paad, --alen)
            *(p_blk0_8 + i) ^= *paad;

        AesEncrypt(&p_blk0,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        ccm_data->blocks++;

        Uint64 alen_16 = alen / 16;
        for (Uint64 j = 0; j < alen_16; j++) {
            aad_128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(paad));
            // CBC XOR operation
            p_blk0 = _mm_xor_si128(p_blk0, aad_128);
            // CBC Encrypt operation
            AesEncrypt(&p_blk0,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            ccm_data->blocks++;
            paad += 16;
        }

        // Reduce already processed value from alen
        alen -= alen_16 * 16;

        if (alen != 0) {
            // Process the rest in default way
            for (i = 0; i < 16 && alen; i++, paad++, alen--)
                *(p_blk0_8 + i) ^= *paad;

            // CBC Encrypt last block
            AesEncrypt(&p_blk0,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            ccm_data->blocks++;
        }

        // Store generated partial tag (cmac)
        _mm_store_si128(reinterpret_cast<__m128i*>(ccm_data->cmac), p_blk0);

        EXIT();
    }

    inline void CtrInc(__m128i* ctr)
    {
        ENTER();
        __m128i one = _mm_set_epi32(1, 0, 0, 0);
        __m128i swap_ctr =
            _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);
        *ctr = _mm_shuffle_epi8(*ctr, swap_ctr);
        *ctr = _mm_add_epi32(*ctr, one);
        *ctr = _mm_shuffle_epi8(*ctr, swap_ctr);
        EXITG();
    }

    CCM_ERROR Encrypt(ccm_data_t* ccm_data,
                      const Uint8 pinp[],
                      Uint8       pout[],
                      size_t      len)
    {
        // Implementation block diagram
        // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_encryption.png
        ENTER();
        size_t        n;
        unsigned int  i, q;
        unsigned char flags0 = ccm_data->nonce[0];
        const Uint8*  p_key  = ccm_data->key;
        __m128i       cmac, nonce, in_reg, temp_reg;
        Uint8*        p_cmac_8  = reinterpret_cast<Uint8*>(&cmac);
        Uint8*        p_nonce_8 = reinterpret_cast<Uint8*>(&nonce);
        Uint8*        p_temp_8  = reinterpret_cast<Uint8*>(&temp_reg);

        // Load nonce to process
        nonce = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce));

        // No additonal data, so encrypt nonce and set it as cmac
        if (!(flags0 & 0x40)) {
            cmac = nonce;
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(p_key),
                       ccm_data->rounds);
            ccm_data->blocks++;
        } else {
            // Additional data exists so load the cmac (already done in encrypt
            // aad)
            cmac = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac));
        }

        // Set nonce to just length to store size of plain text
        // extracted from flags
        p_nonce_8[0] = q = flags0 & 7;

        // Reconstruct length of plain text
        for (n = 0, i = 15 - q; i < 15; ++i) {
            n |= p_nonce_8[i];
            p_nonce_8[i] = 0;
            n <<= 8;
        }
        n |= p_nonce_8[15]; /* reconstructed length */
        p_nonce_8[15] = 1;

        // Check if input length matches the intialized length
        if (n != len) {
            EXITB();
            return CCM_ERROR::LEN_MISMATCH; /* length mismatch */
        }

        // Check with everything combined we won't have too many blocks to
        // encrypt
        ccm_data->blocks += ((len + 15) >> 3) | 1;
        if (ccm_data->blocks > (Uint64(1) << 61)) {
            EXITB();
            return CCM_ERROR::DATA_OVERFLOW; /* too much data */
        }
        while (len >= 16) {
            // Load the PlainText
            in_reg = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pinp));

            // CBC XOR
            cmac = _mm_xor_si128(cmac, in_reg);

            temp_reg = nonce;
            // CMAC is CBC's encrypt to generate tag, temp_reg is CTR's encrypt
            // to generate CT
            AesEncrypt(&cmac,
                       &temp_reg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            // AES-CTR conter inc and xor.
            CtrInc(&nonce); // Increment counter
            temp_reg = _mm_xor_si128(temp_reg, in_reg);

            // Store CipherText
            _mm_storeu_si128(reinterpret_cast<__m128i*>(pout), temp_reg);

            pinp += 16;
            pout += 16;
            len -= 16;
        }

        if (len) {
            /* CBC */
            // For what ever is left, generate block to encrypt using ctr
            for (i = 0; i < len; ++i)
                p_cmac_8[i] ^= pinp[i];
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            /* CTR */
            temp_reg = nonce;
            AesEncrypt(&temp_reg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            for (i = 0; i < len; ++i)
                pout[i] = p_temp_8[i] ^ pinp[i];
        }

        // Zero out counter part
        for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
            p_nonce_8[i] = 0;

        // CTR encrypt first counter and XOR with the partial tag to generate
        // the real tag
        temp_reg = nonce; // Copy counter
        AesEncrypt(&temp_reg,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        cmac = _mm_xor_si128(temp_reg, cmac);

        // Restore flags into nonce to restore nonce to original state
        p_nonce_8[0] = flags0;

        // Copy the current state of cmac and nonce back to memory.
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac), cmac);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce), nonce);

        // Encryption cannot proceed after this.
        EXITG();
        return CCM_ERROR::NO_ERROR;
    }

    CCM_ERROR Decrypt(ccm_data_t* ccm_data,
                      const Uint8 pinp[],
                      Uint8       pout[],
                      size_t      len)
    {
        // Implementation block diagram
        // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_decryption.png
        ENTER();
        size_t        n;
        unsigned int  i, q;
        unsigned char flags0 = ccm_data->nonce[0];
        const Uint8*  p_key  = ccm_data->key;
        __m128i       cmac, nonce, in_reg, temp_reg;
        Uint8*        p_cmac_8  = reinterpret_cast<Uint8*>(&cmac);
        Uint8*        p_nonce_8 = reinterpret_cast<Uint8*>(&nonce);
        Uint8*        p_temp_8  = reinterpret_cast<Uint8*>(&temp_reg);

        // Load nonce to process
        nonce = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce));

        // No additonal data, so encrypt nonce and set it as cmac
        if (!(flags0 & 0x40)) {
            cmac = nonce;
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(p_key),
                       ccm_data->rounds);
            ccm_data->blocks++;
        } else {
            // Additional data exists so load the cmac (already done in encrypt
            // aad)
            cmac = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac));
        }

        // Set nonce to just length to store size of plain text
        // extracted from flags
        p_nonce_8[0] = q = flags0 & 7;

        // Reconstruct length of plain text
        for (n = 0, i = 15 - q; i < 15; ++i) {
            n |= p_nonce_8[i];
            p_nonce_8[i] = 0;
            n <<= 8;
        }
        n |= p_nonce_8[15]; /* reconstructed length */
        p_nonce_8[15] = 1;

        // Check if input length matches the intialized length
        if (n != len) {
            EXITB();
            return CCM_ERROR::LEN_MISMATCH; /* length mismatch */
        }

#if 1
        while (len >= 32) {
            /* CTR */
            temp_reg = nonce; // Copy Counter
            CtrInc(&nonce);
            __m128i temp_reg_1 = nonce;
            CtrInc(&nonce);
            AesEncrypt(&temp_reg,
                       &temp_reg_1,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            in_reg = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pinp)); // Load CipherText
            temp_reg = _mm_xor_si128(
                in_reg, temp_reg); // Generate PlainText (Complete CTR)
            in_reg = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pinp + 16)); // Load CipherText
            temp_reg_1 = _mm_xor_si128(
                in_reg, temp_reg_1); // Generate PlainText (Complete CTR)

            /* CBC */

            _mm_storeu_si128(reinterpret_cast<__m128i*>(pout),
                             temp_reg); // Store plaintext.
            _mm_storeu_si128(reinterpret_cast<__m128i*>(pout + 16),
                             temp_reg_1); // Store plaintext.

            cmac = _mm_xor_si128(cmac, temp_reg); // Generate Partial result

            // Generate the partial tag, Xor of CBC is above
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            cmac = _mm_xor_si128(cmac, temp_reg_1); // Generate Partial result

            // Generate the partial tag, Xor of CBC is above
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            pinp += 32;
            pout += 32;
            len -= 32;
        }
#endif

        while (len >= 16) {

            /* CTR */
            temp_reg = nonce; // Copy Counter
            AesEncrypt(&temp_reg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            CtrInc(&nonce);

            in_reg = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pinp)); // Load CipherText
            temp_reg = _mm_xor_si128(
                in_reg, temp_reg); // Generate PlainText (Complete CTR)

            /* CBC */
            cmac = _mm_xor_si128(cmac, temp_reg); // Generate Partial result

            _mm_storeu_si128(reinterpret_cast<__m128i*>(pout),
                             temp_reg); // Store plaintext.

            // Generate the partial tag, Xor of CBC is above
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            pinp += 16;
            pout += 16;
            len -= 16;
        }

        if (len) {

            /* CTR */
            temp_reg = nonce; // Copy Counter
            AesEncrypt(&temp_reg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            for (i = 0; i < len; ++i) {
                // CTR XOR operation to generate plaintext
                pout[i] = p_temp_8[i] ^ pinp[i];
                // CBC XOR operation to generate cmac
                p_cmac_8[i] ^= pout[i];
            }

            /* CBC */
            // CBC Xor is above, Encrypt the partial result to create partial
            // tag
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
        }

        // Zero out counter part
        for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
            p_nonce_8[i] = 0;

        // CTR encrypt first counter and XOR with the partial tag to generate
        // the real tag
        temp_reg = nonce;
        AesEncrypt(&temp_reg,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        cmac = _mm_xor_si128(cmac, temp_reg);

        // Restore flags into nonce to restore nonce to original state
        p_nonce_8[0] = flags0;

        // Copy the current state of cmac and nonce back to memory.
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac), cmac);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce), nonce);

        EXITG();
        return CCM_ERROR::NO_ERROR;
    }

}} // namespace alcp::cipher::aesni::ccm
