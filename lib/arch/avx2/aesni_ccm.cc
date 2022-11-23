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

#include <cstdint>
#include <immintrin.h>
#include <string.h>
#include <wmmintrin.h>

#include "cipher/aes.hh"
#include "cipher/aes_ccm.hh"
#include "cipher/aesni.hh"

#include "error.hh"
#include "key.hh"

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
namespace alcp::cipher { namespace aesni {

    void CcmSetAad(ccm_data_p ccm_data, const Uint8* paad, size_t alen)
    {
        ENTER();
        __m128i pBlk0   = { 0 };
        __m128i aad_128 = { 0 };
        Uint8*  pBlk0_8 = reinterpret_cast<Uint8*>(&pBlk0);
        Uint64  i       = 0;

        if (alen == 0) {
            EXITB();
            return;
        }

        ccm_data->nonce[0] |= 0x40; /* set Adata flag */

        pBlk0 =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(ccm_data->nonce));

        // ccm_data->cmac should be inside pBlk0
        AesEncrypt(&pBlk0,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        ccm_data->blocks++;

        if (alen < (0x10000 - 0x100)) {
            // alen < (2^16 - 2^8)
            *(pBlk0_8 + 0) ^= static_cast<Uint8>(alen >> 8);
            *(pBlk0_8 + 1) ^= static_cast<Uint8>(alen);
            i = 2;
        } else if (sizeof(alen) == 8 && alen >= ((size_t)1 << 32)) {
            // alen > what 32 bits can hold.
            *(pBlk0_8 + 0) ^= 0xFF;
            *(pBlk0_8 + 1) ^= 0xFF;
            *(pBlk0_8 + 2) ^= static_cast<Uint8>(alen >> 56);
            *(pBlk0_8 + 3) ^= static_cast<Uint8>(alen >> 48);
            *(pBlk0_8 + 4) ^= static_cast<Uint8>(alen >> 40);
            *(pBlk0_8 + 5) ^= static_cast<Uint8>(alen >> 32);
            *(pBlk0_8 + 6) ^= static_cast<Uint8>(alen >> 24);
            *(pBlk0_8 + 7) ^= static_cast<Uint8>(alen >> 16);
            *(pBlk0_8 + 8) ^= static_cast<Uint8>(alen >> 8);
            *(pBlk0_8 + 9) ^= static_cast<Uint8>(alen);
            i = 10;
        } else {
            // alen is represented by 32 bits but larger than
            // what 16 bits can hold
            *(pBlk0_8 + 0) ^= 0xFF;
            *(pBlk0_8 + 1) ^= 0xFE;
            *(pBlk0_8 + 2) ^= static_cast<Uint8>(alen >> 24);
            *(pBlk0_8 + 3) ^= static_cast<Uint8>(alen >> 16);
            *(pBlk0_8 + 4) ^= static_cast<Uint8>(alen >> 8);
            *(pBlk0_8 + 5) ^= static_cast<Uint8>(alen);
            i = 6;
        }

        // i=2,6,10 to i=16 do the CBC operation
        for (; i < 16 && alen; ++i, ++paad, --alen)
            *(pBlk0_8 + i) ^= *paad;

        AesEncrypt(&pBlk0,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        ccm_data->blocks++;

        Uint64 alen_16 = alen / 16;
        for (Uint64 j = 0; j < alen_16; j++) {
            aad_128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(paad));
            // CBC XOR operation
            pBlk0 = _mm_xor_si128(pBlk0, aad_128);
            // CBC Encrypt operation
            AesEncrypt(&pBlk0,
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
                *(pBlk0_8 + i) ^= *paad;

            // CBC Encrypt last block
            AesEncrypt(&pBlk0,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            ccm_data->blocks++;
        }

        // Store generated partial tag (cmac)
        _mm_store_si128(reinterpret_cast<__m128i*>(ccm_data->cmac), pBlk0);

        EXIT();
    }

    inline void CcmCtrInc(__m128i* ctr)
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

    int CcmEncrypt(ccm_data_p   ccm_data,
                   const Uint8* pinp,
                   Uint8*       pout,
                   size_t       len)
    {
        // Implementation block diagram
        // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_encryption.png
        ENTER();
        size_t        n;
        unsigned int  i, q;
        unsigned char flags0 = ccm_data->nonce[0];
        const Uint8*  pkey   = ccm_data->key;
        __m128i       cmac, nonce, inReg, tempReg;
        Uint8*        pcmac_8  = reinterpret_cast<Uint8*>(&cmac);
        Uint8*        pnonce_8 = reinterpret_cast<Uint8*>(&nonce);
        Uint8*        ptemp_8  = reinterpret_cast<Uint8*>(&tempReg);

        // Load nonce to process
        nonce = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce));

        // No additonal data, so encrypt nonce and set it as cmac
        if (!(flags0 & 0x40)) {
            cmac = nonce;
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(pkey),
                       ccm_data->rounds);
            ccm_data->blocks++;
        } else {
            // Additional data exists so load the cmac (already done in encrypt
            // aad)
            cmac = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac));
        }

        // Set nonce to just length to store size of plain text
        // extracted from flags
        pnonce_8[0] = q = flags0 & 7;

        // Reconstruct length of plain text
        for (n = 0, i = 15 - q; i < 15; ++i) {
            n |= pnonce_8[i];
            pnonce_8[i] = 0;
            n <<= 8;
        }
        n |= pnonce_8[15]; /* reconstructed length */
        pnonce_8[15] = 1;

        // Check if input length matches the intialized length
        if (n != len) {
            EXITB();
            return -1; /* length mismatch */
        }

        // Check with everything combined we won't have too many blocks to
        // encrypt
        ccm_data->blocks += ((len + 15) >> 3) | 1;
        if (ccm_data->blocks > (Uint64(1) << 61)) {
            EXITB();
            return -2; /* too much data */
        }

        while (len >= 16) {
            // Load the PlainText
            inReg = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pinp));

            /* CBC */
            // Generate CMAC given plaintext by using cbc algorithm
            cmac = _mm_xor_si128(cmac, inReg);
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            /* CTR */
            // Generate ciphetext given plain text by using ctr algitrithm
            tempReg = nonce;
            AesEncrypt(&tempReg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            CcmCtrInc(&nonce); // Increment counter
            tempReg = _mm_xor_si128(tempReg, inReg);

            // Store CipherText
            _mm_storeu_si128(reinterpret_cast<__m128i*>(pout), tempReg);

            pinp += 16;
            pout += 16;
            len -= 16;
        }

        if (len) {
            /* CBC */
            // For what ever is left, generate block to encrypt using ctr
            for (i = 0; i < len; ++i)
                pcmac_8[i] ^= pinp[i];
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            /* CTR */
            tempReg = nonce;
            AesEncrypt(&tempReg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            for (i = 0; i < len; ++i)
                pout[i] = ptemp_8[i] ^ pinp[i];
        }

        // Zero out counter part
        for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
            pnonce_8[i] = 0;

        // CTR encrypt first counter and XOR with the partial tag to generate
        // the real tag
        tempReg = nonce; // Copy counter
        AesEncrypt(&tempReg,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        cmac = _mm_xor_si128(tempReg, cmac);

        // Restore flags into nonce to restore nonce to original state
        pnonce_8[0] = flags0;

        // Copy the current state of cmac and nonce back to memory.
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac), cmac);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce), nonce);

        // Encryption cannot proceed after this.
        EXITG();
        return 0;
    }

    int CcmDecrypt(ccm_data_p   ccm_data,
                   const Uint8* pinp,
                   Uint8*       pout,
                   size_t       len)
    {
        // Implementation block diagram
        // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_decryption.png
        ENTER();
        size_t        n;
        unsigned int  i, q;
        unsigned char flags0 = ccm_data->nonce[0];
        const Uint8*  pkey   = ccm_data->key;
        __m128i       cmac, nonce, inReg, tempReg;
        Uint8*        pcmac_8  = reinterpret_cast<Uint8*>(&cmac);
        Uint8*        pnonce_8 = reinterpret_cast<Uint8*>(&nonce);
        Uint8*        ptemp_8  = reinterpret_cast<Uint8*>(&tempReg);

        // Load nonce to process
        nonce = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce));

        // No additonal data, so encrypt nonce and set it as cmac
        if (!(flags0 & 0x40)) {
            cmac = nonce;
            AesEncrypt(&cmac,
                       reinterpret_cast<const __m128i*>(pkey),
                       ccm_data->rounds);
            ccm_data->blocks++;
        } else {
            // Additional data exists so load the cmac (already done in encrypt
            // aad)
            cmac = _mm_loadu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac));
        }

        // Set nonce to just length to store size of plain text
        // extracted from flags
        pnonce_8[0] = q = flags0 & 7;

        // Reconstruct length of plain text
        for (n = 0, i = 15 - q; i < 15; ++i) {
            n |= pnonce_8[i];
            pnonce_8[i] = 0;
            n <<= 8;
        }
        n |= pnonce_8[15]; /* reconstructed length */
        pnonce_8[15] = 1;

        // Check if input length matches the intialized length
        if (n != len) {
            EXITB();
            return -1; /* length mismatch */
        }

        while (len >= 16) {

            /* CTR */
            tempReg = nonce; // Copy Counter
            AesEncrypt(&tempReg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            CcmCtrInc(&nonce);

            inReg = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pinp)); // Load CipherText
            tempReg = _mm_xor_si128(
                inReg, tempReg); // Generate PlainText (Complete CTR)

            /* CBC */
            cmac = _mm_xor_si128(cmac, tempReg); // Generate Partial result

            _mm_storeu_si128(reinterpret_cast<__m128i*>(pout),
                             tempReg); // Store plaintext.

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
            tempReg = nonce; // Copy Counter
            AesEncrypt(&tempReg,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);

            for (i = 0; i < len; ++i) {
                // CTR XOR operation to generate plaintext
                pout[i] = ptemp_8[i] ^ pinp[i];
                // CBC XOR operation to generate cmac
                pcmac_8[i] ^= pout[i];
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
            pnonce_8[i] = 0;

        // CTR encrypt first counter and XOR with the partial tag to generate
        // the real tag
        tempReg = nonce;
        AesEncrypt(&tempReg,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        cmac = _mm_xor_si128(cmac, tempReg);

        // Restore flags into nonce to restore nonce to original state
        pnonce_8[0] = flags0;

        // Copy the current state of cmac and nonce back to memory.
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->cmac), cmac);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ccm_data->nonce), nonce);

        EXITG();
        return 0;
    }

}} // namespace alcp::cipher::aesni
