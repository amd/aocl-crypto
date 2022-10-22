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
/*
 * First you setup M and L parameters and pass the key schedule. This is
 * called once per session setup...
 */

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

// TODO: Debug Stuff Needs to be removed at the end.
char*
bytesToHexString(const unsigned char* bytes, int length)
{
    char* outputHexString = (char*)malloc(sizeof(char) * ((length * 2) + 1));
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            switch (chararray[j]) {
                case 0x0:
                    chararray[j] = '0';
                    break;
                case 0x1:
                    chararray[j] = '1';
                    break;
                case 0x2:
                    chararray[j] = '2';
                    break;
                case 0x3:
                    chararray[j] = '3';
                    break;
                case 0x4:
                    chararray[j] = '4';
                    break;
                case 0x5:
                    chararray[j] = '5';
                    break;
                case 0x6:
                    chararray[j] = '6';
                    break;
                case 0x7:
                    chararray[j] = '7';
                    break;
                case 0x8:
                    chararray[j] = '8';
                    break;
                case 0x9:
                    chararray[j] = '9';
                    break;
                case 0xa:
                    chararray[j] = 'a';
                    break;
                case 0xb:
                    chararray[j] = 'b';
                    break;
                case 0xc:
                    chararray[j] = 'c';
                    break;
                case 0xd:
                    chararray[j] = 'd';
                    break;
                case 0xe:
                    chararray[j] = 'e';
                    break;
                case 0xf:
                    chararray[j] = 'f';
                    break;
                default:
                    printf("%x %d\n", chararray[j], j);
            }
            outputHexString[i * 2 + j] = chararray[j];
        }
    }
    outputHexString[length * 2] = 0x0;
    return outputHexString;
}

char*
bytesToHexString(Uint8* bytes, int length)
{
    char* outputHexString = (char*)malloc(sizeof(char) * ((length * 2) + 1));
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            switch (chararray[j]) {
                case 0x0:
                    chararray[j] = '0';
                    break;
                case 0x1:
                    chararray[j] = '1';
                    break;
                case 0x2:
                    chararray[j] = '2';
                    break;
                case 0x3:
                    chararray[j] = '3';
                    break;
                case 0x4:
                    chararray[j] = '4';
                    break;
                case 0x5:
                    chararray[j] = '5';
                    break;
                case 0x6:
                    chararray[j] = '6';
                    break;
                case 0x7:
                    chararray[j] = '7';
                    break;
                case 0x8:
                    chararray[j] = '8';
                    break;
                case 0x9:
                    chararray[j] = '9';
                    break;
                case 0xa:
                    chararray[j] = 'a';
                    break;
                case 0xb:
                    chararray[j] = 'b';
                    break;
                case 0xc:
                    chararray[j] = 'c';
                    break;
                case 0xd:
                    chararray[j] = 'd';
                    break;
                case 0xe:
                    chararray[j] = 'e';
                    break;
                case 0xf:
                    chararray[j] = 'f';
                    break;
                default:
                    printf("%x %d\n", chararray[j], j);
            }
            outputHexString[i * 2 + j] = chararray[j];
        }
    }
    outputHexString[length * 2] = 0x0;
    return outputHexString;
}

namespace alcp::cipher { namespace aesni {
    void CcmInit(ccm_data_p ccm_data, unsigned int t, unsigned int q)
    {
        ENTER();
        memset(ccm_data->nonce, 0, sizeof(ccm_data->nonce));
        ccm_data->nonce[0] =
            ((Uint8)(q - 1) & 7) | (Uint8)(((t - 2) / 2) & 7) << 3;
        ccm_data->blocks = 0;
        EXIT();
    }

    int CcmSetIv(ccm_data_p   ccm_data,
                 const Uint8* nonce,
                 size_t       nlen,
                 size_t       mlen)
    {
        ENTER();
        unsigned int q = ccm_data->nonce[0] & 7; /* the L parameter */

        if (nlen < (14 - q)) {
            EXITB();
            return -1; /* nonce is too short */
        }
        if (sizeof(mlen) == 8 && q >= 3) {
            ccm_data->nonce[8]  = (Uint8)(mlen >> (56 % (sizeof(mlen) * 8)));
            ccm_data->nonce[9]  = (Uint8)(mlen >> (48 % (sizeof(mlen) * 8)));
            ccm_data->nonce[10] = (Uint8)(mlen >> (40 % (sizeof(mlen) * 8)));
            ccm_data->nonce[11] = (Uint8)(mlen >> (32 % (sizeof(mlen) * 8)));
        } else {
            memset(ccm_data->nonce + 8, 0, 8);
            // ccm_data->nonce.u[1] = 0;
        }

        ccm_data->nonce[12] = (Uint8)(mlen >> 24);
        ccm_data->nonce[13] = (Uint8)(mlen >> 16);
        ccm_data->nonce[14] = (Uint8)(mlen >> 8);
        ccm_data->nonce[15] = (Uint8)mlen;

        ccm_data->nonce[0] &= ~0x40; /* clear Adata flag */
        memcpy(&ccm_data->nonce[1], nonce, 14 - q);
        EXITG();
        return 0;
    }

    void CcmSetAad(ccm_data_p ccm_data, const Uint8* aad, size_t alen)
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
        } else if (sizeof(alen) == 8 && alen >= (size_t)1 << (32 % 64)) {
            // alen > what 32 bits can hold.
            *(pBlk0_8 + 0) ^= 0xFF;
            *(pBlk0_8 + 1) ^= 0xFF;
            *(pBlk0_8 + 2) ^= static_cast<Uint8>(alen >> (56 % 64));
            *(pBlk0_8 + 3) ^= static_cast<Uint8>(alen >> (48 % 64));
            *(pBlk0_8 + 4) ^= static_cast<Uint8>(alen >> (40 % 64));
            *(pBlk0_8 + 5) ^= static_cast<Uint8>(alen >> (32 % 64));
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
        for (; i < 16 && alen; ++i, ++aad, --alen)
            *(pBlk0_8 + i) ^= *aad;

        AesEncrypt(&pBlk0,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        ccm_data->blocks++;

        Uint64 alen_16 = alen / 16;
        for (Uint64 j = 0; j < alen_16; j++) {
            aad_128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(aad));
            // CBC XOR operation
            pBlk0 = _mm_xor_si128(pBlk0, aad_128);
            // CBC Encrypt operation
            AesEncrypt(&pBlk0,
                       reinterpret_cast<const __m128i*>(ccm_data->key),
                       ccm_data->rounds);
            ccm_data->blocks++;
            aad += 16;
        }

        // Reduce already processed value from alen
        alen -= alen_16 * 16;

        // Process the rest in default way
        for (i = 0; i < 16 && alen; i++, aad++, alen--)
            *(pBlk0_8 + i) ^= *aad;

        // CBC Encrypt last block
        AesEncrypt(&pBlk0,
                   reinterpret_cast<const __m128i*>(ccm_data->key),
                   ccm_data->rounds);
        ccm_data->blocks++;

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
                   const Uint8* inp,
                   Uint8*       out,
                   size_t       len)
    {
        // Implementation block diagram
        // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_encryption.png
        ENTER();
        size_t        n;
        unsigned int  i, q;
        unsigned char flags0 = ccm_data->nonce[0];
        const Uint8*  key    = ccm_data->key;
        __m128i       cmac, nonce, inReg, tempReg;
        Uint8*        cmac_8  = reinterpret_cast<Uint8*>(&cmac);
        Uint8*        nonce_8 = reinterpret_cast<Uint8*>(&nonce);
        Uint8*        temp_8  = reinterpret_cast<Uint8*>(&tempReg);

        // Load nonce to process
        nonce = _mm_loadu_si128((const __m128i*)ccm_data->nonce);

        // No additonal data, so encrypt nonce and set it as cmac
        if (!(flags0 & 0x40)) {
            cmac = nonce;
            AesEncrypt(&cmac, (const __m128i*)key, ccm_data->rounds);
            ccm_data->blocks++;
        } else {
            // Additional data exists so load the cmac (already done in encrypt
            // aad)
            cmac = _mm_loadu_si128((const __m128i*)ccm_data->cmac);
        }

        // Set nonce to just length to store size of plain text
        // extracted from flags
        nonce_8[0] = q = flags0 & 7;

        // Reconstruct length of plain text
        for (n = 0, i = 15 - q; i < 15; ++i) {
            n |= nonce_8[i];
            nonce_8[i] = 0;
            n <<= 8;
        }
        n |= nonce_8[15]; /* reconstructed length */
        nonce_8[15] = 1;

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
            inReg = _mm_loadu_si128((__m128i*)inp);

            /* CBC */
            // Generate CMAC given plaintext by using cbc algorithm
            cmac = _mm_xor_si128(cmac, inReg);
            AesEncrypt(&cmac, (const __m128i*)ccm_data->key, ccm_data->rounds);

            /* CTR */
            // Generate ciphetext given plain text by using ctr algitrithm
            tempReg = nonce;
            AesEncrypt(
                &tempReg, (const __m128i*)ccm_data->key, ccm_data->rounds);
            CcmCtrInc(&nonce); // Increment counter
            tempReg = _mm_xor_si128(tempReg, inReg);

            // Store CipherText
            _mm_storeu_si128((__m128i*)(out), tempReg);

            inp += 16;
            out += 16;
            len -= 16;
        }

        if (len) {

            /* CBC */
            // For what ever is left, generate block to encrypt using ctr
            for (i = 0; i < len; ++i)
                cmac_8[i] ^= inp[i];
            AesEncrypt(&cmac, (const __m128i*)ccm_data->key, ccm_data->rounds);

            /* CTR */
            tempReg = nonce;
            AesEncrypt(
                &tempReg, (const __m128i*)ccm_data->key, ccm_data->rounds);
            for (i = 0; i < len; ++i)
                out[i] = temp_8[i] ^ inp[i];
        }

        // Zero out counter part
        for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
            nonce_8[i] = 0;

        // CTR encrypt first counter and XOR with the partial tag to generate
        // the real tag
        tempReg = nonce; // Copy counter
        AesEncrypt(&tempReg, (const __m128i*)ccm_data->key, ccm_data->rounds);
        cmac = _mm_xor_si128(tempReg, cmac);

        // Restore flags into nonce to restore nonce to original state
        nonce_8[0] = flags0;

        // Copy the current state of cmac and nonce back to memory.
        memcpy(ccm_data->cmac, &cmac, 128 / 8);
        memcpy(ccm_data->nonce, &nonce, 128 / 8);

        // Encryption cannot proceed after this.
        EXITG();
        return 0;
    }

    int CcmDecrypt(ccm_data_p   ccm_data,
                   const Uint8* inp,
                   Uint8*       out,
                   size_t       len)
    {
        // Implementation block diagram
        // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_decryption.png
        ENTER();
        size_t        n;
        unsigned int  i, q;
        unsigned char flags0 = ccm_data->nonce[0];
        const Uint8*  key    = ccm_data->key;
        __m128i       cmac, nonce, inReg, tempReg;
        Uint8*        cmac_8  = reinterpret_cast<Uint8*>(&cmac);
        Uint8*        nonce_8 = reinterpret_cast<Uint8*>(&nonce);
        Uint8*        temp_8  = reinterpret_cast<Uint8*>(&tempReg);

        // Load nonce to process
        nonce = _mm_loadu_si128((const __m128i*)ccm_data->nonce);

        // No additonal data, so encrypt nonce and set it as cmac
        if (!(flags0 & 0x40)) {
            cmac = nonce;
            AesEncrypt(&cmac, (const __m128i*)key, ccm_data->rounds);
            ccm_data->blocks++;
        } else {
            // Additional data exists so load the cmac (already done in encrypt
            // aad)
            cmac = _mm_loadu_si128((const __m128i*)ccm_data->cmac);
        }

        // Set nonce to just length to store size of plain text
        // extracted from flags
        nonce_8[0] = q = flags0 & 7;

        // Reconstruct length of plain text
        for (n = 0, i = 15 - q; i < 15; ++i) {
            n |= nonce_8[i];
            nonce_8[i] = 0;
            n <<= 8;
        }
        n |= nonce_8[15]; /* reconstructed length */
        nonce_8[15] = 1;

        // Check if input length matches the intialized length
        if (n != len) {
            EXITB();
            return -1; /* length mismatch */
        }

        while (len >= 16) {

            /* CTR */
            tempReg = nonce; // Copy Counter
            AesEncrypt(
                &tempReg, (const __m128i*)ccm_data->key, ccm_data->rounds);
            CcmCtrInc(&nonce);

            inReg   = _mm_loadu_si128((__m128i*)inp); // Load CipherText
            tempReg = _mm_xor_si128(
                inReg, tempReg); // Generate PlainText (Complete CTR)

            /* CBC */
            cmac = _mm_xor_si128(cmac, tempReg); // Generate Partial result

            _mm_storeu_si128((__m128i*)out, tempReg); // Store plaintext.

            // Generate the partial tag, Xor of CBC is above
            AesEncrypt(&cmac, (const __m128i*)ccm_data->key, ccm_data->rounds);

            inp += 16;
            out += 16;
            len -= 16;
        }

        if (len) {

            /* CTR */
            tempReg = nonce; // Copy Counter
            AesEncrypt(
                &tempReg, (const __m128i*)ccm_data->key, ccm_data->rounds);

            for (i = 0; i < len; ++i) {
                // CTR XOR operation to generate plaintext
                out[i] = temp_8[i] ^ inp[i];
                // CBC XOR operation to generate cmac
                cmac_8[i] ^= out[i];
            }

            /* CBC */
            // CBC Xor is above, Encrypt the partial result to create partial
            // tag
            AesEncrypt(&cmac, (const __m128i*)ccm_data->key, ccm_data->rounds);
        }

        // Zero out counter part
        for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
            nonce_8[i] = 0;

        // CTR encrypt first counter and XOR with the partial tag to generate
        // the real tag
        tempReg = nonce;
        AesEncrypt(&tempReg, (const __m128i*)ccm_data->key, ccm_data->rounds);
        cmac = _mm_xor_si128(cmac, tempReg);

        // Restore flags into nonce to restore nonce to original state
        nonce_8[0] = flags0;

        // Copy the current state of cmac and nonce back to memory.
        memcpy(ccm_data->cmac, &cmac, 128 / 8);
        memcpy(ccm_data->nonce, &nonce, 128 / 8);

        EXITG();
        return 0;
    }

    size_t CcmGetTag(ccm_data_p ctx, Uint8* tag, size_t len)
    {
        ENTER();
        unsigned int t = (ctx->nonce[0] >> 3) & 7; /* the M parameter */

        t *= 2;
        t += 2;
        if (len != t) {
            EXITB();
            return 0;
        }
        memcpy(tag, ctx->cmac, t);
        EXITG();
        return t;
    }

}} // namespace alcp::cipher::aesni