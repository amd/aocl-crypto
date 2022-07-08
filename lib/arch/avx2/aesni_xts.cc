/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include <sstream>
#include <string.h>

#include "cipher/aesni.hh"
#include "error.hh"

#define DEBUG_P  1
#define trace(x) std::cout << #x << " : " << std::endl;
#ifdef DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("\n %s", S);                                                        \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %2x", I[x]);                                                  \
    }                                                                          \
    printf("\n");
#else // DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)
#endif // DEBUG_P

namespace alcp::cipher { namespace aesni {
    std::string parseBytesToHexStr(const uint8_t* bytes, const int length)
    {
        std::stringstream ss;
        for (int i = 0; i < length; i++) {
            int               charRep;
            std::stringstream il;
            charRep = bytes[i];
            // Convert int to hex
            il << std::hex << charRep;
            std::string ilStr = il.str();
            // 01 will be 0x1 so we need to make it 0x01
            if (ilStr.size() != 2) {
                ilStr = "0" + ilStr;
            }
            ss << ilStr;
        }
        return ss.str();
    }

    static void carrylessMul(__m128i a, __m128i b, __m128i* c, __m128i* d)
    {
        __m128i e, f;
        /* carryless multiplication of a1:a0 * b1:b0 */
        *c = _mm_clmulepi64_si128(a, b, 0x00); // C1:C0 = a0*b0
        *d = _mm_clmulepi64_si128(a, b, 0x11); // D1:D0 = a1*b1
        e  = _mm_clmulepi64_si128(a, b, 0x10); // E1:E0 = a0*b1
        f  = _mm_clmulepi64_si128(a, b, 0x01); // F1:F0 = a1*b0
        /*
         * compute D1  :  D0+E1+F1 : C1+E0+F0: C0
         */
        e = _mm_xor_si128(e, f);  // E1+F1 : E0+F0
        f = _mm_slli_si128(e, 8); // E0+F0:0
        e = _mm_srli_si128(e, 8); // 0:E1+F1

        /* d : c = D1 : D0+E1+F1 : C1+E0+F0 : C0 */
        *c = _mm_xor_si128(*c, f); // C1+(E0+F0):C0
        *d = _mm_xor_si128(*d, e); // D1:D0+(E1+F1)
    }

    /*
     Modulo Reduction of 256bit to 128bit
     Modulo reduction algorithm 5 in "Intel carry-less multiplication
     instruction in gcm mode" paper is used.
    */
    static void redMod(__m128i x10, __m128i x32, __m128i* res)
    {
        __m128i a, b, c, d, e, f, g;

        /* shifting x10 and x32 left by 1 */
        a = _mm_slli_epi64(x10, 1);  //(x1:x0)<<1
        c = _mm_srli_epi64(x10, 63); //(x1:x0)>>63

        b = _mm_slli_epi64(x32, 1);  //(x3:x2)<<1
        d = _mm_srli_epi64(x32, 63); //(x3:x2)>>63

        e = _mm_slli_si128(c, 8); // x0>>63 : 0
        f = _mm_srli_si128(c, 8); //     0 : x1>>63
        g = _mm_slli_si128(d, 8); // x2>>63 : 0

        x10 = _mm_or_si128(e, a);   // (x0>>63|x1<<1 ) : (0|x0<<1)
        x32 = _mm_or_si128(g, b);   // (x3<<1 |x2>>63) : (x2<<1)
        x32 = _mm_or_si128(f, x32); // (x3<<1 |x2>>63) : (x2<<1 | x1>>63)

        /* compute A, B and C */
        a = _mm_slli_epi64(x10, 63); //*:x0<<63
        b = _mm_slli_epi64(x10, 62); //*:x0<<62
        c = _mm_slli_epi64(x10, 57); //*:x0<<57

        /* compute D = a⊕b⊕c */
        a = _mm_xor_si128(a, b);  //       *:a⊕b
        a = _mm_xor_si128(a, c);  //       *:a⊕b⊕c
        a = _mm_slli_si128(a, 8); // a⊕b⊕c:0

        /* compute d:x0 */
        d = _mm_xor_si128(x10, a); // x1 ⊕ (a⊕b⊕c) : x0 ⊕ 0

        /* e1:e0, f1:f0, g1:g0 */
        // e1:e0
        a = _mm_srli_epi64(d, 1);  // d:x0>>1
        e = _mm_slli_epi64(d, 63); // d:x0<<63
        // f1:f0
        b = _mm_srli_epi64(d, 2);  // d:x0>>2
        f = _mm_slli_epi64(d, 62); // d:x0<<62
        // g1:g0
        c = _mm_srli_epi64(d, 7);  // d:x0>>7
        g = _mm_slli_epi64(d, 57); // d:x0>>57

        /* compute Part1 of  e1⊕f1⊕g1 : e0⊕f0⊕g0 */
        a = _mm_xor_si128(b, a); // e1⊕f1    : e0⊕f0
        a = _mm_xor_si128(c, a); // e1⊕f1⊕g1 : e0⊕f0⊕g0

        /* compute Part2 of  e1⊕f1⊕g1 : e0⊕f0⊕g0 */
        e = _mm_xor_si128(e, f); // e1⊕f1    : e0⊕f0
        e = _mm_xor_si128(e, g); // e1⊕f1⊕g1 : e0⊕f0⊕g0
        e = _mm_srli_si128(e, 8);

        /* combine part1 and part2 */
        a = _mm_xor_si128(e, a); // part1 ⊕ part2

        /* compute H1:H0 */
        a = _mm_xor_si128(d, a); // H1:H0 = d⊕e1⊕f1⊕g1 : x0⊕e0⊕f0⊕g0

        /* X3⊕H1: X2⊕H0 */
        *res = _mm_xor_si128(x32, a);
    }

    static void gMul(__m128i a, __m128i b, __m128i* res)
    {
        __m128i c, d;
        carrylessMul(a, b, &c, &d);
        redMod(c, d, res);
    }

    static void pprint(__m128i x)
    {
        uint32_t* val = (uint32_t*)&x;
        printf("%x %x %x %x", val[0], val[1], val[2], val[3]);
        // std::cout << std::hex << val[0] <<" "<< val[1] <<" "<<val[2]<<"
        // "<<val[3]<<" ";
    }

    // void encryptLastTwoRound(const __m128i* pSrc,const __m128i* pDest, ){

    // }

    static void ppText(__m128i x)
    {
        printf("\n");
        uint16_t* z = (uint16_t*)&x;
        for (int i = 0; i < 8; i++) {
            printf("%2x ", ((z[i])));
        }
        printf("\n");
    }

    static void ppText2(const uint8_t* x)
    {
        trace(x);
        for (int i = 0; i < 16; i++) {
            printf("%2x ", ((x[i])));
        }
        printf("\n");
    }

    alc_error_t EncryptXts(const uint8_t* pSrc,
                           uint8_t*       pDest,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
        auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
        auto p_src128       = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128      = reinterpret_cast<__m128i*>(pDest);
        // pprint(p_src128[0]);
        __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);
        // ppText2(pIv);
        // ppText(iv128);
        ppText(p_src128[0]);
        uint64_t blocks          = len / Rijndael::cBlockSize;
        int      last_Round_Byte = len % Rijndael::cBlockSize;
        printf("No of blocks %d and bytes left %d\n", blocks, last_Round_Byte);

        __m128i alpha = _mm_cvtsi32_si128(
            2); // primitive Element for galois Field (2 ^ 128)
        __m128i current_alpha = _mm_cvtsi32_si128(2);
        while (blocks > 2 || (blocks > 1 && (last_Round_Byte > 0))) {
            // printf("encrypting blocks\n");
            __m128i blk0 = iv128;
            ALCP_PRINT_TEXT(pTweakKey, 16, "TweakKey :\n");
            aesni::AesEncrypt(&blk0, p_tweak_key128, nRounds);
            // ppText(iv128);
            // printf(" first tweak pata kar raha he");
            // ppText(blk0);
            __m128i TweakValue = _mm_cvtsi32_si128(0);
            gMul(current_alpha, blk0, &TweakValue);
            uint8_t* t = (uint8_t*)&TweakValue;
            ALCP_PRINT_TEXT(t, 16, "TweakValue :\n");
            // ppText(p_src128[0]);
            __m128i tweaked_src_text = _mm_xor_si128(TweakValue, p_src128[0]);
            // ppText(tweaked_src_text);
            AesEncrypt(&tweaked_src_text, p_key128, nRounds);
            // ppText(tweaked_src_text);
            // ppText(TweakValue);
            __m128i newTweak = _mm_xor_si128(tweaked_src_text, TweakValue);
            // ppText(newTweak);
            _mm_storeu_si128(&p_dest128[0], newTweak);
            // ALCP_PRINT_TEXT(
            //     (uint8_t*)p_dest128[0], sizeof(p_dest128), "blockchiper :");
            p_dest128++;
            p_src128++;
            __m128i new_alpha = _mm_cvtsi32_si128(0);
            gMul(current_alpha, alpha, &new_alpha);
            current_alpha = new_alpha;
            blocks--;
        }
        // if (blocks == 1 && (last_Round_Byte == 0)) {
        //     __m128i blk0 = iv128;
        //     AesEncrypt(&blk0, p_tweak_key128, nRounds);
        //     __m128i TweakValue = _mm_cvtsi32_si128(0);
        //     gMul(current_alpha, blk0, &TweakValue);

        //     __m128i tweaked_src_text = _mm_xor_si128(TweakValue,
        //     p_src128[0]); AesEncrypt(&tweaked_src_text, p_key128, nRounds);
        //     tweaked_src_text = _mm_xor_si128(TweakValue, tweaked_src_text);

        //     _mm_storeu_si128(&p_dest128[0], tweaked_src_text);
        //     return ALC_ERROR_NONE;
        // }
        // ALCP_PRINT_TEXT((uint8_t*)&pp_dest, len, "mid chiper :");
        printf("No of blocks %d and bytes left %d\n", blocks, last_Round_Byte);
        __m128i blk0 = iv128;
        AesEncrypt(&blk0, p_tweak_key128, nRounds);
        __m128i TweakValue = _mm_cvtsi32_si128(0);
        gMul(current_alpha, blk0, &TweakValue);
        uint8_t* t = (uint8_t*)&TweakValue;
        ALCP_PRINT_TEXT(t, 16, "TweakValue :\n");
        __m128i tweaked_src_text = _mm_xor_si128(TweakValue, p_src128[0]);
        AesEncrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(TweakValue, tweaked_src_text);
        uint8_t* a       = (uint8_t*)&tweaked_src_text;
        __m128i  b       = _mm_set1_epi8(0);
        // if (last_Round_Byte != 0)
        memcpy((uint8_t*)&b, a, last_Round_Byte);
        // ALCP_PRINT_TEXT((uint8_t*)&b, 16, "b :");
        // std::cout << parseBytesToHexStr((uint8_t*)(&b), 16) << std::endl;
        // ppText(b);
        // printf(" b was printed here \n");
        // printf(" size done \n");
        p_src128++;
        __m128i new_alpha = _mm_cvtsi32_si128(0);
        gMul(current_alpha, alpha, &new_alpha);
        current_alpha = new_alpha;
        __m128i temp  = p_src128[0];
        // std::cout << " temp :  " << parseBytesToHexStr((uint8_t*)(&temp), 16)
        //           << std::endl;
        // if (last_Round_Byte != 0)
        memcpy((uint8_t*)&temp + last_Round_Byte,
               a + last_Round_Byte,
               16 - last_Round_Byte);
        // std::cout << " temp :  " << parseBytesToHexStr((uint8_t*)(&temp), 16)
        //           << std::endl;
        // cout << p_src128[0]<<"\n";
        blk0 = iv128;
        AesEncrypt(&blk0, p_tweak_key128, nRounds);
        TweakValue = _mm_cvtsi32_si128(0);
        gMul(current_alpha, blk0, &TweakValue);
        tweaked_src_text = _mm_xor_si128(TweakValue, temp);
        AesEncrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(TweakValue, tweaked_src_text);
        _mm_storeu_si128(&p_dest128[0], tweaked_src_text);
        // std::cout << " pdest0 " << parseBytesToHexStr((uint8_t*)(p_dest128),
        // 16)
        //           << std::endl;
        p_dest128++;
        memcpy(((uint8_t*)&p_dest128[0]), (uint8_t*)&b, last_Round_Byte);
        // std::cout << " pdest1 " << parseBytesToHexStr((uint8_t*)(p_dest128),
        // 16)
        //           << std::endl;
        // _mm_storeu_si128(, b);
        // std::cout << "\nencrypt : ";
        // pprint(p_dest[0]);
        return ALC_ERROR_NONE;
    }

    alc_error_t DecryptXts(const uint8_t* pSrc,
                           uint8_t*       pDest,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
        auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
        auto p_src128       = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128      = reinterpret_cast<__m128i*>(pDest);
        // pprint(p_src128[0]);
        __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);
        // ppText2(pIv);
        // ppText(iv128);
        // ppText(p_src128[0]);
        uint64_t blocks          = len / Rijndael::cBlockSize;
        int      last_Round_Byte = len % Rijndael::cBlockSize;
        printf("No of blocks %d and bytes left %d\n", blocks, last_Round_Byte);

        __m128i alpha = _mm_cvtsi32_si128(
            2); // primitive Element for galois Field (2 ^ 128)
        __m128i current_alpha = _mm_cvtsi32_si128(2);
        while (blocks > 2 || (blocks > 1 && (last_Round_Byte > 0))) {
            // printf("encrypting blocks\n");
            __m128i blk0 = iv128;
            AesEncrypt(&blk0, p_tweak_key128, nRounds);
            // ppText(iv128);
            // ppText(blk0);
            __m128i TweakValue = _mm_cvtsi32_si128(0);
            gMul(current_alpha, blk0, &TweakValue);
            // ppText(p_src128[0]);
            __m128i tweaked_src_text = _mm_xor_si128(TweakValue, p_src128[0]);
            // ppText(tweaked_src_text);
            AesDecrypt(&tweaked_src_text, p_key128, nRounds);
            // ppText(tweaked_src_text);
            // ppText(TweakValue);
            __m128i newTweak = _mm_xor_si128(tweaked_src_text, TweakValue);
            // ppText(newTweak);
            _mm_storeu_si128(&p_dest128[0], newTweak);
            // ALCP_PRINT_TEXT(
            //     (uint8_t*)p_dest128[0], sizeof(p_dest128), "blockchiper :");
            p_dest128++;
            p_src128++;
            __m128i new_alpha = _mm_cvtsi32_si128(0);
            gMul(current_alpha, alpha, &new_alpha);
            current_alpha = new_alpha;
            blocks--;
        }
        // if (blocks == 1 && (last_Round_Byte == 0)) {
        //     __m128i blk0 = iv128;
        //     AesEncrypt(&blk0, p_tweak_key128, nRounds);
        //     __m128i TweakValue = _mm_cvtsi32_si128(0);
        //     gMul(current_alpha, blk0, &TweakValue);

        //     __m128i tweaked_src_text = _mm_xor_si128(TweakValue,
        //     p_src128[0]); AesDecrypt(&tweaked_src_text, p_key128, nRounds);
        //     tweaked_src_text = _mm_xor_si128(TweakValue, tweaked_src_text);

        //     _mm_storeu_si128(&p_dest128[0], tweaked_src_text);
        //     return ALC_ERROR_NONE;
        // }
        // ALCP_PRINT_TEXT((uint8_t*)&pp_dest, len, "mid chiper :");
        printf("No of blocks %d and bytes left %d\n", blocks, last_Round_Byte);
        __m128i blk0 = iv128;
        AesEncrypt(&blk0, p_tweak_key128, nRounds);
        __m128i TweakValue = _mm_cvtsi32_si128(0);
        __m128i new_alpha  = _mm_cvtsi32_si128(0);
        gMul(current_alpha, alpha, &new_alpha);
        gMul(new_alpha, blk0, &TweakValue);
        // std::cout << " psrc0 " << parseBytesToHexStr((uint8_t*)(p_src128),
        // 16)
        //           << std::endl;
        __m128i tweaked_src_text = _mm_xor_si128(TweakValue, p_src128[0]);
        AesDecrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(TweakValue, tweaked_src_text);
        uint8_t* a       = (uint8_t*)&tweaked_src_text;
        __m128i  b       = _mm_set1_epi8(0);

        // if (last_Round_Byte != 0)
        memcpy((uint8_t*)&b, a, last_Round_Byte);
        // ALCP_PRINT_TEXT((uint8_t*)&b, 16, "b :");
        // std::cout << parseBytesToHexStr((uint8_t*)(&b), 16) << std::endl;
        // ppText(b);
        // printf(" b was printed here \n");
        // printf(" size done \n");
        p_src128++;

        // current_alpha = new_alpha;
        __m128i temp = p_src128[0];
        // std::cout << " psrc1 :  " << parseBytesToHexStr((uint8_t*)(&temp),
        // 16)
        //           << std::endl;
        // if (last_Round_Byte != 0)
        memcpy((uint8_t*)&temp + last_Round_Byte,
               a + last_Round_Byte,
               16 - last_Round_Byte);
        // std::cout << " temp :  " << parseBytesToHexStr((uint8_t*)(&temp), 16)
        //           << std::endl;
        // cout << p_src128[0]<<"\n";
        blk0 = iv128;
        AesEncrypt(&blk0, p_tweak_key128, nRounds);
        TweakValue = _mm_cvtsi32_si128(0);
        gMul(current_alpha, blk0, &TweakValue);
        tweaked_src_text = _mm_xor_si128(TweakValue, temp);
        AesDecrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(TweakValue, tweaked_src_text);
        _mm_storeu_si128(&p_dest128[0], tweaked_src_text);
        p_dest128++;
        memcpy(((uint8_t*)&p_dest128[0]), (uint8_t*)&b, last_Round_Byte);

        // _mm_storeu_si128(, b);
        // std::cout << "\nencrypt : ";
        // pprint(p_dest[0]);
        return ALC_ERROR_NONE;
    }

}} // namespace alcp::cipher::aesni
