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

#include <immintrin.h>

#include "alcp/error.h"

#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "cipher/vaes.hh"

#include "utils/copy.hh"

namespace alcp::cipher {

uint8_t
__sbox(uint8_t offset, bool use_invsbox = false)
{
    static const uint8_t sBox[] = {
        /* 0   1     2     3     4      5     6    7 */
        /* 8   9     10    11    12    13    14    15  */
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, /*0*/
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, /*1*/
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, /*2*/
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, /*3*/
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, /*4*/
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, /*5*/
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, /*6*/
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, /*7*/
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, /*8*/
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, /*9*/
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, /*a*/
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, /*b*/
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, /*c*/
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, /*d*/
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, /*e*/
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 /*f*/
    };

    static const uint8_t invsBox[257] = {
        /*
         0     1     2     3     4     5     6     7
         8     9     a     b     c     d     e     f
         */
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, /*0*/
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, /*1*/
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, /*2*/
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, /*3*/
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, /*4*/
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, /*5*/
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, /*6*/
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, /*7*/
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, /*8*/
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, /*9*/
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, /*a*/
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, /*b*/
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, /*c*/
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, /*d*/
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, /*e*/
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d /*f*/
    };

    if (use_invsbox)
        return invsBox[offset];

    return sBox[offset];
}

static inline uint8_t
__ffmul(uint8_t a, uint8_t b)
{
    uint8_t bw[4];
    uint8_t res = 0;

    bw[0] = b;

    for (int i = 1; i < 4; i++) {
        bw[i] = bw[i - 1] << 1;
        if (bw[i - 1] & 0x80) {
            bw[i] ^= 0x1b;
        }
    }

    for (int i = 0; i < 4; i++) {
        if ((a >> i) & 0x01) {
            res ^= bw[i];
        }
    }

    return res;
}

void
Rijndael::subBytes(uint8_t state[][4]) noexcept
{
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = __sbox(state[r][c]);
        }
    }
}

void
Rijndael::shiftRows(uint8_t state[][4]) noexcept
{
    uint8_t t[4];
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            t[c] = state[r][(c + r) % 4];
        }
        for (int c = 0; c < 4; c++) {
            state[r][c] = t[c];
        }
    }
}

#define BYTE0_TO_WORD(x) utils::BytesToWord<uint8_t>((x), 0, 0, 0)
// clang-format off
/*
 * FIPS-197 Section 4.2
 * s_round_constants[] contains
 * [x**(i),{00},{00},{00}], i=0,..,10 GF(256)
 */
static const uint32_t s_round_constants[] = {
    BYTE0_TO_WORD(0x01), BYTE0_TO_WORD(0x02), BYTE0_TO_WORD(0x04), BYTE0_TO_WORD(0x08),
    BYTE0_TO_WORD(0x10), BYTE0_TO_WORD(0x20), BYTE0_TO_WORD(0x40), BYTE0_TO_WORD(0x80),
    BYTE0_TO_WORD(0x1B), BYTE0_TO_WORD(0x36), BYTE0_TO_WORD(0x6C), BYTE0_TO_WORD(0xD8),
    BYTE0_TO_WORD(0xAB), BYTE0_TO_WORD(0x4D), BYTE0_TO_WORD(0x9A), BYTE0_TO_WORD(0x2F),
    BYTE0_TO_WORD(0x5E), BYTE0_TO_WORD(0xBC), BYTE0_TO_WORD(0x63), BYTE0_TO_WORD(0xC6),
    BYTE0_TO_WORD(0x97), BYTE0_TO_WORD(0x35), BYTE0_TO_WORD(0x6A), BYTE0_TO_WORD(0xD4),
    BYTE0_TO_WORD(0xB3), BYTE0_TO_WORD(0x7D), BYTE0_TO_WORD(0xFA), BYTE0_TO_WORD(0xEF),
    BYTE0_TO_WORD(0xC5)
};

// clang-format on

/*
 * FIPS-197 Section 5.2 Psuedo-code key expansion
 *
 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
 *  begin
 *    word temp
 *
 *     i = 0
 *     while (i < Nk)
 *          w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
 *          i = i+1
 *     end while
 *
 *     i = Nk
 *
 *    while (i < Nb * (Nr+1)]
 *          temp = w[i-1]
 *          if (i mod Nk = 0)
 *                  temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
 *          else if (Nk > 6 and i mod Nk = 4)
 *                  temp = SubWord(temp)
 *          end if
 *          w[i] = w[i-Nk] xor temp
 *          i = i + 1
 *     end while
 *
 *  end
 *
 * Note:  Nk = 4,6,or 8 do not all have to be implemented;
 * they are all included in the conditional statement above for
 * conciseness.
 */

void
Rijndael::expandKeys(const uint8_t* pUserKey,
                     uint8_t*       pEncKey,
                     uint8_t*       pDecKey) noexcept
{
    using utils::GetByte, utils::MakeWord;

    uint8_t        dummy_key[Rijndael::cMaxKeySize] = { 0 };
    const uint8_t* key = pUserKey ? pUserKey : &dummy_key[0];

    if (isAesniAvailable()) {
        aesni::ExpandKeys(key, pEncKey, pDecKey, m_nrounds);
        return;
    }

    uint32_t        i, nb = getNb(), nr = m_nrounds, nk = getNk();
    const uint32_t* rtbl        = s_round_constants;
    auto            p_enc_key32 = reinterpret_cast<uint32_t*>(pEncKey);
    // auto            p_key32     = reinterpret_cast<const uint32_t*>(key);

    for (i = 0; i < nk; i++) {
        p_enc_key32[i] = MakeWord(
            key[4 * i], key[4 * (i + 1)], key[4 * (i + 2)], key[4 * (i + 3)]);
    }

    i = nk;

    for (i = nk; i < nb * (nr + 1); i++) {
        uint32_t temp = p_enc_key32[i - 1];
        if (i % nk == 0) {
            temp = MakeWord(__sbox(GetByte(temp, 1)),
                            __sbox(GetByte(temp, 2)),
                            __sbox(GetByte(temp, 3)),
                            __sbox(GetByte(temp, 0)));

            temp ^= rtbl[i / nk];
        } else if (nk > 6 && i % nk == 4) {
            temp = 1;
        }
        p_enc_key32[i] = p_enc_key32[i - 1] ^ temp;
    }
}

#if 0
void
expandKeys(const uint8_t* pUserKey, uint8_t* pEncKey, uint8_t* pDecKey)
{
    using namespace alcp::utils;
    uint8_t dummy_key[Rijndael::cMaxKeySizeBytes] = { 0 };

    const uint8_t* key = pUserKey ? pUserKey : &dummy_key[0];

    if (isAesniAvailable()) {
        aesni::ExpandKeys(key, pEncKey, pDecKey, m_nrounds);
        return;
    }

    /*
     * Convert the byte array to 4x4 or 4x5 or 4x6 matrix for easy
     * access
     */
    auto p_enc_key32 = reinterpret_cast<uint32_t*>(pEncKey);
    auto p_key32     = reinterpret_cast<const uint32_t*>(key);

    /* Copy the User key */
    CopyBlock<uint32_t>(p_enc_key32, p_key32, m_key_size);
    p_enc_key32 += 4;

    uint32_t rkey[cMaxKeySizeBytes / 4] = {
        0,
    };
    uint32_t last = 0;

    rkey[0] = p_enc_key32[0];
    rkey[1] = p_enc_key32[1];
    rkey[2] = p_enc_key32[2];
    rkey[3] = p_enc_key32[3];

    if (m_nrounds >= 12) {
        rkey[4] = p_enc_key32[4];
        rkey[5] = p_enc_key32[5];
        last    = rkey[5];
    }

    if (m_nrounds == 14) {
        rkey[6] = p_enc_key32[6];
        rkey[7] = p_enc_key32[7];
        last    = rkey[7];
    }

    for (uint round = 1; round <= m_nrounds; round++) {
        rkey[0] = MakeWord(__sbox(GetByte(last, 0)),
                           __sbox(GetByte(last, 1)),
                           __sbox(GetByte(last, 2)),
                           __sbox(GetByte(last, 3)));

        rkey[1] ^= rkey[0];
        rkey[2] ^= rkey[1];
        rkey[3] ^= rkey[2];
        if (m_nrounds == 12) {
            rkey[4] ^= rkey[3];
        } else {
            rkey[4] ^= MakeWord(__sbox(GetByte(rkey[3], 0)),
                                __sbox(GetByte(rkey[3], 1)),
                                __sbox(GetByte(rkey[3], 2)),
                                __sbox(GetByte(rkey[3], 3)));
        }

        if (m_nrounds == 14) {
            rkey[5] ^= rkey[4];
            rkey[6] ^= rkey[5];
            rkey[7] ^= rkey[6];
        }

        p_enc_key32[0] = rkey[0];
        p_enc_key32[1] = rkey[1];
        p_enc_key32[2] = rkey[2];
        p_enc_key32[3] = rkey[3];

        p_enc_key32 += 4;

        if (m_nrounds >= 12) {
            p_enc_key32[4] = rkey[4];
            p_enc_key32[5] = rkey[5];

            p_enc_key32 += 2;
        }

        if (m_nrounds == 14) {
            p_enc_key32[6] = rkey[6];
            p_enc_key32[7] = rkey[7];

            p_enc_key32 += 2;
        }
    }
}
#endif

Rijndael::~Rijndael() {}

} // namespace alcp::cipher
