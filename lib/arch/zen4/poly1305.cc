/*
 * Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
 * Portions of this file consist of AI-generated content.
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

#include <array>
#include <cassert>
#include <cstring>
#include <immintrin.h>
#include <tuple>

#include "alcp/mac/poly1305_common.hh"
#include "alcp/mac/poly1305_zen4.hh"
#include "alcp/utils/copy.hh"

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#include <iostream>
#include <string>

void
debug_print(std::string in)
{
    std::cout << in;
    std::cout << std::endl;
}
#else
void
debug_print(std::string in)
{
}
#endif

namespace alcp::mac::poly1305::zen4 {

// Pure C++ Functions

/**
 * @brief Assemble bytes (128bit) into radix44 (3x64)
 *
 * @param msg      Input Bytes
 * @param output   Output Radix 44 value
 */
void
radix44(Uint8 msg[], Uint64 output[3])
{
    // Wipe the output buffer
    std::fill(output, output + 3, 0);

    Uint8* msg_input_ptr = msg;
    for (int i = 0; i < 3; i++) {
        // Load 64 bits from msg_input into output[i] using std::copy
        if (i == 2) {
            // Only 6 more bytes are left for the last message
            std::copy(msg_input_ptr, msg_input_ptr + 6, (Uint8*)&output[i]);
        } else {
            // Load 8 bytes into output[i]
            std::copy(msg_input_ptr, msg_input_ptr + 8, (Uint8*)&output[i]);
        }
        // Right shift output by extra bits
        output[i] >>= 4 * i;
        // Mask output by 44 bits
        output[i] &= Radix44::mask_low_limb;
        msg_input_ptr += 5;
    }
}

// Begin Radix44 Implementation
inline void
poly1305_multiplyx2_radix44(Uint64 a[3], Uint64 r[3], Uint64 s[2])
{
    /*
        d0 = a0r0 + a1s2 + a2s1
        d1 = a0r1 + a1r0 + a2s2
        d2 = a0r2 + a1r1 + a2r0

        reg0 = r0, r1, r2,..... * a0
        reg1 = s2, r0, r1...... * a1
        reg2 = s1, s2, r0...... * a2

        reg0 + reg1 + reg2 = {d0, d1, d2,....}
    */
    __m512i r_reg = _mm512_maskz_loadu_epi64(0x07, r);
    __m512i s_reg = _mm512_maskz_loadu_epi64(0x03, s);
    // Reg0 is same as r_reg
    __m512i reg0 = r_reg;
    __m512i idx  = _mm512_setr_epi64(1 << 3 | 1, 0, 1, 6, 6, 6, 6, 6);
    __m512i reg1 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx          = _mm512_setr_epi64(1 << 3 | 0, 1 << 3 | 1, 0, 6, 6, 6, 6, 6);
    __m512i reg2 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);

    // First Part of multiplication
    __m512i regtemp = _mm512_set1_epi64(a[0]);
    __m512i t_reg1_lo =
        _mm512_madd52lo_epu64(_mm512_setzero_si512(), regtemp, reg0);
    __m512i t_reg1_hi =
        _mm512_madd52hi_epu64(_mm512_setzero_si512(), regtemp, reg0);

    // Second Part of multiplication
    regtemp           = _mm512_set1_epi64(a[1]);
    __m512i t_reg2_lo = _mm512_madd52lo_epu64(t_reg1_lo, regtemp, reg1);
    __m512i t_reg2_hi = _mm512_madd52hi_epu64(t_reg1_hi, regtemp, reg1);

    // Third Part of multiplication
    regtemp   = _mm512_set1_epi64(a[2]);
    t_reg1_lo = _mm512_madd52lo_epu64(t_reg2_lo, regtemp, reg2);
    t_reg1_hi = _mm512_madd52hi_epu64(t_reg2_hi, regtemp, reg2);

    // Carry propagation
    idx       = _mm512_setr_epi64(44, 44, 42, 0, 0, 0, 0, 0);
    regtemp   = _mm512_srlv_epi64(t_reg1_lo, idx); // High bits
    idx       = _mm512_setr_epi64(8, 8, 10, 0, 0, 0, 0, 0);
    t_reg1_hi = _mm512_sllv_epi64(t_reg1_hi, idx);
    t_reg1_hi = _mm512_or_epi64(t_reg1_hi, regtemp);
    idx       = _mm512_setr_epi64(
        Radix44::mask_low_limb, Radix44::mask_low_limb, Radix44::mask_last_limb, 0, 0, 0, 0, 0);
    t_reg1_lo = _mm512_and_epi64(t_reg1_lo, idx);
    idx       = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp   = _mm512_permutexvar_epi64(idx, t_reg1_hi);
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // d0 should be 44 bits, but d1 and d2 can be more than 44 bit
    regtemp   = _mm512_set_epi64(0xfffff00000000000UL,
                               0xfffff00000000000UL,
                               0xfffffc0000000000UL,
                               0,
                               0,
                               0,
                               0,
                               0);
    regtemp   = _mm512_and_epi64(regtemp, t_reg1_lo);
    idx       = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp   = _mm512_permutexvar_epi64(idx, regtemp);
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // d0 and d1 should be 44 bits, d2 can be more than 44 bits

    // Mask 0xfffff00000000000,0xfffff00000000000,0xfffffc0000000000,0,0,0,0,0;
    // to regtemp
    //      d0                  d1                 d2               , excess
    regtemp = _mm512_set_epi64(0xfffff00000000000UL,
                               0xfffff00000000000UL,
                               0xfffffc0000000000UL,
                               0,
                               0,
                               0,
                               0,
                               0);

    regtemp   = _mm512_and_epi64(regtemp, t_reg1_lo);
    idx       = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp   = _mm512_permutexvar_epi64(idx, regtemp);
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // Only excess is left to be processed
    idx     = _mm512_setr_epi64(3, 6, 6, 6, 6, 6, 6, 6);
    regtemp = _mm512_permutexvar_epi64(idx, t_reg1_lo);
    // Multiply excess with 5
    regtemp = _mm512_mullo_epi64(regtemp, _mm512_set1_epi64(5)); // Modulo Trick
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // Carry propagate
    // Mask 0xfffff00000000000,0xfffff00000000000,0xfffffc0000000000,0,0,0,0,0;
    // to regtemp
    //      d0                  d1                 d2               , excess
    regtemp   = _mm512_set_epi64(0xfffff00000000000UL,
                               0xfffff00000000000UL,
                               0xfffffc0000000000UL,
                               0,
                               0,
                               0,
                               0,
                               0);
    regtemp   = _mm512_and_epi64(regtemp, t_reg1_lo);
    idx       = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp   = _mm512_permutexvar_epi64(idx, regtemp);
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // d0 should be 44 bits, but d1 and d2 can be more than 44 bits
    // Stopping carry propagation here for now.

    _mm512_mask_storeu_epi64(a, 0x7, t_reg1_lo);
}

// FIXME: Below two functions can be fused with use of template to eliminate
// branches
inline int
loadx1_message_radix44(const Uint8* p_msg,
                       __m512i&     m0,
                       __m512i&     m1,
                       __m512i&     m2)
{
    // Load 128 bits from p_msg into m0 using _mm512_maskz_loadu_epi64
    m0 = _mm512_maskz_loadu_epi64(0x03, p_msg);
    // Unpack 64 bit integers from m0 and m1 and save it to m0 and m1
    m1 = _mm512_unpackhi_epi64(m0, m0);
    m0 = _mm512_unpacklo_epi64(m0, m0);
    // Radix first value calculation
    // Truncate to 44 bits
    __m512i lo_masked = _mm512_and_epi64(m0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    __m512i lo_shifted = _mm512_srlv_epi64(m0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    __m512i hi_shifted = _mm512_sllv_epi64(m1, _mm512_set1_epi64(20));
    // Or lo_shifted and hi_shifted and save it to lo_or
    __m512i lo_or = _mm512_or_epi64(lo_shifted, hi_shifted);
    // Truncate to 44 bits
    lo_or = _mm512_and_epi64(lo_or, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    __m512i hi_shifted_40 = _mm512_srlv_epi64(m1, _mm512_set1_epi64(24));
    // Truncate to 42 bits
    hi_shifted_40 =
        _mm512_and_epi64(hi_shifted_40, _mm512_set1_epi64(Radix44::mask_last_limb));

    hi_shifted_40 =
        _mm512_or_epi64(hi_shifted_40, _mm512_set1_epi64(1ULL << 40));

    m0 = lo_masked;
    m1 = lo_or;
    m2 = hi_shifted_40;
    return 128;
}

inline int
loadx1_message_radix44_nopad(const Uint8* p_msg,
                             __m512i&     m0,
                             __m512i&     m1,
                             __m512i&     m2)
{
    // Load 128 bits from p_msg into m0 using _mm512_maskz_loadu_epi64
    m0 = _mm512_maskz_loadu_epi64(0x03, p_msg);
    // Unpack 64 bit integers from m0 and m1 and save it to m0 and m1
    m1 = _mm512_unpackhi_epi64(m0, m0);
    m0 = _mm512_unpacklo_epi64(m0, m0);
    // Radix first value calculation
    // Truncate to 44 bits
    __m512i lo_masked = _mm512_and_epi64(m0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    __m512i lo_shifted = _mm512_srlv_epi64(m0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    __m512i hi_shifted = _mm512_sllv_epi64(m1, _mm512_set1_epi64(20));
    // Or lo_shifted and hi_shifted and save it to lo_or
    __m512i lo_or = _mm512_or_epi64(lo_shifted, hi_shifted);
    // Truncate to 44 bits
    lo_or = _mm512_and_epi64(lo_or, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    __m512i hi_shifted_40 = _mm512_srlv_epi64(m1, _mm512_set1_epi64(24));
    // Truncate to 42 bits
    hi_shifted_40 =
        _mm512_and_epi64(hi_shifted_40, _mm512_set1_epi64(Radix44::mask_last_limb));

    m0 = lo_masked;
    m1 = lo_or;
    m2 = hi_shifted_40;
    return 128;
}

inline void
load_message_scalar_radix44(const Uint8* p_msg,
                            Uint64&      m0,
                            Uint64&      m1,
                            Uint64&      m2)
{
    Uint64 lo, hi;
    std::memcpy(&lo, p_msg, sizeof(lo));
    std::memcpy(&hi, p_msg + 8, sizeof(hi));

    constexpr Uint64 mask44 = (1ULL << 44) - 1;
    constexpr Uint64 mask42 = (1ULL << 42) - 1;

    m0 = lo & mask44;
    m1 = ((lo >> 44) | (hi << 20)) & mask44;
    m2 = ((hi >> 24) & mask42) | (1ULL << 40);
}

inline void
load_message_scalar_radix44_nopad(const Uint8* p_msg,
                                  Uint64&      m0,
                                  Uint64&      m1,
                                  Uint64&      m2)
{
    Uint64 lo, hi;
    std::memcpy(&lo, p_msg, sizeof(lo));
    std::memcpy(&hi, p_msg + 8, sizeof(hi));

    constexpr Uint64 mask44 = (1ULL << 44) - 1;
    constexpr Uint64 mask42 = (1ULL << 42) - 1;

    m0 = lo & mask44;
    m1 = ((lo >> 44) | (hi << 20)) & mask44;
    m2 = (hi >> 24) & mask42;
}

inline void
poly1305_mult_scalar_radix44(Uint64& a0,
                             Uint64& a1,
                             Uint64& a2,
                             Uint64  r0,
                             Uint64  r1,
                             Uint64  r2,
                             Uint64  s1,
                             Uint64  s2)
{
    constexpr Uint64 mask44 = (1ULL << 44) - 1;
    constexpr Uint64 mask42 = (1ULL << 42) - 1;

    // BMI2+ADX (mulx + addcarryx) based scalar kernel.
    unsigned long long d0_lo, d0_hi, d1_lo, d1_hi, d2_lo, d2_hi;
    unsigned long long t_lo, t_hi;
    unsigned char      carry;

    d0_lo = _mulx_u64(a0, r0, &d0_hi);
    t_lo  = _mulx_u64(a1, s2, &t_hi);
    carry = _addcarryx_u64(0, d0_lo, t_lo, &d0_lo);
    carry = _addcarryx_u64(carry, d0_hi, t_hi, &d0_hi);
    t_lo  = _mulx_u64(a2, s1, &t_hi);
    carry = _addcarryx_u64(0, d0_lo, t_lo, &d0_lo);
    carry = _addcarryx_u64(carry, d0_hi, t_hi, &d0_hi);

    d1_lo = _mulx_u64(a0, r1, &d1_hi);
    t_lo  = _mulx_u64(a1, r0, &t_hi);
    carry = _addcarryx_u64(0, d1_lo, t_lo, &d1_lo);
    carry = _addcarryx_u64(carry, d1_hi, t_hi, &d1_hi);
    t_lo  = _mulx_u64(a2, s2, &t_hi);
    carry = _addcarryx_u64(0, d1_lo, t_lo, &d1_lo);
    carry = _addcarryx_u64(carry, d1_hi, t_hi, &d1_hi);

    d2_lo = _mulx_u64(a0, r2, &d2_hi);
    t_lo  = _mulx_u64(a1, r1, &t_hi);
    carry = _addcarryx_u64(0, d2_lo, t_lo, &d2_lo);
    carry = _addcarryx_u64(carry, d2_hi, t_hi, &d2_hi);
    t_lo  = _mulx_u64(a2, r0, &t_hi);
    carry = _addcarryx_u64(0, d2_lo, t_lo, &d2_lo);
    carry = _addcarryx_u64(carry, d2_hi, t_hi, &d2_hi);

    // Reduce to radix44 limbs (44/44/42) with modulo trick.
    unsigned long long c;
    a0 = d0_lo & mask44;
    c  = (d0_lo >> 44) | (d0_hi << 20);
    carry = _addcarryx_u64(0, d1_lo, c, &d1_lo);
    d1_hi += carry;

    a1 = d1_lo & mask44;
    c  = (d1_lo >> 44) | (d1_hi << 20);
    carry = _addcarryx_u64(0, d2_lo, c, &d2_lo);
    d2_hi += carry;

    a2 = d2_lo & mask42;
    c  = (d2_lo >> 42) | (d2_hi << 22);
    a0 += c * Radix44::wrap_factor;

    c = a0 >> 44;
    a0 &= mask44;
    a1 += c;
    c = a1 >> 44;
    a1 &= mask44;
    a2 += c;
    c = a2 >> 42;
    a2 &= mask42;
    a0 += c * Radix44::wrap_factor;
    c = a0 >> 44;
    a0 &= mask44;
    a1 += c;
}

inline int
loadx8_message_radix44(const Uint8* p_msg,
                       __m512i&     m0,
                       __m512i&     m1,
                       __m512i&     m2)
{
    __m512i temp0, temp1, temp2, temp3;
    // Load 512 bits from p_msg into m0 and m1 using _mm512_loadu_si512
    m0 = _mm512_loadu_si512(p_msg);
    m1 = _mm512_loadu_si512(p_msg + 64);

    // Unpack 64 bit integers from m0 and m1 and save it to temp0 and temp1
    temp0 = _mm512_unpacklo_epi64(m0, m1);
    temp1 = _mm512_unpackhi_epi64(m0, m1);

    // Radix first value calculation
    // Truncate to 44 bits
    m0 = _mm512_and_epi64(temp0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    temp2 = _mm512_srlv_epi64(temp0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    temp3 = _mm512_sllv_epi64(temp1, _mm512_set1_epi64(20));
    // Or temp2 and temp3 to create radix second value
    temp2 = _mm512_or_epi64(temp2, temp3);
    // Truncate to 44 bits
    m1 = _mm512_and_epi64(temp2, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    temp3 = _mm512_srlv_epi64(temp1, _mm512_set1_epi64(24));
    // Truncate to 44 bits
    m2 = _mm512_and_epi64(temp3, _mm512_set1_epi64(Radix44::mask_low_limb));
    m2 = _mm512_or_epi64(m2, _mm512_set1_epi64(1ULL << 40));

    return 512;
}

inline int
loadx7_message_radix44(const Uint8* p_msg,
                       __m512i&     m0,
                       __m512i&     m1,
                       __m512i&     m2)
{
    __m512i temp0, temp1, temp2, temp3;
    // Load 512 bits from p_msg into m0 and m1 using _mm512_loadu_si512
    m0 = _mm512_setzero_si512();
    m0 = _mm512_mask_loadu_epi64(m0, 0b11111100, p_msg - 16);
    m1 = _mm512_loadu_si512(p_msg + 48);

    // Unpack 64 bit integers from m0 and m1 and save it to temp0 and temp1
    temp0 = _mm512_unpacklo_epi64(m0, m1);
    temp1 = _mm512_unpackhi_epi64(m0, m1);

    // Radix first value calculation
    // Truncate to 44 bits
    m0 = _mm512_and_epi64(temp0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    temp2 = _mm512_srlv_epi64(temp0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    temp3 = _mm512_sllv_epi64(temp1, _mm512_set1_epi64(20));
    // Or temp2 and temp3 to create radix second value
    temp2 = _mm512_or_epi64(temp2, temp3);
    // Truncate to 44 bits
    m1 = _mm512_and_epi64(temp2, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    temp3 = _mm512_srlv_epi64(temp1, _mm512_set1_epi64(24));
    // Truncate to 44 bits
    m2 = _mm512_and_epi64(temp3, _mm512_set1_epi64(Radix44::mask_low_limb));
    m2 = _mm512_or_epi64(m2,
                         _mm512_setr_epi64(0,
                                           1ULL << 40,
                                           1ULL << 40,
                                           1ULL << 40,
                                           1ULL << 40,
                                           1ULL << 40,
                                           1ULL << 40,
                                           1ULL << 40));

    return 384;
}

// Function to broadcast r value to reg0, reg1, reg2 which are 512 bit registers
inline void
broadcast_r(const Uint64 r[3], __m512i& reg0, __m512i& reg1, __m512i& reg2)
{
    reg0 = _mm512_set1_epi64(r[0]);
    reg1 = _mm512_set1_epi64(r[1]);
    reg2 = _mm512_set1_epi64(r[2]);
}

inline void
poly1305_calculate_modulo_trick_value(const __m512i reg1,
                                      const __m512i reg2,
                                      __m512i&      sreg1,
                                      __m512i&      sreg2)
{
    // Calculate sreg1 and sreg2 using modulo trick
    // sreg1 = reg1 * 5 * 4
    sreg1 = _mm512_mullo_epi64(reg1, _mm512_set1_epi64(5 * 4));
    // sreg2 = reg2 * 5 * 4
    sreg2 = _mm512_mullo_epi64(reg2, _mm512_set1_epi64(5 * 4));
}

inline void
poly1305_multx8_radix44(__m512i& a0,
                        __m512i& a1,
                        __m512i& a2,
                        __m512i  r0,
                        __m512i  r1,
                        __m512i  r2,
                        __m512i  s1,
                        __m512i  s2)
{
    // Multiply
    __m512i extra;
    __m512i d0l = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a0, r0);
    __m512i d0h = _mm512_madd52hi_epu64(_mm512_setzero_si512(), a0, r0);
    __m512i d1l = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a0, r1);
    __m512i d1h = _mm512_madd52hi_epu64(_mm512_setzero_si512(), a0, r1);
    __m512i d2l = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a0, r2);
    __m512i d2h = _mm512_madd52hi_epu64(_mm512_setzero_si512(), a0, r2);

    d0l = _mm512_madd52lo_epu64(d0l, a1, s2);
    d0h = _mm512_madd52hi_epu64(d0h, a1, s2);
    d1l = _mm512_madd52lo_epu64(d1l, a1, r0);
    d1h = _mm512_madd52hi_epu64(d1h, a1, r0);
    d2l = _mm512_madd52lo_epu64(d2l, a1, r1);
    d2h = _mm512_madd52hi_epu64(d2h, a1, r1);

    // Third round - optimized scheduling
    d0l = _mm512_madd52lo_epu64(d0l, a2, s1);
    d0h = _mm512_madd52hi_epu64(d0h, a2, s1);
    d1l = _mm512_madd52lo_epu64(d1l, a2, s2);
    d1h = _mm512_madd52hi_epu64(d1h, a2, s2);
    d2l = _mm512_madd52lo_epu64(d2l, a2, r0);
    d2h = _mm512_madd52hi_epu64(d2h, a2, r0);

    // Bit Adjust
    extra = _mm512_srlv_epi64(d0l, _mm512_set1_epi64(44));
    d0l   = _mm512_and_epi64(d0l, _mm512_set1_epi64(Radix44::mask_low_limb));
    d0h   = _mm512_sllv_epi64(d0h, _mm512_set1_epi64(8));
    d0h   = _mm512_add_epi64(d0h, extra);

    extra = _mm512_srlv_epi64(d1l, _mm512_set1_epi64(44));
    d1l   = _mm512_and_epi64(d1l, _mm512_set1_epi64(Radix44::mask_low_limb));
    d1h   = _mm512_sllv_epi64(d1h, _mm512_set1_epi64(8));
    d1h   = _mm512_add_epi64(d1h, extra);

    extra = _mm512_srlv_epi64(d2l, _mm512_set1_epi64(42));
    d2l   = _mm512_and_epi64(d2l, _mm512_set1_epi64(Radix44::mask_last_limb));
    d2h   = _mm512_sllv_epi64(d2h, _mm512_set1_epi64(10));
    d2h   = _mm512_add_epi64(d2h, extra);

    d1l = _mm512_add_epi64(d0h, d1l);
    d2l = _mm512_add_epi64(d1h, d2l);

// Optimization value *=5 can be writen as value = (value * 4 + value)
#if 1
    extra = _mm512_sllv_epi64(d2h, _mm512_set1_epi64(2));
    d2h   = _mm512_add_epi64(extra, d2h);
    d0l   = _mm512_add_epi64(d2h, d0l);
#else
    d0l = _mm512_add_epi64(_mm512_mullo_epi64(d2h, _mm512_set1_epi64(5)), d0l);
#endif

    // Propagrate carry
    extra = _mm512_srlv_epi64(d0l, _mm512_set1_epi64(44));
    d0l   = _mm512_and_epi64(d0l, _mm512_set1_epi64(Radix44::mask_low_limb));
    d1l   = _mm512_add_epi64(d1l, extra);
    extra = _mm512_srlv_epi64(d1l, _mm512_set1_epi64(44));
    d1l   = _mm512_and_epi64(d1l, _mm512_set1_epi64(Radix44::mask_low_limb));
    d2l   = _mm512_add_epi64(d2l, extra);
    extra = _mm512_srlv_epi64(d2l, _mm512_set1_epi64(42));
    d2l   = _mm512_and_epi64(d2l, _mm512_set1_epi64(Radix44::mask_last_limb));
    d0h   = _mm512_sllv_epi64(extra, _mm512_set1_epi64(2));
    extra = _mm512_add_epi64(extra, d0h);
    d0l   = _mm512_add_epi64(d0l, extra);

// FIXME: Make sure this is not needed
#if 0
    // extra = _mm512_srlv_epi64(d0l, _mm512_set1_epi64(44));
    // d0l   = _mm512_and_epi64(d0l, _mm512_set1_epi64(Radix44::mask_low_limb));
    // d1l   = _mm512_add_epi64(d1l, extra);
#endif

    // Store d0l, d1l, d2l to a0, a1, a2
    a0 = d0l;
    a1 = d1l;
    a2 = d2l;
}

void
poly1305_multx1_radix44_standalone(const Uint64 a[3],
                                   const Uint64 b[3],
                                   Uint64       out[3])
{
    __m512i reg0, reg1, reg2;
    __m512i m0, m1, m2;
    // Compute out = a*b
    broadcast_r(b, reg0, reg1, reg2);

    broadcast_r(a, m0, m1, m2);

    // Compute s value
    __m512i s1, s2;
    poly1305_calculate_modulo_trick_value(reg1, reg2, s1, s2);

    // Multiply reg0, reg1, reg2 with m0, m1, m2
    poly1305_multx8_radix44(m0, m1, m2, reg0, reg1, reg2, s1, s2);

    // Store m0, m1, m2 to out
    _mm512_mask_storeu_epi64(out, 0x01, m0);
    _mm512_mask_storeu_epi64(out + 1, 0x01, m1);
    _mm512_mask_storeu_epi64(out + 2, 0x01, m2);
}

inline void
load_all_r(Uint64   r[3],
           Uint64   r2[3],
           Uint64   r3[3],
           Uint64   r4[3],
           Uint64   r5[3],
           Uint64   r6[3],
           Uint64   r7[3],
           Uint64   r8[3],
           __m512i& reg0,
           __m512i& reg1,
           __m512i& reg2)
{
    // FIXME: Order of r, r2, r3, r4, r5, r6, r7, r8 is wrong
    reg0 = _mm512_setr_epi64(
        r8[0], r4[0], r7[0], r3[0], r6[0], r2[0], r5[0], r[0]);
    reg1 = _mm512_setr_epi64(
        r8[1], r4[1], r7[1], r3[1], r6[1], r2[1], r5[1], r[1]);
    reg2 = _mm512_setr_epi64(
        r8[2], r4[2], r7[2], r3[2], r6[2], r2[2], r5[2], r[2]);
}

inline void
load_r1_to_r7(Uint64   r[3],
              Uint64   r2[3],
              Uint64   r3[3],
              Uint64   r4[3],
              Uint64   r5[3],
              Uint64   r6[3],
              Uint64   r7[3],
              __m512i& reg0,
              __m512i& reg1,
              __m512i& reg2)
{
    // FIXME: Order of r, r2, r3, r4, r5, r6, r7, r8 is wrong
    reg0 = _mm512_setr_epi64(r7[0], r3[0], r6[0], r2[0], r5[0], r[0], r4[0], 1);
    reg1 = _mm512_setr_epi64(r7[1], r3[1], r6[1], r2[1], r5[1], r[1], r4[1], 0);
    reg2 = _mm512_setr_epi64(r7[2], r3[2], r6[2], r2[2], r5[2], r[2], r4[2], 0);
}

static inline Uint64
hadd_u64x2(__m128i v)
{
    return static_cast<Uint64>(_mm_cvtsi128_si64(v))
           + static_cast<Uint64>(_mm_extract_epi64(v, 1));
}

static inline void
poly1305_blocksx8_final(__m512i& a0,
                        __m512i& a1,
                        __m512i& a2,
                        Uint64   r[3],
                        Uint64   r2[3],
                        Uint64   r3[3],
                        Uint64   r4[3],
                        Uint64   r5[3],
                        Uint64   r6[3],
                        Uint64   r7[3],
                        Uint64   r8[3])
{
    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;
    load_all_r(r, r2, r3, r4, r5, r6, r7, r8, reg_r0, reg_r1, reg_r2);

    // acc *= r,r2,r3,r4,r5,r6,r7,r8
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);

    poly1305_multx8_radix44(a0, a1, a2, reg_r0, reg_r1, reg_r2, reg_s1, reg_s2);

    // Horizontal addition
    // Downgrade to avx2, a0_256_0 and a0_256_1, a1_256_0 and a1_256_1 and
    // a2_256_0 and a2_256_1
    __m256i a0_256_0 = _mm512_extracti64x4_epi64(a0, 0);
    __m256i a0_256_1 = _mm512_extracti64x4_epi64(a0, 1);
    __m256i a1_256_0 = _mm512_extracti64x4_epi64(a1, 0);
    __m256i a1_256_1 = _mm512_extracti64x4_epi64(a1, 1);
    __m256i a2_256_0 = _mm512_extracti64x4_epi64(a2, 0);
    __m256i a2_256_1 = _mm512_extracti64x4_epi64(a2, 1);
    // Add a0_256_0 and a0_256_1 and save it to a0_256_0
    a0_256_0 = _mm256_add_epi64(a0_256_0, a0_256_1);
    // Add a1_256_0 and a1_256_1 and save it to a1_256_0
    a1_256_0 = _mm256_add_epi64(a1_256_0, a1_256_1);
    // Add a2_256_0 and a2_256_1 and save it to a2_256_0
    a2_256_0 = _mm256_add_epi64(a2_256_0, a2_256_1);

    // Downgrade to SSE, a0_128_0, a0_128_1, a1_128_0, a1_128_1, a2_128_0,
    // a2_128_1
    __m128i a0_128_0 = _mm256_extracti128_si256(a0_256_0, 0);
    __m128i a0_128_1 = _mm256_extracti128_si256(a0_256_0, 1);
    __m128i a1_128_0 = _mm256_extracti128_si256(a1_256_0, 0);
    __m128i a1_128_1 = _mm256_extracti128_si256(a1_256_0, 1);
    __m128i a2_128_0 = _mm256_extracti128_si256(a2_256_0, 0);
    __m128i a2_128_1 = _mm256_extracti128_si256(a2_256_0, 1);
    // Add a0_128_0 and a0_128_1 and save it to a0_128_0
    a0_128_0 = _mm_add_epi64(a0_128_0, a0_128_1);
    // Add a1_128_0 and a1_128_1 and save it to a1_128_0
    a1_128_0 = _mm_add_epi64(a1_128_0, a1_128_1);
    // Add a2_128_0 and a2_128_1 and save it to a2_128_0
    a2_128_0 = _mm_add_epi64(a2_128_0, a2_128_1);

    // Fold a0_128_0, a1_128_0, a2_128_0 to a0, a1, a2
    Uint64 _a0, _a1, _a2;
    _a0 = hadd_u64x2(a0_128_0);
    _a1 = hadd_u64x2(a1_128_0);
    _a2 = hadd_u64x2(a2_128_0);

    // Save back _a0, _a1, _a2 to a0, a1, a2, set all other values to 0
    a0 = _mm512_setr_epi64(_a0, 0, 0, 0, 0, 0, 0, 0);
    a1 = _mm512_setr_epi64(_a1, 0, 0, 0, 0, 0, 0, 0);
    a2 = _mm512_setr_epi64(_a2, 0, 0, 0, 0, 0, 0, 0);

    // Optimization: Use 64 bit math to calculate a0, a1, a2 than using 512 bit
    // math. Carry propagation with modulo Right shift a0 by 44 bits
    __m512i carry = _mm512_srlv_epi64(a0, _mm512_set1_epi64(44));
    // Mask Radix44::mask_low_limb (44 bits) to a0
    a0 = _mm512_and_epi64(a0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Add carry to a1
    a1 = _mm512_add_epi64(a1, carry);
    // Right shift a1 by 44 bits
    carry = _mm512_srlv_epi64(a1, _mm512_set1_epi64(44));
    // Mask Radix44::mask_low_limb (44 bits) to a1
    a1 = _mm512_and_epi64(a1, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Add carry to a2
    a2 = _mm512_add_epi64(a2, carry);
    // Right shift a2 by 42 bits
    carry = _mm512_srlv_epi64(a2, _mm512_set1_epi64(42));
    // Mask Radix44::mask_last_limb (42 bits) to a2
    a2 = _mm512_and_epi64(a2, _mm512_set1_epi64(Radix44::mask_last_limb));
    // Add carry to a0
    a0 = _mm512_add_epi64(a0, _mm512_mullo_epi64(carry, _mm512_set1_epi64(5)));
    // Right shift a0 by 44 bits
    carry = _mm512_srlv_epi64(a0, _mm512_set1_epi64(44));
    // Mask Radix44::mask_low_limb (44 bits) to a0
    a0 = _mm512_and_epi64(a0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Add carry to a1
    a1 = _mm512_add_epi64(a1, carry);
}

void
poly1305_init(Poly1305State44& state, const Uint8 key[32])
{
    Uint8 r[16];
    Uint8 s[16];

    utils::SecureCopy<Uint8>(r, 16, key, 16);
    utils::SecureCopy<Uint8>(s, 16, key + 16, 16);

    poly1305_clamp_r(r);

    radix44(r, state.r);
    radix44(s, state.s);

    // FIXME: Use poly1305_multiplyx2_radix44 to optimize
    // Compute r**2..r**3..r**4..r**5..r**6..r**7..r**8
    // Multiply r1_key with r1_key and save it to r2_key
    // R Square
    poly1305_multx1_radix44_standalone(state.r, state.r, state.r2);
    // R Cube
    poly1305_multx1_radix44_standalone(state.r2, state.r, state.r3);
    // R Biquadrate / Quartic
    poly1305_multx1_radix44_standalone(state.r3, state.r, state.r4);
    // R Sursolid / Quintic
    poly1305_multx1_radix44_standalone(state.r4, state.r, state.r5);
    // R Zenzicube / Sextic
    poly1305_multx1_radix44_standalone(state.r5, state.r, state.r6);
    // R Second Sursolid / Septic
    poly1305_multx1_radix44_standalone(state.r6, state.r, state.r7);
    // R Zenzizenzizenzic / Octic
    poly1305_multx1_radix44_standalone(state.r7, state.r, state.r8);
    // R**16 (for 2x x8 combine path)
    poly1305_multx1_radix44_standalone(state.r8, state.r8, state.r16);
}

#if 0
inline void
poly1305_blocksx8_radix44(Poly1305State44& state,
                          const Uint8*&    pMsg,
                          Uint64&          len)
{
    __m512i reg_msg0, reg_msg1, reg_msg2;
    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    __m512i reg_r0{}, reg_r1{}, reg_r2{};
    __m512i reg_s1{}, reg_s2{};

    // Length should be >256
    assert(len > 256);
    if (state.fold == false) {
        state.fold = true;
        broadcast_r(state.r8, reg_r0, reg_r1, reg_r2);
        poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);
        // Load Initial Message
        loadx8_message_radix44(pMsg, reg_msg0, reg_msg1, reg_msg2);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);
        len -= 128;
        pMsg += 128;
    }
    while ((len >= 128) && state.fold) {
        loadx8_message_radix44(pMsg, reg_msg0, reg_msg1, reg_msg2);

        poly1305_multx8_radix44(reg_acc0,
                                reg_acc1,
                                reg_acc2,
                                reg_r0,
                                reg_r1,
                                reg_r2,
                                reg_s1,
                                reg_s2);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);

        len -= 128;
        pMsg += 128;
    }

    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}
#else

/**
 * @brief Downgrades X1 state to X8 state.
 *
 * X8 state is divided into 8 acc
 * Each acc is to be properly multiplied and added together
 *
 *  =========================================================
 * | acc[0] = acc[0]                                         |
 * | acc[1] = 0                                              |
 * | acc[2] = 0                                              |
 * | acc[3] = 0                                              |
 * | acc[4] = 0                                              |
 * | acc[5] = 0                                              |
 * | acc[6] = 0                                              |
 * | acc[7] = 0                                              |
 *  =========================================================
 * @param state
 * @param pMsg
 * @param len
 */
inline void
poly1305_blocksx1_to_blocksx8(Poly1305State44& state,
                              const Uint8*&    pMsg,
                              Uint64&          len)
{
    // Upgrade x1 to x8
    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    __m512i reg_msg0, reg_msg1, reg_msg2;

    // Mask every value except the first acc
    __m512i mask = _mm512_setr_epi64(-1, 0, 0, 0, 0, 0, 0, 0);

    reg_acc0 = _mm512_and_epi64(reg_acc0, mask);
    reg_acc1 = _mm512_and_epi64(reg_acc1, mask);
    reg_acc2 = _mm512_and_epi64(reg_acc2, mask);

    loadx7_message_radix44(pMsg, reg_msg0, reg_msg1, reg_msg2);

    reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
    reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
    reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);

    len -= 112;
    pMsg += 112;

    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}

inline void
poly1305_blocksx8_radix44(Poly1305State44& state,
                          const Uint8*&    pMsg,
                          Uint64&          len)
{
    __m512i reg_msg0, reg_msg1, reg_msg2;

    __m512i reg_r0{}, reg_r1{}, reg_r2{};
    __m512i reg_s1{}, reg_s2{};
    __m512i reg_r0_16{}, reg_r1_16{}, reg_r2_16{};
    __m512i reg_s1_16{}, reg_s2_16{};

    if (state.fold == false) {
        // Check if accumulator is zero (fresh state)
        __m512i reg_acc0 = _mm512_load_epi64(state.acc0);
        __m512i reg_acc1 = _mm512_load_epi64(state.acc1);
        __m512i reg_acc2 = _mm512_load_epi64(state.acc2);
        __m512i zero     = _mm512_setzero_si512();

        bool acc_is_zero =
            (_mm512_cmpeq_epi64_mask(reg_acc0, zero) == 0xFF) &&
            (_mm512_cmpeq_epi64_mask(reg_acc1, zero) == 0xFF) &&
            (_mm512_cmpeq_epi64_mask(reg_acc2, zero) == 0xFF);

        if (acc_is_zero && state.msg_buffer_len == 0 && len >= 128) {
            // Direct x8 start: load first 8 blocks as initial accumulators
            loadx8_message_radix44(pMsg, reg_acc0, reg_acc1, reg_acc2);
            _mm512_store_epi64(state.acc0, reg_acc0);
            _mm512_store_epi64(state.acc1, reg_acc1);
            _mm512_store_epi64(state.acc2, reg_acc2);
            pMsg += 128;
            len -= 128;
        } else {
            // Existing path for non-fresh state
            poly1305_blocksx1_to_blocksx8(state, pMsg, len);
        }
        state.fold = true;
    }

    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    // Move to init sequence
    broadcast_r(state.r8, reg_r0, reg_r1, reg_r2);
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);
    broadcast_r(state.r16, reg_r0_16, reg_r1_16, reg_r2_16);
    poly1305_calculate_modulo_trick_value(reg_r1_16, reg_r2_16, reg_s1_16, reg_s2_16);

    while (len >= 256) {
        __m512i reg_msg0_0, reg_msg1_0, reg_msg2_0;
        __m512i reg_msg0_1, reg_msg1_1, reg_msg2_1;

        loadx8_message_radix44(pMsg, reg_msg0_0, reg_msg1_0, reg_msg2_0);
        loadx8_message_radix44(pMsg + 128, reg_msg0_1, reg_msg1_1, reg_msg2_1);

        // Combine two Horner steps:
        //   acc = (acc*r^8 + m0)*r^8 + m1
        //       = acc*r^16 + (m0*r^8) + m1
        // This breaks the acc->acc dependency between the two multiplications.
        poly1305_multx8_radix44(reg_acc0,
                                reg_acc1,
                                reg_acc2,
                                reg_r0_16,
                                reg_r1_16,
                                reg_r2_16,
                                reg_s1_16,
                                reg_s2_16);

        poly1305_multx8_radix44(reg_msg0_0,
                                reg_msg1_0,
                                reg_msg2_0,
                                reg_r0,
                                reg_r1,
                                reg_r2,
                                reg_s1,
                                reg_s2);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0_0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1_0);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2_0);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0_1);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1_1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2_1);

        len -= 256;
        pMsg += 256;
    }

    while (len >= 128) {
        loadx8_message_radix44(pMsg, reg_msg0, reg_msg1, reg_msg2);

        poly1305_multx8_radix44(reg_acc0,
                                reg_acc1,
                                reg_acc2,
                                reg_r0,
                                reg_r1,
                                reg_r2,
                                reg_s1,
                                reg_s2);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);

        len -= 128;
        pMsg += 128;
    }

    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}

#endif

/**
 * @brief Downgrades X8 state to X1 state.
 *
 * X8 state is divided into 8 acc
 * Each acc is to be properly multiplied and added together
 *
 * acc[0] =
 *  =========================================================
 * | acc[0]*r**7 + acc[1]*r**6 + acc[2]*r**5 + acc[3]*r**4 + |
 * | acc[4]*r**3 + acc[5]*r**2 + acc[6]*r**1 + acc[7]*r**0   |
 *  =========================================================
 * @param state
 * @param pMsg
 * @param len
 */
inline void
poly1305_blocksx8_to_blocksx1(Poly1305State44& state) // len is useless here
{
    // Downgrade x8 to x1

    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;

    load_r1_to_r7(state.r,
                  state.r2,
                  state.r3,
                  state.r4,
                  state.r5,
                  state.r6,
                  state.r7,
                  reg_r0,
                  reg_r1,
                  reg_r2);

    // acc *= 1,r,r2,r3,r4,r5,r6,r7
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);

    poly1305_multx8_radix44(
        reg_acc0, reg_acc1, reg_acc2, reg_r0, reg_r1, reg_r2, reg_s1, reg_s2);

    // Horizontal addition
    // Downgrade to avx2, a0_256_0 and a0_256_1, a1_256_0 and a1_256_1 and
    // a2_256_0 and a2_256_1
    __m256i a0_256_0 = _mm512_extracti64x4_epi64(reg_acc0, 0);
    __m256i a0_256_1 = _mm512_extracti64x4_epi64(reg_acc0, 1);
    __m256i a1_256_0 = _mm512_extracti64x4_epi64(reg_acc1, 0);
    __m256i a1_256_1 = _mm512_extracti64x4_epi64(reg_acc1, 1);
    __m256i a2_256_0 = _mm512_extracti64x4_epi64(reg_acc2, 0);
    __m256i a2_256_1 = _mm512_extracti64x4_epi64(reg_acc2, 1);
    // Add a0_256_0 and a0_256_1 and save it to a0_256_0
    a0_256_0 = _mm256_add_epi64(a0_256_0, a0_256_1);
    // Add a1_256_0 and a1_256_1 and save it to a1_256_0
    a1_256_0 = _mm256_add_epi64(a1_256_0, a1_256_1);
    // Add a2_256_0 and a2_256_1 and save it to a2_256_0
    a2_256_0 = _mm256_add_epi64(a2_256_0, a2_256_1);

    // Downgrade to SSE, a0_128_0, a0_128_1, a1_128_0, a1_128_1, a2_128_0,
    // a2_128_1
    __m128i a0_128_0 = _mm256_extracti128_si256(a0_256_0, 0);
    __m128i a0_128_1 = _mm256_extracti128_si256(a0_256_0, 1);
    __m128i a1_128_0 = _mm256_extracti128_si256(a1_256_0, 0);
    __m128i a1_128_1 = _mm256_extracti128_si256(a1_256_0, 1);
    __m128i a2_128_0 = _mm256_extracti128_si256(a2_256_0, 0);
    __m128i a2_128_1 = _mm256_extracti128_si256(a2_256_0, 1);
    // Add a0_128_0 and a0_128_1 and save it to a0_128_0
    a0_128_0 = _mm_add_epi64(a0_128_0, a0_128_1);
    // Add a1_128_0 and a1_128_1 and save it to a1_128_0
    a1_128_0 = _mm_add_epi64(a1_128_0, a1_128_1);
    // Add a2_128_0 and a2_128_1 and save it to a2_128_0
    a2_128_0 = _mm_add_epi64(a2_128_0, a2_128_1);

    // Fold a0_128_0, a1_128_0, a2_128_0 to a0, a1, a2
    Uint64 _a0, _a1, _a2;
    _a0 = hadd_u64x2(a0_128_0);
    _a1 = hadd_u64x2(a1_128_0);
    _a2 = hadd_u64x2(a2_128_0);

    // Save back _a0, _a1, _a2 to a0, a1, a2, set all other values to 0
    reg_acc0 = _mm512_setr_epi64(_a0, 0, 0, 0, 0, 0, 0, 0);
    reg_acc1 = _mm512_setr_epi64(_a1, 0, 0, 0, 0, 0, 0, 0);
    reg_acc2 = _mm512_setr_epi64(_a2, 0, 0, 0, 0, 0, 0, 0);

    // Optimization: Use 64 bit math to calculate a0, a1, a2 than using 512 bit
    // math. Carry propagation with modulo Right shift a0 by 44 bits
    __m512i carry = _mm512_srlv_epi64(reg_acc0, _mm512_set1_epi64(44));
    // Mask Radix44::mask_low_limb (44 bits) to a0
    reg_acc0 = _mm512_and_epi64(reg_acc0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Add carry to a1
    reg_acc1 = _mm512_add_epi64(reg_acc1, carry);
    // Right shift reg_acc1 by 44 bits
    carry = _mm512_srlv_epi64(reg_acc1, _mm512_set1_epi64(44));
    // Mask Radix44::mask_low_limb (44 bits) to reg_acc1
    reg_acc1 = _mm512_and_epi64(reg_acc1, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Add carry to a2
    reg_acc2 = _mm512_add_epi64(reg_acc2, carry);
    // Right shift reg_acc2 by 42 bits
    carry = _mm512_srlv_epi64(reg_acc2, _mm512_set1_epi64(42));
    // Mask Radix44::mask_last_limb (42 bits) to reg_acc2
    reg_acc2 = _mm512_and_epi64(reg_acc2, _mm512_set1_epi64(Radix44::mask_last_limb));
    // Add carry to reg_acc0
    reg_acc0 = _mm512_add_epi64(
        reg_acc0, _mm512_mullo_epi64(carry, _mm512_set1_epi64(5)));
    // Right shift reg_acc0 by 44 bits
    carry = _mm512_srlv_epi64(reg_acc0, _mm512_set1_epi64(44));
    // Mask Radix44::mask_low_limb (44 bits) to reg_acc0
    reg_acc0 = _mm512_and_epi64(reg_acc0, _mm512_set1_epi64(Radix44::mask_low_limb));
    // Add carry to reg_acc1
    reg_acc1 = _mm512_add_epi64(reg_acc1, carry);

    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}

inline void
poly1305_blocksx1_radix44(Poly1305State44& state,
                          const Uint8*&    pMsg,
                          Uint64&          len)
{
    if (state.fold) {
        // No need to completely fold
        poly1305_blocksx8_to_blocksx1(state);
        state.fold = false;
    }

    Uint64 a0 = state.acc0[0];
    Uint64 a1 = state.acc1[0];
    Uint64 a2 = state.acc2[0];

    const Uint64 r0 = state.r[0];
    const Uint64 r1 = state.r[1];
    const Uint64 r2 = state.r[2];
    const Uint64 s1 = r1 * (5 * 4);
    const Uint64 s2 = r2 * (5 * 4);

    // Fresh-state fast-path: q = 0*r + m == m (skip first multiply).
    if (len >= 16 && (a0 | a1 | a2) == 0) {
        load_message_scalar_radix44(pMsg, a0, a1, a2);
        pMsg += 16;
        len -= 16;
    }

    while (len >= 16) {
        Uint64 m0, m1, m2;
        load_message_scalar_radix44(pMsg, m0, m1, m2);

        poly1305_mult_scalar_radix44(a0, a1, a2, r0, r1, r2, s1, s2);

        a0 += m0;
        a1 += m1;
        a2 += m2;

        pMsg += 16;
        len -= 16;
    }

    state.acc0[0] = a0;
    state.acc1[0] = a1;
    state.acc2[0] = a2;
    for (int i = 1; i < 8; i++) {
        state.acc0[i] = 0;
        state.acc1[i] = 0;
        state.acc2[i] = 0;
    }
}

inline void
poly1305_blockx1_final(__m512i& a0, __m512i& a1, __m512i& a2, Uint64 r[3])
{
    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;

    broadcast_r(r, reg_r0, reg_r1, reg_r2);
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);

    /* Do the last multiplication with "r" */
    poly1305_multx8_radix44(a0, a1, a2, reg_r0, reg_r1, reg_r2, reg_s1, reg_s2);
}

void
poly1305_partial_blocks(Poly1305State44& state)
{
    Uint8* p_msg = state.msg_buffer;

    assert(state.msg_buffer_len < 16);
    if (state.fold == true) {
        poly1305_blocksx8_to_blocksx1(state);
        state.fold = false;
    }

    // Padding
    poly1305_pad_partial_block(p_msg, state.msg_buffer_len);

    Uint64 m0, m1, m2;
    load_message_scalar_radix44_nopad(p_msg, m0, m1, m2);

    state.msg_buffer_len = 0; // Reset message buffer

    Uint64 a0 = state.acc0[0];
    Uint64 a1 = state.acc1[0];
    Uint64 a2 = state.acc2[0];

    const Uint64 r0 = state.r[0];
    const Uint64 r1 = state.r[1];
    const Uint64 r2 = state.r[2];
    const Uint64 s1 = r1 * (5 * 4);
    const Uint64 s2 = r2 * (5 * 4);

    if ((a0 | a1 | a2) == 0) {
        a0 = m0;
        a1 = m1;
        a2 = m2;
    } else {
        poly1305_mult_scalar_radix44(a0, a1, a2, r0, r1, r2, s1, s2);
        a0 += m0;
        a1 += m1;
        a2 += m2;
    }

    state.acc0[0] = a0;
    state.acc1[0] = a1;
    state.acc2[0] = a2;
    for (int i = 1; i < 8; i++) {
        state.acc0[i] = 0;
        state.acc1[i] = 0;
        state.acc2[i] = 0;
    }
}

bool
poly1305_update(Poly1305State44& state, const Uint8* pMsg, Uint64 len)
{
    if (state.finalized == true) {
        return false;
    }
    if (state.msg_buffer_len != 0) {
        Uint64 copy_len = len > (16 - state.msg_buffer_len)
                              ? (16 - state.msg_buffer_len)
                              : len;
        // Handle overhanging data
        std::copy(
            pMsg, pMsg + copy_len, state.msg_buffer + state.msg_buffer_len);
        len -= copy_len;
        state.msg_buffer_len += copy_len;
        pMsg += copy_len;

        const Uint8* p_temp_ptr = state.msg_buffer;
        Uint64       temp_len   = 16;

        if (state.msg_buffer_len == 16) {
            poly1305_blocksx1_radix44(state, p_temp_ptr, temp_len);
            state.msg_buffer_len = 0;
        }
    }
    if (len >= 128) {
        poly1305_blocksx8_radix44(state, pMsg, len);
    }
    if (len >= 16) {
        poly1305_blocksx1_radix44(state, pMsg, len);
    }
    if (len) {
        std::copy(pMsg, pMsg + len, state.msg_buffer);
        state.msg_buffer_len = len;
    }

    return true;
}

bool
poly1305_finalize(Poly1305State44& state,
                          Uint8*           digest,
                          Uint64           digest_len)
{
    if (state.finalized == true) {
        return false;
    }
    // Implement Partial Blocks
    if (state.msg_buffer_len != 0) {
        poly1305_partial_blocks(state);
    }
    if (state.fold) {
        __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
                reg_acc1 = _mm512_load_epi64(state.acc1),
                reg_acc2 = _mm512_load_epi64(state.acc2);
        poly1305_blocksx8_final(reg_acc0,
                                reg_acc1,
                                reg_acc2,
                                state.r,
                                state.r2,
                                state.r3,
                                state.r4,
                                state.r5,
                                state.r6,
                                state.r7,
                                state.r8);
        state.fold = false;

        reg_acc0 = _mm512_add_epi64(reg_acc0, _mm512_set1_epi64(state.s[0]));
        reg_acc1 = _mm512_add_epi64(reg_acc1, _mm512_set1_epi64(state.s[1]));
        reg_acc2 = _mm512_add_epi64(reg_acc2, _mm512_set1_epi64(state.s[2]));

        // Carry Propagation
        // carry = a0>>44
        __m512i carry = _mm512_srli_epi64(reg_acc0, 44);
        // a1 = a1 + carry
        reg_acc1 = _mm512_add_epi64(reg_acc1, carry);
        // a0 = a0 & Radix44::mask_low_limb
        reg_acc0 = _mm512_and_epi64(reg_acc0, _mm512_set1_epi64(Radix44::mask_low_limb));

        // carry = reg_acc1>>44
        carry = _mm512_srli_epi64(reg_acc1, 44);
        // a2 = a2 + carry
        reg_acc2 = _mm512_add_epi64(reg_acc2, carry);
        // reg_acc1 = reg_acc1 & Radix44::mask_low_limb
        reg_acc1 = _mm512_and_epi64(reg_acc1, _mm512_set1_epi64(Radix44::mask_low_limb));

        _mm512_store_epi64(state.acc0, reg_acc0);
        _mm512_store_epi64(state.acc1, reg_acc1);
        _mm512_store_epi64(state.acc2, reg_acc2);
    } else {
        Uint64 a0 = state.acc0[0];
        Uint64 a1 = state.acc1[0];
        Uint64 a2 = state.acc2[0];

        const Uint64 r0 = state.r[0];
        const Uint64 r1 = state.r[1];
        const Uint64 r2 = state.r[2];
        const Uint64 s1 = r1 * (5 * 4);
        const Uint64 s2 = r2 * (5 * 4);

        poly1305_mult_scalar_radix44(a0, a1, a2, r0, r1, r2, s1, s2);

        a0 += state.s[0];
        a1 += state.s[1];
        a2 += state.s[2];

        constexpr Uint64 mask44 = (1ULL << 44) - 1;
        Uint64           carry = a0 >> 44;
        a0 &= mask44;
        a1 += carry;
        carry = a1 >> 44;
        a1 &= mask44;
        a2 += carry;

        state.acc0[0] = a0;
        state.acc1[0] = a1;
        state.acc2[0] = a2;
        for (int i = 1; i < 8; i++) {
            state.acc0[i] = 0;
            state.acc1[i] = 0;
            state.acc2[i] = 0;
        }
    }

    Uint64 digest_temp[2];

    digest_temp[0] = state.acc0[0] | state.acc1[0] << 44;
    digest_temp[1] = (state.acc1[0] >> 20) | state.acc2[0] << 24;

    std::copy(reinterpret_cast<Uint8*>(digest_temp),
              reinterpret_cast<Uint8*>(digest_temp) + 16,
              digest);

    state.finalized = true;
    return true;
}

// End Radix44 Implementation

} // namespace alcp::mac::poly1305::zen4
