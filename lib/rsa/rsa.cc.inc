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

namespace montgomery {

#ifdef COMPILER_IS_GCC
#define UNROLL_7  _Pragma("GCC unroll 7")
#define UNROLL_8  _Pragma("GCC unroll 8")
#define UNROLL_13 _Pragma("GCC unroll 13")
#define UNROLL_14 _Pragma("GCC unroll 14")
#define UNROLL_16 _Pragma("GCC unroll 16")
#define UNROLL_30 _Pragma("GCC unroll 30")
#define UNROLL_64 _Pragma("GCC unroll 64")
#else
#define UNROLL_7
#define UNROLL_8
#define UNROLL_13
#define UNROLL_14
#define UNROLL_16
#define UNROLL_30
#define UNROLL_64
#endif

/*
 * Square of bignum is based on
 *
 * https://ieeexplore.ieee.org/document/6209072
 * "Speeding Up Big-Numbers Squaring"
 *
 */

/*
 * MontMult is based on
 *
 * https://ieeexplore.ieee.org/document/502403
 * Analyzing and comparing Montgomery multiplication algorithms
 *
 */

constexpr Uint64 one_msb = 0x8000000000000000LLU;

struct BigNum
{
    Uint64* m_num  = nullptr;
    Uint64  m_size = 0;
    Uint64  m_pos  = 0;
};

// res size is always 1 greater than second
static inline void
SubBigNum(BigNum& bigNumRes, BigNum& bigNumMod)
{
    Uint64* res = bigNumRes.m_num;
    Uint64* mod = bigNumMod.m_num;

    Uint8 carry = 0;
    for (Uint32 i = 0; i <= bigNumMod.m_pos; i++) {
        carry =
            _subborrow_u64(carry, res[i], mod[i], (unsigned long long*)&res[i]);
    }
    res[bigNumMod.m_pos + 1] -= carry;
    bigNumRes.m_pos = res[bigNumRes.m_pos] == 0 ? bigNumRes.m_pos - 1
                                                : bigNumRes.m_pos;
}

static inline bool
BigNumGreaterEqual(const BigNum& bigNum1, const BigNum& bigNum2)
{
    if (bigNum1.m_pos - bigNum2.m_pos != 0) {
        return bigNum1.m_pos > bigNum2.m_pos;
    }

    Uint64* num1 = bigNum1.m_num;
    Uint64* num2 = bigNum2.m_num;
    for (Uint64 i = bigNum1.m_pos; i >= 0; i--) {
        if (num1[i] != num2[i])
            return (num1[i] > num2[i]) ? true : false;
    }
    return true;
}

static inline void
DoubleBigNum(BigNum& bigNum)
{

    Uint64* num = bigNum.m_num;

    Uint64 carry = 0;
    for (Uint64 i = 0; i <= bigNum.m_pos; i++) {
        carry =
            _addcarryx_u64(carry, num[i], num[i], (unsigned long long*)&num[i]);
    }

    if (carry) {
        num[++bigNum.m_pos] = carry;
    }
}

// k0 = -mod^-1 mod 2^(1024 / 4096 / 8096)
static inline Uint64
computeMontFactor(Uint64 mod)
{
    Uint64 res = 1;
    Uint64 hi = 0, lo = 0;
    Uint64 mask = 3;
    for (Uint64 i = 2; i <= 64; i++) {
        lo = _mulx_u64(mod, res, (long long unsigned int*)&hi);
        if ((lo & mask) != 1) {
            res += (1ULL << (i - 1));
        }
        mask = ((mask << 1) | 1);
    }

    return 0 - res;
}

static inline void
computeMontConverter(BigNum& bigNumRes, BigNum& bigNumMod)
{
    Uint64* mod = bigNumMod.m_num;
    Uint64  len = bigNumMod.m_size * 64 * 2;

    Uint64 i;
    for (i = bigNumMod.m_pos; i >= 0 && mod[i] == 0; i--) {
    }

    // one extra size to store the carry on doubling
    auto res_mod = std::make_unique<Uint64[]>(bigNumMod.m_size + 1);

    BigNum bigNumTmp;
    bigNumTmp.m_num  = res_mod.get();
    bigNumTmp.m_size = bigNumMod.m_size + 1;
    bigNumTmp.m_pos  = i;

    Uint64 num_leading_zero = _lzcnt_u64(mod[i]);
    bigNumTmp.m_num[i]      = 1llu << (64 - num_leading_zero - 1);

    for (Uint64 j = i * 64 + (64 - num_leading_zero); j <= len; j++) {
        DoubleBigNum(bigNumTmp);
        if (BigNumGreaterEqual(bigNumTmp, bigNumMod)) {
            SubBigNum(bigNumTmp, bigNumMod);
        }
    }
    alcp::utils::CopyChunk(
        bigNumRes.m_num, bigNumTmp.m_num, bigNumRes.m_size * 8);
}

static inline Uint8
SubBigNum(Uint64* res, const Uint64* first, const Uint64* second, Uint32 size)
{
    Uint8 carry = 0;
    for (Uint32 i = 0; i < size; i++) {
        carry = _subborrow_u64(
            carry, first[i], second[i], (unsigned long long*)&res[i]);
    }
    return carry;
}

// both numbers size is eqaul
static inline Uint8
AddBigNum(Uint64* res, const Uint64* first, const Uint64* second, Uint32 size)
{
    Uint8 carry = 0;
    for (Uint32 i = 0; i < size; i++) {
        carry = _addcarryx_u64(
            carry, first[i], second[i], (unsigned long long*)&res[i]);
    }
    return carry;
}

// both numbers size is unequal
static inline void
AddBigNum(Uint64*       res,
          Uint32        size,
          const Uint64* first,
          const Uint64* second,
          const Uint64  secondSize)
{
    Uint8 carry = 0;
    for (Uint32 i = 0; i < secondSize; i++) {
        carry = _addcarryx_u64(
            carry, first[i], second[i], (unsigned long long*)&res[i]);
    }

    for (Uint32 i = secondSize; i < size; i++) {
        carry =
            _addcarryx_u64(carry, first[i], 0, (unsigned long long*)&res[i]);
    }
}

static inline void
CopyConditional(Uint64* dest, Uint64* src, Uint64 len, Uint64 mask)
{
    for (Uint64 i = 0; i < len; i++) {
        dest[i] = (src[i] & mask) ^ (dest[i] & ~mask);
    }
}

static inline Uint64
IsZero(Uint64 num)
{
    return 0ULL - (~num & (num - 1) >> 63);
}

static inline void
MontSub(Uint64* res, Uint64* inp1, Uint64* inp2, Uint64* mod, Uint64 size)
{
    Uint64 carry = SubBigNum(res, inp1, inp2, size);

    auto temp     = std::make_unique<Uint64[]>(size);
    auto temp_ptr = temp.get();

    AddBigNum(temp_ptr, res, mod, size);

    CopyConditional(res, temp_ptr, size, ~IsZero(carry));
}
// for i = 0 to s - 1
// 	C = 0

// 	(C,S) := t[0] + a[0] * b[i] + C

// 	C1:=0

// 	m := S * n’[0] mod W
// 	(C1,S) = S + m * n[0]

// 	for j = 1 to s - 1
// 		(C,S) := t[j] + a[j] * b[i] + C
// 	    (C1,S) := S + m * n[j] + C1
// 		t[j- 1] := S

// 	(C,S) := carry_last + C
// 	(C1,S) := S + C1

// 	t[s - 1] := S
// 	carry_last := C + C1

static inline void
MontMult(Uint64*       res,
         const Uint64* first,
         const Uint64* second,
         const Uint64* mod,
         Uint64        k0,
         Uint64        size)
{
    Uint64 carry = 0;
    Uint64 carry0, carry1;
    Uint64 carry_last = 0;
    auto   temp       = std::make_unique<Uint64[]>(size);
    auto   temp_ptr   = temp.get();

    Uint64 lo_t, hi_t, y, lo_t2, hi_t2;
    for (Uint32 i = 0; i < size; i++) {

        Uint64 mult  = second[i];
        Uint64 rem_t = 0, rem_t2 = 0;
        lo_t  = _mulx_u64(first[0], mult, (unsigned long long*)&hi_t);
        carry = _addcarryx_u64(0,
                               (unsigned long long)temp_ptr[0],
                               lo_t,
                               (unsigned long long*)&lo_t);
        rem_t += (carry + hi_t);

        y = lo_t * k0;

        lo_t2 = _mulx_u64(mod[0], y, (unsigned long long*)&hi_t2);

        carry = _addcarryx_u64(0, lo_t2, lo_t, (unsigned long long*)&lo_t);

        rem_t2 += (carry + hi_t2);

        for (Uint32 j = 1; j < size; j++) {

            lo_t   = _mulx_u64(first[j], mult, (unsigned long long*)&hi_t);
            carry0 = _addcarryx_u64(0,
                                    (unsigned long long)temp_ptr[j],
                                    lo_t,
                                    (unsigned long long*)&lo_t);
            carry1 = _addcarryx_u64(0, lo_t, rem_t, (unsigned long long*)&lo_t);

            rem_t = (carry0 + carry1 + hi_t);

            lo_t2 = _mulx_u64(mod[j], y, (unsigned long long*)&hi_t2);

            carry0 = _addcarryx_u64(0, lo_t2, lo_t, (unsigned long long*)&lo_t);

            carry1 =
                _addcarryx_u64(0, rem_t2, lo_t, (unsigned long long*)&lo_t);

            rem_t2 = (carry0 + carry1 + hi_t2);

            temp_ptr[j - 1] = lo_t;
        }

        carry0 =
            _addcarryx_u64(0, rem_t, carry_last, (unsigned long long*)&lo_t);

        carry1 = _addcarryx_u64(
            0, lo_t, rem_t2, (unsigned long long*)&temp_ptr[size - 1]);

        carry_last = carry0 + carry1;
    }
    carry = SubBigNum(res, temp_ptr, mod, size);

    // carry_last will be either 0 or negative
    carry_last -= carry;

    CopyConditional(res, temp_ptr, size, ~IsZero(carry_last));
}

static inline void
MontReduce(Uint64* res, Uint64* inp, Uint64* mod, Uint64 k0, Uint64 size)
{
    Uint64 half_size  = size / 2;
    Uint64 carry_last = 0;

    for (Uint64 i = 0; i < half_size; i++) {
        Uint64  carry = 0;
        Uint64  y     = inp[i] * k0;
        Uint64  lo = 0, hi = 0;
        Uint8   c0 = 0, c1 = 0;
        Uint64* inp_mod = inp + i;
        for (Uint64 j = 0; j < half_size; j++) {
            lo = _mulx_u64(mod[j], y, (long long unsigned*)&hi);
            c0 = _addcarryx_u64(0, lo, inp_mod[j], (long long unsigned*)&lo);
            c1 = _addcarryx_u64(0, lo, carry, (long long unsigned*)&lo);
            inp_mod[j] = lo;
            carry      = hi + c0 + c1;
        }

        c0 = _addcarryx_u64(0,
                            inp_mod[half_size],
                            carry,
                            (long long unsigned*)&inp_mod[half_size]);

        carry_last = _addcarryx_u64(0,
                                    carry_last,
                                    inp_mod[half_size],
                                    (long long unsigned*)&inp_mod[half_size]);

        carry_last += c0;
    }

    Uint64 carry = SubBigNum(res, &inp[half_size], mod, half_size);

    // carry_last will be either 0 or negative
    carry_last -= carry;

    CopyConditional(res, &inp[half_size], half_size, ~IsZero(carry_last));
}

static inline void
CreateContext(MontContextBignum& context, Uint64* mod, Uint64 size)
{
    Uint64* r1 = new Uint64[size]{};
    Uint64* r2 = new Uint64[size]{};

    context.m_r1.reset(r1);
    context.m_r2.reset(r2);
    context.m_size = size;
    context.m_k0   = computeMontFactor(mod[0]);

    BigNum inp{ mod, size, size - 1 }, res{ r2, size, size - 1 };

    computeMontConverter(res, inp);

    auto param     = std::make_unique<Uint64[]>(size * 2);
    auto param_ptr = param.get();
    alcp::utils::CopyChunk(param_ptr, r2, size * 8);

    MontReduce(r1, param_ptr, mod, context.m_k0, size * 2);
}

static inline void
mul(Uint64* res, Uint64* inp1, Uint64 inp1Size, Uint64* inp2, Uint64 inp2Size)
{

    Uint64 hi = 0, lo = 0;
    for (Uint64 i = 0; i < inp1Size; i++) {
        Uint64 a     = inp1[i];
        Uint64 carry = 0;
        for (Uint64 j = 0; j < inp2Size; j++) {
            lo = _mulx_u64(a, inp2[j], (long long unsigned*)&hi);
            Uint8 c1 =
                _addcarryx_u64(0, lo, res[i + j], (long long unsigned*)&lo);
            Uint8 c0 =
                _addcarryx_u64(0, lo, carry, (long long unsigned*)&res[i + j]);
            carry = hi + c1 + c0;
        }
        res[inp2Size + i] = carry;
    }
}

static inline void
Sq512(Uint64* res, Uint64* inp)
{
    UNROLL_7
    for (Uint64 i = 0; i < 7; i++) {
        Uint64 hi    = 0;
        Uint64 lo    = 0;
        Uint64 carry = 0;
        for (Uint64 j = i + 1; j < 8; j++) {

            lo = _mulx_u64(inp[i], inp[j], (long long unsigned*)&hi);
            Uint8 c1 =
                _addcarryx_u64(0, lo, res[i + j], (long long unsigned*)&lo);
            Uint8 c0 =
                _addcarryx_u64(0, lo, carry, (long long unsigned*)&res[i + j]);
            carry = hi + c1 + c0;
        }
        res[i + 8] = carry;
    }
    Uint64 lo = 0;
    Uint8  c1 = 0;
    Uint8  c2 = 0;

    UNROLL_14
    for (Uint64 i = 1; i < 15; i++) {
        lo = res[i];
        c1 = _addcarryx_u64(c1, lo, lo, (long long unsigned*)&lo);

        c2     = _addcarryx_u64(c2, lo, 0, (long long unsigned*)&lo);
        res[i] = lo;
    }
    res[15] = c1 + c2;

    Uint64 hi = 0;
    Uint8  c0 = 0;
    c1        = 0;
    UNROLL_8
    for (Uint64 i = 0; i < 8; i++) {
        Uint64 index      = 2 * i;
        Uint64 next_index = 2 * i + 1;

        lo = inp[i];
        lo = _mulx_u64(lo, lo, (long long unsigned*)&hi);
        c0 = _addcarryx_u64(
            c0, lo, res[index], (long long unsigned*)&res[index]);
        c1 =
            _addcarryx_u64(c1, 0, res[index], (long long unsigned*)&res[index]);

        c0 = _addcarryx_u64(
            c0, hi, res[next_index], (long long unsigned*)&res[next_index]);
        c1 = _addcarryx_u64(
            c1, 0, res[next_index], (long long unsigned*)&res[next_index]);
    }
}

static inline void
Sq1024(Uint64* res, Uint64* inp)
{
    Uint64 hi    = 0;
    Uint64 lo    = 0;
    Uint64 carry = 0;

    UNROLL_7
    for (Uint64 i = 0; i < 7; i++) {
        for (Uint64 j = i + 1; j < 8; j++) {

            lo = _mulx_u64(inp[i], inp[j], (long long unsigned*)&hi);
            Uint8 c1 =
                _addcarryx_u64(0, lo, res[i + j], (long long unsigned*)&lo);
            Uint8 c0 =
                _addcarryx_u64(0, lo, carry, (long long unsigned*)&res[i + j]);
            carry = hi + c1 + c0;
        }
        res[i + 8] = carry;
        carry      = 0;
    }

    UNROLL_8
    for (Uint64 i = 0; i < 8; i++) {

        UNROLL_8
        for (Uint64 j = 8; j < 16; j++) {
            lo = _mulx_u64(inp[i], inp[j], (long long unsigned*)&hi);
            Uint8 c1 =
                _addcarryx_u64(0, lo, res[i + j], (long long unsigned*)&lo);
            Uint8 c0 =
                _addcarryx_u64(0, lo, carry, (long long unsigned*)&res[i + j]);
            carry = hi + c1 + c0;
        }
        res[i + 16] = carry;
        carry       = 0;
    }

    UNROLL_7
    for (Uint64 i = 8; i < 15; i++) {
        for (Uint64 j = i + 1; j < 16; j++) {

            lo = _mulx_u64(inp[i], inp[j], (long long unsigned*)&hi);
            Uint8 c1 =
                _addcarryx_u64(0, lo, res[i + j], (long long unsigned*)&lo);
            Uint8 c0 =
                _addcarryx_u64(0, lo, carry, (long long unsigned*)&res[i + j]);
            carry = hi + c1 + c0;
        }
        res[i + 16] = carry;
        carry       = 0;
    }

    Uint8 c1 = 0;
    Uint8 c2 = 0;

    UNROLL_30
    for (Uint64 i = 1; i < 31; i++) {
        lo = res[i];
        c1 = _addcarryx_u64(c1, lo, lo, (long long unsigned*)&lo);

        c2     = _addcarryx_u64(c2, lo, 0, (long long unsigned*)&lo);
        res[i] = lo;
    }
    res[31] = c1 + c2;

    Uint8 c0 = 0;
    c1       = 0;

    UNROLL_16
    for (Uint64 i = 0; i < 16; i++) {
        Uint64 index      = 2 * i;
        Uint64 next_index = 2 * i + 1;

        lo = inp[i];
        lo = _mulx_u64(lo, lo, (long long unsigned*)&hi);
        c0 = _addcarryx_u64(
            c0, lo, res[index], (long long unsigned*)&res[index]);
        c1 =
            _addcarryx_u64(c1, 0, res[index], (long long unsigned*)&res[index]);

        c0 = _addcarryx_u64(
            c0, hi, res[next_index], (long long unsigned*)&res[next_index]);
        c1 = _addcarryx_u64(
            c1, 0, res[next_index], (long long unsigned*)&res[next_index]);
    }
}

static inline void
MontSq1024(Uint64* res, Uint64* inp, Uint64* mod, Uint64 k0)
{
    Uint64 temp_res[32] = {};
    Sq1024(temp_res, inp);
    MontReduce(res, temp_res, mod, k0, 32);
}

static inline void
MontSq512(Uint64* res, Uint64* inp, Uint64* mod, Uint64 k0)
{
    Uint64 temp_res[16] = {};
    Sq512(temp_res, inp);
    MontReduce(res, temp_res, mod, k0, 16);
}

static inline void
MultAndSquare(
    Uint64* res, Uint64* mult, Uint64* mod, Uint64 k0, Uint64 size, Uint64 val)
{
    // MontMult(res, res, res, mod, k0, size);
    MontSq1024(res, res, mod, k0);
    if (val & one_msb) {
        MontMult(res, res, mult, mod, k0, size);
    }
}

static inline void
PutInTable(Uint64* t, Uint64 index, Uint64* num, Uint64 size, Uint64 limit)
{

    for (Uint64 i = 0; i < size; i++) {
        t[index] = num[i];
        index += limit;
    }
}
static inline void
GetFromTable(Uint64* t, Uint64 index, Uint64* num, Uint64 size, Uint64 limit)
{
    for (Uint64 i = 0; i < size; i++) {
        num[i] = t[index];
        index += limit;
    }
}
// INPUT: an element g ∈ G and positive integer e = (etet−1...e1e0)b
// OUTPUT: g^e
// 1. Precomputation
//      g0 ← 1
//      For i from 1 to (2^k − 1)
//        do: g(i) ← g(i−1).g (g(i) = g^i)
// 2. A ← 1
// 3. For i from t down to 0 do the following:
//      A ← (A^2)^k (k is window size)
//      A ← A · g(ei)
// 4. return(A)
// todo this will be instantiated / optimized depending on the size
static inline void
MontgomeryExpConstantTime(Uint64* res,
                          Uint64* input,
                          Uint64  inpSize,
                          Uint64* exp,
                          Uint64  expSize,
                          Uint64* mod,
                          Uint64* r1,
                          Uint64* r2,
                          Uint64  k0)
{
    __attribute__((aligned(64))) Uint64 t[16 * 8] = {};
    // conversion to mont domain by multiplying with mont converter
    MontMult(res, input, r2, mod, k0, inpSize);
    // to do check which window size is correct
    Uint64 winSize    = 4;
    Uint64 valueLimit = 1 << 4;
    // putting one in montgomery form
    PutInTable(t, 0, r1, inpSize, valueLimit);
    PutInTable(t, 1, input, inpSize, valueLimit);
    auto temp_buff_0 = std::make_unique<Uint64[]>(inpSize);
    auto sq          = temp_buff_0.get();
    auto temp_buff_1 = std::make_unique<Uint64[]>(inpSize);
    auto mult        = temp_buff_1.get();
    alcp::utils::CopyChunk(mult, res, inpSize * 8);
    for (Uint64 i = 2; i < valueLimit; i++) {
        MontMult(mult, mult, res, mod, k0, inpSize);
        PutInTable(t, i, mult, inpSize, valueLimit);
    }
    const Uint8* exp_byte_ptr = reinterpret_cast<const Uint8*>(exp);
    Uint8        index_value  = exp_byte_ptr[63];
    GetFromTable(t, index_value >> 4, sq, inpSize, valueLimit);
    for (Uint64 i = 0; i < winSize; i++) {
        MontSq512(sq, sq, mod, k0);
    }
    GetFromTable(t, index_value & 0xf, mult, inpSize, valueLimit);
    MontMult(sq, sq, mult, mod, k0, inpSize);
    for (Int64 i = 62; i >= 0; --i) {
        for (Uint64 i = 0; i < winSize; i++) {
            MontSq512(sq, sq, mod, k0);
        }
        index_value = exp_byte_ptr[i];
        GetFromTable(t, index_value >> 4, mult, inpSize, valueLimit);
        MontMult(sq, mult, sq, mod, k0, inpSize);
        for (Uint64 i = 0; i < winSize; i++) {
            MontSq512(sq, sq, mod, k0);
        }
        GetFromTable(t, index_value & 0xf, mult, inpSize, valueLimit);
        MontMult(sq, mult, sq, mod, k0, inpSize);
    }

    // convert from mont domain to residue domain
    auto param     = std::make_unique<Uint64[]>(inpSize * 2);
    auto param_ptr = param.get();
    alcp::utils::CopyChunk(param_ptr, sq, inpSize * 8);

    MontReduce(res, param_ptr, mod, k0, inpSize * 2);
}

static inline void
MontgomeryExp(Uint64*       res,
              const Uint64* input,
              Uint64        inpSize,
              Uint64*       exp,
              Uint64        expSize,
              Uint64*       mod,
              Uint64*       r2,
              Uint64        k0)
{
    // conversion to mont domain by multiplying with mont converter
    MontMult(res, input, r2, mod, k0, inpSize);

    Uint64 val = exp[expSize - 1];

    Uint64 num_leading_zero = _lzcnt_u64(val);

    Uint64 index = num_leading_zero + 1;

    val = val << index;

    auto temp_buff = std::make_unique<Uint64[]>(inpSize);
    auto mult      = temp_buff.get();

    alcp::utils::CopyChunk(mult, res, inpSize * 8);

    while (index++ < 64) {
        MultAndSquare(res, mult, mod, k0, inpSize, val);
        val <<= 1;
    }

    for (Int64 i = expSize - 2; i >= 0; i--) {
        val = exp[i];
        UNROLL_64
        for (Uint64 j = 0; j < 64; j++) {
            MultAndSquare(res, mult, mod, k0, inpSize, val);
            val <<= 1;
        }
    }

    // convert from mont domain to residue domain
    auto param     = std::make_unique<Uint64[]>(inpSize * 2);
    auto param_ptr = param.get();
    alcp::utils::CopyChunk(param_ptr, res, inpSize * 8);

    MontReduce(res, param_ptr, mod, k0, inpSize * 2);
}

} // namespace montgomery

// currently it supports equal sizes of P and Q this is faster than the unequal
// sizes preliminary investigation suggest no benefis on using different sizes
// for P and Q
static inline void
decryptUsingCRT(Uint64*              res,
                const Uint64*        inp,
                RsaPrivateKeyBignum& privKey,
                MontContextBignum&   contextP,
                MontContextBignum&   contextQ)
{
    auto size        = contextP.m_size;
    auto temp_buff   = std::make_unique<Uint64[]>(size * 2);
    auto temp_buff_0 = std::make_unique<Uint64[]>(size);
    auto temp_buff_1 = std::make_unique<Uint64[]>(size);

    auto buff_p   = temp_buff.get();
    auto buff_0_p = temp_buff_0.get();
    auto buff_1_p = temp_buff_1.get();
    auto p_mod    = privKey.m_p.get();
    auto p_exp    = privKey.m_dp.get();
    auto q_mod    = privKey.m_q.get();
    auto q_exp    = privKey.m_dq.get();
    auto r1_p     = contextP.m_r1.get();
    auto r2_p     = contextP.m_r2.get();
    auto r1_q     = contextQ.m_r1.get();
    auto r2_q     = contextQ.m_r2.get();
    auto qinv     = privKey.m_qinv.get();
    auto p_k0     = contextP.m_k0;
    auto q_k0     = contextQ.m_k0;

    // P reduction - ap
    alcp::utils::CopyChunk(buff_p, inp, size * 8 * 2);
    montgomery::MontReduce(buff_0_p, buff_p, p_mod, p_k0, size * 2);

    montgomery::MontMult(buff_0_p, buff_0_p, r2_p, p_mod, p_k0, size);

    // Q reduction - aq
    alcp::utils::CopyChunk(buff_p, inp, size * 8 * 2);
    montgomery::MontReduce(buff_1_p, buff_p, q_mod, q_k0, size * 2);
    montgomery::MontMult(buff_1_p, buff_1_p, r2_q, q_mod, q_k0, size);

    // ap = ap ^ dp mod p
    montgomery::MontgomeryExpConstantTime(
        buff_0_p, buff_0_p, size, p_exp, size, p_mod, r1_p, r2_p, p_k0);

    // aq = aq ^dq mod q
    montgomery::MontgomeryExpConstantTime(
        buff_1_p, buff_1_p, size, q_exp, size, q_mod, r1_q, r2_q, q_k0);

    // convert aq to aq mod p
    montgomery::MontSub(buff_1_p, buff_1_p, p_mod, p_mod, size);

    // ap = (ap - aq) mod p
    montgomery::MontSub(buff_0_p, buff_0_p, buff_1_p, p_mod, size);

    // ap = ap*qInv mod P

    // convert qInv to qInv * r mod P
    montgomery::MontMult(res, qinv, r2_p, p_mod, p_k0, size);

    // qInv * r * ap * r^-1 mod P -> qInv * ap mod P
    montgomery::MontMult(buff_0_p, buff_0_p, res, p_mod, p_k0, size);

    alcp::utils::PadBlock(buff_p, 0, size * 8 * 2);

    // ap * Q
    montgomery::mul(buff_p, buff_0_p, size, q_mod, size);

    // res = aq + ap*Q
    montgomery::AddBigNum(res, size * 2, buff_p, buff_1_p, size);
    return;
}

void
archEncryptPublic(Uint8*              pEncText,
                  const Uint64*       pTextBignum,
                  RsaPublicKeyBignum& pubKey,
                  MontContextBignum&  context)
{
    auto size              = pubKey.m_size;
    auto res_buffer_bignum = alcp::rsa::CreateBigNum(nullptr, size * 8);

    auto mod = pubKey.m_mod.get();
    auto r2  = context.m_r2.get();
    auto k0  = context.m_k0;
    auto exp = &pubKey.m_public_exponent;

    montgomery::MontgomeryExp(
        res_buffer_bignum, pTextBignum, size, exp, 1, mod, r2, k0);

    Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
    for (Int64 i = pubKey.m_size * 8 - 1, j = 0; i >= 0; --i, ++j) {
        pEncText[j] = enc_text[i];
    }

    delete[] res_buffer_bignum;
}

void
archDecryptPrivate(Uint8*               pText,
                   const Uint64*        pEncTextBigNum,
                   RsaPrivateKeyBignum& privKey,
                   MontContextBignum&   contextP,
                   MontContextBignum&   contextQ)
{
    auto res_buffer_bignum =
        alcp::rsa::CreateBigNum(nullptr, privKey.m_size * 8 * 2);

    decryptUsingCRT(
        res_buffer_bignum, pEncTextBigNum, privKey, contextP, contextQ);

    Uint8* dec_text = reinterpret_cast<Uint8*>(res_buffer_bignum);

    for (Int64 i = privKey.m_size * 8 * 2 - 1, j = 0; i >= 0; --i, ++j) {
        pText[j] = dec_text[i];
    }

    delete[] res_buffer_bignum;
}

void
archCreateContext(MontContextBignum& context, Uint64* mod, Uint64 size)
{
    montgomery::CreateContext(context, mod, size);
}