// Poly1305 AVX2 radix-26 kernel body, shared by the avx2:: and zen3:: shims.

static inline void
blocks_to_limb(const Uint8 block[16], Uint64 limb[5], bool with_padding)
{
    Uint32 t[4];
    std::memcpy(t, block, 16);
    limb[0] = static_cast<Uint64>(t[0]) & Radix26::mask_low_limb;
    limb[1] = ((static_cast<Uint64>(t[0]) >> Radix26::limb_bits)
               | (static_cast<Uint64>(t[1]) << 6))
              & Radix26::mask_low_limb;
    limb[2] = ((static_cast<Uint64>(t[1]) >> 20)
               | (static_cast<Uint64>(t[2]) << 12))
              & Radix26::mask_low_limb;
    limb[3] = ((static_cast<Uint64>(t[2]) >> 14)
               | (static_cast<Uint64>(t[3]) << 18))
              & Radix26::mask_low_limb;
    limb[4] = static_cast<Uint64>(t[3]) >> 8;
    if (with_padding) {
        limb[4] |= Radix26::high_pad_bit;
    }
}

static inline void
poly1305_mult_scalar_radix26(Uint64&      a0,
                             Uint64&      a1,
                             Uint64&      a2,
                             Uint64&      a3,
                             Uint64&      a4,
                             const Uint64 r0,
                             const Uint64 r1,
                             const Uint64 r2,
                             const Uint64 r3,
                             const Uint64 r4,
                             const Uint64 s0,
                             const Uint64 s1,
                             const Uint64 s2,
                             const Uint64 s3)
{
    const Uint64 d0 = a0 * r0 + a1 * s3 + a2 * s2 + a3 * s1 + a4 * s0;
    const Uint64 d1 = a0 * r1 + a1 * r0 + a2 * s3 + a3 * s2 + a4 * s1;
    const Uint64 d2 = a0 * r2 + a1 * r1 + a2 * r0 + a3 * s3 + a4 * s2;
    const Uint64 d3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0 + a4 * s3;
    const Uint64 d4 = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0;

    Uint64 c;
    Uint64 b0 = d0;
    Uint64 b1 = d1;
    Uint64 b2 = d2;
    Uint64 b3 = d3;
    Uint64 b4 = d4;

    // Carry propagate, then fold limb-4 overflow into limb-0 * wrap_factor.
    c  = b0 >> Radix26::limb_bits;
    b0 &= Radix26::mask_low_limb;
    b1 += c;
    c  = b1 >> Radix26::limb_bits;
    b1 &= Radix26::mask_low_limb;
    b2 += c;
    c  = b2 >> Radix26::limb_bits;
    b2 &= Radix26::mask_low_limb;
    b3 += c;
    c  = b3 >> Radix26::limb_bits;
    b3 &= Radix26::mask_low_limb;
    b4 += c;
    c  = b4 >> Radix26::limb_bits;
    b4 &= Radix26::mask_low_limb;
    b0 += c * Radix26::wrap_factor;
    c  = b0 >> Radix26::limb_bits;
    b0 &= Radix26::mask_low_limb;
    b1 += c;

    a0 = b0;
    a1 = b1;
    a2 = b2;
    a3 = b3;
    a4 = b4;
}

static inline void
poly1305_multx1_standalone(const Uint64 a[5], const Uint64 b[5], Uint64 out[5])
{
    // Pre-scale upper r limbs by wrap_factor so the wraparound terms are ready.
    const Uint64 s0 = b[1] * Radix26::wrap_factor;
    const Uint64 s1 = b[2] * Radix26::wrap_factor;
    const Uint64 s2 = b[3] * Radix26::wrap_factor;
    const Uint64 s3 = b[4] * Radix26::wrap_factor;

    Uint64 a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    poly1305_mult_scalar_radix26(
        a0, a1, a2, a3, a4, b[0], b[1], b[2], b[3], b[4], s0, s1, s2, s3);
    out[0] = a0;
    out[1] = a1;
    out[2] = a2;
    out[3] = a3;
    out[4] = a4;
}

static inline void
loadx4_message_radix26_pad(const Uint8* p_msg, __m256i out[5])
{
    // Permute control that undoes the lane crossing introduced by the unpacks.
    constexpr int cFixLaneCross = 0xD8;

    __m256i lo01 = loadu(p_msg + 0);
    __m256i lo23 = loadu(p_msg + 32);

    __m256i lo_unord = _mm256_unpacklo_epi64(lo01, lo23);
    __m256i hi_unord = _mm256_unpackhi_epi64(lo01, lo23);

    __m256i lo = _mm256_permute4x64_epi64(lo_unord, cFixLaneCross);
    __m256i hi = _mm256_permute4x64_epi64(hi_unord, cFixLaneCross);

    const __m256i mask26 = _mm256_set1_epi64x(Radix26::mask_low_limb);

    out[0] = _mm256_and_si256(lo, mask26);
    out[1] = _mm256_and_si256(_mm256_srli_epi64(lo, Radix26::limb_bits), mask26);

    __m256i tmp = _mm256_or_si256(_mm256_srli_epi64(lo, 52),
                                  _mm256_slli_epi64(hi, 12));
    out[2]      = _mm256_and_si256(tmp, mask26);
    out[3]      = _mm256_and_si256(_mm256_srli_epi64(hi, 14), mask26);

    const __m256i pad = _mm256_set1_epi64x(Radix26::high_pad_bit);
    out[4]            = _mm256_or_si256(_mm256_srli_epi64(hi, 40), pad);
}


// 4-way Poly1305 Horner multiply (a * r mod P).
static inline void
poly1305_multx4_radix26(__m256i&      a0,
                        __m256i&      a1,
                        __m256i&      a2,
                        __m256i&      a3,
                        __m256i&      a4,
                        const __m256i r0,
                        const __m256i r1,
                        const __m256i r2,
                        const __m256i r3,
                        const __m256i r4,
                        const __m256i s0,
                        const __m256i s1,
                        const __m256i s2,
                        const __m256i s3)
{
    __m256i d0 = _mm256_mul_epu32(a0, r0);
    d0         = _mm256_add_epi64(d0, _mm256_mul_epu32(a1, s3));
    d0         = _mm256_add_epi64(d0, _mm256_mul_epu32(a2, s2));
    d0         = _mm256_add_epi64(d0, _mm256_mul_epu32(a3, s1));
    d0         = _mm256_add_epi64(d0, _mm256_mul_epu32(a4, s0));

    __m256i d1 = _mm256_mul_epu32(a0, r1);
    d1         = _mm256_add_epi64(d1, _mm256_mul_epu32(a1, r0));
    d1         = _mm256_add_epi64(d1, _mm256_mul_epu32(a2, s3));
    d1         = _mm256_add_epi64(d1, _mm256_mul_epu32(a3, s2));
    d1         = _mm256_add_epi64(d1, _mm256_mul_epu32(a4, s1));

    __m256i d2 = _mm256_mul_epu32(a0, r2);
    d2         = _mm256_add_epi64(d2, _mm256_mul_epu32(a1, r1));
    d2         = _mm256_add_epi64(d2, _mm256_mul_epu32(a2, r0));
    d2         = _mm256_add_epi64(d2, _mm256_mul_epu32(a3, s3));
    d2         = _mm256_add_epi64(d2, _mm256_mul_epu32(a4, s2));

    __m256i d3 = _mm256_mul_epu32(a0, r3);
    d3         = _mm256_add_epi64(d3, _mm256_mul_epu32(a1, r2));
    d3         = _mm256_add_epi64(d3, _mm256_mul_epu32(a2, r1));
    d3         = _mm256_add_epi64(d3, _mm256_mul_epu32(a3, r0));
    d3         = _mm256_add_epi64(d3, _mm256_mul_epu32(a4, s3));

    __m256i d4 = _mm256_mul_epu32(a0, r4);
    d4         = _mm256_add_epi64(d4, _mm256_mul_epu32(a1, r3));
    d4         = _mm256_add_epi64(d4, _mm256_mul_epu32(a2, r2));
    d4         = _mm256_add_epi64(d4, _mm256_mul_epu32(a3, r1));
    d4         = _mm256_add_epi64(d4, _mm256_mul_epu32(a4, r0));

    const __m256i mask26 = _mm256_set1_epi64x(Radix26::mask_low_limb);
    __m256i       c;

    c  = _mm256_srli_epi64(d0, Radix26::limb_bits);
    d0 = _mm256_and_si256(d0, mask26);
    d1 = _mm256_add_epi64(d1, c);

    c  = _mm256_srli_epi64(d1, Radix26::limb_bits);
    d1 = _mm256_and_si256(d1, mask26);
    d2 = _mm256_add_epi64(d2, c);

    c  = _mm256_srli_epi64(d2, Radix26::limb_bits);
    d2 = _mm256_and_si256(d2, mask26);
    d3 = _mm256_add_epi64(d3, c);

    c  = _mm256_srli_epi64(d3, Radix26::limb_bits);
    d3 = _mm256_and_si256(d3, mask26);
    d4 = _mm256_add_epi64(d4, c);

    c  = _mm256_srli_epi64(d4, Radix26::limb_bits);
    d4 = _mm256_and_si256(d4, mask26);

    __m256i c5 = _mm256_add_epi64(_mm256_slli_epi64(c, 2), c);
    d0         = _mm256_add_epi64(d0, c5);

    c  = _mm256_srli_epi64(d0, Radix26::limb_bits);
    d0 = _mm256_and_si256(d0, mask26);
    d1 = _mm256_add_epi64(d1, c);

    a0 = d0;
    a1 = d1;
    a2 = d2;
    a3 = d3;
    a4 = d4;
}

static inline void
load_powers(const Uint64 pack[5][4],
            const Uint64 s[4][4],
            __m256i&     r0,
            __m256i&     r1,
            __m256i&     r2,
            __m256i&     r3,
            __m256i&     r4,
            __m256i&     s0,
            __m256i&     s1,
            __m256i&     s2,
            __m256i&     s3)
{
    r0 = loadu(pack[0]);
    r1 = loadu(pack[1]);
    r2 = loadu(pack[2]);
    r3 = loadu(pack[3]);
    r4 = loadu(pack[4]);
    s0 = loadu(s[0]);
    s1 = loadu(s[1]);
    s2 = loadu(s[2]);
    s3 = loadu(s[3]);
}

static void
ensure_powers(Poly1305State26x4& state)
{
    if (state.powers_computed) {
        return;
    }

    Uint64 r1[5];
    r1[0] = state.r1_pack[0][0];
    r1[1] = state.r1_pack[1][0];
    r1[2] = state.r1_pack[2][0];
    r1[3] = state.r1_pack[3][0];
    r1[4] = state.r1_pack[4][0];

    Uint64 r2[5], r3[5], r4[5];
    poly1305_multx1_standalone(r1, r1, r2);
    poly1305_multx1_standalone(r2, r1, r3);
    poly1305_multx1_standalone(r2, r2, r4);

    for (int i = 0; i < 5; i++) {
        state.r4_pack[i][0] = r4[i];
        state.r4_pack[i][1] = r4[i];
        state.r4_pack[i][2] = r4[i];
        state.r4_pack[i][3] = r4[i];

        state.rp_pack[i][0] = r4[i];
        state.rp_pack[i][1] = r3[i];
        state.rp_pack[i][2] = r2[i];
        state.rp_pack[i][3] = r1[i];
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state.r4_s[i][j] = state.r4_pack[i + 1][j] * Radix26::wrap_factor;
            state.rp_s[i][j] = state.rp_pack[i + 1][j] * Radix26::wrap_factor;
        }
    }

    state.powers_computed = true;
}

static void
ensure_powers8(Poly1305State26x4& state)
{
    // The x8 path adds r^5..r^8 on top of the x4 tables (r^8 advances each
    // stream, r^8..r^5 fold the streams). Cached once per key.
    ensure_powers(state);
    if (state.powers8_computed) {
        return;
    }

    Uint64 r1[5], r2[5], r3[5], r4[5], r5[5], r6[5], r7[5], r8[5];
    for (int i = 0; i < 5; i++) {
        r1[i] = state.r1_pack[i][0];
        r2[i] = state.rp_pack[i][2];
        r3[i] = state.rp_pack[i][1];
        r4[i] = state.r4_pack[i][0];
    }

    poly1305_multx1_standalone(r4, r1, r5);
    poly1305_multx1_standalone(r4, r2, r6);
    poly1305_multx1_standalone(r4, r3, r7);
    poly1305_multx1_standalone(r4, r4, r8);

    for (int i = 0; i < 5; i++) {
        state.r8_pack[i][0] = r8[i];
        state.r8_pack[i][1] = r8[i];
        state.r8_pack[i][2] = r8[i];
        state.r8_pack[i][3] = r8[i];

        // r8_pack: r^8 broadcast (loop multiplier). r8p_pack: stream-A fold
        // powers [r^8, r^7, r^6, r^5].
        state.r8p_pack[i][0] = r8[i];
        state.r8p_pack[i][1] = r7[i];
        state.r8p_pack[i][2] = r6[i];
        state.r8p_pack[i][3] = r5[i];
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state.r8_s[i][j] = state.r8_pack[i + 1][j] * Radix26::wrap_factor;
            state.r8p_s[i][j] = state.r8p_pack[i + 1][j] * Radix26::wrap_factor;
        }
    }

    state.powers8_computed = true;
}

static inline void
poly1305_blocksx1_radix26(Poly1305State26x4& state,
                          const Uint8*&      pMsg,
                          Uint64&            len)
{
    Uint64 a0 = state.acc_scalar[0];
    Uint64 a1 = state.acc_scalar[1];
    Uint64 a2 = state.acc_scalar[2];
    Uint64 a3 = state.acc_scalar[3];
    Uint64 a4 = state.acc_scalar[4];

    const Uint64 r0 = state.r1_pack[0][0];
    const Uint64 r1 = state.r1_pack[1][0];
    const Uint64 r2 = state.r1_pack[2][0];
    const Uint64 r3 = state.r1_pack[3][0];
    const Uint64 r4 = state.r1_pack[4][0];
    const Uint64 s0 = state.r1_s[0][0];
    const Uint64 s1 = state.r1_s[1][0];
    const Uint64 s2 = state.r1_s[2][0];
    const Uint64 s3 = state.r1_s[3][0];

    while (len >= 16) {
        Uint64 m[5];
        blocks_to_limb(pMsg, m, true);

        a0 += m[0];
        a1 += m[1];
        a2 += m[2];
        a3 += m[3];
        a4 += m[4];

        poly1305_mult_scalar_radix26(
            a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s0, s1, s2, s3);

        pMsg += 16;
        len -= 16;
    }

    state.acc_scalar[0] = a0;
    state.acc_scalar[1] = a1;
    state.acc_scalar[2] = a2;
    state.acc_scalar[3] = a3;
    state.acc_scalar[4] = a4;
}


// Seed the SIMD accumulator: carry any scalar accumulator into lane 0, then
// absorb the first 4 blocks across the lanes.
static inline void
poly1305_blocksx1_to_blocksx4(Poly1305State26x4& state,
                              const Uint8*&      pMsg,
                              Uint64&            len)
{
    __m256i a0 = _mm256_setzero_si256();
    __m256i a1 = _mm256_setzero_si256();
    __m256i a2 = _mm256_setzero_si256();
    __m256i a3 = _mm256_setzero_si256();
    __m256i a4 = _mm256_setzero_si256();

    if ((state.acc_scalar[0] | state.acc_scalar[1] | state.acc_scalar[2]
         | state.acc_scalar[3] | state.acc_scalar[4])
        != 0) {
        a0 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[0]);
        a1 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[1]);
        a2 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[2]);
        a3 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[3]);
        a4 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[4]);

        state.acc_scalar[0] = 0;
        state.acc_scalar[1] = 0;
        state.acc_scalar[2] = 0;
        state.acc_scalar[3] = 0;
        state.acc_scalar[4] = 0;
    }

    __m256i m[5];
    loadx4_message_radix26_pad(pMsg, m);

    a0 = _mm256_add_epi64(a0, m[0]);
    a1 = _mm256_add_epi64(a1, m[1]);
    a2 = _mm256_add_epi64(a2, m[2]);
    a3 = _mm256_add_epi64(a3, m[3]);
    a4 = _mm256_add_epi64(a4, m[4]);

    pMsg += 64;
    len -= 64;

    storeu(&state.acc[0][0], a0);
    storeu(&state.acc[1][0], a1);
    storeu(&state.acc[2][0], a2);
    storeu(&state.acc[3][0], a3);
    storeu(&state.acc[4][0], a4);
}

static inline void
poly1305_blocksx4_radix26(Poly1305State26x4& state,
                          const Uint8*&      pMsg,
                          Uint64&            len)
{
    if (!state.fold) {
        poly1305_blocksx1_to_blocksx4(state, pMsg, len);
        state.fold = true;
    }

    __m256i a0 = loadu(&state.acc[0][0]);
    __m256i a1 = loadu(&state.acc[1][0]);
    __m256i a2 = loadu(&state.acc[2][0]);
    __m256i a3 = loadu(&state.acc[3][0]);
    __m256i a4 = loadu(&state.acc[4][0]);

    __m256i r0, r1, r2, r3, r4, s0, s1, s2, s3;
    // r^4 broadcast: the x4 loop multiplier.
    load_powers(state.r4_pack, state.r4_s, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    while (len >= 64) {
        __m256i m[5];
        poly1305_multx4_radix26(
            a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s0, s1, s2, s3);

        // Load the message only after the multiply: it is not needed until the
        // add, and loading earlier would keep 5 extra vectors live through the
        // register-heavy multiply, forcing stack spills.
        loadx4_message_radix26_pad(pMsg, m);
        a0 = _mm256_add_epi64(a0, m[0]);
        a1 = _mm256_add_epi64(a1, m[1]);
        a2 = _mm256_add_epi64(a2, m[2]);
        a3 = _mm256_add_epi64(a3, m[3]);
        a4 = _mm256_add_epi64(a4, m[4]);

        pMsg += 64;
        len -= 64;
    }

    storeu(&state.acc[0][0], a0);
    storeu(&state.acc[1][0], a1);
    storeu(&state.acc[2][0], a2);
    storeu(&state.acc[3][0], a3);
    storeu(&state.acc[4][0], a4);
}


// Horizontal sum of the 4 u64 lanes of a ymm register.
static inline Uint64
hsum_u64(__m256i v)
{
    __m128i lo = _mm256_castsi256_si128(v);
    __m128i hi = _mm256_extracti128_si256(v, 1);
    __m128i s  = _mm_add_epi64(lo, hi);
    return static_cast<Uint64>(_mm_cvtsi128_si64(s))
           + static_cast<Uint64>(_mm_extract_epi64(s, 1));
}

static inline void
fold_vecx4_to_scalar(Poly1305State26x4& state,
                     __m256i            a0,
                     __m256i            a1,
                     __m256i            a2,
                     __m256i            a3,
                     __m256i            a4)
{
    Uint64 b0 = hsum_u64(a0);
    Uint64 b1 = hsum_u64(a1);
    Uint64 b2 = hsum_u64(a2);
    Uint64 b3 = hsum_u64(a3);
    Uint64 b4 = hsum_u64(a4);

    Uint64 c;
    c  = b0 >> Radix26::limb_bits;
    b0 &= Radix26::mask_low_limb;
    b1 += c;
    c  = b1 >> Radix26::limb_bits;
    b1 &= Radix26::mask_low_limb;
    b2 += c;
    c  = b2 >> Radix26::limb_bits;
    b2 &= Radix26::mask_low_limb;
    b3 += c;
    c  = b3 >> Radix26::limb_bits;
    b3 &= Radix26::mask_low_limb;
    b4 += c;
    c  = b4 >> Radix26::limb_bits;
    b4 &= Radix26::mask_low_limb;
    b0 += c * Radix26::wrap_factor;
    c  = b0 >> Radix26::limb_bits;
    b0 &= Radix26::mask_low_limb;
    b1 += c;

    state.acc_scalar[0] = b0;
    state.acc_scalar[1] = b1;
    state.acc_scalar[2] = b2;
    state.acc_scalar[3] = b3;
    state.acc_scalar[4] = b4;
}

static inline void
poly1305_blocksx4_to_blocksx1(Poly1305State26x4& state)
{
    __m256i a0 = loadu(&state.acc[0][0]);
    __m256i a1 = loadu(&state.acc[1][0]);
    __m256i a2 = loadu(&state.acc[2][0]);
    __m256i a3 = loadu(&state.acc[3][0]);
    __m256i a4 = loadu(&state.acc[4][0]);

    __m256i r0, r1, r2, r3, r4, s0, s1, s2, s3;
    load_powers(state.rp_pack, state.rp_s, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    poly1305_multx4_radix26(
        a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    fold_vecx4_to_scalar(state, a0, a1, a2, a3, a4);

    std::fill_n(&state.acc[0][0], 5 * 4, 0);
}

static inline void
poly1305_blocksx8_dualstream_radix26(Poly1305State26x4& state,
                                     const Uint8*&      pMsg,
                                     Uint64&            len)
{
    /*
     * Two independent x4 streams (A: blocks 0-3,8-11,...; B: blocks 4-7,...)
     * break the single x4 dependency chain so the CPU has more parallel work.
     * Each stream advances by r^8 (8 blocks between updates) and the pair is
     * folded back to one scalar accumulator on exit; x8 holds no persistent
     * state.
     */
    if (state.fold) {
        poly1305_blocksx4_to_blocksx1(state);
        state.fold = false;
    }
    if (len < 128) {
        return;
    }

    __m256i a0 = _mm256_setzero_si256();
    __m256i a1 = _mm256_setzero_si256();
    __m256i a2 = _mm256_setzero_si256();
    __m256i a3 = _mm256_setzero_si256();
    __m256i a4 = _mm256_setzero_si256();

    // Seed stream A: fold any prior scalar accumulator into lane 0, then
    // absorb the first 4 blocks.
    if ((state.acc_scalar[0] | state.acc_scalar[1] | state.acc_scalar[2]
         | state.acc_scalar[3] | state.acc_scalar[4])
        != 0) {
        a0 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[0]);
        a1 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[1]);
        a2 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[2]);
        a3 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[3]);
        a4 = _mm256_set_epi64x(0, 0, 0, state.acc_scalar[4]);

        state.acc_scalar[0] = 0;
        state.acc_scalar[1] = 0;
        state.acc_scalar[2] = 0;
        state.acc_scalar[3] = 0;
        state.acc_scalar[4] = 0;
    }

    __m256i m[5];
    loadx4_message_radix26_pad(pMsg, m);
    a0 = _mm256_add_epi64(a0, m[0]);
    a1 = _mm256_add_epi64(a1, m[1]);
    a2 = _mm256_add_epi64(a2, m[2]);
    a3 = _mm256_add_epi64(a3, m[3]);
    a4 = _mm256_add_epi64(a4, m[4]);
    pMsg += 64;
    len -= 64;

    // Seed stream B with the next 4 blocks (no scalar history: it all went to A).
    __m256i b0 = _mm256_setzero_si256();
    __m256i b1 = _mm256_setzero_si256();
    __m256i b2 = _mm256_setzero_si256();
    __m256i b3 = _mm256_setzero_si256();
    __m256i b4 = _mm256_setzero_si256();

    loadx4_message_radix26_pad(pMsg, m);
    b0 = _mm256_add_epi64(b0, m[0]);
    b1 = _mm256_add_epi64(b1, m[1]);
    b2 = _mm256_add_epi64(b2, m[2]);
    b3 = _mm256_add_epi64(b3, m[3]);
    b4 = _mm256_add_epi64(b4, m[4]);
    pMsg += 64;
    len -= 64;

    __m256i r0, r1, r2, r3, r4, s0, s1, s2, s3;
    // r^8 broadcast: both x8 streams advance 8 blocks between updates.
    load_powers(state.r8_pack, state.r8_s, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    while (len >= 128) {
        // Advance stream A by r^8, then absorb 4 blocks (multiply before load
        // to keep message limbs out of the multiply's live range).
        poly1305_multx4_radix26(
            a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s0, s1, s2, s3);
        loadx4_message_radix26_pad(pMsg, m);
        a0 = _mm256_add_epi64(a0, m[0]);
        a1 = _mm256_add_epi64(a1, m[1]);
        a2 = _mm256_add_epi64(a2, m[2]);
        a3 = _mm256_add_epi64(a3, m[3]);
        a4 = _mm256_add_epi64(a4, m[4]);
        pMsg += 64;
        len -= 64;

        // Advance stream B likewise; A and B are independent dependency chains.
        poly1305_multx4_radix26(
            b0, b1, b2, b3, b4, r0, r1, r2, r3, r4, s0, s1, s2, s3);
        loadx4_message_radix26_pad(pMsg, m);
        b0 = _mm256_add_epi64(b0, m[0]);
        b1 = _mm256_add_epi64(b1, m[1]);
        b2 = _mm256_add_epi64(b2, m[2]);
        b3 = _mm256_add_epi64(b3, m[3]);
        b4 = _mm256_add_epi64(b4, m[4]);
        pMsg += 64;
        len -= 64;
    }

    // Fold to one accumulator: scale stream A lanes by [r^8..r^5] and stream B
    // by [r^4..r], add, then collapse lanes to scalar.
    load_powers(state.r8p_pack, state.r8p_s, r0, r1, r2, r3, r4, s0, s1, s2, s3);
    poly1305_multx4_radix26(
        a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    load_powers(state.rp_pack, state.rp_s, r0, r1, r2, r3, r4, s0, s1, s2, s3);
    poly1305_multx4_radix26(
        b0, b1, b2, b3, b4, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    a0 = _mm256_add_epi64(a0, b0);
    a1 = _mm256_add_epi64(a1, b1);
    a2 = _mm256_add_epi64(a2, b2);
    a3 = _mm256_add_epi64(a3, b3);
    a4 = _mm256_add_epi64(a4, b4);
    fold_vecx4_to_scalar(state, a0, a1, a2, a3, a4);
}

static void
poly1305_partial_blocks(Poly1305State26x4& state)
{
    if (state.fold) {
        poly1305_blocksx4_to_blocksx1(state);
        state.fold = false;
    }

    poly1305_pad_partial_block(state.msg_buffer, state.msg_buffer_len);

    Uint64 m[5];
    blocks_to_limb(state.msg_buffer, m, false);
    state.msg_buffer_len = 0;

    Uint64 a0 = state.acc_scalar[0];
    Uint64 a1 = state.acc_scalar[1];
    Uint64 a2 = state.acc_scalar[2];
    Uint64 a3 = state.acc_scalar[3];
    Uint64 a4 = state.acc_scalar[4];

    const Uint64 r0 = state.r1_pack[0][0];
    const Uint64 r1 = state.r1_pack[1][0];
    const Uint64 r2 = state.r1_pack[2][0];
    const Uint64 r3 = state.r1_pack[3][0];
    const Uint64 r4 = state.r1_pack[4][0];
    const Uint64 s0 = state.r1_s[0][0];
    const Uint64 s1 = state.r1_s[1][0];
    const Uint64 s2 = state.r1_s[2][0];
    const Uint64 s3 = state.r1_s[3][0];

    a0 += m[0];
    a1 += m[1];
    a2 += m[2];
    a3 += m[3];
    a4 += m[4];

    poly1305_mult_scalar_radix26(
        a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s0, s1, s2, s3);

    state.acc_scalar[0] = a0;
    state.acc_scalar[1] = a1;
    state.acc_scalar[2] = a2;
    state.acc_scalar[3] = a3;
    state.acc_scalar[4] = a4;
}

void
poly1305_init(Poly1305State26x4& state, const Uint8 key[32])
{
    Uint8 r[16];
    utils::SecureCopy<Uint8>(r, 16, key, 16);
    poly1305_clamp_r(r);

    Uint64 r1[5];
    blocks_to_limb(r, r1, false);

    state.r1_pack[0][0] = r1[0];
    state.r1_pack[1][0] = r1[1];
    state.r1_pack[2][0] = r1[2];
    state.r1_pack[3][0] = r1[3];
    state.r1_pack[4][0] = r1[4];

    state.r1_s[0][0] = r1[1] * Radix26::wrap_factor;
    state.r1_s[1][0] = r1[2] * Radix26::wrap_factor;
    state.r1_s[2][0] = r1[3] * Radix26::wrap_factor;
    state.r1_s[3][0] = r1[4] * Radix26::wrap_factor;

    std::memcpy(state.s_key, key + 16, 16);

    state.reset(false);
}

bool
poly1305_update(Poly1305State26x4& state, const Uint8* pMsg, Uint64 len)
{
    if (state.finalized) {
        return false;
    }

    if (state.msg_buffer_len != 0) {
        Uint64 want = 16 - state.msg_buffer_len;
        Uint64 take = len < want ? len : want;
        std::memcpy(state.msg_buffer + state.msg_buffer_len, pMsg, take);
        state.msg_buffer_len += take;
        pMsg += take;
        len -= take;


        // A full 16-byte buffer must be drained scalar-side first. Fold any live
        // SIMD lanes back beforehand, else the scalar path reads a stale (zero)
        // acc_scalar.
        if (state.msg_buffer_len == 16) {
            if (state.fold) {
                poly1305_blocksx4_to_blocksx1(state);
                state.fold = false;
            }
            const Uint8* p_temp = state.msg_buffer;
            Uint64       l_temp = 16;
            poly1305_blocksx1_radix26(state, p_temp, l_temp);
            state.msg_buffer_len = 0;
        }
    }

    if (len >= 2048) {
        // x8 only pays off once its setup/fold-back cost is amortized.
        ensure_powers8(state);
        poly1305_blocksx8_dualstream_radix26(state, pMsg, len);
    }

    // x4 break-even is ~256 B; below that the r-power setup loses to scalar.
    if (len >= 256) {
        ensure_powers(state);
        poly1305_blocksx4_radix26(state, pMsg, len);
    }

    if (len >= 16) {
        if (state.fold) {
            poly1305_blocksx4_to_blocksx1(state);
            state.fold = false;
        }
        poly1305_blocksx1_radix26(state, pMsg, len);
    }

    if (len > 0) {
        std::memcpy(state.msg_buffer, pMsg, len);
        state.msg_buffer_len = len;
    }

    return true;
}

bool
poly1305_finalize(Poly1305State26x4& state, Uint8* digest, Uint64 digestLen)
{
    if (state.finalized) {
        return false;
    }
    if (digestLen != 16) {
        return false;
    }

    if (state.msg_buffer_len != 0) {
        poly1305_partial_blocks(state);
    } else if (state.fold) {
        poly1305_blocksx4_to_blocksx1(state);
        state.fold = false;
    }

    Uint64 a0 = state.acc_scalar[0];
    Uint64 a1 = state.acc_scalar[1];
    Uint64 a2 = state.acc_scalar[2];
    Uint64 a3 = state.acc_scalar[3];
    Uint64 a4 = state.acc_scalar[4];

    Uint64 c;
    c  = a1 >> Radix26::limb_bits;
    a1 &= Radix26::mask_low_limb;
    a2 += c;
    c  = a2 >> Radix26::limb_bits;
    a2 &= Radix26::mask_low_limb;
    a3 += c;
    c  = a3 >> Radix26::limb_bits;
    a3 &= Radix26::mask_low_limb;
    a4 += c;
    c  = a4 >> Radix26::limb_bits;
    a4 &= Radix26::mask_low_limb;
    a0 += c * Radix26::wrap_factor;
    c  = a0 >> Radix26::limb_bits;
    a0 &= Radix26::mask_low_limb;
    a1 += c;

    /*
     * Final reduction: t = a + 5 - 2^130; bit 63 of t4 is the borrow flag.
     * The select is branchless: a secret-dependent `if` here would be a timing
     * side channel.
     */
    Uint64 t0 = a0 + 5;
    c         = t0 >> Radix26::limb_bits;
    t0 &= Radix26::mask_low_limb;
    Uint64 t1 = a1 + c;
    c         = t1 >> Radix26::limb_bits;
    t1 &= Radix26::mask_low_limb;
    Uint64 t2 = a2 + c;
    c         = t2 >> Radix26::limb_bits;
    t2 &= Radix26::mask_low_limb;
    Uint64 t3 = a3 + c;
    c         = t3 >> Radix26::limb_bits;
    t3 &= Radix26::mask_low_limb;
    Uint64 t4 = a4 + c - (Radix26::mask_low_limb + 1);

    // all-ones when a >= P (borrow clear), all-zeros when a < P.
    const Uint64 take_reduced = (t4 >> 63) - 1;
    a0 = (t0 & take_reduced) | (a0 & ~take_reduced);
    a1 = (t1 & take_reduced) | (a1 & ~take_reduced);
    a2 = (t2 & take_reduced) | (a2 & ~take_reduced);
    a3 = (t3 & take_reduced) | (a3 & ~take_reduced);
    a4 = (t4 & take_reduced) | (a4 & ~take_reduced);

    Uint32 packed[4];
    packed[0] = static_cast<Uint32>((a0 | (a1 << 26)) & 0xffffffffu);
    packed[1] = static_cast<Uint32>(((a1 >> 6) | (a2 << 20)) & 0xffffffffu);
    packed[2] = static_cast<Uint32>(((a2 >> 12) | (a3 << 14)) & 0xffffffffu);
    packed[3] = static_cast<Uint32>(((a3 >> 18) | (a4 << 8)) & 0xffffffffu);

    Uint64 f;
    f         = static_cast<Uint64>(packed[0]) + state.s_key[0];
    packed[0] = static_cast<Uint32>(f);
    f         = static_cast<Uint64>(packed[1]) + state.s_key[1] + (f >> 32);
    packed[1] = static_cast<Uint32>(f);
    f         = static_cast<Uint64>(packed[2]) + state.s_key[2] + (f >> 32);
    packed[2] = static_cast<Uint32>(f);
    f         = static_cast<Uint64>(packed[3]) + state.s_key[3] + (f >> 32);
    packed[3] = static_cast<Uint32>(f);

    std::memcpy(digest, packed, 16);

    state.finalized = true;
    return true;
}
