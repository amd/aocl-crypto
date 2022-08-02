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
#include <algorithm>
#include <climits>
#include <functional>
#include <string>

#ifdef USE_AOCL_CPUID
#include "alci/cpu_features.h"
#endif

#include "digest/sha2_512.hh"

#include "digest/sha_avx2.hh"

#include "utils/bits.hh"
#include "utils/copy.hh"
#include "utils/endian.hh"

namespace utils = alcp::utils;

namespace alcp::digest {

/*
 * first 64 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */
static constexpr Uint64 cIv[] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                                  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

/*
 * Round constants:
 * For each round, there is one round constant k[i] and one entry in the
 * message schedule array w[i], 0 ≤ i ≤ 80.
 * Values are first 64 bits of the fractional parts of the cube
 * roots of the first 80 primes 2.409.
 */
__attribute__((aligned(64))) static constexpr Uint64 cRoundConstants[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static bool
isAvx2Available()
{
    static bool s_avx2_available = true;
    return s_avx2_available;
}

Sha512::Sha512()
    : m_msg_len{ 0 }
    , m_hash{ 0,}
    , m_idx{ 0 }
    , m_finished{ false }
{
    m_mode             = ALC_SHA2_512;
    m_digest_len       = ALC_DIGEST_LEN_512;
    m_digest_len_bytes = 512 / 8;

    utils::CopyQWord(&m_hash[0], &cIv[0], cHashSize);
}

Sha512::Sha512(const alc_digest_info_t& rDigestInfo)
    : Sha512()
{}

Sha512::~Sha512() {}

alc_error_t
Sha512::setIv(const void* pIv, Uint64 size)
{
    utils::CopyBytes(m_hash, pIv, size);

    return ALC_ERROR_NONE;
}

void
Sha512::reset()
{
    m_msg_len  = 0;
    m_finished = false;
    m_idx      = 0;
    utils::CopyQWord(&m_hash[0], &cIv[0], cHashSize);
}

alc_error_t
Sha512::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pHash == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    if (size < cHashSize) {
        Error::setGeneric(err, ALC_ERROR_INVALID_SIZE);
    }

    if (!Error::isError(err))
        utils::CopyBlockWith<Uint64>(
            pHash, m_hash, cHashSize, utils::ToBigEndian<Uint64>);

    return err;
}

static inline void
CompressMsg(Uint64 pMsgSchArray[], Uint64* pHash, const Uint64* pHashConstants)
{
    Uint64 a, b, c, d, e, f, g, h;
    a = pHash[0];
    b = pHash[1];
    c = pHash[2];
    d = pHash[3];
    e = pHash[4];
    f = pHash[5];
    g = pHash[6];
    h = pHash[7];
    for (Uint32 i = 0; i < 80; i++) {
        Uint64 s1, ch, temp1, s0, maj, temp2;
        s1    = RotateRight(e, 14) ^ RotateRight(e, 18) ^ RotateRight(e, 41);
        ch    = (e & f) ^ (~e & g);
        temp1 = h + s1 + ch + pHashConstants[i] + pMsgSchArray[i];
        s0    = RotateRight(a, 28) ^ RotateRight(a, 34) ^ RotateRight(a, 39);
        maj   = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;
        h     = g;
        g     = f;
        f     = e;
        e     = d + temp1;
        d     = c;
        c     = b;
        b     = a;
        a     = temp1 + temp2;
    }

    pHash[0] += a;
    pHash[1] += b;
    pHash[2] += c;
    pHash[3] += d;
    pHash[4] += e;
    pHash[5] += f;
    pHash[6] += g;
    pHash[7] += h;
}

static inline void
ExtendMsg(Uint64 w[], Uint32 start, Uint32 end)
{
    for (Uint32 i = start; i < end; i++) {
        const Uint64 s0 = RotateRight(w[i - 15], 1) ^ RotateRight(w[i - 15], 8)
                          ^ (w[i - 15] >> 7);
        const Uint64 s1 = RotateRight(w[i - 2], 19) ^ RotateRight(w[i - 2], 61)
                          ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

void
Sha512::compressMsg(Uint64 w[])
{
    CompressMsg(w, m_hash, cRoundConstants);
}

alc_error_t
Sha512::processChunk(const Uint8* pSrc, Uint64 len)
{

    static bool avx2_available = isAvx2Available();

    /* we need len to be multiple of cChunkSize */
    assert((len & Sha512::cChunkSizeMask) == 0);

    if (avx2_available) {
        return avx2::ShaUpdate512(m_hash, pSrc, len, cRoundConstants);
    }

    Uint64  msg_size       = len;
    Uint64* p_msg_buffer64 = (Uint64*)pSrc;

    Uint64 w[cNumRounds];

    while (msg_size) {
        utils::CopyBlockWith<Uint64>(
            w, p_msg_buffer64, cChunkSize, utils::ToBigEndian<Uint64>);
        // Extend the first 16 words into the remaining words of the message
        // schedule array:
        ExtendMsg(w, cChunkSizeWords, cNumRounds);

        // Compress the message
        compressMsg(w);

        p_msg_buffer64 += cChunkSizeWords;
        msg_size -= cChunkSize;
    }

    return ALC_ERROR_NONE;
}

alc_error_t
Sha512::update(const Uint8* pSrc, Uint64 input_size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pSrc == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    /*
     * input_size == 0 is valid in shani case
     * Returned hash is same as IV
     */
    if (Error::isError(err) || input_size == 0)
        return err;

    if (m_finished) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
        return err;
    }

    m_msg_len += input_size;

    Uint64 to_process = std::min((input_size + m_idx), cChunkSize);
    if (to_process < cChunkSize) {
        /* copy them to internal buffer and return */
        utils::CopyBytes(&m_buffer[m_idx], pSrc, input_size);
        m_idx += input_size;

        return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
        /*
         * Last call to update(), had some unprocessed bytes which is part
         * of internal buffer, we process first block by copying from pSrc the
         * remaining bytes of a chunk.
         */
        to_process = std::min(input_size, cChunkSize - idx);
        utils::CopyBytes(&m_buffer[idx], pSrc, to_process);

        pSrc += to_process;
        input_size -= to_process;
        idx += to_process;

        if (idx == cChunkSize) {
            err = processChunk(m_buffer, cChunkSize);
            idx = 0;
        }
    }

    /* No of bytes that can be processed as Chunks */
    to_process = input_size - (input_size & Sha512::cChunkSizeMask);
    if (to_process > 0) {
        err = processChunk(pSrc, input_size);

        input_size -= to_process;
        pSrc += to_process;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (input_size) {
        assert(input_size <= cChunkSize);

        utils::CopyBytes(&m_buffer[idx], pSrc, input_size);
        idx += input_size;
    }

    m_idx = idx;

    return err;
}

/*
 * We may have some left over data for which the hash to be computed padding
 * the rest of it to ensure correct computation Default padding is 'length
 * encoding'
 */
alc_error_t
Sha512::finalize(const Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished)
        return err;

    if (pBuf && size)
        err = update(pBuf, size);

    if (Error::isError(err)) {
        return err;
    }

    /*
     * When the bytes left in the current chunk are less than 8, current chunk
     * can NOT accomodate the message length. The current chunk is processed and
     * the message length is placed in a new chunk and will be processed.
     */
    m_buffer[m_idx++] = 0x80;

    Uint64 buf_len = m_idx < (cChunkSize - 16) ? cChunkSize : sizeof(m_buffer);
    // Uint64 bytes_left = buf_len - m_idx - utils::BytesInDWord<Uint64>;
    Uint64 bytes_left = buf_len - m_idx - 16;

    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, bytes_left);

#ifdef __SIZEOF_INT128__
    /* Store total length in the last 128-bit (16-bytes) */
    __uint128_t  len_in_bits = m_msg_len * 8;
    __uint128_t* msg_len_ptr = reinterpret_cast<__uint128_t*>(
        &m_buffer[buf_len] - sizeof(__uint128_t));
    msg_len_ptr[0] = utils::ToBigEndian(len_in_bits);
#else
    Uint64 len_in_bits_high;
    Uint64 len_in_bits;

    if (m_msg_len > ULLONG_MAX / 8) { // overflow happens
        // extract the left most 3bits
        len_in_bits_high = m_msg_len >> 61;
        len_in_bits      = m_msg_len << 3;

    } else {
        len_in_bits_high = 0;
        len_in_bits      = m_msg_len * 8;
    }
    Uint64* msg_len_ptr =
        reinterpret_cast<Uint64*>(&m_buffer[buf_len] - (sizeof(Uint64) * 2));
    msg_len_ptr[0] = utils::ToBigEndian(len_in_bits_high);
    msg_len_ptr[1] = utils::ToBigEndian(len_in_bits);
#endif
    err = processChunk(m_buffer, buf_len);

    m_idx = 0;

    m_finished = true;

    return err;
}

void
Sha512::finish()
{
    // delete pImpl();
    // pImpl() = nullptr;
}

} // namespace alcp::digest
