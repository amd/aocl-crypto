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
#include "config.h"
#include <algorithm>
#include <climits>
#include <functional>
#include <string>

#include "alcp/digest/sha2_512.hh"

#include "alcp/digest/sha_avx2.hh"
#include "alcp/digest/sha_avx256.hh"
#include "alcp/digest/sha_avx512.hh"

#include "alcp/utils/bits.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "alcp/utils/endian.hh"

namespace utils = alcp::utils;

using alcp::utils::CpuId;

namespace alcp::digest {

/*
 * first 64 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */
static constexpr Uint64 cIv_512[] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                                      0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                      0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                      0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

static constexpr Uint64 cIv_384[] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                                      0x9159015a3070dd17, 0x152fecd8f70e5939,
                                      0x67332667ffc00b31, 0x8eb44a8768581511,
                                      0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };

static constexpr Uint64 cIv_256[] = { 0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
                                      0x2393b86b6f53b151, 0x963877195940eabd,
                                      0x96283ee2a88effe3, 0xbe5e1e2553863992,
                                      0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2 };

static constexpr Uint64 cIv_224[] = { 0x8c3d37c819544da2, 0x73e1996689dcd4d6,
                                      0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
                                      0x0f6d2b697bd44da8, 0x77e36f7304c48942,
                                      0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1 };

Sha512::Sha512(alc_digest_len_t digest_len)
    : m_msg_len{ 0 }
    , m_hash{ 0,}
    , m_idx{ 0 }
    , m_finished{ false }
{
    m_mode       = ALC_SHA2_512;
    m_digest_len = digest_len;
    m_Iv         = cIv_512;
    switch (digest_len) {
        case ALC_DIGEST_LEN_224:
            m_digest_len_bytes = 224 / 8;
            m_Iv               = cIv_224;
            break;
        case ALC_DIGEST_LEN_256:
            m_digest_len_bytes = 256 / 8;
            m_Iv               = cIv_256;
            break;
        case ALC_DIGEST_LEN_384:
            m_digest_len_bytes = 384 / 8;
            m_Iv               = cIv_384;
            break;
        default:
            m_digest_len_bytes = 512 / 8;
            m_Iv               = cIv_512;
    }

    utils::CopyQWord(&m_hash[0], m_Iv, cIvSizeBytes);
}

Sha512::Sha512(const alc_digest_info_t& rDigestInfo)
    : Sha512(rDigestInfo.dt_len)
{}

Sha512::~Sha512() = default;

alc_error_t
Sha512::setIv(const void* pIv, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (!pIv) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (size != cIvSizeBytes) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_SIZE;
    }

    if (!err)
        utils::CopyBlock(m_hash, pIv, size);

    return err;
}

void
Sha512::reset()
{
    m_msg_len  = 0;
    m_finished = false;
    m_idx      = 0;
    utils::CopyQWord(&m_hash[0], &m_Iv[0], cIvSizeBytes);
}

alc_error_t
Sha512::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (!pHash) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (size != m_digest_len_bytes) {
        err = ALC_ERROR_INVALID_SIZE;
    }

    if (!err) {
        utils::CopyBlockWith<Uint64>(
            pHash, m_hash, m_digest_len_bytes, utils::ToBigEndian<Uint64>);

        if (m_digest_len == ALC_DIGEST_LEN_224) {
            // last 4 bytes can be copied after reversing the 64 bit since it is
            // in little endian form
            Uint64 hash = utils::ToBigEndian<Uint64>(m_hash[3]);
            utils::CopyBlock(&pHash[24], &hash, 4);
        }
    }

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
    static bool cpu_is_zen3 = CpuId::cpuIsZen3();
    static bool cpu_is_zen4 = CpuId::cpuIsZen4();

    /* we need len to be multiple of cChunkSize */
    assert((len & Sha512::cChunkSizeMask) == 0);

    if (cpu_is_zen4) {
        return zen4::ShaUpdate512(m_hash, pSrc, len);
    } else if (cpu_is_zen3) {
        return zen3::ShaUpdate512(m_hash, pSrc, len);
    } else if (CpuId::cpuHasAvx2()) {
        return avx2::ShaUpdate512(m_hash, pSrc, len);
    }
    // Else fall to reference implementation.

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
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
    }

    /*
     * input_size == 0 is valid in shani case
     * Returned hash is same as IV
     */
    if (err || input_size == 0)
        return err;

    if (m_finished) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    m_msg_len += input_size;

    Uint64 to_process = std::min((input_size + m_idx), cChunkSize);
    if (to_process < cChunkSize) {
        /* copy them to internal buffer and return */
        utils::CopyBlock(&m_buffer[m_idx], pSrc, input_size);
        m_idx += input_size;

        return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
        /*
         * Last call to update(), had some unprocessed bytes which is part
         * of internal buffer, we process first block by copying from pSrc
         * the remaining bytes of a chunk.
         */
        to_process = std::min(input_size, cChunkSize - idx);
        utils::CopyBlock(&m_buffer[idx], pSrc, to_process);

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
        err = processChunk(pSrc, to_process);

        input_size -= to_process;
        pSrc += to_process;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (input_size) {
        assert(input_size <= cChunkSize);

        utils::CopyBlock(&m_buffer[idx], pSrc, input_size);
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

    if (err) {
        return err;
    }

    /*
     * When the bytes left in the current chunk are less than 16, current chunk
     * can NOT accomodate the message length. The current chunk is processed and
     * the message length is placed in a new chunk and will be processed.
     */
    m_buffer[m_idx++] = 0x80;

    Uint64 buf_len = m_idx <= (cChunkSize - 16) ? cChunkSize : sizeof(m_buffer);
    // Uint64 bytes_left = buf_len - m_idx - utils::BytesInDWord<Uint64>;
    Uint64 bytes_left = buf_len - m_idx - 16;

    utils::PadBlock<Uint64>(&m_buffer[m_idx], 0x0, bytes_left);

#ifdef __SIZEOF_INT128__
    /* Store total length in the last 128-bit (16-bytes) */
    __uint128_t  len_in_bits = m_msg_len * 8;
    __uint128_t* msg_len_ptr = reinterpret_cast<__uint128_t*>(
        &m_buffer[buf_len] - sizeof(__uint128_t));

    /* TODO: Due to memory alignment, msg_len_ptr gets optimized in Windows.So,
     * using CopyBytes to copy every bits*/
    __uint128_t len_bits_copy = utils::ToBigEndian(len_in_bits);
    utils::CopyBlock(&msg_len_ptr[0], &len_bits_copy, 16);
    // msg_len_ptr[0] = utils::ToBigEndian(len_in_bits);
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

Uint64
Sha512::getHashSize()
{
    return m_digest_len_bytes;
}
Uint64
Sha512::getInputBlockSize()
{
    return cChunkSize;
}

} // namespace alcp::digest
