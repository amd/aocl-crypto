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

#include "digest/sha2.hh"

#include "utils/bits.hh"
#include "utils/copy.hh"
#include "utils/endian.hh"

namespace utils = alcp::utils;

namespace alcp::digest {

/*
 * first 64 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */
static constexpr uint64_t cIv[] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
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
static constexpr uint64_t cRoundConstants[] = {
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

static constexpr uint64 /* define word size */
    cWordSize                               = 64,
    /* num rounds in sha512 */ cNumRounds   = 80,
    /* chunk size in bits */ cChunkSizeBits = 1024,
    /* chunks to proces */ cChunkSize       = cChunkSizeBits / 8,
    /*  */ cChunkSizeMask                   = cChunkSize - 1,
    /* same in words */ cChunkSizeWords     = cChunkSizeBits / cWordSize,
    /* same in bits */ cHashSizeBits        = 512,
    /* Hash size in bytes */ cHashSize      = cHashSizeBits / 8,
    cHashSizeWords                          = cHashSizeBits / cWordSize;

class Sha512::Impl
{
  public:
    Impl();
    ~Impl();

    alc_error_t update(const uint8* buf, uint64 size);
    alc_error_t finalize(const uint8* buf, uint64 size);
    alc_error_t copyHash(uint8* buf, uint64 size);

    alc_error_t setIv(const void* pIv, uint64 size);

    /*
     * \brief  Checks if SHANI feature is enabled
     */
    static bool isShaniAvailable()
    {
        /*
         * FIXME: call cpuid::isShaniAvailable() initialize
         */
        static bool s_shani_available = false;
        return s_shani_available;
    }

  private:
    static void extendMsg(uint64 w[], uint32 start, uint32 end);
    void        compressMsg(uint64 w[]);
    alc_error_t processChunk(const uint8* pSrc, uint64 len);

  private:
    uint64 m_msg_len;
    /* Any unprocessed bytes from last call to update() */
    uint8  m_buffer[cChunkSize];
    uint64 m_hash[cHashSizeWords];
    /* index to m_buffer of previously unprocessed bytes */
    uint32 m_idx;
    bool   m_finished;
};

Sha512::Impl::Impl()
    : m_msg_len{ 0 }
    , m_hash{0,}
    , m_idx{ 0 }
    , m_finished{ false }
{

    utils::CopyQWord(&m_hash[0], &cIv[0], cHashSize);
}

alc_error_t
Sha512::Impl::setIv(const void* pIv, uint64 size)
{
    utils::CopyBytes(m_hash, pIv, size);

    return ALC_ERROR_NONE;
}

Sha512::Impl::~Impl() {}

alc_error_t
Sha512::Impl::copyHash(uint8* pHash, uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pHash == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    if (size < cHashSize) {
        Error::setGeneric(err, ALC_ERROR_INVALID_SIZE);
    }

    if (!Error::isError(err)) {
        uint64* pBuff64 = (uint64*)pHash;
        for (uint64 i = 0; i < cHashSizeWords; ++i) {
            *pBuff64++ = utils::ToBigEndian(m_hash[i]);
        }
    }

    return err;
}

void
Sha512::Impl::extendMsg(uint64 w[], uint32 start, uint32 end)
{
    for (uint32 i = start; i < end; i++) {
        const uint64 s0 = RotateRight(w[i - 15], 1) ^ RotateRight(w[i - 15], 8)
                          ^ (w[i - 15] >> 7);
        const uint64 s1 = RotateRight(w[i - 2], 19) ^ RotateRight(w[i - 2], 61)
                          ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

void
Sha512::Impl::compressMsg(uint64 w[])
{
    uint64 a, b, c, d, e, f, g, h;

    a = m_hash[0];
    b = m_hash[1];
    c = m_hash[2];
    d = m_hash[3];
    e = m_hash[4];
    f = m_hash[5];
    g = m_hash[6];
    h = m_hash[7];

    /* Compression function main loop: */
    for (uint32 i = 0; i < cNumRounds; i++) {
        uint64 s1, ch, temp1, s0, maj, temp2;
        s1    = RotateRight(e, 14) ^ RotateRight(e, 18) ^ RotateRight(e, 41);
        ch    = (e & f) ^ (~e & g);
        temp1 = h + s1 + ch + cRoundConstants[i] + w[i];
        s0    = RotateRight(a, 28) ^ RotateRight(a, 34) ^ RotateRight(a, 39);
        maj   = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    /* Add the compressed chunk to the current hash value: */
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
    m_hash[4] += e;
    m_hash[5] += f;
    m_hash[6] += g;
    m_hash[7] += h;
}

alc_error_t
Sha512::Impl::processChunk(const uint8* pSrc, uint64 len)
{

    /* we need len to be multiple of cChunkSize */
    assert((len & cChunkSizeMask) == 0);

    uint64  msg_size       = len;
    uint64* p_msg_buffer64 = (uint64*)pSrc;

    uint64 w[cNumRounds];

    while (msg_size) {
        utils::CopyBlockWith<uint64>(w,
                                     p_msg_buffer64,
                                     utils::DWordToBytes(16),
                                     utils::ToBigEndian<uint64>);
        // Extend the first 16 words into the remaining words of the message
        // schedule array:
        extendMsg(w, 16, cNumRounds);

        // Compress the message
        compressMsg(w);

        p_msg_buffer64 += cChunkSizeWords;
        msg_size -= cChunkSize;
    }

    return ALC_ERROR_NONE;
}

alc_error_t
Sha512::Impl::update(const uint8* pSrc, uint64 input_size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
        return err;
    }

    /*
     * Valid request, last computed has itself is good,
     * default is m_iv
     */
    if (input_size == 0) {
        return err;
    }

    uint64 to_process = std::min((input_size + m_idx), cChunkSize);
    if (to_process < cChunkSize) {
        /* copy them to internal buffer and return */
        utils::CopyBytes(&m_buffer[m_idx], pSrc, to_process);
        m_idx += to_process;
        m_msg_len += to_process;
        return err;
    }

    uint64 idx               = m_idx;
    uint64 msg_len_processed = m_idx + input_size;

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
            err = processChunk(pSrc, input_size);
            idx = 0;
        }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    uint64 num_chunks = input_size / cChunkSize;
    if (num_chunks) {
        uint64 size = num_chunks * cChunkSize;

        err = processChunk(pSrc, size);

        pSrc += size;
        input_size -= size;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (input_size) {
        utils::CopyBytes(&m_buffer[idx], pSrc, input_size);
        idx += input_size;
    }

    m_idx = idx;
    m_msg_len += msg_len_processed;

    return err;
}

alc_error_t
Sha512::Impl::finalize(const uint8* pBuf, uint64 size)
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
     * We may have some left over data for which the hash to be computed
     * padding the rest of it to ensure correct computation
     * Default padding is 'length encoding'
     */

    /*
     * When the bytes left in the current chunk are less than 8,
     * current chunk can NOT accomodate the message length.
     * The curent chunk is processed and the message length is
     * placed in a new chunk and will be processed.
     */
    uint8 local_buf[cChunkSize * 2];
    utils::CopyBlock(local_buf, m_buffer, m_idx);

    local_buf[m_idx++] = 0x80;

    uint64 buf_len = m_idx < (cChunkSize - 8) ? cChunkSize : sizeof(local_buf);
    // uint64 bytes_left = buf_len - m_idx - utils::BytesInDWord<uint64>;
    uint64 bytes_left = buf_len - m_idx - 16;

    utils::PadBlock<uint8>(&local_buf[m_idx], 0x0, bytes_left);
#ifdef __SIZEOF_INT128__
    /* Store total length in the last 128-bit (16-bytes) */
    __uint128_t  len_in_bits = m_msg_len * 8;
    __uint128_t* msg_len_ptr = reinterpret_cast<__uint128_t*>(
        &local_buf[buf_len] - sizeof(__uint128_t));
    msg_len_ptr[0] = utils::ToBigEndian(len_in_bits);
#else
    uint64 len_in_bits_high;
    uint64 len_in_bits;

    if (m_msg_len > ULLONG_MAX / 8) { // overflow happens
        // extract the left most 3bits
        len_in_bits_high = m_msg_len >> 61;
        len_in_bits      = m_msg_len << 3;

    } else {
        len_in_bits_high = 0;
        len_in_bits      = m_msg_len * 8;
    }
    uint64* msg_len_ptr =
        reinterpret_cast<uint64*>(&local_buf[buf_len] - (sizeof(uint64) * 2));
    msg_len_ptr[0] = utils::ToBigEndian(len_in_bits_high);
    msg_len_ptr[1] = utils::ToBigEndian(len_in_bits);
#endif
    err = processChunk(local_buf, buf_len);

    m_idx = 0;

    m_finished = true;

    return err;
}

Sha512::Sha512()
    : Sha2{ "sha2-512" }
    , m_pimpl{ new Sha512::Impl() }

{
    m_mode             = ALC_SHA2_512;
    m_digest_len       = ALC_DIGEST_LEN_512;
    m_digest_len_bytes = 512 / 8;
}

Sha512::Sha512(const alc_digest_info_t& rDigestInfo)
    : Sha512()
{}

Sha512::~Sha512()
{
    delete m_pimpl;
}
alc_error_t
Sha512::setIv(const void* pIv, uint64_t size)
{
    return m_pimpl->setIv(pIv, size);
}

alc_error_t
Sha512::update(const uint8* pSrc, uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pSrc == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    if (!alcp_is_error(err))
        err = m_pimpl->update(pSrc, size);

    return err;
}

alc_error_t
Sha512::finalize(const uint8* pSrc, uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    err = m_pimpl->finalize(pSrc, size);

    return err;
}

void
Sha512::finish()
{
    delete m_pimpl;
}

alc_error_t
Sha512::copyHash(uint8* pHash, uint64 size) const
{
    return m_pimpl->copyHash(pHash, size);
}

} // namespace alcp::digest
