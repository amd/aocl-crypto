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
#include <functional>
#include <string>

#include "digest.hh"
#include "digest/shani.hh"
#include "utils/copy.hh"

namespace alcp::digest {

/*
 * first 32 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */
static constexpr uint32_t cIv[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/*
 * Round constants:
 * For each round, there is one round constant k[i] and one entry in the
 * message schedule array w[i], 0 ≤ i ≤ 63.
 * Values are first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes 2..311
 */
static constexpr uint32_t cRoundConstants[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static constexpr uint64_t /* define word size */
    cWordSize                               = 32,
    /* num rounds in sha256 */ cNumRounds   = 64,
    /* chunk size in bits */ cChunkSizeBits = 512,
    /* chunks to proces */ cChunkSize       = cChunkSizeBits / 8,
    /* same in words */ cChunkSizeWrods     = cChunkSizeBits / cWordSize,
    /* same in bits */ cHashSizeBits        = 256,
    /* Hash size in bytes */ cHashSize      = cHashSizeBits / 8,
    cHashSizeWords                          = cHashSizeBits / cWordSize;

class Sha256::Impl
{
  public:
    Impl();
    ~Impl();

    alc_error_t update(const uint8_t* buf, uint64_t size);
    alc_error_t finalize(const uint8_t* buf, uint64_t size);
    alc_error_t copyHash(uint8_t* buf, uint64_t size);

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
    static void extendMsg(uint32_t w[], uint32_t start, uint32_t end);
    void        compressMsg(uint32_t w[]);
    alc_error_t processChunk(const uint8_t* pSrc, uint64_t len);

  private:
    uint64_t m_msg_len;
    /* Any unprocessed bytes from last call to update() */
    uint8_t  m_buffer[cChunkSize];
    uint32_t m_hash[cHashSizeWords];
    /* index to m_buffer of previously unprocessed bytes */
    uint32_t m_idx;
    bool     m_finished;
};

Sha256::Impl::Impl()
    : m_msg_len{ 0 }
    , m_hash{0,} 
    , m_idx{ 0 }
    , m_finished{ false }
{

    utils::CopyDWord(&m_hash[0], &cIv[0], cHashSize);
}

Sha256::Impl::~Impl() {}

alc_error_t
Sha256::Impl::copyHash(uint8_t* pHash, uint64_t size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pHash == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    if (size < cHashSize) {
        Error::setGeneric(err, ALC_ERROR_INVALID_SIZE);
    }

    for (unsigned long int i = 0, j = 0; i < cHashSizeWords; ++i) {
        //uint32_t tmp = m_hash[i];
        pHash[j++] = (uint8_t)(m_hash[i] >> 24);
        pHash[j++] = (uint8_t)(m_hash[i] >> 16);
        pHash[j++] = (uint8_t)(m_hash[i] >> 8);
        pHash[j++] = (uint8_t)m_hash[i];
    }

    return err;
}

void
Sha256::Impl::extendMsg(uint32_t w[], uint32_t start, uint32_t end)
{
    for (uint32_t i = start; i < end; i++) {
        const uint32_t s0 = RotateRight(w[i - 15], 7)
                            ^ RotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = RotateRight(w[i - 2], 17)
                            ^ RotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

void
Sha256::Impl::compressMsg(uint32_t w[])
{
    uint32_t a, b, c, d, e, f, g, h;

    a = m_hash[0];
    b = m_hash[1];
    c = m_hash[2];
    d = m_hash[3];
    e = m_hash[4];
    f = m_hash[5];
    g = m_hash[6];
    h = m_hash[7];

    /* Compression function main loop: */
    for (uint32_t i = 0; i < cNumRounds; i++) {
        uint32_t s1, ch, temp1, s0, maj, temp2;
        s1    = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
        ch    = (e & f) ^ (~e & g);
        temp1 = h + s1 + ch + cRoundConstants[i] + w[i];
        s0    = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
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
} // namespace alcp::digest

alc_error_t
Sha256::Impl::processChunk(const uint8_t* pSrc, uint64_t len)
{
    bool shani_available = isShaniAvailable();

    assert(len == cChunkSize);

    if (shani_available) {
        return shani::ShaUpdate256(m_hash, pSrc, len, cRoundConstants);
    }

    uint64_t input_buffer_index = 0;
    uint64_t msg_size           = len;
    uint8_t* msg_buffer         = (uint8_t*)pSrc;
    uint8_t* chunk = NULL;

    uint32_t w[cNumRounds];

    while (1) {
        if (input_buffer_index >= msg_size) {
            break;
        }

        if (input_buffer_index + cChunkSize <= len) {
            chunk = msg_buffer;
            msg_buffer += cChunkSize;
            input_buffer_index += cChunkSize;
        }
        for (uint64_t i = 0; i < 16; i++) {
            w[i] = alcp::digest::ToBigEndian(*((uint32_t*)&chunk[i*4]));
        }
        // Extend the first 16 words into the remaining words of the message
        // schedule array:
        extendMsg(w, 16, cNumRounds);

        // Compress the message
        compressMsg(w);

    }

    return ALC_ERROR_NONE;
}

alc_error_t
Sha256::Impl::update(const uint8_t* pSrc, uint64_t input_size)
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

    uint64_t to_process = std::min((input_size + m_idx), cChunkSize);
    if (to_process < cChunkSize) {
        /* copy them to internal buffer and return */
        utils::CopyBytes(&m_buffer[m_idx], pSrc, to_process);
        m_idx += to_process;
        m_msg_len += to_process;
        return err;
    }

    uint64_t idx               = m_idx;
    uint64_t msg_len_processed = m_idx + input_size;

    if (idx) {

        /*
         * Last call to update(), had some unprocessed bytes which are now part
         * of internal buffer, we process first block by copying from pSrc the
         * remaining bytes of a chunk.
         */
        to_process = std::min(input_size, cChunkSize - idx);
        utils::CopyBlock(&m_buffer[idx], pSrc, to_process);

        pSrc += to_process;
        input_size -= to_process;
        idx += to_process;

        if (idx == cChunkSize) {
            err = processChunk(pSrc, input_size);
            idx = 0;
        }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    uint64_t num_chunks = input_size / cChunkSize;
    if (num_chunks) {
        uint64_t size = num_chunks * cChunkSize;

        err = processChunk(pSrc, size);

        pSrc += size;
        input_size -= size;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (input_size) {
        utils::CopyBlock<uint8_t>(&m_buffer[idx], pSrc, input_size);
        idx += input_size;
    }

    m_idx = idx;
    m_msg_len += msg_len_processed;

    return err;
}

alc_error_t
Sha256::Impl::finalize(const uint8_t* pBuf, uint64_t size)
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
    m_buffer[m_idx++]   = 0x80;
    uint64_t bytes_left = cChunkSize - m_idx;

    if (bytes_left < 8) {
        utils::PadBlock<uint8_t>(&m_buffer[m_idx], 0x0, bytes_left);
        err = processChunk(m_buffer, cChunkSize);
        m_idx = 0;
        bytes_left = cChunkSize;
    }
    utils::PadBlock<uint8_t>(&m_buffer[m_idx], 0x0, bytes_left);

    /* Store total length in the last 64-bit (8-bytes) */
    uint8_t* msg_len_ptr = (uint8_t*)&m_buffer[sizeof(m_buffer) - 8];

    int64_t len_in_bits = m_msg_len * 8;
    msg_len_ptr[0] = (uint8_t)(len_in_bits >> 56);
    msg_len_ptr[1] = (uint8_t)(len_in_bits >> 48);
    msg_len_ptr[2] = (uint8_t)(len_in_bits >> 40);
    msg_len_ptr[3] = (uint8_t)(len_in_bits >> 32);
    msg_len_ptr[4] = (uint8_t)(len_in_bits >> 24);
    msg_len_ptr[5] = (uint8_t)(len_in_bits >> 16);
    msg_len_ptr[6] = (uint8_t)(len_in_bits >> 8);
    msg_len_ptr[7] = (uint8_t)(len_in_bits);
    err = processChunk(m_buffer, cChunkSize);

    m_finished = true;

    return err;
}

Sha256::Sha256()
    : Sha2{ "sha2-256" }
    , m_pimpl{ new Sha256::Impl() }

{
    m_mode             = ALC_SHA2_256;
    m_digest_len       = ALC_DIGEST_LEN_256;
    m_digest_len_bytes = 256 / 8;
}

Sha256::Sha256(const alc_digest_info_t& rDigestInfo)
    : Sha256()
{}

Sha256::~Sha256()
{
    delete m_pimpl;
}

alc_error_t
Sha256::update(const uint8_t* pSrc, uint64_t size)
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
Sha256::finalize(const uint8_t* pSrc, uint64_t size)
{
    alc_error_t err = ALC_ERROR_NONE;

    err = m_pimpl->finalize(pSrc, size);

    return err;
}

void
Sha256::finish()
{
    delete m_pimpl;
}

alc_error_t
Sha256::copyHash(uint8_t* pHash, uint64_t size) const
{
    return m_pimpl->copyHash(pHash, size);
}

Sha2::~Sha2() {}

} // namespace alcp::digest
