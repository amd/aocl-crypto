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
#include <functional>
#include <string>

#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha_avx2.hh"
#include "alcp/digest/shani.hh"

#include "alcp/utils/bits.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "alcp/utils/endian.hh"

namespace utils = alcp::utils;
using utils::CpuId;

namespace alcp::digest {

/*
 * first 32 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */
static constexpr Uint32 cIv[] = {
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
static constexpr Uint32 cRoundConstants[] = {
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

class Sha256::Impl
{
  public:
    Impl();
    ~Impl();

    alc_error_t update(const Uint8* buf, Uint64 size);
    alc_error_t finalize(const Uint8* buf, Uint64 size);
    alc_error_t copyHash(Uint8* buf, Uint64 size) const;

    alc_error_t setIv(const void* pIv, Uint64 size);
    void        reset();

#if defined(USE_ALCP_MEMPOOL)
    static void* operator new(size_t size)
    {
        return alcp::utils::mem::PoolAllocator pa =
                   alcp::digest::GetDefaultPool().allocate(size);
    }

    static void operator delete(void* ptr, size_t size)
    {
        auto p = reinterpret_cast<Sha256::Impl*>(ptr);
        GetDefaultDigestPool().deallocate(p, size);
    }
#endif

  private:
    static void extendMsg(Uint32 w[], Uint32 start, Uint32 end);
    void        compressMsg(Uint32 w[]);
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);

  private:
    Uint64 m_msg_len;
    /* Any unprocessed bytes from last call to update() */
    alignas(64) Uint8 m_buffer[2 * cChunkSize];
    alignas(64) Uint32 m_hash[cHashSizeWords];
    /* index to m_buffer of previously unprocessed bytes */
    Uint32 m_idx;
    bool   m_finished;
};

Sha256::Impl::Impl()
    : m_msg_len{ 0 }
    , m_hash{ 0, }
    , m_idx{ 0 }
    , m_finished{ false }
{

    utils::CopyDWord(&m_hash[0], &cIv[0], cHashSize);
}

alc_error_t
Sha256::Impl::setIv(const void* pIv, Uint64 size)
{
    utils::CopyBytes(m_hash, pIv, size);

    return ALC_ERROR_NONE;
}

void
Sha256::Impl::reset()
{
    m_msg_len  = 0;
    m_finished = false;
    m_idx      = 0;
    utils::CopyDWord(&m_hash[0], &cIv[0], cHashSize);
}

Sha256::Impl::~Impl() = default;

alc_error_t
Sha256::Impl::copyHash(Uint8* pHash, Uint64 size) const
{
    utils::CopyBlockWith<Uint32>(
        pHash, m_hash, cHashSize, utils::ToBigEndian<Uint32>);

    return ALC_ERROR_NONE;
}

void
Sha256::Impl::extendMsg(Uint32 w[], Uint32 start, Uint32 end)
{
    for (Uint32 i = start; i < end; i++) {
        const Uint32 s0 = RotateRight(w[i - 15], 7) ^ RotateRight(w[i - 15], 18)
                          ^ (w[i - 15] >> 3);
        const Uint32 s1 = RotateRight(w[i - 2], 17) ^ RotateRight(w[i - 2], 19)
                          ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

void
Sha256::Impl::compressMsg(Uint32 w[])
{
    alcp::digest::CompressMsg(w, m_hash, cRoundConstants);
}

alc_error_t
Sha256::Impl::processChunk(const Uint8* pSrc, Uint64 len)
{
    static bool shani_available = CpuId::cpuHasShani();
    // FIXME: AVX2 is deliberately disabled due to poor performance
#if 0
    static bool avx2_available  = utils::CpuId::cpuHasAvx2();
#else
    static bool avx2_available = false;
#endif

    /* we need len to be multiple of cChunkSize */
    assert((len & cChunkSizeMask) == 0);

    if (shani_available) {
        return shani::ShaUpdate256(m_hash, pSrc, len, cRoundConstants);
    } else if (avx2_available) {
        return avx2::ShaUpdate256(m_hash, pSrc, len, cRoundConstants);
    }

    Uint64  msg_size       = len;
    Uint32* p_msg_buffer32 = (Uint32*)pSrc;

    Uint32 w[cNumRounds];

    while (msg_size) {
        utils::CopyBlockWith<Uint32>(
            w, p_msg_buffer32, cChunkSize, utils::ToBigEndian<Uint32>);

        // Extend the first 16 words into the remaining words of the message
        // schedule array:
        extendMsg(w, cChunkSizeWords, cNumRounds);

        // Compress the message
        compressMsg(w);

        p_msg_buffer32 += cChunkSizeWords;
        msg_size -= cChunkSize;
    }

    return ALC_ERROR_NONE;
}

alc_error_t
Sha256::Impl::update(const Uint8* pSrc, Uint64 input_size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        /* TODO Change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    /*
     * Valid request, last computed has itself is good,
     * default is m_iv
     */
    if (input_size == 0) {
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
            err = processChunk(m_buffer, idx);
            idx = 0;
        }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    Uint64 num_chunks = input_size / cChunkSize;
    if (num_chunks) {

        Uint64 size = num_chunks * cChunkSize;

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
    return err;
}

alc_error_t
Sha256::Impl::finalize(const Uint8* pBuf, Uint64 size)
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
     * We may have some left over data for which the hash to be computed
     * padding the rest of it to ensure correct computation
     * Default padding is 'length encoding'
     */

    m_buffer[m_idx++] = 0x80;

    Uint64 buf_len = m_idx <= (cChunkSize - 8) ? cChunkSize : sizeof(m_buffer);
    Uint64 bytes_left = buf_len - m_idx - utils::BytesPerDWord;

    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, bytes_left);

    /* Store total length in the last 64-bit (8-bytes) */
    Uint64  len_in_bits = m_msg_len * 8;
    Uint64* msg_len_ptr =
        reinterpret_cast<Uint64*>(&m_buffer[buf_len] - sizeof(Uint64));
    msg_len_ptr[0] = utils::ToBigEndian(len_in_bits);

    err = processChunk(m_buffer, buf_len);

    m_idx = 0;

    m_finished = true;

    return err;
}

Sha256::Sha256()
    : Sha2{ "sha2-256" }
    , m_pimpl{ std::make_unique<Sha256::Impl>() }

{
    m_mode             = ALC_SHA2_256;
    m_digest_len       = ALC_DIGEST_LEN_256;
    m_digest_len_bytes = 256 / 8;
}

Sha256::Sha256(const alc_digest_info_t& rDigestInfo)
    : Sha256()
{}

Sha256::~Sha256() = default;

alc_error_t
Sha256::setIv(const void* pIv, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pIv == nullptr) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (size != cIvSizeBytes) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_SIZE;
    }

    if (!alcp_is_error(err))
        err = pImpl()->setIv(pIv, size);

    return err;
}

alc_error_t
Sha256::update(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pSrc == nullptr) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
    }

    if (!err)
        err = pImpl()->update(pSrc, size);

    return err;
}

alc_error_t
Sha256::finalize(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    err = pImpl()->finalize(pSrc, size);

    return err;
}

alc_error_t
Sha256::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (!pHash) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (size != cHashSize) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_SIZE;
    }

    if (!err) {
        err = pImpl()->copyHash(pHash, size);
    }

    return err;
}

void
Sha256::finish()
{
    // delete pImpl();
    // pImpl() = nullptr;
}

void
Sha256::reset()
{
    pImpl()->reset();
}

Sha2::~Sha2() {}

Uint64
Sha256::getInputBlockSize()
{
    return cChunkSize;
}
Uint64
Sha256::getHashSize()
{
    return cHashSize;
}

} // namespace alcp::digest
