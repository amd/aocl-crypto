/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

template<alc_digest_len_t digest_len>
alc_error_t
Sha2<digest_len>::processChunk(const Uint8* pSrc, Uint64 len)
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
        alcp::digest::extendMsg(w, cChunkSizeWords, cNumRounds);

        // Compress the message
        alcp::digest::CompressMsg(w, m_hash, cRoundConstants);

        p_msg_buffer32 += cChunkSizeWords;
        msg_size -= cChunkSize;
    }

    return ALC_ERROR_NONE;
}

template<alc_digest_len_t digest_len>
Sha2<digest_len>::Sha2()
{
    m_digest_len = digest_len / 8;
    m_block_len  = cChunkSize;
}

template<alc_digest_len_t digest_len>
Sha2<digest_len>::Sha2(const Sha2& src)
{
    m_msg_len    = src.m_msg_len;
    m_digest_len = src.m_digest_len;
    m_block_len  = src.m_block_len;
    memcpy(m_buffer, src.m_buffer, sizeof(m_buffer));
    memcpy(m_hash, src.m_hash, sizeof(m_hash));
    m_idx      = src.m_idx;
    m_finished = src.m_finished;
}

template<alc_digest_len_t digest_len>
void
Sha2<digest_len>::init(void)
{
    if constexpr (digest_len == ALC_DIGEST_LEN_256) {
        m_hash[0] = 0x6a09e667;
        m_hash[1] = 0xbb67ae85;
        m_hash[2] = 0x3c6ef372;
        m_hash[3] = 0xa54ff53a;
        m_hash[4] = 0x510e527f;
        m_hash[5] = 0x9b05688c;
        m_hash[6] = 0x1f83d9ab;
        m_hash[7] = 0x5be0cd19;
    } else {
        m_hash[0] = 0xc1059ed8;
        m_hash[1] = 0x367cd507;
        m_hash[2] = 0x3070dd17;
        m_hash[3] = 0xf70e5939;
        m_hash[4] = 0xffc00b31;
        m_hash[5] = 0x68581511;
        m_hash[6] = 0x64f98fa7;
        m_hash[7] = 0xbefa4fa4;
    }
    m_finished = false;
    m_msg_len  = 0;
    m_idx      = 0;
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha2<digest_len>::update(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pSrc == nullptr) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (m_finished) {
        /* TODO Change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    /*
     * Valid request, last computed has itself is good,
     * default is m_iv
     */
    if (size == 0) {
        return err;
    }
    m_msg_len += size;

    Uint64 to_process = std::min((size + m_idx), cChunkSize);
    if (to_process < cChunkSize) {
        /* copy them to internal buffer and return */
        utils::CopyBlock(&m_buffer[m_idx], pSrc, size);
        m_idx += size;
        return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
        /*
         * Last call to update(), had some unprocessed bytes which is part
         * of internal buffer, we process first block by copying from pSrc the
         * remaining bytes of a chunk.
         */
        to_process = std::min(size, cChunkSize - idx);
        utils::CopyBlock(&m_buffer[idx], pSrc, to_process);

        pSrc += to_process;
        size -= to_process;
        idx += to_process;

        if (idx == cChunkSize) {
            err = processChunk(m_buffer, idx);
            idx = 0;
        }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    Uint64 num_chunks = size / cChunkSize;
    if (num_chunks) {

        Uint64 sizeChunk = num_chunks * cChunkSize;

        err = processChunk(pSrc, sizeChunk);

        pSrc += sizeChunk;
        size -= sizeChunk;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (size) {
        utils::CopyBlock(&m_buffer[idx], pSrc, size);
        idx += size;
    }

    m_idx = idx;
    return err;
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha2<digest_len>::finalize(Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
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

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    if (pBuf != nullptr && size == m_digest_len) {
        utils::CopyBlockWith<Uint32, true>(
            pBuf, m_hash, m_digest_len, utils::ToBigEndian<Uint32>);
        m_idx      = 0;
        m_finished = true;
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_INVALID_ARG;
    }
}

template class Sha2<ALC_DIGEST_LEN_224>;
template class Sha2<ALC_DIGEST_LEN_256>;

} // namespace alcp::digest
