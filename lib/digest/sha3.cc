/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "alcp/utils/cpuid.hh"
#include "digest/sha3.hh"
#include "digest/sha3_zen.hh"
#include "utils/bits.hh"
#include "utils/copy.hh"
#include "utils/endian.hh"

namespace utils = alcp::utils;
using namespace alcp::digest;

using alcp::utils::CpuId;

#include "sha3_inplace.hh"

namespace alcp::digest {

#include "sha3_inplace.cc.inc"

// maximum size of message block in bits is used for shake128 digest
static constexpr Uint32 MaxDigestBlockSizeBits = 1344;

class Sha3::Impl
{
  public:
    Impl(const alc_digest_info_t& rDigestInfo);
    ~Impl() = default;

    alc_error_t update(const Uint8* buf, Uint64 size);
    alc_error_t finalize(const Uint8* buf, Uint64 size);
    alc_error_t copyHash(Uint8* buf, Uint64 size) const;

    Uint64 getInputBlockSize();
    Uint64 getHashSize();

    void reset();

  private:
    void        absorbChunk(Uint64* p_msg_buf_64);
    void        squeezeChunk();
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    void        round(Uint64 round_const);
    void        fFunction();

  private:
    std::string  m_name;
    Uint64       m_chunk_size, m_chunk_size_u64, m_hash_size;
    const Uint64 m_num_rounds = 24;
    Uint32       m_idx        = 0;

    // buffer size to hold the chunk size to be processed
    Uint8 m_buffer[MaxDigestBlockSizeBits / 8];
    // state matrix to represent the keccak 1600 bits representation of
    // intermediate hash
    __attribute__((aligned(64))) Uint64 m_state[cDim][cDim];
    // flat representation of the state, used in absorbing the user message.
    Uint64* m_state_flat = &m_state[0][0];
    // buffer to copy intermediate hash value
    std::vector<Uint8> m_hash;
};

Uint64
Sha3::Impl::getInputBlockSize()
{
    return m_chunk_size;
}

Uint64
Sha3::Impl::getHashSize()
{
    return m_hash_size;
}

Sha3::Impl::Impl(const alc_digest_info_t& rDigestInfo)
    : m_idx{ 0 }
{
    Uint64 chunk_size_bits = 0;
    m_hash_size            = rDigestInfo.dt_len / 8;

    // chunk_size_bits are as per specs befined in
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    switch (rDigestInfo.dt_mode.dm_sha3) {
        case ALC_SHA3_224:
            chunk_size_bits = 1152;
            m_name          = "SHA3-224";
            break;
        case ALC_SHA3_256:
            chunk_size_bits = 1088;
            m_name          = "SHA3-256";
            break;
        case ALC_SHA3_384:
            chunk_size_bits = 832;
            m_name          = "SHA3-384";
            break;
        case ALC_SHA3_512:
            chunk_size_bits = 576;
            m_name          = "SHA3-512";
            break;
        case ALC_SHAKE_128:
            chunk_size_bits = 1344;
            m_name          = "SHA3-SHAKE-128";
            m_hash_size     = rDigestInfo.dt_custom_len;
            break;
        case ALC_SHAKE_256:
            chunk_size_bits = 1088;
            m_name          = "SHA3-SHAKE-256";
            m_hash_size     = rDigestInfo.dt_custom_len;
            break;
        default:;
    }

    m_chunk_size_u64 = chunk_size_bits / 64;
    m_chunk_size     = chunk_size_bits / 8;

    memset(m_state, 0, sizeof(m_state));
    m_hash.resize(m_hash_size);
}

void
Sha3::Impl::absorbChunk(Uint64* pMsgBuffer64)
{
    for (Uint64 i = 0; i < m_chunk_size_u64; ++i) {
        m_state_flat[i] ^= pMsgBuffer64[i];
    }
    // keccak function
    fFunction();
}

void
Sha3::Impl::squeezeChunk()
{
    static CpuId cpuId;
    Uint64       hash_copied = 0;

    static bool zen1_available = cpuId.cpuIsZen1() || cpuId.cpuIsZen2();
    static bool zen3_available = cpuId.cpuIsZen3() || cpuId.cpuIsZen4();

    if (zen3_available) {
        return zen3::Sha3Finalize(
            (Uint8*)m_state_flat, &m_hash[0], m_hash_size, m_chunk_size);
    }

    if (zen1_available) {
        return zen::Sha3Finalize(
            (Uint8*)m_state_flat, &m_hash[0], m_hash_size, m_chunk_size);
    }

    while (m_chunk_size <= m_hash_size - hash_copied) {
        Uint64 data_chunk_copied = std::min(m_hash_size, m_chunk_size);

        utils::CopyBlock(
            &m_hash[hash_copied], (Uint8*)m_state_flat, data_chunk_copied);
        hash_copied += data_chunk_copied;

        if (hash_copied < m_hash_size) {
            fFunction();
        }
    }

    if (m_hash_size > hash_copied) {
        utils::CopyBlock(&m_hash[hash_copied],
                         (Uint8*)m_state_flat,
                         m_hash_size - hash_copied);
    }
}

inline void
Sha3::Impl::round(Uint64 roundConst)
{
    // theta stage
    Uint64 c[cDim], d[cDim];

    for (int x = 0; x < cDim; ++x) {
        c[x] = m_state[0][x];
        for (int y = 1; y < cDim; ++y) {
            c[x] ^= m_state[y][x];
        }
    }

    for (int x = 0; x < cDim; ++x) {
        d[x] = c[(cDim + x - 1) % cDim]
               ^ alcp::digest::RotateLeft(c[(x + 1) % cDim], 1);
    }

    for (int x = 0; x < cDim; ++x) {
        for (int y = 0; y < cDim; ++y) {
            m_state[x][y] ^= d[y];
        }
    }

    // Rho stage
    Uint64 temp[cDim][cDim];
    for (int x = 0; x < cDim; x++) {
        for (int y = 0; y < cDim; y++) {
            temp[x][y] = alcp::digest::RotateLeft(m_state[x][y],
                                                  cRotationConstants[x][y]);
        }
    }

    // pi stage
    for (int x = 0; x < cDim; ++x) {
        int x_indx = 2 * x;
        for (int y = 0; y < cDim; ++y) {
            m_state[(x_indx + 3 * y) % cDim][y] = temp[y][x];
        }
    }

    // xi stage
    utils::CopyBlock(temp, m_state, sizeof(temp));
    for (int x = 0; x < cDim; ++x) {
        for (int y = 0; y < cDim; ++y) {
            m_state[x][y] =
                temp[x][y]
                ^ (~temp[x][(y + 1) % cDim] & temp[x][(y + 2) % cDim]);
        }
    }

    // iota stage
    m_state[0][0] ^= roundConst;
}

void
Sha3::Impl::fFunction()
{
    for (Uint64 i = 0; i < m_num_rounds; ++i) {
        round(cRoundConstants[i]);
    }
}

void
Sha3::Impl::reset()
{
    m_idx = 0;
    memset(m_state, 0, sizeof(m_state));
}

alc_error_t
Sha3::Impl::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (size != m_hash_size) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }

    utils::CopyBlock(pHash, m_hash.data(), size);
    return err;
}

alc_error_t
Sha3::Impl::processChunk(const Uint8* pSrc, Uint64 len)
{
    static CpuId cpuId;
    Uint64       msg_size       = len;
    Uint64*      p_msg_buffer64 = (Uint64*)pSrc;

    // FIXME: Suggestion, in Zen1 this algorithm works and gives better
    // performance. I guess having similar code in avx2 arch will be better.
    static bool zen1_available = cpuId.cpuIsZen1() || cpuId.cpuIsZen2();
    static bool zen3_available = cpuId.cpuIsZen3() || cpuId.cpuIsZen4();

    if (zen3_available) {
        return zen3::Sha3Update(
            m_state_flat, p_msg_buffer64, msg_size, m_chunk_size);
    }

    if (zen1_available) {
        return zen::Sha3Update(
            m_state_flat, p_msg_buffer64, msg_size, m_chunk_size);
    }

    while (msg_size) {
        // xor message chunk into m_state.
        absorbChunk(p_msg_buffer64);
        p_msg_buffer64 += m_chunk_size_u64;
        msg_size -= m_chunk_size;
    }

    return ALC_ERROR_NONE;
}

alc_error_t
Sha3::Impl::update(const Uint8* pSrc, Uint64 inputSize)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 to_process = std::min((inputSize + m_idx), m_chunk_size);
    if (to_process < m_chunk_size) {
        /* copy them to internal buffer and return */
        utils::CopyBlock(&m_buffer[m_idx], pSrc, inputSize);
        m_idx += inputSize;
        return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
        /*
         * Last call to update(), had some unprocessed bytes which is part
         * of internal buffer, we process first block by copying from pSrc
         * the remaining bytes of a chunk.
         */
        to_process = std::min(inputSize, m_chunk_size - idx);
        utils::CopyBlock(&m_buffer[idx], pSrc, to_process);

        pSrc += to_process;
        inputSize -= to_process;
        idx += to_process;
        if (idx == m_chunk_size) {
            err = processChunk(m_buffer, m_chunk_size);
            idx = 0;
        }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    Uint64 num_chunks = inputSize / m_chunk_size;

    if (num_chunks) {
        Uint64 size = num_chunks * m_chunk_size;
        err         = processChunk(pSrc, size);
        pSrc += size;
        inputSize -= size;
    }

    /*
     * We still have some leftover bytes, copy them to internal buffer
     */
    if (inputSize) {
        utils::CopyBlock(&m_buffer[idx], pSrc, inputSize);
        idx += inputSize;
    }

    m_idx = idx;

    return err;
}

alc_error_t
Sha3::Impl::finalize(const Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pBuf && size) {
        err = update(pBuf, size);
    }

    // sha3 padding
    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, m_chunk_size - m_idx);

    if (m_name == "SHA3-SHAKE-128" || m_name == "SHA3-SHAKE-256") {
        m_buffer[m_idx] = 0x1f;
    } else {
        m_buffer[m_idx] = 0x06;
    }

    m_buffer[m_chunk_size - 1] |= 0x80;

    if (err) {
        return err;
    }

    err = processChunk(m_buffer, m_chunk_size);

    squeezeChunk();

    m_idx = 0;

    return err;
}

Sha3::Sha3(const alc_digest_info_t& rDigestInfo)
    : m_pimpl{ std::make_unique<Sha3::Impl>(rDigestInfo) }
    , m_finished{ false }
{}

Sha3::~Sha3() {}

alc_error_t
Sha3::update(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished || pSrc == nullptr) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (size == 0) {
        /* TODO: change to Status */
        err = ALC_ERROR_NONE;
        return err;
    }

    if (!alcp_is_error(err) && m_pimpl)
        err = m_pimpl->update(pSrc, size);

    return err;
}

alc_error_t
Sha3::finalize(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        return err;
    }

    if (m_pimpl)
        err = m_pimpl->finalize(pSrc, size);

    m_finished = true;
    return err;
}

alc_error_t
Sha3::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pHash == nullptr) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
    }

    if (!err && m_pimpl) {
        err = m_pimpl->copyHash(pHash, size);
    }

    return err;
}

void
Sha3::finish()
{
    m_pimpl = nullptr;
}

void
Sha3::reset()
{
    if (m_pimpl) {
        m_pimpl->reset();
    }

    m_finished = false;
}

Uint64
Sha3::getInputBlockSize()
{
    return m_pimpl->getInputBlockSize();
}
Uint64
Sha3::getHashSize()
{
    return m_pimpl->getHashSize();
}

} // namespace alcp::digest
