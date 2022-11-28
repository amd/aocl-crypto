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
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "digest/sha3.hh"
#include "digest/sha3_avx2.hh"
#include "utils/bits.hh"
#include "utils/copy.hh"
#include "utils/endian.hh"

#ifdef ALCP_ENABLE_AOCL_CPUID
#include "alci/cpu_features.h"
#endif

namespace utils = alcp::utils;

namespace alcp::digest {

/*
 * Round constants:
 * For each round, there is one round constant
 * Values are first 64 buts. These are used only in the Iota Step of the round
 * function
 */
// clang-format off
static constexpr Uint64 cRoundConstants[24] = {
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
};

// matrix dimension
static constexpr Uint8 cDim = 5;

/*
 * Rotation constants:
 * They take each of the 25 lanes of m_state i.e., word of 64 bits.
 * And rotate it by a fixed number of positions
 */
static constexpr Uint8 cRotationConstants [cDim][cDim] =
{
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};
// clang-format on

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
    bool         m_finished   = false;

    // buffer size to hold the chunk size to be processed
    Uint8 m_buffer[MaxDigestBlockSizeBits / 8];
    // state matrix to represent the keccak 1600 bits representation of
    // intermediate hash
    Uint64 m_state[cDim][cDim];
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
    , m_finished{ false }
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
    Uint64 hash_copied = 0;

    return avx2::Sha3Finalize(
        (Uint8*)m_state_flat, &m_hash[0], m_hash_size, m_chunk_size);

    while (m_chunk_size <= m_hash_size - hash_copied) {
        Uint64 data_chunk_copied = std::min(m_hash_size, m_chunk_size);

        utils::CopyBytes(
            &m_hash[hash_copied], (Uint8*)m_state_flat, data_chunk_copied);
        hash_copied += data_chunk_copied;

        if (hash_copied < m_hash_size) {
            fFunction();
        }
    }

    if (m_hash_size > hash_copied) {
        utils::CopyBytes(&m_hash[hash_copied],
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
    utils::CopyBytes(temp, m_state, sizeof(temp));
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
    m_finished = false;
    m_idx      = 0;
    memset(m_state, 0, sizeof(m_state));
}

alc_error_t
Sha3::Impl::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (size != m_hash_size) {
        Error::setGeneric(err, ALC_ERROR_INVALID_SIZE);
        return err;
    }

    utils::CopyBytes(pHash, m_hash.data(), size);
    return err;
}

alc_error_t
Sha3::Impl::processChunk(const Uint8* pSrc, Uint64 len)
{
    Uint64  msg_size       = len;
    Uint64* p_msg_buffer64 = (Uint64*)pSrc;

    return avx2::Sha3Update(
        m_state_flat, p_msg_buffer64, msg_size, m_chunk_size);

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

    if (m_finished) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
        return err;
    }

    if (pSrc == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }
    if (inputSize == 0) {
        return err;
    }

    Uint64 to_process = std::min((inputSize + m_idx), m_chunk_size);
    if (to_process < m_chunk_size) {
        /* copy them to internal buffer and return */
        utils::CopyBytes(&m_buffer[m_idx], pSrc, inputSize);
        m_idx += inputSize;
        return err;
    }

    Uint64 idx = m_idx;

    if (idx) {
        /*
         * Last call to update(), had some unprocessed bytes which is part
         * of internal buffer, we process first block by copying from pSrc the
         * remaining bytes of a chunk.
         */
        to_process = std::min(inputSize, m_chunk_size - idx);
        utils::CopyBytes(&m_buffer[idx], pSrc, to_process);

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
        utils::CopyBytes(&m_buffer[idx], pSrc, inputSize);
        idx += inputSize;
    }

    m_idx = idx;

    return err;
}

alc_error_t
Sha3::Impl::finalize(const Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        return err;
    }

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

    if (Error::isError(err)) {
        return err;
    }

    err = processChunk(m_buffer, m_chunk_size);

    squeezeChunk();

    m_idx      = 0;
    m_finished = true;

    return err;
}

Sha3::Sha3(const alc_digest_info_t& rDigestInfo)
    : m_pimpl{ std::make_unique<Sha3::Impl>(rDigestInfo) }
{}

Sha3::~Sha3() {}

alc_error_t
Sha3::update(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pSrc == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    if (!alcp_is_error(err) && m_pimpl)
        err = m_pimpl->update(pSrc, size);

    return err;
}

alc_error_t
Sha3::finalize(const Uint8* pSrc, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_pimpl)
        err = m_pimpl->finalize(pSrc, size);

    return err;
}

alc_error_t
Sha3::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pHash == nullptr) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
    }

    if (!Error::isError(err) && m_pimpl) {
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
    if (m_pimpl)
        m_pimpl->reset();
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
