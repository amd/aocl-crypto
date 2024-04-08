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

#include <algorithm>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "alcp/digest/sha3.hh"
#include "alcp/digest/sha3_zen.hh"
#include "alcp/utils/bits.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "alcp/utils/endian.hh"

namespace utils = alcp::utils;
using namespace alcp::digest;

using alcp::utils::CpuId;

#include "sha3_inplace.hh"

namespace alcp::digest {

#include "sha3_inplace.cc.inc"

static inline void
round(Uint64 roundConst, Uint64 state[cDim][cDim])
{
    // theta stage
    Uint64 c[cDim], d[cDim];

    for (int x = 0; x < cDim; ++x) {
        c[x] = state[0][x];
        for (int y = 1; y < cDim; ++y) {
            c[x] ^= state[y][x];
        }
    }

    for (int x = 0; x < cDim; ++x) {
        d[x] = c[(cDim + x - 1) % cDim]
               ^ alcp::digest::RotateLeft(c[(x + 1) % cDim], 1);
    }

    for (int x = 0; x < cDim; ++x) {
        for (int y = 0; y < cDim; ++y) {
            state[x][y] ^= d[y];
        }
    }

    // Rho stage
    Uint64 temp[cDim][cDim];
    for (int x = 0; x < cDim; x++) {
        for (int y = 0; y < cDim; y++) {
            temp[x][y] =
                alcp::digest::RotateLeft(state[x][y], cRotationConstants[x][y]);
        }
    }

    // pi stage
    for (int x = 0; x < cDim; ++x) {
        int x_indx = 2 * x;
        for (int y = 0; y < cDim; ++y) {
            state[(x_indx + 3 * y) % cDim][y] = temp[y][x];
        }
    }

    // xi stage
    utils::CopyBlock(temp, state, sizeof(temp));
    for (int x = 0; x < cDim; ++x) {
        for (int y = 0; y < cDim; ++y) {
            state[x][y] =
                temp[x][y]
                ^ (~temp[x][(y + 1) % cDim] & temp[x][(y + 2) % cDim]);
        }
    }

    // iota stage
    state[0][0] ^= roundConst;
}

static inline void
fFunction(Uint64* stateFlat)
{
    const Uint64 num_rounds = 24;
    for (Uint64 i = 0; i < num_rounds; ++i) {
        round(cRoundConstants[i], reinterpret_cast<Uint64(*)[5]>(stateFlat));
    }
}

static inline void
absorbChunk(Uint64* pMsgBuffer64, Uint64* stateFlat, Uint64 size)
{
    for (Uint64 i = 0; i < size; ++i) {
        stateFlat[i] ^= pMsgBuffer64[i];
    }
    // keccak function
    fFunction(stateFlat);
}

template<alc_digest_len_t digest_len>
void
Sha3<digest_len>::squeezeChunk()
{
    Uint64 hash_copied = 0;

    static bool zen1_available = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen3_available = CpuId::cpuIsZen3() || CpuId::cpuIsZen4();

    if (zen3_available) {
        return zen3::Sha3Finalize(
            (Uint8*)m_state_flat, &m_hash[0], m_digest_len, m_block_len);
    }

    if (zen1_available) {
        return zen::Sha3Finalize(
            (Uint8*)m_state_flat, &m_hash[0], m_digest_len, m_block_len);
    }

    while (m_block_len <= m_digest_len - hash_copied) {
        Uint64 data_chunk_copied = std::min(m_digest_len, m_block_len);

        utils::CopyBlock(
            &m_hash[hash_copied], (Uint8*)m_state_flat, data_chunk_copied);
        hash_copied += data_chunk_copied;

        if (hash_copied < m_digest_len) {
            fFunction(m_state_flat);
        }
    }

    if (m_digest_len > hash_copied) {
        utils::CopyBlock(&m_hash[hash_copied],
                         (Uint8*)m_state_flat,
                         m_digest_len - hash_copied);
    }
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha3<digest_len>::processChunk(const Uint8* pSrc, Uint64 len)
{
    Uint64  msg_size       = len;
    Uint64* p_msg_buffer64 = (Uint64*)pSrc;
    Uint64  chunk_size_u64 = m_block_len / 8;

    static bool zen1_available = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen3_available = CpuId::cpuIsZen3() || CpuId::cpuIsZen4();

    if (zen3_available) {
        return zen3::Sha3Update(
            m_state_flat, p_msg_buffer64, msg_size, m_block_len);
    }

    if (zen1_available) {
        return zen::Sha3Update(
            m_state_flat, p_msg_buffer64, msg_size, m_block_len);
    }

    while (msg_size) {
        // xor message chunk into m_state.
        absorbChunk(p_msg_buffer64, m_state_flat, chunk_size_u64);
        p_msg_buffer64 += chunk_size_u64;
        msg_size -= m_block_len;
    }

    return ALC_ERROR_NONE;
}

template<alc_digest_len_t digest_len>
Sha3<digest_len>::Sha3()
{
    // chunk_size_bits are as per specs befined in
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    Uint64 chunk_size_bits = 1600 - 2 * digest_len;
    m_digest_len           = digest_len / 8;
    m_block_len            = chunk_size_bits / 8;
    m_hash.resize(m_digest_len);
}

template<>
Sha3<ALC_DIGEST_LEN_CUSTOM_SHAKE_128>::Sha3()
{
    // chunk_size_bits are as per specs befined in
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    Uint64 chunk_size_bits = 1600 - 2 * ALC_DIGEST_LEN_128;
    m_digest_len           = ALC_DIGEST_LEN_128 / 8;
    m_block_len            = chunk_size_bits / 8;
    m_hash.resize(m_digest_len);
}

template<>
Sha3<ALC_DIGEST_LEN_CUSTOM_SHAKE_256>::Sha3()
{
    // chunk_size_bits are as per specs befined in
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    Uint64 chunk_size_bits = 1600 - 2 * ALC_DIGEST_LEN_256;
    m_digest_len           = ALC_DIGEST_LEN_256 / 8;
    m_block_len            = chunk_size_bits / 8;
    m_hash.resize(m_digest_len);
}

template<alc_digest_len_t digest_len>
Sha3<digest_len>::Sha3(const Sha3& src)
{
    m_block_len  = src.m_block_len;
    m_digest_len = src.m_digest_len;
    m_idx        = src.m_idx;
    memcpy(m_buffer, src.m_buffer, MaxDigestBlockSizeBits / 8);
    memcpy(m_state, src.m_state, sizeof(m_state));
    m_hash     = src.m_hash;
    m_finished = src.m_finished;
}

template<alc_digest_len_t digest_len>
void
Sha3<digest_len>::init(void)
{
    m_idx = 0;
    memset(m_state, 0, sizeof(m_state));
    m_finished = false;
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha3<digest_len>::update(const Uint8* pSrc, Uint64 inputSize)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished || pSrc == nullptr) {
        /* TODO: change to Status */
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    if (inputSize == 0) {
        /* TODO: change to Status */
        err = ALC_ERROR_NONE;
        return err;
    }

    Uint64 to_process = std::min((inputSize + m_idx), m_block_len);
    if (to_process < m_block_len) {
        /* copy them to internal buffer and return */
        utils::CopyBytes(&m_buffer[m_idx], pSrc, inputSize);
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
        to_process = std::min(inputSize, m_block_len - idx);
        utils::CopyBytes(&m_buffer[idx], pSrc, to_process);

        pSrc += to_process;
        inputSize -= to_process;
        idx += to_process;
        if (idx == m_block_len) {
            err = processChunk(m_buffer, m_block_len);
            idx = 0;
        }
    }

    /* Calculate leftover bytes that can be processed as multiple chunks */
    Uint64 num_chunks = inputSize / m_block_len;

    if (num_chunks) {
        Uint64 size = num_chunks * m_block_len;
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

template<alc_digest_len_t digest_len>
alc_error_t
Sha3<digest_len>::finalize(Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        return err;
    }

    // sha3 padding
    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, m_block_len - m_idx);

    m_buffer[m_idx] = 0x06;

    m_buffer[m_block_len - 1] |= 0x80;

    if (err) {
        return err;
    }

    err = processChunk(m_buffer, m_block_len);

    if (err != ALC_ERROR_NONE) {
        return err;
    }
    squeezeChunk();

    // ToDO: add the m_digest_len check when the classes for sha3 / shake has
    // been divided
    if (pBuf != nullptr && m_digest_len == size) {
        utils::CopyBlock(pBuf, m_hash.data(), size);
        m_idx      = 0;
        m_finished = true;
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_INVALID_ARG;
    }
}

template<>
alc_error_t
Sha3<ALC_DIGEST_LEN_CUSTOM_SHAKE_128>::finalize(Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        return err;
    }

    // sha3 padding
    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, m_block_len - m_idx);

    m_buffer[m_idx] = 0x1f;

    m_buffer[m_block_len - 1] |= 0x80;

    if (err) {
        return err;
    }

    err = processChunk(m_buffer, m_block_len);

    if (err != ALC_ERROR_NONE) {
        return err;
    }
    squeezeChunk();

    if (pBuf != nullptr && size != 0) {
        utils::CopyBlock(pBuf, m_hash.data(), size);
        m_idx      = 0;
        m_finished = true;
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_INVALID_ARG;
    }
}

template<>
alc_error_t
Sha3<ALC_DIGEST_LEN_CUSTOM_SHAKE_256>::finalize(Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finished) {
        return err;
    }

    // sha3 padding
    utils::PadBlock<Uint8>(&m_buffer[m_idx], 0x0, m_block_len - m_idx);

    m_buffer[m_idx] = 0x1f;

    m_buffer[m_block_len - 1] |= 0x80;

    if (err) {
        return err;
    }

    err = processChunk(m_buffer, m_block_len);

    if (err != ALC_ERROR_NONE) {
        return err;
    }
    squeezeChunk();

    // ToDO: add the m_digest_len check when the classes for sha3 / shake has
    // been divided
    if (pBuf != nullptr && size != 0) {
        utils::CopyBlock(pBuf, m_hash.data(), size);
        m_idx      = 0;
        m_finished = true;
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_INVALID_ARG;
    }
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha3<digest_len>::setShakeLength(Uint64 shakeLength)
{
    if (m_finished
        || (digest_len != ALC_DIGEST_LEN_CUSTOM_SHAKE_128
            && digest_len != ALC_DIGEST_LEN_CUSTOM_SHAKE_256)) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    m_digest_len = shakeLength;
    m_hash.resize(m_digest_len);
    return ALC_ERROR_NONE;
}

template<alc_digest_len_t digest_len>
alc_error_t
Sha3<digest_len>::shakeSqueeze(Uint8* pBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    // Implement the squeeze function

    if (!m_finished) {
        return finalize(pBuf, size);
    } else {
        squeezeChunk();

        if (pBuf != nullptr) {
            utils::CopyBlock(pBuf, m_hash.data(), size);
            err = ALC_ERROR_NONE;
        } else {
            err = ALC_ERROR_INVALID_ARG;
        }
    }
    return err;
}

template class Sha3<ALC_DIGEST_LEN_224>;
template class Sha3<ALC_DIGEST_LEN_256>;
template class Sha3<ALC_DIGEST_LEN_384>;
template class Sha3<ALC_DIGEST_LEN_512>;
template class Sha3<ALC_DIGEST_LEN_CUSTOM_SHAKE_128>;
template class Sha3<ALC_DIGEST_LEN_CUSTOM_SHAKE_256>;

} // namespace alcp::digest
