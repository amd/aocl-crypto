/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include "alcp/digest.hh"
#include "config.h"

#include <memory>

namespace alcp::digest {

// matrix dimension
static constexpr Uint8 cDim = 5;

/*
 * Rotation constants:
 * They take each of the 25 lanes of m_state i.e., word of 64 bits.
 * And rotate it by a fixed number of positions
 */
static constexpr Uint8 cRotationConstants[cDim][cDim] = {
    { 0, 1, 62, 28, 27 },
    { 36, 44, 6, 55, 20 },
    { 3, 10, 43, 25, 39 },
    { 41, 45, 15, 21, 8 },
    { 18, 2, 61, 56, 14 }
};
// maximum size of message block in bits is used for shake128 digest
static constexpr Uint32 MaxDigestBlockSizeBits = 1344;

class ALCP_API_EXPORT Sha3 : public Digest
{
  public:
    Sha3(const alc_digest_info_t& rDigestInfo);
    Sha3(const Sha3& src);
    ~Sha3();

  public:
    /**
     * @brief   Updates hash for given buffer
     *
     * @note    Can be called repeatedly, if the message size is smaller than
     *          chunksize it will be cached for future use. and hash is only
     *          updated after finalize() is called.
     *
     * @param    pMsgBuf    Pointer to message buffer
     *
     * @param    size    should be valid size > 0
     *
     */
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size);

    /**
     * @brief   Cleans up any resource that was allocated
     *
     * @note    finish() to be called as a means to cleanup, no operation
     *          permitted after this call.
     *
     * @return  nothing
     */
    void finish();

    /**
     * @brief    Resets the internal state.
     *
     * @note     reset() to be called as a means to reset the internal state.
     *           This enables the processing the new buffer.
     *
     * @return   nothing
     */
    void reset();

    /**
     * @brief    Call for the final chunk
     *
     * @note     finish() to be called as a means to cleanup, necessary
     *           actions. Application can also call finalize() with
     *           empty/null args application must call copyHash before
     *           calling finish()
     *
     * @param    pMsgBuf     Either valid pointer to last chunk or nullptr,
     *                       once finalize() is called, only operation that
     *                       can be performed is copyHash()
     *
     * @param    size    Either valid size or 0, if @buf is nullptr, size
     *                   is assumed to be zero
     */
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size);

    /**
     * @brief  Copies the has from object to supplied buffer
     *
     * @note   finalize() to be called before with last chunks that should
     *           perform all the necessary actions, can be called with
     *           NULL argument.
     *
     * @param    pHash   pointer to the final hash generated
     *
     * @param    size    hash size to be copied from the object
     */
    alc_error_t copyHash(Uint8* pHash, Uint64 size) const;

    /**
     * @return The input block size to the hash function in bytes
     */
    Uint64 getInputBlockSize();

    /**
     * @return The digest size in bytes
     */
    Uint64 getHashSize();

    /**
     * @brief To set the Digest Size for SHAKE128 or SHAKE256. Should be set
     * before finalizing.
     * @param shakeLength Custom Output Size
     * @return
     */
    alc_error_t setShakeLength(Uint64 shakeLength);

  private:
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    void        squeezeChunk();
    std::string m_name;
    Uint64      m_chunk_size, m_chunk_size_u64, m_hash_size;
    Uint32      m_idx = 0;

    // buffer size to hold the chunk size to be processed
    alignas(64) Uint8 m_buffer[MaxDigestBlockSizeBits / 8];
    // state matrix to represent the keccak 1600 bits representation of
    // intermediate hash
    alignas(64) Uint64 m_state[cDim][cDim];
    // flat representation of the state, used in absorbing the user message.
    Uint64* m_state_flat = &m_state[0][0];
    // buffer to copy intermediate hash value
    std::vector<Uint8> m_hash;
    bool               m_finished = false;
};

namespace zen3 {

    alc_error_t Sha3Update(Uint64* state,
                           Uint64* pSrc,
                           Uint64  msg_size,
                           Uint64  m_src_size_u64);

    void Sha3Finalize(Uint8* state,
                      Uint8* hash,
                      Uint64 hash_size,
                      Uint64 chunk_size);
} // namespace zen3
} // namespace alcp::digest
