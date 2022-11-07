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

#pragma once

#include "digest.hh"

namespace alcp::digest {

class Sha3 : public Digest
{
  public:
    Sha3(const alc_digest_info_t& rDigestInfo);
    ~Sha3();

  public:
    /**
     * \brief   Updates hash for given buffer
     *
     * \notes    Can be called repeatedly, if the message size is smaller than
     *           chunksize it will be cached for future use. and hash is only
     * updated after finalize() is called.
     *
     * \param    pMsgBuf    Pointer to message buffer
     *
     * \param    size    should be valid size > 0
     *
     */
    alc_error_t update(const uint8_t* pMsgBuf, Uint64 size);

    /**
     * \brief   Cleans up any resource that was allocated
     *
     * \notes   `finish()` to be called as a means to cleanup, no operation
     *           permitted after this call.
     *
     * \return nothing
     */
    void finish();

    /**
     * \brief    Resets the internal state.
     *
     * \notes   `reset()` to be called as a means to reset the internal state.
     *           This enables the processing the new buffer.
     *
     * \return nothing
     */
    void reset();

    /**
     * \brief    Call for the final chunk
     *
     * \notes   `finish()` to be called as a means to cleanup, necessary
     *           actions. Application can also call finalize() with
     *           empty/null args application must call copyHash before
     *           calling finish()
     *
     * \param    pMsgBuf     Either valid pointer to last chunk or nullptr,
     *                       once finalize() is called, only operation that
     *                       can be performed is copyHash()
     *
     * \param    size    Either valid size or 0, if \buf is nullptr, size
     *                   is assumed to be zero
     */
    alc_error_t finalize(const uint8_t* pMsgBuf, Uint64 size);

    /**
     * \brief  Copies the has from object to supplied buffer
     *
     * \notes `finalize()` to be called before with last chunks that should
     *           perform all the necessary actions, can be called with
     *           NULL argument.
     *
     * \param    pHash   pointer to the final hash generated
     *
     * \param    size    hash size to be copied from the object
     */
    alc_error_t copyHash(uint8_t* pHash, Uint64 size) const;

    /**
     * @return The input block size to the hash function in bytes
     */
    Uint64 getInputBlockSize();

    /**
     * @return The digest size in bytes
     */
    Uint64 getHashSize();

  private:
    class Impl;
    std::unique_ptr<Impl> m_pimpl;
};
} // namespace alcp::digest
