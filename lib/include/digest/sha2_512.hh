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
#include "sha2.hh"

namespace alcp::digest {

class Sha512 final : public Sha2
{
  public:
    static constexpr Uint64 cWordSizeBits = 64,   /* define word size */
        cNumRounds                        = 80,   /* num rounds in sha512 */
        cChunkSizeBits                    = 1024, /* chunk size in bits */
        cChunkSize      = cChunkSizeBits / 8,     /* chunks to proces */
        cChunkSizeMask  = cChunkSize - 1,         /*  */
        cChunkSizeWords = cChunkSizeBits / cWordSizeBits, /* same in words */
        cHashSizeBits   = 512,                            /* same in bits */
        cHashSize       = cHashSizeBits / 8, /* Hash size in bytes */
        cHashSizeWords  = cHashSizeBits / cWordSizeBits;

  public:
    Sha512();
    Sha512(const alc_digest_info_t& rDigestInfo);

  private:
    virtual ~Sha512();

  public:
    /**
     * \brief   Updates hash for given buffer
     *
     * \notes    Can be called repeatedly, if the hashsize is smaller
     *           it will be cached for future use. and hash is only updated
     *           after finalize() is called.
     *
     * \param    pBuf    Pointer to message buffer
     *
     * \param    size    should be valid size > 0
     */
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;

    /**
     * \brief   Cleans up any resource that was allocated
     *
     * \notes   `finish()` to be called as a means to cleanup, no operation
     *           permitted after this call. The context will be unusable.
     *
     * \return nothing
     */
    void finish() override;

    /**
     * \brief    Resets the internal state.
     *
     * \notes   `reset()` to be called as a means to reset the internal state.
     *           This enables the processing the new buffer.
     *
     * \return nothing
     */
    void reset() override;

    /**
     * \brief    Call for the final chunk
     *
     * \notes   `finish()` to be called as a means to cleanup, necessary
     *           actions. Application can also call finalize() with
     *           empty/null args application must call copyHash before
     *           calling finish()
     *
     * \param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once finalize()
     *                   is called, only operation that can be performed
     *                   is copyHash()
     *
     * \param    size    Either valid size or 0, if \buf is nullptr, size
     *                   is assumed to be zero
     */
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;

    /**
     * \brief  Copies the has from context to supplied buffer
     *
     * \notes `finalize()` to be called with last chunks that should
     *           perform all the necessary actions, can be called with
     *           NULL argument.
     *
     * \param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once finalize()
     *                   is called, only operation that can  be performed
     *                   is copyHash()
     *
     * \param    size    Either valid size or 0, if \buf is nullptr, size is
     *                   assumed to be zero
     */
    alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const override;

    alc_error_t setIv(const void* pIv, Uint64 size);

  private:
    void        compressMsg(Uint64 w[]);
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);

  private:
    Uint64 m_msg_len;
    /* Any unprocessed bytes from last call to update() */
    Uint8  m_buffer[2 * cChunkSize];
    Uint64 m_hash[cHashSizeWords];
    /* index to m_buffer of previously unprocessed bytes */
    Uint32 m_idx;
    bool   m_finished;
};

class Sha384 final : public Sha2
{
  public:
    Sha384();
    Sha384(const alc_digest_info_t& rDInfo);
    virtual ~Sha384();
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;
    void        finish() override;
    void        reset() override;
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;
    alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const override;

  private:
    Sha512* m_psha512;
};

} // namespace alcp::digest
