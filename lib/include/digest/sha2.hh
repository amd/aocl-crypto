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

class Sha2 : public Digest
{
  public:
    Sha2(const std::string& name)
        : m_name{ name }
        , m_msg_len{ 0 }
    {}

    Sha2(const char* name)
        : Sha2(std::string(name))
    {}

    // TODO : Removing Return here causes an error
    /**
     * @return  0 when function is not implemented
     */

    Uint64 getInputBlockSize() { return 0; };

    /**
     * @return 0 when the function is not implemented
     */
    Uint64 getHashSize() { return 0; };

  protected:
    Sha2() {}
    virtual ~Sha2();

  protected:
    alc_sha2_mode_t m_mode;
    std::string     m_name;
    Uint64          m_msg_len;
    // alc_sha2_param_t m_param;
};

class Sha256 final : public Sha2
{
  public:
    static constexpr Uint64 /* define word size */
        cWordSizeBits   = 32,
        cNumRounds      = 64,                 /* num rounds in sha256 */
        cChunkSizeBits  = 512,                /* chunk size in bits */
        cChunkSize      = cChunkSizeBits / 8, /* chunks to proces */
        cChunkSizeMask  = cChunkSize - 1,
        cChunkSizeWords = cChunkSizeBits / cWordSizeBits, /* same in words */
        cHashSizeBits   = 256,                            /* same in bits */
        cHashSize       = cHashSizeBits / 8, /* Hash size in bytes */
        cHashSizeWords  = cHashSizeBits / cWordSizeBits,
        cIvSizeBytes    = 32; /* IV size in bytes */

  public:
    ALCP_API_EXPORT Sha256();
    Sha256(const alc_digest_info_t& rDigestInfo);
    virtual ALCP_API_EXPORT ~Sha256();

    /**
     * @return The input block size to the hash function in bytes
     */
    ALCP_API_EXPORT Uint64 getInputBlockSize() override;

    /**
     * @return The digest size in bytes
     */
    ALCP_API_EXPORT Uint64 getHashSize() override;

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
    ALCP_API_EXPORT alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;

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
    ALCP_API_EXPORT alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;

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
    ALCP_API_EXPORT alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const override;

  public:
    ALCP_API_EXPORT alc_error_t setIv(const void* pIv, Uint64 size);

  private:
    class Impl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }
    std::unique_ptr<Impl> m_pimpl;
};

class ALCP_API_EXPORT Sha224 final : public Sha2
{
  public:
    Sha224();
    Sha224(const alc_digest_info_t& rDInfo);
    ~Sha224();
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;
    void        finish() override;
    void        reset() override;
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;
    alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const override;

    /**
     * @return The input block size to the hash function in bytes
     */
    Uint64 getInputBlockSize() override;

    /**
     * @return The digest size in bytes
     */
    Uint64 getHashSize() override;

  private:
    std::shared_ptr<Sha256> m_psha256;
};

static inline void
CompressMsg(Uint32* pMsgSchArray, Uint32* pHash, const Uint32* pHashConstants)
{
    Uint32 a, b, c, d, e, f, g, h;
    a = pHash[0];
    b = pHash[1];
    c = pHash[2];
    d = pHash[3];
    e = pHash[4];
    f = pHash[5];
    g = pHash[6];
    h = pHash[7];
    for (Uint32 i = 0; i < 64; i++) {
        Uint32 s1, ch, temp1, s0, maj, temp2;
        s1    = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
        ch    = (e & f) ^ (~e & g);
        temp1 = h + s1 + ch + pHashConstants[i] + pMsgSchArray[i];
        s0    = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
        maj   = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;
        h     = g;
        g     = f;
        f     = e;
        e     = d + temp1;
        d     = c;
        c     = b;
        b     = a;
        a     = temp1 + temp2;
    }

    pHash[0] += a;
    pHash[1] += b;
    pHash[2] += c;
    pHash[3] += d;
    pHash[4] += e;
    pHash[5] += f;
    pHash[6] += g;
    pHash[7] += h;
}

} // namespace alcp::digest
