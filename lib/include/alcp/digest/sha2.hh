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
#include "alcp/utils/bits.hh"

#include <memory> // for unique_ptr
using alcp::utils::RotateRight;
namespace alcp::digest {

template<alc_digest_len_t digest_len>
class Sha2 final : public IDigest
{
    static_assert(ALC_DIGEST_LEN_224 == digest_len
                  || ALC_DIGEST_LEN_256 == digest_len);

  public:
    static constexpr Uint64 /* define word size */
        cWordSizeBits   = 32,
        cNumRounds      = 64,                 /* num rounds in sha256 */
        cChunkSizeBits  = 512,                /* chunk size in bits */
        cChunkSize      = cChunkSizeBits / 8, /* chunks to proces */
        cChunkSizeMask  = cChunkSize - 1,
        cChunkSizeWords = cChunkSizeBits / cWordSizeBits, /* same in words */
        cHashSizeBits   = ALC_DIGEST_LEN_256,             /* same in bits */
        cHashSize       = cHashSizeBits / 8, /* Hash size in bytes */
        cHashSizeWords  = cHashSizeBits / cWordSizeBits;

  public:
    ALCP_API_EXPORT Sha2();
    ALCP_API_EXPORT Sha2(const Sha2& src);
    virtual ALCP_API_EXPORT ~Sha2() = default;

  public:
    /**
     * \brief    inits the internal state.
     *
     * \notes   `init()` to be called as a means to reset the internal state.
     *           This enables the processing the new buffer.
     *
     * \return nothing
     */
    ALCP_API_EXPORT void init(void) override;
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
    ALCP_API_EXPORT alc_error_t update(const Uint8* pMsgBuf,
                                       Uint64       size) override;

    /**
     * \brief    Call for the final chunk
     *
     *
     * \param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once finalize()
     *                   is called, only operation that can be performed
     *                   is copyHash()
     *
     * \param    size    Either valid size or 0, if \buf is nullptr, size
     *                   is assumed to be zero
     */
    ALCP_API_EXPORT alc_error_t finalize(const Uint8* pMsgBuf,
                                         Uint64       size) override;

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
    ALCP_API_EXPORT alc_error_t copyHash(Uint8* pHashBuf,
                                         Uint64 size) const override;

  private:
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    /* Any unprocessed bytes from last call to update() */
    alignas(64) Uint8 m_buffer[2 * cChunkSize]{};
    alignas(64) Uint32 m_hash[cHashSizeWords]{};
};

typedef Sha2<ALC_DIGEST_LEN_224> Sha224;
typedef Sha2<ALC_DIGEST_LEN_256> Sha256;

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

static inline void
extendMsg(Uint32 w[], Uint32 start, Uint32 end)
{
    for (Uint32 i = start; i < end; i++) {
        const Uint32 s0 = RotateRight(w[i - 15], 7) ^ RotateRight(w[i - 15], 18)
                          ^ (w[i - 15] >> 3);
        const Uint32 s1 = RotateRight(w[i - 2], 17) ^ RotateRight(w[i - 2], 19)
                          ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

} // namespace alcp::digest
