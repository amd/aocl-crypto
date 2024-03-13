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
#include "sha2.hh"

namespace alcp::digest {

/*
 * Round constants:
 * For each round, there is one round constant k[i] and one entry in the
 * message schedule array w[i], 0 ≤ i ≤ 80.
 * Values are first 64 bits of the fractional parts of the cube
 * roots of the first 80 primes 2.409.
 */
__attribute__((aligned(64))) static constexpr Uint64 cRoundConstants[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static inline void
ShaRound(Uint64  a,
         Uint64  b,
         Uint64  c,
         Uint64& d,
         Uint64  e,
         Uint64  f,
         Uint64  g,
         Uint64& h,
         Uint64  x)
{
    Uint64 s0 = 0, s1 = 0, maj = 0, ch = 0;
    maj      = (a & ((b ^ c))) + (b & c);
    ch       = (e & f) + (~e & g);
    s0       = RotateRight(a, 28) ^ RotateRight(a, 34) ^ RotateRight(a, 39);
    s1       = RotateRight(e, 14) ^ RotateRight(e, 18) ^ RotateRight(e, 41);
    Uint64 t = x + h + s1 + ch;
    h        = t + s0 + maj;
    d += t;
}

/* TODO: Add pImpl support as done in sha256 */

class ALCP_API_EXPORT Sha512 final : public Sha2
{
  public:
    // clang-format off
    static constexpr Uint64
        cWordSizeBits                     = 64,                             /* define word size */
        cNumRounds                        = 80,                             /* num rounds in sha512 */
        cChunkSizeBits                    = 1024,                           /* chunk size in bits for sha384,sha512,sha512/224,sha512/256*/
        cChunkSize                        = cChunkSizeBits / 8,             /* chunks to proces */
        cChunkSizeMask                    = cChunkSize - 1,                 /*  */
        cChunkSizeWords                   = cChunkSizeBits / cWordSizeBits, /* same in words */
        cHashSizeBits                     = 512,                            /* same in bits */
        cHashSize                         = cHashSizeBits / 8,              /* Hash size in bytes */
        cHashSizeWords                    = cHashSizeBits / cWordSizeBits,
        cIvSizeBytes                      = 64;                             /* IV size in bytes */
    // clang-format on
  public:
    Sha512(alc_digest_len_t digest_len = ALC_DIGEST_LEN_512);
    Sha512(const alc_digest_info_t& rDigestInfo);
    Sha512(const Sha512& src);
    virtual ~Sha512();

  public:
    /**
     * @brief   Updates hash for given buffer
     *
     * @note    Can be called repeatedly, if the hashsize is smaller
     *           it will be cached for future use. and hash is only updated
     *           after finalize() is called.
     *
     * @param    pBuf    Pointer to message buffer
     *
     * @param    size    should be valid size > 0
     */
    alc_error_t update(const Uint8* pMsgBuf, Uint64 size) override;

    /**
     * @brief   Cleans up any resource that was allocated
     *
     * @note   `finish()` to be called as a means to cleanup, no operation
     *           permitted after this call. The context will be unusable.
     *
     * @return nothing
     */
    void finish() override;

    /**
     * @brief    Resets the internal state.
     *
     * @note   `reset()` to be called as a means to reset the internal
     * state. This enables the processing the new buffer.
     *
     * @return nothing
     */
    void reset() override;

    /**
     * @brief    Call for the final chunk
     *
     * @note
     *           - \ref finish() to be called as a means to cleanup, necessary
     *           actions.
     *           - Application can also call finalize() with
     *           empty/null args application must call copyHash before
     *           calling finish()
     *
     * @param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once
     *                  finalize() is called, only operation that can be
     *                  performed is copyHash()
     *
     * @param    size    Either valid size or 0, if pMsgBuf is nullptr, size
     *                   is assumed to be zero
     */
    alc_error_t finalize(const Uint8* pMsgBuf, Uint64 size) override;

    /**
     * @brief  Copies the has from context to supplied buffer
     *
     * @note     \ref finalize() to be called with last chunks that should
     *           perform all the necessary actions, can be called with
     *           NULL argument.
     *
     * @param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once
     *                  finalize() is called, only operation that can be
     *                  performed is copyHash()
     *
     * @param    size    Either valid size or 0, if @buf is nullptr, size is
     *                   assumed to be zero
     */
    alc_error_t copyHash(Uint8* pHashBuf, Uint64 size) const override;

    alc_error_t setIv(const void* pIv, Uint64 size);

    /**
     * @return The input block size to the hash function in bytes
     */
    Uint64 getInputBlockSize() override;

    /**
     * @return The digest size in bytes
     */
    Uint64 getHashSize() override;

  private:
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    Uint64      m_msg_len;
    /* Any unprocessed bytes from last call to update() */
    alignas(64) Uint8 m_buffer[2 * cChunkSize];
    alignas(64) Uint64 m_hash[cHashSizeWords];
    /* index to m_buffer of previously unprocessed bytes */
    Uint32        m_idx;
    bool          m_finished;
    const Uint64* m_Iv = nullptr;
    Uint64        m_digest_len_bytes;
    Uint64        m_digest_len;
};

} // namespace alcp::digest
