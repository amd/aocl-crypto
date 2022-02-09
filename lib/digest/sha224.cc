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

#include "digest/sha2.hh"

#include "utils/copy.hh"

namespace alcp::digest {

/*
 * first 32 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */

static constexpr uint32 cIv[] = { 0xc1059ed8, 0x367cd507, 0x3070dd17,
                                  0xf70e5939, 0xffc00b31, 0x68581511,
                                  0x64f98fa7, 0xbefa4fa4 };

static constexpr uint64 /* define word size */
    cWordSize                               = 32,
    /* num rounds in sha256 */ cNumRounds   = 64,
    /* chunk size in bits */ cChunkSizeBits = 512,
    /* chunks to proces */ cChunkSize       = cChunkSizeBits / 8,
    /*  */ cChunkSizeMask                   = cChunkSize - 1,
    /* same in words */ cChunkSizeWords     = cChunkSizeBits / cWordSize,
    /* same in bits */ cHashSizeBits        = 224,
    /* Hash size in bytes */ cHashSize      = cHashSizeBits / 8,
    cHashSizeWords                          = cHashSizeBits / cWordSize;

Sha224::Sha224(const alc_digest_info_t& rDInfo)
    : Sha2{ "sha2-224" }
{
    m_sha256 = Sha256{ rDInfo };
    m_sha256.setIv(cIv, sizeof(cIv));
}

Sha224::Sha224()
{
    m_sha256.setIv(cIv, sizeof(cIv));
}

alc_error_t
Sha224::update(const uint8_t* pBuf, uint64_t size)
{
    return m_sha256.update(pBuf, size);
}

void
Sha224::finish()
{
    return m_sha256.finish();
}

alc_error_t
Sha224::finalize(const uint8_t* pBuf, uint64_t size)
{
    return m_sha256.finalize(pBuf, size);
}

alc_error_t
Sha224::copyHash(uint8_t* pHash, uint64_t size) const
{
    alc_error_t err = ALC_ERROR_NONE;
    // assert(size < cHashSize);

    uint8_t intrim_hash[cHashSize * 2];
    err = m_sha256.copyHash(intrim_hash, sizeof(intrim_hash));

    if (!Error::isError(err)) {
        uint64_t len = std::min(size, cHashSize);

        utils::CopyBlock(pHash, intrim_hash, len);
    }
    return err;
}

} // namespace alcp::digest
