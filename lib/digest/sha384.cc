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
 * first 64 bits of the fractional parts of the square roots
 * of the first 8 primes 2..19
 */

static constexpr Uint64 cIv[] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                                  0x9159015a3070dd17, 0x152fecd8f70e5939,
                                  0x67332667ffc00b31, 0x8eb44a8768581511,
                                  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };

static constexpr Uint64 /* define word size */
    cWordSize                               = 64,
    /* num rounds in sha512 */ cNumRounds   = 80,
    /* chunk size in bits */ cChunkSizeBits = 1024,
    /* chunks to proces */ cChunkSize       = cChunkSizeBits / 8,
    /*  */ cChunkSizeMask                   = cChunkSize - 1,
    /* same in words */ cChunkSizeWords     = cChunkSizeBits / cWordSize,
    /* same in bits */ cHashSizeBits        = 384,
    /* Hash size in bytes */ cHashSize      = cHashSizeBits / 8,
    cHashSizeWords                          = cHashSizeBits / cWordSize;

Sha384::Sha384(const alc_digest_info_t& rDInfo)
    : Sha2{ "sha2-384" }
{
    m_psha512 = new Sha512{ rDInfo };
    m_psha512->setIv(cIv, sizeof(cIv));
}

Sha384::Sha384() {}
Sha384::~Sha384()
{
    delete m_psha512;
}

alc_error_t
Sha384::update(const Uint8* pBuf, Uint64 size)
{
    return m_psha512->update(pBuf, size);
}

void
Sha384::finish()
{
    return m_psha512->finish();
}

void
Sha384::reset()
{
    m_psha512->reset();
    m_psha512->setIv(cIv, sizeof(cIv));
    return;
}

alc_error_t
Sha384::finalize(const Uint8* pBuf, Uint64 size)
{
    return m_psha512->finalize(pBuf, size);
}

alc_error_t
Sha384::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;
    assert(size >= cHashSize);

    Uint8 intrim_hash[cHashSize * 2];
    err = m_psha512->copyHash(intrim_hash, sizeof(intrim_hash));

    if (!Error::isError(err)) {
        Uint64 len = std::min(size, cHashSize);

        utils::CopyBlock(pHash, intrim_hash, len);
    }
    return err;
}

} // namespace alcp::digest
