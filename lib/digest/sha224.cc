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

static constexpr Uint32 cIv[] = { 0xc1059ed8, 0x367cd507, 0x3070dd17,
                                  0xf70e5939, 0xffc00b31, 0x68581511,
                                  0x64f98fa7, 0xbefa4fa4 };

static constexpr Uint64 /* define word size */
    // clang-format off
    /* chunk size in bits */ cChunkSizeBits = 512,
    /* chunks to proces */ cChunkSize       = cChunkSizeBits / 8,
    /* same in bits */ cHashSizeBits        = 224,
    /* Hash size in bytes */ cHashSize      = cHashSizeBits / 8;
// FIXME: Unused Variables
#if 0
    cWordSize                               = 32,
    /* num rounds in sha256 */ cNumRounds   = 64,
    /*  */ cChunkSizeMask                   = cChunkSize - 1,
    /* same in words */ cChunkSizeWords     = cChunkSizeBits / cWordSize,
    cHashSizeWords                          = cHashSizeBits / cWordSize,
#endif
// clang-format on

Sha224::Sha224(const alc_digest_info_t& rDInfo)
    : Sha2{ "sha2-224" }
{
    m_psha256 = std::make_shared<Sha256>(rDInfo);
    m_psha256->setIv(cIv, sizeof(cIv));
}

Sha224::Sha224()
{
    // Initializing the structure with default value
    alc_digest_info_t d_info;
    d_info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    d_info.dt_len          = ALC_DIGEST_LEN_224;
    d_info.dt_mode.dm_sha2 = ALC_SHA2_224;
    d_info.dt_custom_len   = 0;
    d_info.dt_data         = { 0 };

    m_psha256 = std::make_shared<Sha256>(d_info);
    m_psha256->setIv(cIv, sizeof(cIv));
}

Sha224::~Sha224() = default;

alc_error_t
Sha224::update(const Uint8* pBuf, Uint64 size)
{
    return m_psha256->update(pBuf, size);
}

void
Sha224::finish()
{
    return m_psha256->finish();
}

void
Sha224::reset()
{
    m_psha256->reset();
    m_psha256->setIv(cIv, sizeof(cIv));
    return;
}

alc_error_t
Sha224::finalize(const Uint8* pBuf, Uint64 size)
{
    return m_psha256->finalize(pBuf, size);
}

alc_error_t
Sha224::copyHash(Uint8* pHash, Uint64 size) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (size != cHashSize) {
        Error::setGeneric(err, ALC_ERROR_INVALID_SIZE);
        return err;
    }

    if (!pHash) {
        Error::setGeneric(err, ALC_ERROR_INVALID_ARG);
        return err;
    }

    // We should set intrim_hash size as 256 bit as we are calling into SHA256
    // algorithm. Later we should trim it to exact 224 bits
    Uint8 intrim_hash[cHashSize + 4];
    err = m_psha256->copyHash(intrim_hash, sizeof(intrim_hash));

    if (!Error::isError(err)) {
        utils::CopyBlock(pHash, intrim_hash, size);
    }
    return err;
}

Uint64
Sha224::getInputBlockSize()
{
    return cChunkSize;
}

Uint64
Sha224::getHashSize()
{
    return cHashSize;
}

} // namespace alcp::digest
