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

#include "alcp/digest/sha2_384.hh"
#include "alcp/utils/copy.hh"

namespace alcp::digest {

static constexpr Uint64 /* define word size */
    // clang-format off
    /* same in bits */ cHashSizeBits        = 384,
    /* Hash size in bytes */ cHashSize      = cHashSizeBits / 8;
// clang-format on

Sha384::Sha384(const alc_digest_info_t& rDInfo)
    : Sha2{ "sha2-384" }
{
    m_psha512 = std::make_shared<Sha512>(rDInfo);
}

Sha384::Sha384()
{
    // Initializing the structure with default value
    alc_digest_info_t d_info;
    d_info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    d_info.dt_len          = ALC_DIGEST_LEN_384;
    d_info.dt_mode.dm_sha2 = ALC_SHA2_384;
    d_info.dt_custom_len   = 0;
    d_info.dt_data         = { 0 };

    m_psha512 = std::make_shared<Sha512>(d_info);
}

Sha384::Sha384(const Sha384& src)
{
    // Initializing the structure with default value
    m_psha512 = std::make_shared<Sha512>(*src.m_psha512);
}

Sha384::~Sha384() = default;

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
    return m_psha512->copyHash(pHash, size);
}

Uint64
Sha384::getInputBlockSize()
{
    // Input block size is same for sha384, sha512,sha512/224,sha512/256
    return Sha512::cChunkSize;
}

Uint64
Sha384::getHashSize()
{
    return cHashSize;
}

} // namespace alcp::digest
