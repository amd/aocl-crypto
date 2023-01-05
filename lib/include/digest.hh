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

/* C-API headers */
#include "config.h"

#include "alcp/digest.h"
#include "alcp/types.h"

/* System headers */
#include <memory_resource>
#include <string>

namespace alcp::digest {

// typedef std::pmr::synchronized_pool_resource DigestPool;

std::pmr::synchronized_pool_resource&
GetDefaultDigestPool();

static inline Uint32
RotateRight(Uint32 value, Uint32 count)
{
#if 0
    __asm__("rorl %%cl, %0" : "+r"(value) : "c"(count));
    return value;
#else
    return value >> count | value << (32 - count);
#endif
}

static inline Uint64
RotateRight(Uint64 value, Uint64 count)
{
#if 0
    __asm__("rorq %%cl, %0" : "+r"(value) : "c"(count));
    return value;
#else
    return value >> count | value << (64 - count);
#endif
}

static inline Uint32
RotateLeft(Uint32 value, Uint32 count)
{
    return value << count | value >> (32 - count);
}

static inline Uint64
RotateLeft(Uint64 value, Uint64 count)
{
    return value << count | value >> (64 - count);
}

class IDigest
{
  public:
    IDigest() {}

  public:
    virtual alc_error_t update(const Uint8* pBuf, Uint64 size)   = 0;
    virtual alc_error_t finalize(const Uint8* pBuf, Uint64 size) = 0;
    virtual void        finish()                                 = 0;
    virtual void        reset()                                  = 0;
    // virtual alc_error_t compute(const Uint8* buf, Uint64 size)  = 0;
    virtual alc_error_t copyHash(Uint8* pBuf, Uint64 size) const = 0;

    /**
     * @return The input block size to the hash function in bytes
     */
    virtual Uint64 getInputBlockSize() = 0;

    /**
     * @return The digest size in bytes
     */
    virtual Uint64 getHashSize() = 0;

  protected:
    virtual ~IDigest() {}
};

class Digest : public IDigest
{

  protected:
    alc_digest_len_t  m_digest_len; /* digest len in bytes */
    Uint64            m_digest_len_bytes;
    alc_digest_data_t m_data;

  protected:
    Digest()          = default;
    virtual ~Digest() = default;
};

} // namespace alcp::digest
