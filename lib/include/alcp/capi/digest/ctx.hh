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

#ifndef _CAPI_DIGEST_HH
#define _CAPI_DIGEST_HH 2

#include "alcp/digest.h"

#include "alcp/capi/defs.hh"
#include "alcp/digest.hh"

namespace alcp::digest {

class Context
{
    // using PoolAllocator = alcp::utils::PoolAllocator;

  public:
    void* m_digest = nullptr;

    alc_error_t (*init)(void* pDigest);
    alc_error_t (*update)(void* pDigest, const Uint8* pSrc, Uint64 len);
    alc_error_t (*duplicate)(Context& srcCtx, Context& destCtx);
    alc_error_t (*finalize)(void* pDigest, Uint8* pBuf, Uint64 len);
    alc_error_t (*finish)(void* pDigest);
    alc_error_t (*shakeSqueeze)(void* pDigest, Uint8* pBuf, Uint64 size);
    Status status{ StatusOk() };

#if 0
    static void* operator new(size_t size) { return s_ctx_pool.allocate(size); }

    static void operator delete(void* ptr, size_t size)
    {
        auto p = reinterpret_cast<Context*>(ptr);
        s_ctx_pool.deallocate(p, size);
    }

 private:
    static utils::Pool<digest::Context> s_ctx_pool;
#endif
};

} // namespace alcp::digest

#endif /* _CAPI_DIGEST_HH */
