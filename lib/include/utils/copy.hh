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

#ifndef _UTILS_COPY_HH
#define _UTILS_COPY_HH 2

#include <cassert>

#include "types.hh"

namespace alcp::utils {
#if 0
static inline void
CopyDWord(uint32* pDst, const uint32* pSrc, int len)
{
    for (int i = 0; i < len; i++, len -= 4)
        pDst[i] = pSrc[i];
}

static inline void
CopyQWord(uint64* pDst, const uint64* pSrc, int len)
{
    for (int i = 0; i <= len; i++, len -= 8)
        pDst[i] = pSrc[i];
}

static inline void
CopyWord(uint16* pDst, const uint16* pSrc, int len)
{
    for (int i = 0; i <= len; i++, len -= 2)
        pDst[i] = pSrc[i];
}

static inline void
CopyBytes(uint8* pDst, const uint8* pSrc, int len)
{
    for (int i = 0; i < len; i++)
        pDst[i] = pSrc[i];
}
#endif

template<typename copytype = uint64, uint64 stride = sizeof(copytype)>
void
CopyBlock(void* pDst, const void* pSrc, int len)
{
    auto p_src = reinterpret_cast<const copytype*>(pSrc);
    auto p_dst = reinterpret_cast<copytype*>(pDst);

    for (uint64 i = 0; i < len / stride; i++) {
        p_dst[i] = p_src[i];
    }
}

static inline void
CopyDWord(uint32* pDst, const uint32* pSrc, int len)
{
    CopyBlock<uint32>(pDst, pSrc, len);
}

static inline void
CopyQWord(uint64* pDst, const uint64* pSrc, int len)
{
    CopyBlock<uint64>(pDst, pSrc, len);
}

static inline void
CopyWord(uint16* pDst, const uint16* pSrc, int len)
{
    CopyBlock<uint16>(pDst, pSrc, len);
}

static inline void
CopyBytes(uint8* pDst, const uint8* pSrc, int len)
{
    CopyBlock<uint8>(pDst, pSrc, len);
}

template<typename copytype = uint64, uint64 stride = sizeof(copytype)>
static inline void
PadBlock(void* pDst, copytype val, uint64 len)
{
    auto p_dst = reinterpret_cast<copytype*>(pDst);

    for (uint64 i = 0; i < len / stride; i++) {
        p_dst[i] = val;
    }
}

static inline uint32 constexpr MakeWord(uint8 b, bool msb = false)
{
    return msb ? (uint32)b << 24 : (uint32)b;
}

static inline uint32 constexpr MakeWord(uint8 b0, uint8 b1, uint8 b2, uint8 b3)
{
    return ((uint32)b3 << 24) | ((uint32)b2 << 16) | ((uint32)b1 << 8)
           | ((uint32)b0);
}

static inline uint8 constexpr GetByte(uint32 u, int byte)
{
    assert(byte < 4);
    return (uint8)((u >> (byte * 8)) & 0xFF);
}

} // namespace alcp::utils

#endif /* _UTILS_COPY_HH */
