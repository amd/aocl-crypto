/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include <cassert>
#include <functional>

#include "alcp/types.hh"

namespace alcp::utils {

template<typename copytype = Uint64, Uint64 stride = sizeof(copytype)>
void
CopyChunk(void* pDst, const void* pSrc, int len)
{
    auto p_src = reinterpret_cast<const copytype*>(pSrc);
    auto p_dst = reinterpret_cast<copytype*>(pDst);

    for (Uint64 i = 0; i < len / stride; i++) {
        p_dst[i] = p_src[i];
    }
}

template<typename copytype = Uint64>
void
CopyChunkExact(void* pDst, const void* pSrc, int len)
{
    auto p_src = reinterpret_cast<const copytype*>(pSrc);
    auto p_dst = reinterpret_cast<copytype*>(pDst);

    for (Uint64 i = 0; i < len; i++) {
        p_dst[i] = p_src[i];
    }
}

static inline void
CopyDWord(Uint32* pDst, const Uint32* pSrc, int len)
{
    CopyChunk<Uint32>(pDst, pSrc, len);
}

static inline void
CopyQWord(Uint64* pDst, const Uint64* pSrc, int len)
{
    CopyChunk<Uint64>(pDst, pSrc, len);
}

static inline void
CopyWord(Uint16* pDst, const Uint16* pSrc, int len)
{
    CopyChunk<Uint16>(pDst, pSrc, len);
}

static inline void
CopyBytes(void* pDst, const void* pSrc, int len)
{
    CopyChunk<Uint8>(pDst, pSrc, len);
}

template<typename copytype = Uint64, Uint64 stride = sizeof(copytype)>
void
CopyBlock(void* pDst, const void* pSrc, Uint64 len)
{
    auto p_src = reinterpret_cast<const copytype*>(pSrc);
    auto p_dst = reinterpret_cast<copytype*>(pDst);

    Uint64 i = 0;

    for (; i < len / stride; i++) {
        p_dst[i] = p_src[i];
    }

    Uint64 offset    = i * stride;
    Uint64 remaining = len - offset;

    if (remaining) {
        CopyBytes(&p_dst[i], &p_src[i], remaining);
    }
}

template<typename cptype   = Uint64,
         Uint64 stride     = sizeof(cptype),
         typename trn_func = std::function<cptype(cptype)>>
void
CopyBlockWith(void* pDst, const void* pSrc, Uint64 len, trn_func func)
{
    auto p_src = reinterpret_cast<const cptype*>(pSrc);
    auto p_dst = reinterpret_cast<cptype*>(pDst);

    Uint64 i = 0;

    for (; i < len / stride; i++) {
        p_dst[i] = func(p_src[i]);
    }

    Uint64 offset    = i * stride;
    Uint64 remaining = len - offset;

    if (remaining) {
        CopyBytes(&p_dst[i], &p_src[i], remaining);
    }
}

static inline void
PadBytes(Uint8* pDst, Uint32 val, Uint64 len)
{
    for (Uint64 i = 0; i < len; i++) {
        pDst[i] = (Uint8)(val & 0xff);
    }
}

template<typename copytype = Uint64, Uint64 stride = sizeof(copytype)>
static inline void
PadBlock(void* pDst, copytype val, Uint64 len)
{
    auto   p_dst = reinterpret_cast<copytype*>(pDst);
    Uint64 i     = 0;
    for (i = 0; i < len / stride; i++) {
        p_dst[i] = val;
    }

    Uint64 offset    = i * stride;
    Uint64 remaining = len - offset;

    if (remaining) {
        PadBytes(static_cast<Uint8*>(pDst) + offset, val, remaining);
    }
}

template<typename copytype = Uint64, Uint64 stride = sizeof(copytype)>
static inline void
PadCompleteBlock(void* pDst, copytype val, Uint64 len)
{
    auto   p_dst = reinterpret_cast<copytype*>(pDst);
    Uint64 i     = 0;
    for (i = 0; i < len / stride; i++) {
        p_dst[i] = val;
    }
}

static inline Uint32 constexpr MakeWord(Uint8 b, bool msb = false)
{
    return msb ? (Uint32)b << 24 : (Uint32)b;
}

static inline Uint32 constexpr MakeWord(Uint8 b0, Uint8 b1, Uint8 b2, Uint8 b3)
{
    return ((Uint32)b3 << 24) | ((Uint32)b2 << 16) | ((Uint32)b1 << 8)
           | ((Uint32)b0);
}

static inline Uint8 constexpr GetByte(Uint32 u, int byte)
{
    assert(byte < 4);
    return (Uint8)((u >> (byte * 8)) & 0xFF);
}

} // namespace alcp::utils

#endif /* _UTILS_COPY_HH */
