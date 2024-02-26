/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/utils/copy.hh"
#include "gtest/gtest.h"

// Just a simple function which takes a word as argument and return the same
// word
Uint32
echo(Uint32 word)
{
    return word;
}
using namespace alcp::utils;
TEST(CopyBlockWith, UnalignedDstBuffCopy)
{
    constexpr unsigned int buffer_byte_size = 16;
    alignas(64) Uint8      dst_buff[buffer_byte_size + 1];
    Uint64                 src_buff[buffer_byte_size / 8];
    auto                   p_dst = dst_buff + 1;
    Uint8*                 p_src = reinterpret_cast<Uint8*>(src_buff);

    std::fill(p_src, p_src + buffer_byte_size, 0x01);
    std::fill(p_dst, p_dst + buffer_byte_size, 0x02);

    // Using CopyBlockWith without copyasbytes template parameter set to true
    // when using unaligned memory will cause misaligned store issues
    // CopyBlockWith<Uint32>(p_dst, p_src, buffer_byte_size, echo);
    CopyBlockWith<Uint32, true>(p_dst,
                                p_src,
                                buffer_byte_size,
                                echo); // setting copyasbytes=true since caller
                                       // knows desination buffer is unaligned

    int cmp = memcmp(p_dst, p_src, buffer_byte_size);
    ASSERT_EQ(cmp, 0);
}