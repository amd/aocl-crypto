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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <algorithm>
#include <array>
#include <iostream>
#include <tuple>

#include <openssl/bio.h>
#include <openssl/bn.h>

#include "alcp/base.hh"
#include "alcp/mac/poly1305.hh"
// #include "alcp/mac/mac.hh"

namespace alcp::mac::poly1305 {

void
debug_dump(std::string str, BIGNUM* z)
{
    std::cout << str << "\t";
    BN_print_fp(stdout, z);
    std::cout << std::endl;
}

void
Poly1305::clamp(Uint8 in[16])
{
    constexpr std::array<std::tuple<int, int>, 7> index = {
        std::tuple<int, int>({ 3, 15 }),  std::tuple<int, int>({ 7, 15 }),
        std::tuple<int, int>({ 11, 15 }), std::tuple<int, int>({ 15, 15 }),
        std::tuple<int, int>({ 4, 252 }), std::tuple<int, int>({ 8, 252 }),
        std::tuple<int, int>({ 12, 252 })
    };

    for (const auto& i : index) {
        in[15 - std::get<0>(i)] &= std::get<1>(i);
    }
}

Uint8*
Poly1305::mac(const Uint8 msg[], const Uint8 key[], Uint64 msgLen)
{
    static Uint8 a_mem[16]    = {};
    Uint8        key_copy[32] = {};

    Uint8 p_mem[] = { 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb };
    const Uint8* msg_ptr_cpy = msg;

    std::reverse_copy(key, key + 16, key_copy);
    std::reverse_copy(key + 16, key + 32, key_copy + 16);

    BIGNUM *r = nullptr, *s = nullptr, *a = nullptr, *p = nullptr;
    clamp(key_copy);
    r = BN_bin2bn(key_copy, 16, r);
    debug_dump("R KE2:", r);
    s = BN_bin2bn(key_copy + 16, 16, s);
    a = BN_bin2bn(a_mem, 16, a);
    debug_dump("A CRT:", a);
    p = BN_bin2bn(p_mem, sizeof(p_mem), p);
    debug_dump("P SHL:", p);

    // Ceil Function 'q = x + (y - 1) / y'
    BN_CTX* ctx = BN_CTX_new();

    for (int i = 1; i <= ((msgLen + (16 - 1)) / 16); i++) {
        Uint8 n_buff[17] = {};

        // Find if we are in the last block, if we are, then only do left bytes
        Uint64 curr_blocklen = msgLen - ((i + 1) * 16) < 0 ? msgLen - ((i) * 16)
                                                           : 16;
        std::reverse_copy(msg_ptr_cpy, msg_ptr_cpy + curr_blocklen, n_buff + 1);
        n_buff[0] = 0x01;
        BIGNUM* n = BN_bin2bn(n_buff, 17, n);
        debug_dump("N BLK:", n);

        // We select the next block
        msg_ptr_cpy += curr_blocklen;
        BN_add(a, a, n);
        debug_dump("A ADD:", a);
        BN_mod_mul(a, a, r, p, ctx);
        debug_dump("A END:", a);
    }

    BN_add(a, a, s);
    BN_bn2bin(a, a_mem);
    return a_mem;
}

} // namespace alcp::mac::poly1305
