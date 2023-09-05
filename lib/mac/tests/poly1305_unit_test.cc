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

#include <gtest/gtest.h>
#include <iostream>

#include "alcp/mac/poly1305.hh"

std::string
parseBytesToHexStr(const Uint8* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        // Convert int to hex
        il << std::hex << charRep;
        std::string ilStr = il.str();
        // 01 will be 0x1 so we need to make it 0x01
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    return ss.str();
}

using alcp::mac::poly1305::Poly1305;

TEST(POLY1305, INIT_TEST)
{
    Poly1305 poly;
}

TEST(POLY1305, BLK0)
{
    Uint8 blk[16]          = { 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
                               0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f };
    Uint8 key[32]          = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                               0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                               0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                               0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };
    std::vector<Uint8> out = { 0xfd, 0x86, 0x1c, 0x71, 0x84, 0xf9, 0x8f, 0x45,
                               0xdc, 0x6d, 0x5b, 0x4d, 0xc6, 0xc0, 0x81, 0xe4 };

    Poly1305           poly;
    std::vector<Uint8> mac(16);
    poly.mac(blk, key, 16, &mac.at(0));

    EXPECT_EQ(mac, out);
}

TEST(POLY1305, BLK_ALL)
{
    Uint8 blk[]   = { 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61,
                      0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f, 0x72, 0x75,
                      0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63,
                      0x68, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70 };
    Uint8 key[32] = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                      0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                      0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                      0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };

    std::vector<Uint8> out = { 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                               0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9 };

    Poly1305           poly;
    std::vector<Uint8> mac(16);
    poly.mac(blk, key, sizeof(blk), &mac.at(0));

    EXPECT_EQ(mac, out);
}