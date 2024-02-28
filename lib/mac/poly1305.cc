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
#include "mac/poly1305-ref.hh"

// #define DEBUG

namespace alcp::mac::poly1305 {

using reference::Poly1305BNRef;
using reference::Poly1305Ref;

Poly1305::Poly1305()
{
    poly1305_impl = std::make_unique<Poly1305Ref>();
}

Status
Poly1305::setKey(const Uint8 key[], Uint64 len)
{
    return poly1305_impl->init(key, len);
}

Status
Poly1305::update(const Uint8 pMsg[], Uint64 msgLen)
{
    return poly1305_impl->update(pMsg, msgLen);
}

Status
Poly1305::reset()
{
    return poly1305_impl->reset();
}

Status
Poly1305::finalize(const Uint8 pMsg[], Uint64 msgLen)
{
    return poly1305_impl->finish(pMsg, msgLen);
}

void
Poly1305::finish()
{
}

Status
Poly1305::copy(Uint8 digest[], Uint64 length)
{
    return poly1305_impl->copy(digest, length);
}

} // namespace alcp::mac::poly1305
