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
#include "alcp/rsa.h"
#include "alcp/rsa/rsa_internal.hh"
#include "alcp/utils/copy.hh"
#include <immintrin.h>

namespace alcp::rsa { namespace zen3 {
#include "../../rsa/rsa.cc.inc"
    template void archEncryptPublic<KEY_SIZE_1024>(
        Uint8*                            pEncText,
        const Uint64*                     pTextBignum,
        RsaPublicKeyBignum&               pubKey,
        MontContextBignum<KEY_SIZE_1024>& context);
    template void archEncryptPublic<KEY_SIZE_2048>(
        Uint8*                            pEncText,
        const Uint64*                     pTextBignum,
        RsaPublicKeyBignum&               pubKey,
        MontContextBignum<KEY_SIZE_2048>& context);

    template void archDecryptPrivate<KEY_SIZE_1024>(
        Uint8*                            pText,
        const Uint64*                     pEncTextBigNum,
        RsaPrivateKeyBignum&              privKey,
        MontContextBignum<KEY_SIZE_1024>& contextP,
        MontContextBignum<KEY_SIZE_1024>& contextQ);

    template void archDecryptPrivate<KEY_SIZE_2048>(
        Uint8*                            pText,
        const Uint64*                     pEncTextBigNum,
        RsaPrivateKeyBignum&              privKey,
        MontContextBignum<KEY_SIZE_2048>& contextP,
        MontContextBignum<KEY_SIZE_2048>& contextQ);

    template void archCreateContext<KEY_SIZE_1024>(
        MontContextBignum<KEY_SIZE_1024>& context, Uint64* mod, Uint64 size);

    template void archCreateContext<KEY_SIZE_2048>(
        MontContextBignum<KEY_SIZE_2048>& context, Uint64* mod, Uint64 size);

}} // namespace alcp::rsa::zen3
