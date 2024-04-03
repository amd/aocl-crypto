/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

#include "alcp_cipher_prov_common.h"

/* padding functions needed for provider, similar to openssl */

size_t
ALCP_prov_cipher_fillblock(Uint8*        buf,
                           size_t*       bufLen,
                           size_t        blocksize,
                           const Uint8** in,
                           size_t*       inlen)
{
    ENTER();
    size_t inDataLen = *inlen;

    size_t blockmask = ~(blocksize - 1);
    size_t bufremain = blocksize - *bufLen;

    assert(*bufLen <= blocksize);
    assert(blocksize > 0 && (blocksize & (blocksize - 1)) == 0);

    if (inDataLen < bufremain)
        bufremain = inDataLen;
    memcpy(buf + *bufLen, *in, bufremain);
    *in += bufremain;
    *inlen -= bufremain;
    *bufLen += bufremain;

    return *inlen & blockmask;
}

int
ALCP_prov_cipher_trailingdata(Uint8*        buf,
                              size_t*       bufLen,
                              size_t        blocksize,
                              const Uint8** in,
                              size_t*       inlen)
{
    ENTER();
    size_t inDataLen = *inlen;

    if (inDataLen == 0)
        return 1;

    if (*bufLen + inDataLen > blocksize) {
        // FIXME: add error code
        return 0;
    }

    memcpy(buf + *bufLen, *in, inDataLen);
    *bufLen += inDataLen;
    *inlen = 0;

    return 1;
}

void
ALCP_prov_cipher_padblock(Uint8* buf, size_t* bufLen, size_t blocksize)
{
    ENTER();
    size_t totalLen = *bufLen;
    Uint8  pad      = (Uint8)(blocksize - totalLen);

    for (size_t i = totalLen; i < blocksize; i++) {
        buf[i] = pad;
    }
}

int
ALCP_prov_cipher_unpadblock(Uint8* buf, size_t* bufLen, size_t blocksize)
{
    ENTER();
    size_t pad;
    size_t len = *bufLen;

    if (len != blocksize) {
        // FIXME: add error code
        return 0;
    }

    pad = buf[blocksize - 1];
    if (pad == 0 || pad > blocksize) {
        // FIXME: add error code
        return 0;
    }
    for (size_t i = 0; i < pad; i++) {
        if (buf[--len] != pad) {
            // FIXME: add error code
            return 0;
        }
    }
    *bufLen = len;
    return 1;
}