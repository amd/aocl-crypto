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

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "alcp/capi/cipher/builder.hh"
#include <alcp/alcp.h>

using namespace alcp::cipher;

int
main()
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint8 key[32] = {};
    Uint8 iv[16]  = {};

    int    dataLen    = 256;
    Uint8* inputText  = new Uint8[dataLen];
    Uint8* cipherText = new Uint8[dataLen];
    Uint8* outputText = new Uint8[dataLen];
    Uint8* aad        = new Uint8[16];
    Uint8* tag        = new Uint8[16];

    auto alcpCipher = new CipherFactory<CipherAEADInterface>;
    auto aead = alcpCipher->create("aes-gcm-192", CpuCipherFeatures::eVaes512);

    if (aead == nullptr) {
        printf("\n cipher create failed");
        err = ALC_ERROR_GENERIC;
        goto dealloc;
    }

    // init
    err = aead->init(key, 192, iv, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher init failed");
        goto dealloc;
    }

    // core encrypt + auth
    err = aead->setAad(NULL, aad, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher setAad failed");
        goto dealloc;
    }
    err = aead->encrypt(NULL, inputText, cipherText, dataLen);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher encrypt failed");
        goto dealloc;
    }
    err = aead->getTag(NULL, tag, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher tag failed");
        goto dealloc;
    }

    err = aead->finish(NULL);

dealloc:
    delete alcpCipher;
    delete[] inputText;
    delete[] cipherText;
    delete[] outputText;
    delete[] aad;
    delete[] tag;

    return err;
}