/*
 * Copyright (C) 2024-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher.hh"

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

    memset(inputText, 10, dataLen);
    memset(aad, 30, 16);

    auto alcpCipher = new CipherFactory<iCipherAead>;
    auto aead       = alcpCipher->create("aes-gcm-192");

    if (aead == nullptr) {
        printf("\n cipher create failed\n");
        err = ALC_ERROR_GENERIC;
        goto dealloc;
    }

    err = aead->init(key, 192, iv, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher init failed\n");
        goto dealloc;
    }

    err = aead->setAad(aad, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher setAad failed\n");
        goto dealloc;
    }

    err = aead->encrypt(inputText, cipherText, dataLen);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher encrypt failed\n");
        goto dealloc;
    }
    printf("Encrypt succeeded\n");

    err = aead->getTag(tag, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher tag failed\n");
        goto dealloc;
    }

    err = aead->finish(NULL);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher finish failed\n");
        goto dealloc;
    }

    err = aead->init(key, 192, iv, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher init for decrypt failed\n");
        goto dealloc;
    }

    err = aead->setAad(aad, 16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher setAad for decrypt failed\n");
        goto dealloc;
    }

    err = aead->setTagLength(16);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher setTaglen failed\n");
        goto dealloc;
    }

    // Decrypt
    err = aead->decrypt(cipherText, outputText, dataLen);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher decrypt failed\n");
        goto dealloc;
    }
    printf("Decrypt succeeded\n");

    err = aead->finish(NULL);
    if (err != ALC_ERROR_NONE) {
        printf("\n cipher finish for decrypt failed\n");
        goto dealloc;
    }

    if (memcmp(inputText, outputText, dataLen) != 0) {
        printf("\nInput and decrypted output don't match\n");
        err = ALC_ERROR_GENERIC;
    } else {
        printf("\nInput and decrypted output match\n");
    }

dealloc:
    delete alcpCipher;
    delete[] inputText;
    delete[] cipherText;
    delete[] outputText;
    delete[] aad;
    delete[] tag;

    return err;
}