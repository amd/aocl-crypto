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

#include <alcp/alcp.h>
#include <malloc.h>

#pragma once
#ifndef __ALC_BASE_HH
#define __ALC_BASE_HH 2

#if 1
void
alcp_encrypt_data(
    const uint8_t* plaintxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       key,
    const uint32_t key_len,
    uint8_t*       iv,
    uint8_t*       ciphertxt,
    alc_aes_mode_t mode);

void
alcp_decrypt_data(const uint8_t* ciphertxt,
                  const uint32_t len, /* Describes both 'plaintxt' and
                                         'ciphertxt' */
                  uint8_t*       key,
                  const uint32_t key_len,
                  uint8_t*       iv,
                  uint8_t*       plaintxt,
                  alc_aes_mode_t mode);

#endif

int
encrypt(unsigned char* plaintext,
        int            plaintext_len,
        unsigned char* key,
        int            keylen,
        unsigned char* iv,
        unsigned char* ciphertext);

int
decrypt(unsigned char* ciphertext,
        int            ciphertext_len,
        unsigned char* key,
        int            keylen,
        unsigned char* iv,
        unsigned char* plaintext);

#endif