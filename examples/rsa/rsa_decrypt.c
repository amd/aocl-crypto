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
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alcp/rsa.h"

#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("%s\n", S);                                                         \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %02x", *(I + x));                                             \
    }                                                                          \
    printf("\n");

static alc_error_t
create_demo_session(alc_rsa_handle_t* s_rsa_handle)
{
    alc_error_t err;

    Uint64 size           = alcp_rsa_context_size();
    s_rsa_handle->context = malloc(size);

    err = alcp_rsa_request(s_rsa_handle);

    return err;
}

static alc_error_t
Rsa_decrypt_demo(alc_rsa_handle_t* ps_rsa_handle)
{
    alc_error_t err;
    Uint8*      enc_text = NULL;
    Uint8*      dec_text = NULL;

    Uint64 size_key = alcp_rsa_get_key_size(ps_rsa_handle);

    if (size_key == 0) {
        printf("\n peer1 key size fetch failed");
        return ALC_ERROR_INVALID_SIZE;
    }

    enc_text = malloc(sizeof(Uint8) * size_key);
    memset(enc_text, 0x31, sizeof(Uint8) * size_key);

    ALCP_PRINT_TEXT(enc_text, size_key, "encrypted text")

    printf("\n");

    dec_text = malloc(sizeof(Uint8) * size_key);
    memset(dec_text, 0, sizeof(Uint8) * size_key);

    err = alcp_rsa_privatekey_decrypt(
        ps_rsa_handle, ALCP_RSA_PADDING_NONE, enc_text, size_key, dec_text);
    if (err != ALC_ERROR_NONE) {
        printf("\n private key decryption failed");
        goto out;
    }

    ALCP_PRINT_TEXT(dec_text, size_key, "decrypted text")

out:

    free(enc_text);
    free(dec_text);
    return err;
}

int
main(void)
{
    alc_rsa_handle_t s_rsa_handle;
    alc_error_t      err = create_demo_session(&s_rsa_handle);

    if (!alcp_is_error(err)) {
        err = Rsa_decrypt_demo(&s_rsa_handle);
    }

    alcp_rsa_finish(&s_rsa_handle);
    free(s_rsa_handle.context);

    return 0;
}
