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

#include "alcp/ec.h"
#include "alcp/ecdh.h"

#define SIZE_KEY_X25519 32

#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("%s\n", S);                                                         \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %02x", *(I + x));                                             \
    }                                                                          \
    printf("\n");

static const Uint8 peer1_privk_data[SIZE_KEY_X25519] = {
    0x80, 0x5b, 0x30, 0x20, 0x25, 0x4a, 0x70, 0x2c, 0xad, 0xa9, 0x8d,
    0x7d, 0x47, 0xf8, 0x1b, 0x20, 0x89, 0xd2, 0xf9, 0x14, 0xac, 0x92,
    0x27, 0xf2, 0x10, 0x7e, 0xdb, 0x21, 0xbd, 0x73, 0x73, 0x5d
};

static const Uint8 peer2_privk_data[SIZE_KEY_X25519] = {
    0xf8, 0x84, 0x19, 0x69, 0x79, 0x13, 0x0d, 0xbd, 0xb1, 0x76, 0xd7,
    0x0e, 0x7e, 0x0f, 0xb6, 0xf4, 0x8c, 0x4a, 0x8c, 0x5f, 0xd8, 0x15,
    0x09, 0x0a, 0x71, 0x78, 0x74, 0x92, 0x0f, 0x85, 0xc8, 0x43
};

static alc_error_t
create_demo_session(alc_ec_handle_t* s_ec_handle)
{
    alc_error_t err;

    alc_ec_info_t ecinfo = {
        .ecCurveId     = ALCP_EC_CURVE25519,
        .ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY,
        .ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED,
    };

    Uint64 size          = alcp_ec_context_size(&ecinfo);
    s_ec_handle->context = malloc(size);

    err = alcp_ec_request(&ecinfo, s_ec_handle);

    return err;
}

static alc_error_t
x25519_demo(alc_ec_handle_t* ps_ec_handle_peer1,
            alc_ec_handle_t* ps_ec_handle_peer2)
{
    alc_error_t err;

    /* Peer 1 */
    Uint8 publicKeyData1[SIZE_KEY_X25519];

    err = alcp_ec_set_privatekey(ps_ec_handle_peer1, peer1_privk_data);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 private key set failed");
        return err;
    }

    alcp_ec_get_publickey(ps_ec_handle_peer1, publicKeyData1, peer1_privk_data);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 publickey generation failed");
        return err;
    }
    ALCP_PRINT_TEXT(peer1_privk_data, SIZE_KEY_X25519, "pPrivKey_peer1")
    ALCP_PRINT_TEXT(publicKeyData1, SIZE_KEY_X25519, "publicKey_peer1")

    /* Peer 2 */
    Uint8 publicKeyData2[SIZE_KEY_X25519];

    err = alcp_ec_set_privatekey(ps_ec_handle_peer2, peer2_privk_data);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 private key set failed");
        return err;
    }

    err = alcp_ec_get_publickey(
        ps_ec_handle_peer2, publicKeyData2, peer2_privk_data);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 publickey generation failed");
        return err;
    }
    ALCP_PRINT_TEXT(peer2_privk_data, SIZE_KEY_X25519, "pPrivKey_peer2")
    ALCP_PRINT_TEXT(publicKeyData2, SIZE_KEY_X25519, "publicKey_peer2")
    printf("\n");

    // compute shared secret key of both peers
    Uint8  pSecret_key1[SIZE_KEY_X25519];
    Uint64 keyLength1;
    err = alcp_ec_get_secretkey(
        ps_ec_handle_peer1, pSecret_key1, publicKeyData2, &keyLength1);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 secretkey computation failed");
        return err;
    }

    Uint8  pSecret_key2[SIZE_KEY_X25519];
    Uint64 keyLength2;
    err = alcp_ec_get_secretkey(
        ps_ec_handle_peer2, pSecret_key2, publicKeyData1, &keyLength2);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 secretkey computation failed");
        return err;
    }

    ALCP_PRINT_TEXT(pSecret_key1, SIZE_KEY_X25519, "peer1 common Secretkey")
    ALCP_PRINT_TEXT(pSecret_key2, SIZE_KEY_X25519, "peer2 common Secretkey")
    printf("\n");

    if (memcmp(pSecret_key1, pSecret_key2, keyLength1) == 0) {
        err = ALC_ERROR_NONE;
    } else {
        printf("\n mismatch in secret key computation");
    }
    return err;
}

int
main(void)
{
    alc_ec_handle_t s_ec_handle_peer1;
    alc_error_t     err = create_demo_session(&s_ec_handle_peer1);

    alc_ec_handle_t s_ec_handle_peer2;
    err = create_demo_session(&s_ec_handle_peer2);

    if (!alcp_is_error(err)) {
        err = x25519_demo(&s_ec_handle_peer1, &s_ec_handle_peer2);
    }

    alcp_ec_finish(&s_ec_handle_peer1);
    free(s_ec_handle_peer1.context);

    alcp_ec_finish(&s_ec_handle_peer2);
    free(s_ec_handle_peer2.context);
    return 0;
}
