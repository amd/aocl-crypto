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
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alcp/ec.h"
#include "alcp/ecdh.h"

#define POINT_SIZE    32
#define PVT_KEY_SIZE  POINT_SIZE
#define PUB_KEY_SIZE  POINT_SIZE * 2
#define SCRT_KEY_SIZE POINT_SIZE

static const Uint8 cPeer1PrivkData[PVT_KEY_SIZE] = {
    0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62,
    0x14, 0x63, 0x2e, 0xea, 0xe0, 0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6,
    0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
};

static const Uint8 cPeer2PublicData[PUB_KEY_SIZE] = {
    0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, // X
    0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce,
    0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
    0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, // Y
    0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb,
    0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
};

static const Uint8 cExpectedSecretKey[SCRT_KEY_SIZE] = {
    0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4,
    0x34, 0xfb, 0xdd, 0x2d, 0x25, 0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56,
    0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
};

static alc_error_t
create_demo_session(alc_ec_handle_t* s_ec_handle)
{
    alc_error_t err;

    alc_ec_info_t ecinfo = {
        .ecCurveId     = ALCP_EC_SECP256R1,
        .ecCurveType   = ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS,
        .ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED,
    };

    Uint64 size          = alcp_ec_context_size(&ecinfo);
    s_ec_handle->context = malloc(size);

    err = alcp_ec_request(&ecinfo, s_ec_handle);

    return err;
}

static alc_error_t
p256_demo(alc_ec_handle_t* ps_ec_handle_peer)
{
    alc_error_t err;
    Uint8       p_secret_key1[SCRT_KEY_SIZE];
    Uint64      key_length;

    // Set the private key
    printf("Setting Private Key for Peer 1\n");
    err = alcp_ec_set_privatekey(ps_ec_handle_peer, cPeer1PrivkData);
    if (alcp_is_error(err)) {
        printf("\n peer1 private key set failed");
        return err;
    }

    // Compute the secret key
    printf("Setting Public Key for Peer 2 and generating secret key\n");
    err = alcp_ec_get_secretkey(
        ps_ec_handle_peer, p_secret_key1, cPeer2PublicData, &key_length);
    if (alcp_is_error(err)) {
        printf("\n peer1 secretkey computation failed");
        return err;
    }

    // Verify the secret key is expected one
    if (memcmp(p_secret_key1, cExpectedSecretKey, key_length) == 0) {
        err = ALC_ERROR_NONE;
        printf("Success: Secret Key matches!\n");
    } else {
        printf("Failure: Secret Key mismatch!\n");
    }
    return err;
}

int
main(void)
{
    alc_ec_handle_t s_ec_handle_peer1;
    alc_error_t     err = create_demo_session(&s_ec_handle_peer1);
    err                 = p256_demo(&s_ec_handle_peer1);
    if (alcp_is_error(err))
        return -1;
    alcp_ec_finish(&s_ec_handle_peer1);
    free(s_ec_handle_peer1.context);

    return 0;
}
