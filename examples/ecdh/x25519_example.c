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

#ifdef __linux__
#include <sys/time.h>
#elif WIN32
#include "utils/time.hh"
#endif

#include "alcp/ec.h"
#include "alcp/ecdh.h"

#define SIZE_KEY_X25519 32

// to do: these macro is better to be moved to common header.
#define ALCP_CRYPT_TIMER_INIT struct timeval begin, end;
long   seconds;
long   microseconds;
double elapsed;
double totalTimeElapsed;

#define ALCP_CRYPT_TIMER_START gettimeofday(&begin, 0);

#define ALCP_CRYPT_GET_TIME(X, Y)                                              \
    gettimeofday(&end, 0);                                                     \
    seconds      = end.tv_sec - begin.tv_sec;                                  \
    microseconds = end.tv_usec - begin.tv_usec;                                \
    elapsed      = seconds + microseconds * 1e-6;                              \
    totalTimeElapsed += elapsed;                                               \
    if (X) {                                                                   \
        printf("\t" Y);                                                        \
        printf(" %2.2f ms ", elapsed * 1000);                                  \
    }

#define DEBUG_P /* Enable for debugging only */
/*
    debug prints to be print input, cipher, iv and decrypted output
*/
#ifdef DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("\n %s ", S);                                                       \
    for (int x = 0; x < L; x++) {                                              \
        if ((x % (16 * 4) == 0)) {                                             \
            printf("\n");                                                      \
        }                                                                      \
        if (x % 16 == 0) {                                                     \
            printf("   ");                                                     \
        }                                                                      \
        printf(" %2x", *(I + x));                                              \
    }
#else // DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)
#endif // DEBUG_P

// static alc_ec_handle_t s_ec_handle;

static const Uint8 peer1_privk_data[32] = {
    0x80, 0x5b, 0x30, 0x20, 0x25, 0x4a, 0x70, 0x2c, 0xad, 0xa9, 0x8d,
    0x7d, 0x47, 0xf8, 0x1b, 0x20, 0x89, 0xd2, 0xf9, 0x14, 0xac, 0x92,
    0x27, 0xf2, 0x10, 0x7e, 0xdb, 0x21, 0xbd, 0x73, 0x73, 0x5d
};

static const Uint8 peer2_privk_data[32] = {
    0xf8, 0x84, 0x19, 0x69, 0x79, 0x13, 0x0d, 0xbd, 0xb1, 0x76, 0xd7,
    0x0e, 0x7e, 0x0f, 0xb6, 0xf4, 0x8c, 0x4a, 0x8c, 0x5f, 0xd8, 0x15,
    0x09, 0x0a, 0x71, 0x78, 0x74, 0x92, 0x0f, 0x85, 0xc8, 0x43
};

static const Uint8 expected_result[32] = {
    0x19, 0x71, 0x26, 0x12, 0x74, 0xb5, 0xb1, 0xce, 0x77, 0xd0, 0x79,
    0x24, 0xb6, 0x0a, 0x5c, 0x72, 0x0c, 0xa6, 0x56, 0xc0, 0x11, 0xeb,
    0x43, 0x11, 0x94, 0x3b, 0x01, 0x45, 0xca, 0x19, 0xfe, 0x09
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

    if (alcp_is_error(err)) {
        return err;
    }

    return err;
}

void
getPublicKeySpeed(alc_ec_handle_t* ps_ec_handle_peer,
                  Uint8*           publicKey,
                  const Uint8*     pPrivKey)
{
    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) {
        ALCP_CRYPT_TIMER_START
        alcp_ec_get_publickey(ps_ec_handle_peer, publicKey, pPrivKey);

        ALCP_CRYPT_GET_TIME(0, "key generation time")
        if (totalTimeElapsed > 1) {
            printf("\n  %5d publickeys generated per second", k);
            break;
        }
    }
    // ALCP_PRINT_TEXT(publicKey, 32, "publicKey      ")
}

void
getSecretKeySpeed(alc_ec_handle_t* ps_ec_handle_peer,
                  Uint8*           pSecret_key,
                  const Uint8*     publicKey,
                  Uint64*          pkeyLength)
{

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) {
        ALCP_CRYPT_TIMER_START
        alcp_ec_get_secretkey(
            ps_ec_handle_peer, pSecret_key, publicKey, pkeyLength);

        ALCP_CRYPT_GET_TIME(0, "key generation time")
        if (totalTimeElapsed > 1) {
            printf("\n  %5d secretkeys computed per second\n", k);
            break;
        }
    }
}

static alc_error_t
x25519_demo(alc_ec_handle_t* ps_ec_handle_peer1,
            alc_ec_handle_t* ps_ec_handle_peer2)
{
    alc_error_t err;

    /* Peer 1 */
    Uint8        publicKeyData1[32];
    const Uint8* pPrivKey_input_data1 = peer1_privk_data;
    err                               = alcp_ec_get_publickey(
        ps_ec_handle_peer1, publicKeyData1, peer1_privk_data);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer1 publickey generation failed");
        return err;
    }
    ALCP_PRINT_TEXT(peer1_privk_data, 32, "pPrivKey_peer1      ")
    ALCP_PRINT_TEXT(publicKeyData1, 32, "publicKey_peer1      ")

    /* Peer 2 */
    Uint8 publicKeyData2[32];
    err = alcp_ec_get_publickey(
        ps_ec_handle_peer2, publicKeyData2, peer2_privk_data);
    if (err != ALC_ERROR_NONE) {
        printf("\n peer2 publickey generation failed");
        return err;
    }
    ALCP_PRINT_TEXT(peer2_privk_data, 32, "pPrivKey_peer2      ")
    ALCP_PRINT_TEXT(publicKeyData2, 32, "publicKey_peer2      ")
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

    ALCP_PRINT_TEXT(pSecret_key1, 32, "peer1 common Secretkey      ")
    ALCP_PRINT_TEXT(pSecret_key2, 32, "peer2 common Secretkey      ")
    printf("\n");

    if (memcmp(pSecret_key1, pSecret_key2, keyLength1) == 0) {
        err = ALC_ERROR_NONE;
    } else {
        printf("\n mismatch in secret key computation");
    }

    printf("\n\n Speed Test of alcp x2519");
    getPublicKeySpeed(ps_ec_handle_peer2, publicKeyData2, peer2_privk_data);

    getSecretKeySpeed(
        ps_ec_handle_peer2, pSecret_key2, publicKeyData1, &keyLength2);

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
