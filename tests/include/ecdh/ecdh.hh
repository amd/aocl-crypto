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
#pragma once

#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "alcp/alcp.h"

typedef enum
{
    ALC_PEER_ONE = 0,
    ALC_PEER_TWO = 1,
    ALC_PEER_MAX,
} alc_peer_id_t;

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

#define MAX_SIZE_KEY_DATA        64
#define MAX_CHAR_SIZE_CURVE_NAME 60

namespace alcp::testing {
class ecdh
{

  public:
    /**
     * @brief Function generates public key using input privateKey generated
     * public key is shared with the peer.
     * @param pPublicKey - pointer to Output Publickey generated
     * @param pPrivKey - pointer to Input privateKey used for generating
     * publicKey
     * @return true
     * @return false
     */
    virtual alc_error_t generate_public_key(Uint8*       pPublicKey,
                                            const Uint8* pPrivKey) = 0;

    /**
     * @brief Function compute secret key with publicKey from remotePeer and
     * local privatekey.
     *
     * @param pSecretKey - pointer to output secretKey
     * @param pPublicKey - pointer to Input privateKey used for generating
     * publicKey
     * @param pKeyLength - pointer to keyLength
     * @return true
     * @return false
     */
    virtual alc_error_t compute_secret_key(Uint8*       pSecretKey,
                                           const Uint8* pPublicKey,
                                           Uint64*      pKeyLength) = 0;

    virtual void reset() = 0;
    ~ecdh(){};
};
} // namespace alcp::testing
