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

#include "common/context.hh"
#include "common/error.hh"
#include <alcp/alcp.h>
#include <alcp/types.h>
#include <crypto_mb/x25519.h>
#include <iostream>
#include <ippcp.h>
#include <sstream>
#include <stdint.h>
#include <string.h>

#define NUM_MB              8
#define ECC_X25519_KEY_SIZE 32

mbx_status
mbx_x25519_public_key_mb8(int8u* const       pa_public_key[NUM_MB],
                          const int8u* const pa_private_key[NUM_MB])
{
    printMsg("mbx_x25519_public_key_mb8");
    alc_ec_handle_t handle[NUM_MB];
    alc_error_t     err;

    alc_ec_info_t ecinfo = {
        ALCP_EC_CURVE25519,
        ALCP_EC_CURVE_TYPE_MONTGOMERY,
        ALCP_EC_POINT_FORMAT_UNCOMPRESSED,
    };

    Uint64 size = alcp_ec_context_size(&ecinfo);
    for (int i = 0; i < NUM_MB; i++) {
        handle[i].context = malloc(size);
        if (handle[i].context == nullptr) {
            printErr("Memory allocation error!");
            return ippStsErr;
        }
    }

    for (int i = 0; i < NUM_MB; i++) {
        err = alcp_ec_request(&ecinfo, &handle[i]);
        if (alcp_is_error(err)) {
            Uint8 err_buff[1024];
            alcp_error_str(err, err_buff, 1024);
            printErr(reinterpret_cast<char*>(err_buff));
        }
    }

    for (int i = 0; i < NUM_MB; i++) {
        err =
            alcp_ec_get_publickey(&handle[i],
                                  static_cast<Uint8*>(pa_public_key[i]),
                                  static_cast<const Uint8*>(pa_private_key[i]));
        if (alcp_is_error(err)) {
            Uint8 err_buff[1024];
            alcp_error_str(err, err_buff, 1024);
            printErr(reinterpret_cast<char*>(err_buff));
        }
    }

    for (int i = 0; i < NUM_MB; i++) {
        alcp_ec_finish(&handle[i]);
        free(handle[i].context);
    }
    printMsg("mbx_x25519_public_key_mb8 End");

    return ippStsNoErr;
}

mbx_status
mbx_x25519_mb8(int8u* const       pa_shared_key[NUM_MB],
               const int8u* const pa_private_key[NUM_MB],
               const int8u* const pa_public_key[NUM_MB])
{
    printMsg("mbx_x25519_mb8");
    Uint64 length;

    alc_ec_handle_t handle[NUM_MB];
    alc_error_t     err;

    alc_ec_info_t ecinfo = {
        ALCP_EC_CURVE25519,
        ALCP_EC_CURVE_TYPE_MONTGOMERY,
        ALCP_EC_POINT_FORMAT_UNCOMPRESSED,
    };

    Uint64 size = alcp_ec_context_size(&ecinfo);
    for (int i = 0; i < NUM_MB; i++) {
        handle[i].context = malloc(size);
        if (handle[i].context == nullptr) {
            printErr("Memory allocation error!");
            return ippStsErr;
        }
    }

    for (int i = 0; i < NUM_MB; i++) {
        err = alcp_ec_request(&ecinfo, &handle[i]);
        if (alcp_is_error(err)) {
            Uint8 err_buff[1024];
            alcp_error_str(err, err_buff, 1024);
            printErr(reinterpret_cast<char*>(err_buff));
        }
    }

    for (int i = 0; i < NUM_MB; i++) {

        alcp_ec_get_publickey(&handle[i],
                              static_cast<Uint8*>(pa_shared_key[i]),
                              static_cast<const Uint8*>(pa_private_key[i]));

        err = alcp_ec_get_secretkey(&handle[i],
                                    static_cast<Uint8*>(pa_shared_key[i]),
                                    static_cast<const Uint8*>(pa_public_key[i]),
                                    &length);
        if (alcp_is_error(err)) {
            Uint8 err_buff[1024];
            alcp_error_str(err, err_buff, 1024);
            printErr(reinterpret_cast<char*>(err_buff));
        }
    }

    for (int i = 0; i < NUM_MB; i++) {
        alcp_ec_finish(&handle[i]);
        free(handle[i].context);
    }

    printMsg("mbx_x25519_mb8 End");
    return ippStsNoErr;
}