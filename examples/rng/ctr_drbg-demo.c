
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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/alcp.h"
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>

static alc_drbg_handle_t handle;

void
printHexString(Uint8* bytes, int length)
{
    size_t i;
    for (i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

int
main(int argc, char const* argv[])
{

    alc_drbg_info_t
        drbg_info = { .di_type           = ALC_DRBG_CTR,
                      .max_entropy_len   = 16,
                      .max_nonce_len     = 16,
                      .di_algoinfo       = { .ctr_drbg = { .di_keysize = 128,
                                                           .use_derivation_function =
                                                               true } },
                      .di_rng_sourceinfo = {
                          .custom_rng    = false,
                          .di_sourceinfo = {
                              .rng_info = {
                                  .ri_distrib = ALC_RNG_DISTRIB_UNIFORM,
                                  .ri_source  = ALC_RNG_SOURCE_OS,
                                  .ri_type    = ALC_RNG_TYPE_DISCRETE } } } };

    alc_error_t err = ALC_ERROR_NONE;
    err             = alcp_drbg_supported(&drbg_info);

    if (!alcp_is_error(err)) {
        handle.ch_context = malloc(alcp_drbg_context_size(&drbg_info));
    } else {
        printf("DRBG Information provided is unsupported\n");
        return err;
    }

    err = alcp_drbg_request(&handle, &drbg_info);
    if (alcp_is_error(err)) {
        printf("Error Occurred on DRBG Request - %10" PRId64 "\n", err);
        return err;
    }
    const int cSecurityStrength = 100;
    err = alcp_drbg_initialize(&handle, cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        printf("Error Occurred on DRBG initialize - %10" PRId64 "\n", err);
        return err;
    }
    Uint8 output[16];
    err = alcp_drbg_randomize(
        &handle, output, sizeof(output), cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        printf("Error Occurred on DRBG initialize - %10" PRId64 "\n", err);
        return err;
    }
    printf("First Call: Randomly generated bytes: \n");
    printHexString(output, sizeof(output));
    printf("\n");
    // Generating Again
    err = alcp_drbg_randomize(
        &handle, output, sizeof(output), cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        printf("Error Occurred on DRBG initialize - %10" PRId64 "\n", err);
        return err;
    }
    printf("Second Call: Randomly generated bytes: \n");
    printHexString(output, sizeof(output));
    printf("\n");

    alcp_drbg_finish(&handle);

    if (handle.ch_context) {
        free(handle.ch_context);
        handle.ch_context = NULL;
    }

    return 0;
}
