/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alcp/digest.h"

#define DIGEST_SIZE 32

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA2,
        .dt_len = ALC_DIGEST_LEN_256,
        .dt_mode = {.dm_sha2 = ALC_SHA2_512,},
    };

    Uint64 size         = alcp_digest_context_size(&dinfo);
    s_dg_handle.context = malloc(size);

    err = alcp_digest_request(&dinfo, &s_dg_handle);

    if (alcp_is_error(err)) {
        return err;
    }

    return err;
}

static alc_error_t
hash_demo(const Uint8* src,
          Uint64       src_size,
          Uint8*       output,
          Uint64       out_size,
          Uint64       num_chunks)
{
    alc_error_t err;

    // divide the input size into multiple chunks
    const Uint64 buf_size      = src_size / num_chunks;
    const Uint64 last_buf_size = src_size % num_chunks;
    const Uint8* p             = src;

    while (num_chunks-- > 0) {
        err = alcp_digest_update(&s_dg_handle, p, buf_size);
        if (alcp_is_error(err)) {
            printf("Unable to compute SHA2 hash\n");
            goto out;
        }
        p += buf_size;
    }

    if (last_buf_size == 0) {
        p = NULL;
    }

    alcp_digest_finalize(&s_dg_handle, p, last_buf_size);

    err = alcp_digest_copy(&s_dg_handle, output, out_size);
    if (alcp_is_error(err)) {
        printf("Unable to copy digest\n");
    }

out:
    alcp_digest_finish(&s_dg_handle);
    free(s_dg_handle.context);
    return err;
}

static void
hash_to_string(char string[129], const Uint8 hash[DIGEST_SIZE])
{
    size_t i;
    for (i = 0; i < DIGEST_SIZE; i++) {
        string += sprintf(string, "%02x", hash[i]);
    }
}

int
main(void)
{
    struct string_vector
    {
        Uint8* input;
        char*  output;
        Uint64 num_chunks;
    };

    static const struct string_vector STRING_VECTORS[] = {
        { (Uint8*)"",
          "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
          1 },
        { (Uint8*)"abc",
          "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
          2 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef",
          "604aca8fc36471f3a2498244b365d83de32baf6322fa7a5f4207fe889b07cd87",
          3 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "1c122a430c44df3918a5d534c63d35dea1e7ff2252914d62086cee777e16e003",
          4 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cde",
          "3d1f9a67abccf456f8773712f8bde3acb9ff39ffe806aad5a8a4492b3c3ad0b3",
          5 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "061b6947fee1a53aee8903e6d0d262ce2d10e675dbe0f83fe55d8c6c0eba4621",
          1 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "1c122a430c44df3918a5d534c63d35dea1e7ff2252914d62086cee777e16e003",
          2 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0",
          "26dac7bfda905c286ff40620be79b1118341c17fc40446252a81df39ac1968c0",
          3 },
        { (Uint8*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
          4 },
        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmno",
          "835f9207766637f832cb3022f9d386b8b9426876f398d6b013a4925cc752806d",
          5 }

    };

    Uint8* sample_input;

    char* expected_output;

    Uint64 num_chunks;

    Uint8 sample_output[DIGEST_SIZE] = { 0 };

    char output_string[129];

    for (int i = 0; i < (sizeof STRING_VECTORS / sizeof(struct string_vector));
         i++) {

        sample_input = STRING_VECTORS[i].input;

        expected_output = STRING_VECTORS[i].output;

        num_chunks = STRING_VECTORS[i].num_chunks;

        alc_error_t err = create_demo_session();

        if (!alcp_is_error(err)) {
            err = hash_demo(sample_input,
                            strlen((const char*)sample_input),
                            sample_output,
                            sizeof(sample_output),
                            num_chunks);
        }

        // check if the outputs are matching
        hash_to_string(output_string, sample_output);
        printf("Input : %s\n", sample_input);
        printf("Input chunks : %lu\n", num_chunks);
        printf("output : %s\n", output_string);
        if (strcmp(expected_output, output_string)) {
            printf("=== FAILED ==== \n");
            printf("Expected output : %s\n", expected_output);
        } else {
            printf("=== Passed ===\n");
        }
    }
    return 0;
}
