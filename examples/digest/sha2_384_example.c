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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alcp/digest.h"

#define DIGEST_SIZE 48

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA2,
        .dt_len = ALC_DIGEST_LEN_384,
        .dt_mode = {.dm_sha2 = ALC_SHA2_384,},
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

    alcp_digest_finish(&s_dg_handle);

    free(s_dg_handle.context);

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
    string[97] = '\0';
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
        { "",
          "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274e"
          "debfe76f65fbd51ad2f14898b95b",
          1 },
        { "abc",
          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086"
          "072ba1e7cc2358baeca134c825a7",
          2 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "648a627ba7edae512ab128eb8e4ad9cc13c9e89da332f71fe767f1c4dd0e5c2bd3f8"
          "3009b2855c02c7c7e488bcfc84dc",
          3 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "f932b89b678dbdddb555807703b3e4ff99d7082cc4008d3a623f40361caa24f8b53f"
          "7b112ed46f027ff66ef842d2d08c",
          4 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "436ac328cb192b0077f8c29527f7a91214b8fe1b5c872cb176f5410f76c11d16b8b6"
          "d574aea17454afc4cdcd9e6a52ab",
          5 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "5fe52b687a74a341872e833f53ed68fa1fd2efe237214c6b03bba3ef1c4395ae9574"
          "b75f467d3bde21eef1b0826c9041",
          1 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "f932b89b678dbdddb555807703b3e4ff99d7082cc4008d3a623f40361caa24f8b53f"
          "7b112ed46f027ff66ef842d2d08c",
          2 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "1c95c92db36f7794fa23ea4d354b3bab1187cd8ee4a3dd42b70c343c1cf7d0aa92ba"
          "01e31560260caa23de17a5b76f0d",
          3 },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b045"
          "5a8520bc4e6f5fe95b1fe3c8452b",
          4 },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
          "bdc0f4a6e0d7de88f374e6c2562441d856aeabed3f52553103f55eca811f64b422c7"
          "cb47a8067f123e45c1a8ee303635",
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
                            strlen(sample_input),
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
