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

#define DIGEST_SIZE 32

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA2,
        .dt_len = ALC_DIGEST_LEN_256,
        .dt_mode = {.dm_sha2 = ALC_SHA2_256,},
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
            printf("Unable to compute SHA2 hash 1\n");
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
hash_to_string(char string[65], const Uint8 hash[DIGEST_SIZE])
{
    size_t i;
    for (i = 0; i < DIGEST_SIZE; i++) {
        string += sprintf(string, "%02x", hash[i]);
    }
    string[65] = '\0';
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
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          1 },
        { "abc",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          2 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e",
          3 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "057ee79ece0b9a849552ab8d3c335fe9a5f1c46ef5f1d9b190c295728628299c",
          4 },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "2a6ad82f3620d3ebe9d678c812ae12312699d673240d5be8fac0910a70000d93",
          1 },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          2 },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d"
          "1",
          3 }
    };

    Uint8* sample_input;

    char* expected_output;

    Uint64 num_chunks;

    Uint8 sample_output[DIGEST_SIZE] = { 0 };

    char output_string[65];

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
