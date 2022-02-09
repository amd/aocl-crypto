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

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA2,
        .dt_len = ALC_DIGEST_LEN_224,
        .dt_mode = {.dm_sha2 = ALC_SHA2_224,},
    };

    uint64_t size       = alcp_digest_context_size(&dinfo);
    s_dg_handle.context = malloc(size);

    err = alcp_digest_request(&dinfo, &s_dg_handle);

    if (alcp_is_error(err)) {
        return err;
    }

    return err;
}

static alc_error_t
hash_demo(const uint8_t* src,
          uint64_t       src_size,
          uint8_t*       output,
          uint64_t       out_size)
{
    alc_error_t err;

    err = alcp_digest_update(&s_dg_handle, src, src_size);
    if (alcp_is_error(err)) {
        printf("Unable to compute SHA2 hash\n");
        goto out;
    }

    alcp_digest_finalize(&s_dg_handle, NULL, 0);

    err = alcp_digest_copy(&s_dg_handle, output, out_size);
    if (alcp_is_error(err)) {
        printf("Unable to copy digest\n");
        goto out;
    }

    alcp_digest_finish(&s_dg_handle);

out:
    return err;
}

static void
hash_to_string(char string[65], const uint8_t hash[32])
{
    size_t i;
    for (i = 0; i < 28; i++) {
        string += sprintf(string, "%02x", hash[i]);
    }
}

int
main(void)
{
    struct string_vector
    {
        char* input;
        char* output;
    };

    static const struct string_vector STRING_VECTORS[] = {
        { "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
        { "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "43f95590b27f2afde6dd97d951f5ba4fe1d154056ec3f8ffeaea6347" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "99da0faf832c6b266c5db29a034e536a2a81df95c499ed0ce14d7978" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "0a132954fcaf53473a7d4eb87d44038a17e3175d67214750a963a868" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3" }
    };

    char* sample_input;

    char* expected_output;

    uint8_t sample_output[512] = { 0 };

    char output_string[65];

    for (int i = 0; i < (sizeof STRING_VECTORS / sizeof(struct string_vector));
         i++) {

        sample_input = STRING_VECTORS[i].input;

        expected_output = STRING_VECTORS[i].output;

        alc_error_t err = create_demo_session();

        if (!alcp_is_error(err)) {
            err = hash_demo(sample_input,
                            strlen(sample_input),
                            sample_output,
                            sizeof(sample_output));
        }

        /*
         * Complete the transaction
         */
        if (alcp_is_error(err))
            alcp_digest_finish(&s_dg_handle);

        // check if the outputs are matching
        hash_to_string(output_string, sample_output);
        printf("Input : %s\n", sample_input);
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
