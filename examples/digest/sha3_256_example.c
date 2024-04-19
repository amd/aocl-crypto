/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
#include <inttypes.h>
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

    Uint64 size         = alcp_digest_context_size();
    s_dg_handle.context = malloc(size);

    if (!s_dg_handle.context) {
        return ALC_ERROR_NO_MEMORY;
    }

    err = alcp_digest_request(ALC_SHA3_256, &s_dg_handle);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    err = alcp_digest_init(&s_dg_handle);

    if (err != ALC_ERROR_NONE) {
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
        if (err != ALC_ERROR_NONE) {
            printf("Unable to compute SHA3 hash\n");
            goto out;
        }
        p += buf_size;
    }

    if (last_buf_size) {
        err = alcp_digest_update(&s_dg_handle, p, last_buf_size);
        if (err != ALC_ERROR_NONE) {
            printf("Unable to compute SHA3 hash\n");
            goto out;
        }
    }

    err = alcp_digest_finalize(&s_dg_handle, output, out_size);

    if (err != ALC_ERROR_NONE) {
        printf("Unable to copy digest\n");
    }

out:
    alcp_digest_finish(&s_dg_handle);
    free(s_dg_handle.context);
    return err;
}

static void
hash_to_string(char* string, const Uint8 hash[DIGEST_SIZE])
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
        { (Uint8*)"111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111111111111111111111111111111"
                  "11111111"
                  "111111111111111111111111111111111122",
          "4037dd5fb3932ecff8a17c4ad37e251b6b50cb9033cc3db0d64e42320b119367",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef012345",
          "11063bb01a3aa3206b499c8170aaa78f964ebead863f4411c97da42cea01d6c9",
          2 },

        { (Uint8*)"",
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
          3 },

        { (Uint8*)"abc",
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef",
          "c3eea27e79a4915ed0ebe3645f242d863142d6062c61ef54dbd80ce4ebd7eb3b",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "44b36b3e510e8797e3b090f41ac7fc7864aafec9dd69788ccbc739a00375c168",
          2 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cde",
          "0c0fc587257a8650fc4d18dcb22640a87686001b6319508e722661c45756563f",
          3 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "d59264abd4e1bdaaa6f706baeae5a2280fc049cee539cfa6fba778fffe009e8b",
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "44b36b3e510e8797e3b090f41ac7fc7864aafec9dd69788ccbc739a00375c168",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0",
          "050f918d4be0234f803753488bc5e27b1bd590018fe7238c3a7974303dd08f66",
          2 },

        { (Uint8*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
          3 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmno",
          "3706569f9a29d62991ebe62f080ea3fac18034d2fffd23b136c10f7148fceb38",
          4 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efgh",
          "acc738e667c5dbab2dc0338b2cd7256ec722af18b61bbd4a64092c6eaa9866b8",
          1 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efg",
          "071fab7ea3e62cd3440ebc1dfc1d80a8948a4046d43e7c3efaf86cbaf457d810",
          2 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efghi",
          "1723b5fa4fc5ae6a85866d2e41c395a373210e92cea5af41e5d363f2fc0117c"
          "2",
          3 }
    };

    Uint8* sample_input;

    char* expected_output;

    Uint64 num_chunks;

    Uint8 sample_output[DIGEST_SIZE] = { 0 };

    // every byte in digest is represented as hexadecimal and is null terminated
    char output_string[2 * DIGEST_SIZE + 1];

    for (int i = 0; i < (sizeof STRING_VECTORS / sizeof(struct string_vector));
         i++) {

        sample_input = STRING_VECTORS[i].input;

        expected_output = STRING_VECTORS[i].output;

        num_chunks = STRING_VECTORS[i].num_chunks;

        alc_error_t err = create_demo_session();
        if (err != ALC_ERROR_NONE) {
            return -1;
        }
        err = hash_demo(sample_input,
                        strlen((const char*)sample_input),
                        sample_output,
                        sizeof(sample_output),
                        num_chunks);
        if (err != ALC_ERROR_NONE) {
            return -1;
        }

        // check if the outputs are matching
        hash_to_string(output_string, sample_output);
        printf("Input : %s\n", sample_input);
        printf("output : %s\n", output_string);
        printf("Input chunks : %10" PRId64 "\n", num_chunks);
        if (strcmp(expected_output, output_string)) {
            printf("=== FAILED ==== \n");
            printf("Expected output : %s\n", expected_output);
            return -1;
        } else {
            printf("=== Passed ===\n");
        }
    }
    return 0;
}
