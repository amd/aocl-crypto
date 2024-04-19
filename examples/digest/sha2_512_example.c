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

#define DIGEST_SIZE 64

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

    err = alcp_digest_request(ALC_SHA2_512, &s_dg_handle);

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
            printf("Unable to compute SHA2 hash\n");
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
          "7838ae76add02b5928efc96d5527007a6e84cce2b68cc27e1b77a9b170d806124ad2"
          "e77c25ebb0a86dd1f9dc6215dde0ad58735c32594246132d334c347d7ef1",
          1 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef012345",
          "32c4bc0d883f25fbf89f1a4c4dce86b18325d7557cc8f3d433ee294c7cbd5a958623"
          "6f5dc95196025d2112157ff5b9b7551c7595d51b19a8b455d876751b54b1",
          2 },
        { (Uint8*)"",
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0"
          "d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
          3 },
        { (Uint8*)"abc",
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192"
          "992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          4 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef",
          "ad2981aa58beca63a49b8831274b89d81766a23d7932474f03e55cf00cbe27004e66"
          "fd0912aed0b3cb1afee2aa904115c89db49d6c9bad785523023a9c309561",
          1 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "451e75996b8939bc540be780b33d2e5ab20d6e2a2b89442c9bfe6b4797f6440dac65"
          "c58b6aff10a2ca34c37735008d671037fa4081bf56b4ee243729fa5e768e",
          2 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cde",
          "f650799be4b8aecf38cf6ad17538690b89cdf7291ba8ad6a19b45dcb25b52ddff42e"
          "f38ebbf851145e3b8584785d10821068ee17f1e21b36e2b01d888ca71503",
          3 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "ca8b236e13383f1f2293c9e286376444e99b7f180ba85713f140b55795fd2f8625d8"
          "b84201154d7956b74e2a1e0d5fbff1b61c7288c3f45834ad409e7bdfe536",
          4 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "451e75996b8939bc540be780b33d2e5ab20d6e2a2b89442c9bfe6b4797f6440dac65"
          "c58b6aff10a2ca34c37735008d671037fa4081bf56b4ee243729fa5e768e",
          1 },
        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0",
          "72ddcfd4389b0735b8b5cf758592413ef174df8a2d8e21c285f5ea387369b619faa5"
          "b7b7cb5745a381c65882dd6f1cb757956de9e95b26a38a68b3f75eda6287",
          2 },
        { (Uint8*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd"
          "15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
          3 },
        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmno",
          "90d1bdb9a6cbf9cb0d4a7f185ee0870456f440b81f13f514f4561a08112763523033"
          "245875b68209bb1f5d5215bac81e0d69f77374cc44d1be30f58c8b615141",
          4 }

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
