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
#include <inttypes.h>
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
        .dt_type = ALC_DIGEST_TYPE_SHA3,
        .dt_len = ALC_DIGEST_LEN_384,
        .dt_mode = {.dm_sha3 = ALC_SHA3_384,},
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
            printf("Unable to compute SHA3 hash\n");
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
          "d69f070fa97a306f530cdfe4d8e64c9edbbe34a30d8fbd96b91331c4d6f2d62aa0e4"
          "4"
          "75e824e56faf7a37cb689145856",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef012345",
          "d24bb0a96cfa410457eaaeb24c6136ef1be1f1cffface827872dbe3a9c27770ece68"
          "479670378950b5110e22e9de812a",
          2 },

        { (Uint8*)"",
          "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac371"
          "3"
          "831264adb47fb6bd1e058d5f004",
          3 },

        { (Uint8*)"abc",
          "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d8"
          "8"
          "cea927ac7f539f1edf228376d25",
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef",
          "fcb7582349a4f7e8d13fe6488b275a2daac2eca4e0a303b6386d3e7016586331"
          "7f329795be37ef3a123c2749bfa3e47a",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "605a9162c27bf0a8a2abe8abdf9a649e6a889a1fff5728828563b3cae839412cb5c5"
          "4"
          "30f01eff3367467ddd9a57d1528",
          2 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cde",
          "fd497541c7451befb602abc2e919abace36ae4183f667866fceb1e92ebc44cd"
          "70c41fb5083646edb8510edd7f0925701",
          3 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "3342e284d9293abc4f8b4fac23de01bd89bb6715a795cfc075f53018adb4861bd102"
          "177ef6a9ab494562673f505c48a1",
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "605a9162c27bf0a8a2abe8abdf9a649e6a889a1fff5728828563b3cae839412cb5c5"
          "430f01eff3367467ddd9a57d1528",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0",
          "8e6822047d571739e0e9247786ed79a41c5a480c3c6f5264e6cb7b8efdab955b7"
          "892f5c8f8f90cacac65325db2d0af4a",
          2 },

        { (Uint8*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b"
          "9d4ad5aa04a1f076e62fea19eef51acd0657c22",
          3 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmno",
          "d37238ca41bbf3a5f04680e2f23c6681798678f7b7f4d8a1663507d7c6877cfa"
          "f32d76e7c0a8493bda32e499ee8bf904",
          4 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efgh",
          "e1fe24e27c0103b4d659789804cbb49eb58237014038e826e1c0e6d41c39b214caef"
          "76286f8b826cc0a9c775ab6ae05f",
          1 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efg",
          "e0ea44f082f01015a495ebcde4bdfb23fcda1842b2e86a09adfedae7bddb74241d6a"
          "082b86d6f6a5ae1599eeb6f4ca87",
          2

        },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efghi",
          "cfb9539f640653520a4e9fe79f01caf43bdf558bf31e08cf9f78ed718df25ce54627"
          "2"
          "a6f842c0b6628bc12ba234338ea",
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
        if (alcp_is_error(err)) {
            return -1;
        }
        err = hash_demo(sample_input,
                            strlen((const char*)sample_input),
                            sample_output,
                            sizeof(sample_output),
                            num_chunks);
        if (alcp_is_error(err)) {
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
