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

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(Uint32 digest_size)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA3,
        .dt_len = ALC_DIGEST_LEN_CUSTOM,
        .dt_mode = {.dm_sha3 = ALC_SHAKE_128,},
        .dt_custom_len = digest_size * 8
    };

    Uint64 size         = alcp_digest_context_size();
    s_dg_handle.context = malloc(size);

    err = alcp_digest_request(&dinfo, &s_dg_handle);

    if (alcp_is_error(err)) {
        return err;
    }

    err = alcp_digest_init(&s_dg_handle);

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
hash_to_string(char* string, const Uint8* hash, Uint64 digest_size)
{
    size_t i;
    for (i = 0; i < digest_size; i++) {
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
        Uint32 digest_size; // digest size in bytes
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
          "a597c3e80e9066f95669",
          10,
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef012345",
          "164f5b797de92b76481b95ecada82fbc55f0a147",
          20,
          2 },

        { (Uint8*)"",
          "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66",
          30,
          3 },

        { (Uint8*)"abc",
          "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c5"
          "0"
          "af32acd3f2c",
          40,
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef",
          "f06f86e489f5dae74dbb47026c6f8c3b42bacc3aca17eab6bfbc8f9e3311e2f5"
          "05a0a5357e2671b0ac4e8dcd2f7ceb0c57e3",
          50,
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "036bb02331d87c9a15f1ab5fe322e2f7f31b07b4b266f5a1567d475cbfffafe73dbd"
          "f8447b0a7af9826553b13247c8fa97f9c804a10164a44b458268",
          60,
          2 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cde",
          "bd206b4bccced8eaba6f2b6ab404f3473da10a302b11ecf7d44d438347e311c129c7"
          "0"
          "aa6c90f1a85600309a8517b831e6a36223dc55306fe771118fdc530127b87ccaff64"
          "147",
          70,
          3 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "106c800085c059fac881a6f7853e96f9a67e80834e485d51f95bccd2a60c4f0fc540"
          "3a1fb2f7d8e041139cc1ce93a001b9e0b2ad7b21535aa859d8bfb75f0394d9376acb"
          "690d47e6c0cf008e316e85f2",
          80,
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "036bb02331d87c9a15f1ab5fe322e2f7f31b07b4b266f5a1567d475cbfffafe73dbd"
          "f8447b0a7af9826553b13247c8fa97f9c804a10164a44b458268c56f788cbcf6e6b6"
          "b6d10614df3d9ecee9d7eacfb6fd531e1247fd1e07c8",
          90,
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0",
          "71e42868c713d4490cd506b3c9740d065656eb9085ff514c79bf318b2b7c63e38"
          "5b00ae41b034d1d6487249bd6d17729950776ff6b5e3f3ea90c44eaa0b2d0ca8b"
          "9e23b1f76a5c84a6b38caac9e5482b848b18da52557e88ee80359212dbd68ad65349"
          "d2",
          100,
          2 },

        { (Uint8*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cf"
          "f7bf21f54ee5f19550825a6e070030519e944263ac1c6765287065621"
          "f9fcb3201723e3223b63a46c2938aa953ba8401d0ea77b8d264907755"
          "66407b95673c0f4cc1ce9fd966148d7efdff26bbf9f48a21c6",
          110,
          3 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmno",
          "28e1d757fc91b7e055d01eabee20a50fda48c6bb12c8feab9a929ac55ce1e1007624"
          "6b38486a9dd76fe6e3de8b68bc956455c89b05b2d1bd0fa39f834323040b4bd4dbae"
          "626ff94fd937a3cdea0467ec3aa553e9b9bd952d5c15eedffb8ddcd60b7641ec2eb9"
          "e26c024fa4bc5eff6e9ac84aed4b015a7744",
          120,
          4 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efgh",
          "f7ecb883e545e9259fd1467a5bd984a13a6dfbbb4dd547d47afd308b96b8a78872ef"
          "9e8e8cdd17e0366cfe79383a822232e4de054dd2b508bab1a973eb1f002752be9191"
          "6c694a2e5a409d5709a7d920157b5cdcdc1a3c58500aab74655ce64b5cac7b93242c"
          "417c19d9a0d8bffd762ebad68c7b5c44f49826fe6aa009d2ee7c89cf",
          130,
          1 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efg",
          "7752cddb6eb405a930f3341b51b483b2c3e426920ef3f8d3415c278e866f25f710fa"
          "86204624ac48d0cec642086c5fa1676b5c329e4bea2ec71fd41d7511e4408ea2c2b0"
          "71d510d3993caa7ebb13deb9d31307a88fc89d49954ecee04ef2f3bc694110507e81"
          "fedd81b4ac5031b78a28a7b50f2103b3f02e0f42b651431a134ffe409cdcf2245eb6"
          "7c56341e",
          140,
          2 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efghi",
          "1ca64e3267d1ae6197d91b853c1203ba96e788ff85692bdf4382c74d3b2de4f86617"
          "094635c663fcc852e21ff02e90c9fda20bb0cf3d04d40573de50ac2fa0fbc9fa1dbd"
          "712b9dba3ef55fd89b8208c3598329e5a37185b88b907641cbe157e4f5584aa17f3a"
          "ff347bfb8075c075505e55ec8bac2da1414ba98b77085d2a198b251278d92025b78f"
          "0944845845d5077948cd50d76cd5",
          150,
          3 }

    };

    Uint8* sample_input;

    char* expected_output;

    Uint64 num_chunks;

    Uint8* sample_output;

    // every byte in digest is represented as hexadecimal and is null terminated
    char* output_string;

    for (int i = 0; i < (sizeof STRING_VECTORS / sizeof(struct string_vector));
         i++) {

        sample_input = STRING_VECTORS[i].input;

        expected_output  = STRING_VECTORS[i].output;
        Uint32 hash_size = STRING_VECTORS[i].digest_size;
        num_chunks       = STRING_VECTORS[i].num_chunks;
        sample_output    = malloc(hash_size);
        output_string    = malloc(hash_size * 2 + 1);

        alc_error_t err = create_demo_session(hash_size);
        if (alcp_is_error(err)) {
            return -1;
        }
        err = hash_demo(sample_input,
                        strlen((const char*)sample_input),
                        sample_output,
                        hash_size,
                        num_chunks);
        if (alcp_is_error(err)) {
            return -1;
        }

        // check if the outputs are matching
        hash_to_string(output_string, sample_output, hash_size);
        printf("Input : %s\n", sample_input);
        printf("Input chunks : %10" PRId64 "\n", num_chunks);
        printf("output size : %u\n", hash_size);
        printf("output : %s\n", output_string);
        if (strcmp(expected_output, output_string)) {
            printf("=== FAILED ==== \n");
            printf("Expected output : %s\n", expected_output);
            return -1;
        } else {
            printf("=== Passed ===\n");
        }
        free(sample_output);
        free(output_string);
    }
    return 0;
}
