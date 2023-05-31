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

#define DIGEST_SIZE 64

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA3,
        .dt_len = ALC_DIGEST_LEN_512,
        .dt_mode = {.dm_sha3 = ALC_SHA3_512,},
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
          "c2509d9d11747a41dba76b44034fc7bbf5f36f38abd45e5ae37fc17da6146cabed78"
          "50146a1219b903ee6e1a01bd422b8b2bbf57912b61c0e60fbaea543d4f19",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef012345",
          "d6aa3bf678379d7fa2c684f3044aa48a46c60082bd7eba727b8295f8ee69081ae704"
          "f648991b5f41af9327f627ec686c2949f564afde9d4c714b341b2db9bcf0",
          2 },

        { (Uint8*)"",
          "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2"
          "123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
          3 },

        { (Uint8*)"abc",
          "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e1"
          "16e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef",
          "3554e37ca417001fce0154e047e7878b18c5ee0e587dd94bf764a4846e500a403f5e"
          "304aab1d359c295d2740970311b943771af944f67432e719df628fe77b61",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "0187a5e72fac99b95e76f827ecc111ee2ea9ff810a2a58d082f3eedd435bf6df9274"
          "a6d7e04553b7b582598b3b6933d3ed8feb0f6ce59b387c89d23b4a6f071c",
          2 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cde",
          "50047957fd0dc86770b27a9221a0f7c11fd9249156b6b285631db844c0c832f"
          "4208b6c0d3d4773ee527eb3ea817c970c67bdda262c547e706775dc9f43d425c6",
          3 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "153539e6d6176f4f808ef888ffada1eb9349f96e8f8c1e363d62f30454d49093dc75"
          "06099dbdb370f9b62adafaec759ea961609d737a5635b927343b53b12c93",
          4 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0123"
                  "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
                  "f",
          "0187a5e72fac99b95e76f827ecc111ee2ea9ff810a2a58d082f3eedd435bf6df9274"
          "a6d7e04553b7b582598b3b6933d3ed8feb0f6ce59b387c89d23b4a6f071c",
          1 },

        { (Uint8*)"0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
                  "cdef0",
          "895f5d389335c55b76991ea0a4772b9b65ebe23251ad53e848b43adf4af55521fae1"
          "22ed07124109dabb97c71595993b089ef42dd04603d9f7ffc455cadb8ca1",
          2 },

        { (Uint8*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee69"
          "1fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e",
          3 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmno",
          "ece1f8872b4604379799bca9c0f3539315b47ba866d421a39eca1ad661956dee2736"
          "23f8a5d2432e9a244048b3d11388a241267cdd2a211b5dd67482fc0e8ba5",
          4 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efgh",
          "03ffee86742e264462329844946e3d7c3395dba93061b7f16ee2e2b1114282e8feeb"
          "4eb048a19198cb47c29d4cdeffd825853658ec58ea0f9983e89f0f6ebc96",
          1 },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efg",
          "32d1adacd8c53106644ca6c929e63b3f4e167a8562fe231793cc8a158741a96c2c1d"
          "aa9e6a604e020884a8696b7b49307e6d939513f13106475f75f30fe40231",
          2

        },

        { (Uint8*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                  "lmnoabcd"
                  "efghi",
          "986a078b5a8300fc48cc5459e9a8e61692bb6679d61f3a91725b6ede2e49396559fe"
          "04ec12f98c3fbc349197e81aa876a8f5ad16099811a8fd8fd294fea92bdc",
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
        printf("output : %s\n", output_string);
        printf("Input chunks : %10" PRId64 "\n", num_chunks);
        if (strcmp(expected_output, output_string)) {
            printf("=== FAILED ==== \n");
            printf("Expected output : %s\n", expected_output);
        } else {
            printf("=== Passed ===\n");
        }
    }
    return 0;
}
