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

#define NUM_IP_CHUNKS 1

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(Uint32 digest_size)
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = ALC_DIGEST_TYPE_SHA3,
        .dt_len = ALC_DIGEST_LEN_CUSTOM,
        .dt_mode = {.dm_sha3 = ALC_SHAKE_256,},
        .dt_custom_len = digest_size
    };

    Uint64 size       = alcp_digest_context_size(&dinfo);
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
          Uint64       out_size)
{
    alc_error_t err;
    // divide the input size into multiple chunks
    Uint32       num_chunks      = NUM_IP_CHUNKS;
    const Uint32 chunk_size      = src_size / num_chunks;
    const Uint32 last_chunk_size = src_size % num_chunks;
    const Uint8* p               = src;

    while (num_chunks-- > 0) {
        err = alcp_digest_update(&s_dg_handle, p, chunk_size);
        if (alcp_is_error(err)) {
            printf("Unable to compute SHA3 hash\n");
            goto out;
        }
        p += chunk_size;
    }
    err = alcp_digest_update(&s_dg_handle, p, last_chunk_size);
    if (alcp_is_error(err)) {
        printf("Unable to compute SHA3 hash 2\n");
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
hash_to_string(char *string, const Uint8 *hash, Uint64 digest_size)
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
        char* input;
        char* output;
        Uint32 digest_size; // digest size in bytes
    };

    static const struct string_vector STRING_VECTORS[] = {

       { "11111111111111111111111111111111111111111111111111111111111111111111"
          "11111111111111111111111111111111111111111111111111111111111111111111"
          "11111111111111111111111111111111111111111111111111111111111111111111"
          "11111111111111111111111111111111111111111111111111111111111111111111"
          "11111111111111111111111111111111111111111111111111111111111111111111"
          "11111111111111111111111111111111111111111111111111111111111111111111"
          "11111111111111111111111111111111111111111111111111111111111111111111"
          "111111111111111111111111111111111122",
          "84fc18157139cf4310af",
          10
        },
        
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef012345",
          "c415eeb5bc633489d14a085dc234001ea2f55080",
          20
        },
        
        { "",
          "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5",
          30
        },

        { "abc",
          "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a1"
          "5bef186a5386",
          40
        },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "5a8182c1e37289f4d75106b80e350fcbde176f1e2ec87b9259ffcf8cfa5da018"
          "219989ff123534ec41f2c0c9ad2ee16cb5a4",
          50
        },
        
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "5e61e6b827ac5cf6f54dc0ed8e727fcb1de73d9bb64f12894996dfbbbee00de6f38c"
          "ee078daeb8d90bb63b828c3adc66c42334fb93da864a27f30408",
          60
        },
        
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "8fa1fa518f15e9cd20e5461fccb52dea5a1f5f0bb0ecf76d95f8c405b07c024"
          "1b82266bba48c126902cb308c57991933d5d7573806022995bd5da130390164"
          "70f4561ba663d0",
          70
        },
        
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "b19761b59d470609e72da9a2e9bbbee92c338020c756446fc339a9783d208be5bdbe"
          "89760e8ff20c2ed2464f5d9a0ee9c56206c2e0eb6214e2a3210ac718a31bd6817abb"
          "7eb28d5d1b8e2ad379e59d1e",
          80
        },
        
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "5e61e6b827ac5cf6f54dc0ed8e727fcb1de73d9bb64f12894996dfbbbee00de6f38c"
          "ee078daeb8d90bb63b828c3adc66c42334fb93da864a27f304087aa8fbae00cf3fef"
          "223614d66b15c133341874068692c6e2e492bb967ef0",
          90
        },
        
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "25fceb7469d8c146767ee46a4012ced34a6a338f2beaaba16bf8ce83d6883ef2b"
          "3670131eadfe28d23bc4b6a1e40ab442bcc7596d30fd64f2129ac6bdd0cd1402a"
          "1d30cffc363c4cc77d582078c615b0394274a33eaebaf7dd0f62087b409f08b64"
          "be561",
          100
        },
        
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e332940d"
          "8688a4e6a59aa8060f1f9bc996c05aca3c696a8b66279dc672c740bb224ec37a92b6"
          "5db0539c0203455f51d97cce4cfc49127d7260afc673af208baf19be21233f3debe7"
          "8d06760cfa551ee1e",
          110
        },
        
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
          "c1f5adb085c1c3dae1d1740b29c7140416b697c990f2b7aa4a0b2aa93210bc850e9"
          "3c413135fea498cc41b8a8293b147916f42fe43fb911d4baa4eea751686d8b2485c"
          "7018e449367368089eaf5e3ffc21f515e98815cccff3819135f7fa62bbfe9fbfff4"
          "960106266a5f0e979c6c68fa8807f868cf0c985",
          120
        },

        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoabcd"
          "efgh",
          "3539157b21b73e7333d6766362af3840f0f0caa6a6ce2514954acf6f02fb14c38ed6"
          "d1bfacea94479cb03ff7fc07613c1867ab4b6ded0016dd037c3119e93999a905a791"
          "cef7a25f9b87f334d5033553a02f8f1cb0ef62051eb64722fe4b21a84e7a960af22a"
          "9c73573c5a5d28612d2d51af007f8b67ef3568e31d4e90b630302402",
          130
        },

        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoabcd"
          "efg",
          "5d6fa813bb63da4ee01669d05d28cf1957d8221101f4d02a1c0e79226055237aacad"
          "3e91f95cc7ceabd197f0b6df0728cafdb794f8a3a3a03fa577b977c4c999b6a8faba"
          "f66a48286cf8db366559d1672403024c278a380b2d84af124e464161657b0c556e4e"
          "8ff2246ee6eee51e9bbbc822c63e50ecd616ff976e3776f0af73fda3f60362336cf1"
          "6553b89f",
          140
        },

        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoabcd"
          "efghi",
          "384ef118703db4e696d02a15626ec0d2f1722bb11283992d589e8c25f0af1547f19a"
          "4741aa35d313d11033a188d6168cbba6da851b93f3c00dc840a839c7b31e9cb7e8ba"
          "e955956a9c7ea38e9d1a2688e4af8602d5998a9979cb68fcdff4186004b7b0cf1f7a"
          "c7b51752c63403cfb62a75d8901e9681a10f21b32f535944e4ddeacc7d9a200af065"
          "2db9e0809bb6c764c23f8d450237",
          150
        }

    };

    char* sample_input;

    char* expected_output;

    Uint8 *sample_output;

    // every byte in digest is represented as hexadecimal and is null terminated
    char *output_string;

    for (int i = 0; i < (sizeof STRING_VECTORS / sizeof(struct string_vector));
         i++) {

        sample_input = STRING_VECTORS[i].input;

        expected_output = STRING_VECTORS[i].output;
        Uint32 hash_size = STRING_VECTORS[i].digest_size;
        sample_output =  malloc(hash_size);
        output_string = malloc(hash_size * 2 + 1);
        alc_error_t err = create_demo_session(hash_size);

        if (!alcp_is_error(err)) {
            err = hash_demo(sample_input,
                            strlen(sample_input),
                            sample_output,
                            hash_size);
        }

        /*
         * Complete the transaction
         */
        if (alcp_is_error(err)){
            alcp_digest_finish(&s_dg_handle);
        }
        
        // check if the outputs are matching
        hash_to_string(output_string, sample_output, hash_size);
        printf("Input : %s\n", sample_input);
        printf("output size : %u\n", hash_size);
        printf("output : %s\n", output_string);
        if (strcmp(expected_output, output_string)) {
            printf("=== FAILED ==== \n");
            printf("Expected output : %s\n", expected_output);
        } else {
            printf("=== Passed ===\n");
        }

        free(sample_output);
        free(output_string);
        free(s_dg_handle.context);

    }
    return 0;
}
