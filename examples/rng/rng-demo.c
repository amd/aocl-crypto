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

#include <alcp/rng.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RANDOM_SIZE 50 // Size of buffer

/* Change sources to use different random engine */
alc_rng_source_t source = ALC_RNG_SOURCE_OS;
unsigned char*
bytesToHexString(unsigned char*, int);

int
main(int argc, char const* argv[])
{
    unsigned char    buffer[RANDOM_SIZE];
    unsigned char*   out;
    alc_rng_handle_t handle;

    // Parse Arguments
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--arch") == 0) {
                source = ALC_RNG_SOURCE_ARCH;
            } else if (strcmp(argv[i], "--os") == 0) {
                source = ALC_RNG_SOURCE_OS;
            } else if (strcmp(argv[i], "--help") == 0) {
                printf("Source selection\nUse --os for OS source\nUse --arch "
                       "for SRNG source\n");
                return 0;
            }
        }
    }

    {
        alc_rng_info_t rng_info;
        rng_info.ri_distrib =
            ALC_RNG_DISTRIB_UNIFORM; // Output should be uniform probablilty
        rng_info.ri_source = source;
        rng_info.ri_type   = ALC_RNG_TYPE_DESCRETE; // Discrete output (uint8)

        /* Erase buffer and prove its empty */
        memset(buffer, 0, RANDOM_SIZE); // Erase buffer
        out = bytesToHexString(buffer, RANDOM_SIZE);
        printf("Original Value of Buffer: %s\n", out);
        free(out);

        /* Check if RNG mode is supported with RNG info */
        if (alcp_rng_supported(&rng_info) != ALC_ERROR_NONE) {
            printf("Support Failed!\n");
            return -1;
        }
        printf("Support Success\n");

        /* Application has to allocate memory*/
        handle.rh_context = malloc(alcp_rng_context_size(&rng_info));
        /* Request context for RNG with RNG info */
        if (alcp_rng_request(&rng_info, &handle) != ALC_ERROR_NONE) {
            printf("Request Failed!\n");
            return -1;
        }
        printf("Request Success\n");
        // Life of rng_info ends here and it lives inside context
    }

    /* Generate RANDOM_SIZE bytes of random values */
    if (alcp_rng_gen_random(&handle, buffer, RANDOM_SIZE) != ALC_ERROR_NONE) {
        printf("Random number generation Failed!\n");
        return -1;
    }

    if (alcp_rng_finish(&handle) != ALC_ERROR_NONE) {
        printf("Finish Failed!\n");
        return -1;
    }

    /* Show the buffer randomnumber buffer */
    printf("Random number generation Success!\n");
    out = bytesToHexString(buffer, RANDOM_SIZE);
    printf("Random Value in Buffer: %s\n", out);
    free(out);
    free(handle.rh_context);
    return 0;
}

unsigned char*
bytesToHexString(unsigned char* bytes, int length)
{
    unsigned char* outputHexString = malloc(sizeof(char) * ((length * 2) + 1));
    for (int i = 0; i < length; i++) {
        char chararray[2];
        chararray[0] = (bytes[i] & 0xf0) >> 4;
        chararray[1] = bytes[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            switch (chararray[j]) {
                case 0x0:
                    chararray[j] = '0';
                    break;
                case 0x1:
                    chararray[j] = '1';
                    break;
                case 0x2:
                    chararray[j] = '2';
                    break;
                case 0x3:
                    chararray[j] = '3';
                    break;
                case 0x4:
                    chararray[j] = '4';
                    break;
                case 0x5:
                    chararray[j] = '5';
                    break;
                case 0x6:
                    chararray[j] = '6';
                    break;
                case 0x7:
                    chararray[j] = '7';
                    break;
                case 0x8:
                    chararray[j] = '8';
                    break;
                case 0x9:
                    chararray[j] = '9';
                    break;
                case 0xa:
                    chararray[j] = 'a';
                    break;
                case 0xb:
                    chararray[j] = 'b';
                    break;
                case 0xc:
                    chararray[j] = 'c';
                    break;
                case 0xd:
                    chararray[j] = 'd';
                    break;
                case 0xe:
                    chararray[j] = 'e';
                    break;
                case 0xf:
                    chararray[j] = 'f';
                    break;
                default:
                    printf("%x %d\n", chararray[j], j);
            }
            outputHexString[i * 2 + j] = chararray[j];
        }
    }
    outputHexString[length * 2] = 0x0;
    return outputHexString;
}
