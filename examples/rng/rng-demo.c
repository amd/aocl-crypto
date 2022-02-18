#include <alcp/rng.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RANDOM_SIZE 50 // Size of buffer

/* Change sources to use different random engine */
#define SOURCE ALC_RNG_SOURCE_OS
// #define SOURCE      ALC_RNG_SOURCE_ARCH

char*
bytesToHexString(unsigned char*, int);

int
main(int argc, char const* argv[])
{
    unsigned char    buffer[RANDOM_SIZE];
    unsigned char*   out;
    alc_rng_handle_t ctx;
    {
        alc_rng_info_t rng_info;
        rng_info.r_distrib =
            ALC_RNG_DISTRIB_UNIFORM; // Output should be uniform probablilty
        rng_info.r_source = SOURCE;  // Use OS RNG
        rng_info.r_type   = ALC_RNG_TYPE_DESCRETE; // Discrete output (uint8)

        /* Erase buffer and prove its empty */
        memset(buffer, 0, RANDOM_SIZE); // Erase buffer
        out = bytesToHexString(buffer, RANDOM_SIZE);
        printf("Original Value of Buffer: %s\n", out);
        free(out);

        /* Check if RNG mode is supported with RNG info */
        if (alcp_rng_supported(&rng_info) != ALC_ERROR_NONE) {
            printf("Support Failed!\n");
            exit(-1);
        }
        printf("Support Success\n");

        /* Application has to allocate memory*/
        ctx.context = malloc(alcp_rng_context_size(rng_info));
        /* Request context for RNG with RNG info */
        if (alcp_rng_request(&rng_info, &ctx) != ALC_ERROR_NONE) {
            printf("Request Failed!\n");
            exit(-1);
        }
        printf("Request Success\n");
        // Life of rng_info ends here and it lives inside context
    }

    /* Generate RANDOM_SIZE bytes of random values */
    if (alcp_rng_gen_random(&ctx, buffer, RANDOM_SIZE) != ALC_ERROR_NONE) {
        printf("Random number generation Failed!\n");
        exit(-1);
    }

    if (alcp_rng_finish(&ctx) != ALC_ERROR_NONE) {
        printf("Finish Failed!\n");
        exit(-1);
    }

    /* Show the buffer randomnumber buffer */
    printf("Random number generation Success!\n");
    out = bytesToHexString(buffer, RANDOM_SIZE);
    printf("Random Value in Buffer: %s\n", out);
    free(out);
    free(ctx.context);
    return 0;
}

char*
bytesToHexString(unsigned char* bytes, int length)
{
    char* outputHexString = malloc(sizeof(char) * ((length * 2) + 1));
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