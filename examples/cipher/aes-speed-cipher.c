/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sys/time.h>
#elif WIN32
#include <windows.h>
#endif

#include "alcp/alcp.h"

static alc_cipher_handle_t handle;

// #define DEBUG_P /* Enable for debugging only */

// debug prints to be print input, cipher, iv and decrypted output
static inline void
printText(Uint8* I, Uint64 len, char* s)
{
#ifdef DEBUG_P
    printf("\n %s ", s);
    for (int x = 0; x < len; x++) {
        if ((x % (16 * 4) == 0)) {
            printf("\n");
        }
        if (x % 16 == 0) {
            printf("   ");
        }
        printf(" %2x", *(I + x));
    }
#endif
}

struct timeval begin, end;
long           seconds;
long           microseconds;
double         elapsed;
double         totalTimeElapsed;

#if WIN32
int
gettimeofday(struct timeval* tv, struct timeval* tv1)
{
    FILETIME   f_time;
    Uint64     time;
    SYSTEMTIME s_time;
    // define UNIX EPOCH time for windows
    static const Uint64 EPOCH = ((Uint64)116444736000000000ULL);
    GetSystemTimeAsFileTime(&f_time);
    FileTimeToSystemTime(&f_time, &s_time);
    time = ((Uint64)f_time.dwLowDateTime);
    time += ((Uint64)f_time.dwHighDateTime) << 32;
    tv->tv_sec  = (long)((time - EPOCH) / 10000000L);
    tv->tv_usec = (long)(s_time.wMilliseconds * 1000);
    return 0;
}
#endif

#define ALCP_CRYPT_TIMER_START gettimeofday(&begin, 0);

static inline void
alcp_get_time(int x, char* s)
{
    gettimeofday(&end, 0);
    seconds      = end.tv_sec - begin.tv_sec;
    microseconds = end.tv_usec - begin.tv_usec;
    elapsed      = seconds + microseconds * 1e-6;
    totalTimeElapsed += elapsed;
    if (x) {
        printf("%s\t", s);
        printf(" %2.2f ms ", elapsed * 1000);
    }
}

void
getinput(Uint8* output, int inputLen)
{
    for (int i = 0; i < inputLen; i++) {
        Uint64 x = i + 20 + (i * 3); // simple equation to get generate input
        *output  = (Uint8)x;
        output++;
    }
}

int
create_aes_session(Uint8*                  key,
                   Uint8*                  iv,
                   const Uint32            key_len,
                   const alc_cipher_mode_t mode)
{
    alc_error_t err = ALC_ERROR_NONE;

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size());
    if (!handle.ch_context) {
        printf("Error: context allocation failed \n");
        goto out;
    }

    /* Request a context with mode and key length */
    err = alcp_cipher_request(mode, key_len, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        goto out;
    }

    err = alcp_cipher_init(&handle, key, key_len, iv, 16);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: Unable to init \n");
        goto out;
    }
    return 0;

    // Incase of error, program execution will come here
out:
    return -1;
}

void
end_aes_session()
{
    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);
    free(handle.ch_context);
}

/* AES modes: Encryption Demo */
void
aclp_aes_encrypt_demo(
    const Uint8* plaintxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       ciphertxt)
{
    alc_error_t err;

    err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        return;
    }
}

void
aclp_aes_decrypt_demo(
    const Uint8* ciphertxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       plaintxt)
{
    alc_error_t err;

    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        return;
    }
}

/*
    Demo application for complete path:
    input->encrypt->cipher->decrypt->output.
    input and output is matched for comparison.
*/
void
encrypt_decrypt_demo(Uint8*            inputText,  // plaintext
                     Uint32            inputLen,   // input length
                     Uint8*            cipherText, // ciphertext output
                     alc_cipher_mode_t m,
                     int               i)
{
    int          retval = 0;
    unsigned int keybits;
    Uint8        key[32];

    memset(key, 0, 32);

    Uint8* outputText;
    outputText = malloc(inputLen);

    Uint8* iv;
    iv = malloc(128 * 4);
    memset(iv, 10, 128 * 4);

    Uint8* ref;
    ref = malloc(inputLen);

    {
        keybits = 128 + i * 64;
        printf(" keybits %d ", keybits);
        memset(key, ((i * 10) + m), 32);

        memset(inputText, i, inputLen);

        getinput(inputText, inputLen);

        memset(cipherText, 0, inputLen);
        memset(ref, 0, inputLen);
        memset(outputText, 0, inputLen);
        printText(key, 16, "key      ");
        printText(inputText, inputLen, "inputText");

        // Encrypt speed test
        totalTimeElapsed = 0.0;
        retval           = create_aes_session(key, iv, keybits, m);
        for (int k = 0; k < 100000000; k++) {
            // FIXME: We need a reset API to remove this
            // Create the session
            if (retval != 0)
                goto out;

            ALCP_CRYPT_TIMER_START
            aclp_aes_encrypt_demo(inputText, inputLen, cipherText);

            alcp_get_time(0, "Encrypt time");
            printText(cipherText, inputLen, "cipherTxt");

            if (totalTimeElapsed > .5) {
                printf("\t :  %6.3lf GB Encrypted per second with block size "
                       "(%5d bytes) ",
                       (double)(((k / 1000.0) * inputLen)
                                / (totalTimeElapsed * 1000000.0)),
                       inputLen);
                break;
            }
        }
        end_aes_session();

        // Decrypt speed test
        totalTimeElapsed = 0.0;
        retval           = create_aes_session(key, iv, keybits, m);
        for (int k = 0; k < 100000000; k++) {
            // FIXME: We need a reset API to remove this
            if (retval != 0)
                goto out;

            ALCP_CRYPT_TIMER_START
            aclp_aes_decrypt_demo(
                cipherText,  // pointer to the PLAINTEXT
                inputLen,    // text length in bytes
                outputText); // pointer to the CIPHERTEXT buffer

            alcp_get_time(0, "Decrypt time");
            printText(outputText, inputLen, "outputTxt");

            if (totalTimeElapsed > .5) {
                printf("\t :  %6.3lf GB Decrypted per second with block size "
                       "(%5d bytes) ",
                       (double)(((k / 1000.0) * inputLen)
                                / (totalTimeElapsed * 1000000.0)),
                       inputLen);
                break;
            }
        }
        end_aes_session();
    }

out:
    if (outputText) {
        free(outputText);
    }
    if (iv) {
        free(iv);
    }
    if (ref) {
        free(ref);
    }
}

int
main(void)
{
    Uint8* inputText;
    Uint8* cipherText;

    /*
     * Demo application to demonstrate speed of different AES Cipher modes.
     */

    printf("\n AOCL-CRYPTO: AES Cipher Speed test application ");

    for (alc_cipher_mode_t m = ALC_AES_MODE_CBC; m < ALC_AES_MODE_XTS; m++) {

        if (m == ALC_AES_MODE_CBC) {
            printf("\n\nAES-CBC");
        } else if (m == ALC_AES_MODE_OFB) {
            printf("\n\nAES-OFB");
        } else if (m == ALC_AES_MODE_CTR) {
            printf("\n\nAES-CTR");
        } else if (m == ALC_AES_MODE_CFB) {
            printf("\n\nAES-CFB");
        } else if (m == ALC_AES_MODE_XTS) {
            printf("\n\nAES-XTS\n");
        } else {
            printf("\n Invalid AES mode");
            continue;
        }

// keep length multiple of 128bit (16x8)
#define MAX_TEST_CASE 7
        int testblkSizes[MAX_TEST_CASE] = { 16,   64,    256,  1024,
                                            8192, 16384, 32768 };

        for (int keySizeItr = 0; keySizeItr < 3; keySizeItr++) {
            if ((m == ALC_AES_MODE_XTS) && (keySizeItr > 0)) {
                continue;
            }
            for (int i = 0; i < MAX_TEST_CASE; i++) {
                int inputLen = testblkSizes[i];
                printf(" \n");

                // allocate inputText and cipherText memory
                inputText = malloc(inputLen);
                if (inputText == NULL) {
                    return -1;
                }
                cipherText = malloc(inputLen);
                if (cipherText == NULL) {
                    if (inputText) {
                        free(inputText);
                    }
                    return -1;
                }

                // run full path demo for specific aes mode
                encrypt_decrypt_demo(
                    inputText,
                    inputLen, /* len of both 'plaintxt' and 'ciphertxt' */
                    cipherText,
                    m,
                    keySizeItr);

                // its time to free!
                if (inputText) {
                    free(inputText);
                }
                if (cipherText) {
                    free(cipherText);
                }
            }
            printf(" \n");
        }
    }

    return 0;
}