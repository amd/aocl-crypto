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
#include <stdlib.h> /* for malloc */
#include <string.h>

#ifdef __linux__
#include <sys/time.h>
#elif WIN32
#include <windows.h>
#endif

#include "alcp/alcp.h"

static alc_cipher_handle_t handle;

// #define DEBUG 1

static inline void
printText(Uint8* I, Uint64 len, char* s, bool print)
{
    if (print) {
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
    }
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
alcp_get_time(int x, char* y)
{
    gettimeofday(&end, 0);
    seconds      = end.tv_sec - begin.tv_sec;
    microseconds = end.tv_usec - begin.tv_usec;
    elapsed      = seconds + microseconds * 1e-6;
    totalTimeElapsed += elapsed;
    if (x) {
        printf("%s\t", y);
        printf(" %2.2f ms ", elapsed * 1000);
    }
}

void
getinput(Uint8* output, int inputLen, int seed)
{
    // generate same random input based on seed value.
    srand(seed);
    for (int i = 0; i < inputLen; i++) {
        *output = (Uint8)rand();
        output++;
    }
}

void
create_aes_session(Uint8*                  key,
                   Uint8*                  iv,
                   const Uint32            key_len,
                   const alc_cipher_mode_t mode)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    alc_cipher_aead_info_t cinfo = { // request params
                                     .ci_type   = ALC_CIPHER_TYPE_AES,
                                     .ci_mode   = mode,
                                     .ci_keyLen = key_len,
                                     // init params
                                     .ci_key = key,
                                     .ci_iv  = iv
    };

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cipher mode and keyLen */
    err = alcp_cipher_aead_request(cinfo.ci_mode, cinfo.ci_keyLen, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/* GCM: Authenticated Encryption demo */
void
aclp_aes_gcm_encrypt_demo(
    const Uint8* plaintxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       ciphertxt,
    Uint8*       iv,
    const Uint32 ivLen,
    Uint8*       ad,
    const Uint32 adLen,
    Uint8*       tag,
    const Uint32 tagLen,
    const Uint8* pKey,
    const Uint32 keyLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    // GCM init key
    err = alcp_cipher_aead_set_key(&handle, keyLen, pKey);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // GCM init iv
    err = alcp_cipher_aead_set_iv(&handle, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) { // 100000000
        ALCP_CRYPT_TIMER_START

        // GCM encrypt
        err = alcp_cipher_aead_encrypt_update(
            &handle, plaintxt, ciphertxt, len, iv);
        if (alcp_is_error(err)) {
            printf("Error: unable encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return;
        }

        alcp_get_time(0, "Encrypt time");

        // plaintxt += len;
        // ciphertxt += len;

        if (totalTimeElapsed > .5) {
            printf(
                "\t :  %6.3lf GB Encrypted per second with block size "
                "(%5d bytes) ",
                (double)(((k / 1000.0) * len) / (totalTimeElapsed * 1000000.0)),
                len);
            break;
        }
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tag, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/* GCM: Authenticated Decryption demo */
void
aclp_aes_gcm_decrypt_demo(const Uint8* ciphertxt,
                          const Uint32 len,
                          Uint8*       plaintxt,
                          Uint8*       iv,
                          const Uint32 ivLen,
                          Uint8*       ad,
                          const Uint32 adLen,
                          Uint8*       tag,
                          const Uint32 tagLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    Uint8       tagDecrypt[16];

    // GCM init
    err = alcp_cipher_aead_set_iv(&handle, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) {
        ALCP_CRYPT_TIMER_START

        // GCM decrypt
        err = alcp_cipher_aead_decrypt_update(
            &handle, ciphertxt, plaintxt, len, iv);
        if (alcp_is_error(err)) {
            printf("Error: unable decrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return;
        }

        alcp_get_time(0, "Decrypt time");

        // plaintxt += len;
        // ciphertxt += len;

        if (totalTimeElapsed > .5) {
            printf(
                "\t :  %6.3lf GB Decrypted per second with block size "
                "(%5d bytes) ",
                (double)(((k / 1000.0) * len) / (totalTimeElapsed * 1000000.0)),
                len);
            break;
        }
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tagDecrypt, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // encrypt and decrypt tag will not match, since inputText, cipherText and
    // outputText are overwritten multiple times. So we avoid tag matching part.
}

/*
    Demo application for complete path:
    input->encrypt->cipher->decrypt->output.
    input and output is matched for comparison.
*/
int
encrypt_decrypt_demo(Uint8*            inputText,  // plaintext
                     Uint32            inputLen,   // input length
                     Uint8*            cipherText, // ciphertext output
                     alc_cipher_mode_t m,
                     int               i)
{
    bool         verboseprint = false;
    unsigned int keybits;
    Uint8        key[32];
    int          ret = 0;

    memset(key, 0, 32);

    Uint8* outputText;
    outputText = malloc(inputLen);

    Uint8* iv;
    iv = malloc(128 * 4);
    memset(iv, 10, 128 * 4);

    Uint8* ref;
    ref          = malloc(inputLen);
    Uint32 ivLen = 12;

    /* additional data, tag used in GCM */
    Uint32 adLen  = 20;
    Uint32 tagLen = 16;

    Uint8* ad = malloc(adLen);
    Uint8  tag[16];
    if (adLen) {
        memset(ad, 33, adLen);
    }
    memset(tag, 0, tagLen);

    int u   = i;
    keybits = 128 + u * 64;
    printf(" keybits %d ", keybits);
    int nr;
    memset(key, ((i * 10) + m), 32);

    memset(inputText, i, inputLen);

    /*  Generate random input text based on seed.
        seed is kept constant(1) for simplicity, it can be
        modified for testing. */
    int seed = 1;
    getinput(inputText, inputLen, seed);

    memset(cipherText, 0, inputLen);
    memset(ref, 0, inputLen);
    memset(outputText, 0, inputLen);

    create_aes_session(key, iv, keybits, m);

    // same inputText, cipherText and outputText buffer is used multiple times
    // to measure speed, so inputText and outputText after decrypt will not
    // match.
    aclp_aes_gcm_encrypt_demo(inputText,
                              inputLen,
                              cipherText,
                              iv,
                              ivLen,
                              ad,
                              adLen,
                              tag,
                              tagLen,
                              key,
                              keybits);

    aclp_aes_gcm_decrypt_demo(
        cipherText, inputLen, outputText, iv, ivLen, ad, adLen, tag, tagLen);

    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);
    free(handle.ch_context);

    if (outputText) {
        free(outputText);
    }
    if (iv) {
        free(iv);
    }
    if (ref) {
        free(ref);
    }
    if (ad) {
        free(ad);
    }

    return 0;
}

#define MAX_TEST_CASE 7

int
runGCMSpeedTest()
{
    Uint8* inputText;
    Uint8* cipherText;

    /*
     * Demo application to demonstrate GCM performance for different key and
     * input block sizes.
     */

    printf("\n AOCL-CRYPTO: AES-GCM speed test application \n");

    int testblkSizes[MAX_TEST_CASE] = { 16, 64, 256, 1024, 8192, 16384, 32768 };

    for (int keySizeItr = 0; keySizeItr < 3; keySizeItr++) {

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
                ALC_AES_MODE_GCM,
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
    return 0;
}

int
main(void)
{
    // Run GCM speed test
    return runGCMSpeedTest();
}