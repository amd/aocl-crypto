#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* for malloc */
#include <string.h>
#include <sys/time.h>
#ifdef WIN32
#include <Windows.h>
#endif

#include <immintrin.h>
#include <wmmintrin.h>

#include "alcp/alcp.h"

static alc_cipher_handle_t handle;

#define SPEED_CHECK 1

//#define DEBUG_P /* Enable for debugging only */

/*
    debug prints to be print input, cipher, iv and decrypted output
*/
#ifdef DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("\n %s", S);                                                        \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %2x", I[x]);                                                  \
    }
#else // DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)
#endif // DEBUG_P

// to do: these macro is better to be moved to common header.
#define ALCP_CRYPT_TIMER_INIT struct timeval begin, end;
long   seconds;
long   microseconds;
double elapsed;
double totalTimeElapsed;

#define ALCP_CRYPT_TIMER_START gettimeofday(&begin, 0);

#define ALCP_CRYPT_GET_TIME(X, Y)                                              \
    gettimeofday(&end, 0);                                                     \
    seconds      = end.tv_sec - begin.tv_sec;                                  \
    microseconds = end.tv_usec - begin.tv_usec;                                \
    elapsed      = seconds + microseconds * 1e-6;                              \
    totalTimeElapsed += elapsed;                                               \
    if (X) {                                                                   \
        printf("\t" Y);                                                        \
        printf(" %2.2f ms ", elapsed * 1000);                                  \
    }

void
getinput(uint8_t* output, int inputLen, int seed)
{
    // generate same random input based on seed value.
    srand(seed);
    for (int i = 0; i < inputLen; i++) {
        *output = (uint8_t)rand();
        output++;
    }
}

void
create_aes_session(uint8_t*             key,
                   uint8_t*             iv,
                   const uint32_t       key_len,
                   const alc_aes_mode_t mode)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    alc_aes_info_t aes_data = {
        .ai_mode = mode,
        .ai_iv   = iv,
    };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_mode_data   = {
            .cm_aes = aes_data,
        },
        /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = key,
            .len     = key_len,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/* AES modes: Encryption Demo */
void
aclp_aes_encrypt_demo(
    const uint8_t* plaintxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       ciphertxt,
    uint8_t*       iv)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/* GCM: Authenticated Encryption demo */
void
aclp_aes_gcm_encrypt_demo(
    const uint8_t* plaintxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       ciphertxt,
    uint8_t*       iv,
    const uint32_t ivLen,
    uint8_t*       ad,
    const uint32_t adLen,
    uint8_t*       tag,
    const uint32_t tagLen)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    // GCM init
    err = alcp_cipher_encrypt_update(&handle, NULL, NULL, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // Additional Data
    err = alcp_cipher_encrypt_update(&handle, plaintxt, NULL, adLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // GCM encrypt
    err = alcp_cipher_encrypt_update(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // get tag
    err = alcp_cipher_encrypt_update(&handle, NULL, tag, tagLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

void
aclp_aes_decrypt_demo(
    const uint8_t* ciphertxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       plaintxt,
    uint8_t*       iv)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/* GCM: Authenticated Decryption demo */
void
aclp_aes_gcm_decrypt_demo(const uint8_t* ciphertxt,
                          const uint32_t len,
                          uint8_t*       plaintxt,
                          uint8_t*       iv,
                          const uint32_t ivLen,
                          uint8_t*       ad,
                          const uint32_t adLen,
                          uint8_t*       tag,
                          const uint32_t tagLen)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];
    uint8_t     tagDecrypt[16];

    // GCM init
    err = alcp_cipher_decrypt_update(&handle, NULL, NULL, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm decrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // Additional Data
    err = alcp_cipher_decrypt_update(&handle, plaintxt, NULL, adLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // GCM decrypt
    err = alcp_cipher_decrypt_update(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    // get tag
    err = alcp_cipher_decrypt_update(&handle, NULL, tagDecrypt, tagLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    bool isTagMatched = true;

    for(int i =0; i<tagLen; i++)
    {
        if(tagDecrypt[i]!=tag[i])
        {
            isTagMatched = isTagMatched & false;
        }
    }

    if(isTagMatched==false)
    {
        printf("\n tag mismatched, input encrypted data is not trusthworthy ");
        memset(plaintxt,0,len);
    }

}

/*    GCM Encrypt test vector
 *    Test vector from gcmEncryptExtIV128.rsp file in below path
 *    http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 *
 */
static unsigned char test_key[16] = { 0xc7, 0x51, 0x16, 0xc1, 0x9f, 0x5e,
                                      0xa4, 0xed, 0x1b, 0x10, 0xbf, 0x0e,
                                      0xaa, 0xeb, 0xe5, 0xa1 };
static unsigned char test_iv[12]  = { 0x48, 0xa5, 0x3f, 0xc1, 0x7d, 0x43,
                                     0x00, 0xf4, 0xa2, 0x3a, 0x5a, 0x39 };
static unsigned char test_pt[32]  = { 0x45, 0x69, 0x94, 0x4f, 0xcd, 0xe5, 0xb3,
                                     0xf4, 0xae, 0x4d, 0x50, 0xeb, 0x7a, 0x0e,
                                     0x3e, 0xf8, 0x8d, 0xab, 0x44, 0xb6, 0x84,
                                     0xc7, 0x37, 0xb9, 0x0a, 0xa8, 0x8c, 0xf5,
                                     0x79, 0xbf, 0x05, 0x58 };
static unsigned char test_ct[32]  = { 0xd5, 0x8b, 0x89, 0x30, 0x0c, 0x62, 0xe0,
                                     0xb0, 0xea, 0x72, 0x9d, 0x6d, 0xe3, 0x95,
                                     0x45, 0xea, 0x35, 0xdd, 0xc5, 0xa0, 0x4e,
                                     0x22, 0xb7, 0x09, 0xf4, 0x5a, 0xf5, 0x32,
                                     0xbc, 0x67, 0xd9, 0x0d };
static unsigned char test_tag[14] = {
    0xc4, 0x28, 0xab, 0xd4, 0xbf, 0x85, 0x46,
    0x8d, 0x57, 0x23, 0x6e, 0xd1, 0x6d, 0x36
};

#define VERIFY_GCM_TEST_VECTOR 0

/*
    Demo application for complete path:
    input->encrypt->cipher->decrypt->output.
    input and output is matched for comparison.

*/
int
encrypt_decrypt_demo(uint8_t*       inputText,  // plaintext
                     uint32_t       inputLen,   // input length
                     uint8_t*       cipherText, // ciphertext output
                     alc_aes_mode_t m)
{
    unsigned int keybits;
    uint8_t      key[32];
    int          ret = 0;

    memset(key, 0, 32);

    uint8_t* outputText;
    outputText = malloc(inputLen);

    uint8_t* iv;
    iv = malloc(16 * 4);
    memset(iv, 0, 16 * 4);

    uint8_t* ref;
    ref = malloc(inputLen);

    /* additional data, tag used in GCM */

    uint32_t ivLen  = 12;
    uint32_t adLen  = 0; // 16;
    uint32_t tagLen = 16;
    uint8_t* ad     = malloc(adLen);
    uint8_t  tag[16];
    if (adLen) {
        memset(ad, 33, adLen);
    }
    memset(tag, 0, tagLen);

    for (int i = 0; i < 1; i++) { // limit the test to 128bit.
        // for (int i = 0; i < 3; i++) {
        int u   = i;
        keybits = 128 + u * 64;
        printf("\n keybits %d ", keybits);
        int nr;
        memset(key, ((i * 10) + m), 32);

        memset(inputText, i, inputLen);

        /*  Generate random input text based on seed.
            seed is kept constant(1) for simplicity, it can be
            modified for testing. */
        int seed = 1;
        getinput(inputText, inputLen, seed);
        if (m == ALC_AES_MODE_GCM) {
#if VERIFY_GCM_TEST_VECTOR
            /* Verify gcm encrypt with sample test vector */
            if (inputLen >= 32)
                inputLen = 32;
            memcpy(inputText, test_pt, inputLen);
#endif
            memcpy(key, test_key, 16);
            memcpy(iv, test_iv, 12);
        }
        memset(cipherText, 0, inputLen);
        memset(ref, 0, inputLen);
        memset(outputText, 0, inputLen);
        ALCP_PRINT_TEXT(key, 32, "key      ")
        ALCP_PRINT_TEXT(inputText, inputLen, "inputText")
        ALCP_PRINT_TEXT(iv, 16, "iv       ")

        ALCP_CRYPT_TIMER_INIT
        create_aes_session(key, iv, keybits, m);

#if SPEED_CHECK
        totalTimeElapsed = 0.0;
        for (int k = 0; k < 100000000; k++) {
#endif
            //
            ALCP_CRYPT_TIMER_START

            if (m != ALC_AES_MODE_GCM) {
                aclp_aes_encrypt_demo(inputText, inputLen, cipherText, iv);
            } else {
                aclp_aes_gcm_encrypt_demo(inputText,
                                          inputLen,
                                          cipherText,
                                          iv,
                                          ivLen,
                                          ad,
                                          adLen,
                                          tag,
                                          tagLen);

                ALCP_PRINT_TEXT(tag, tagLen, "tagEnc   ")
            }
#if SPEED_CHECK
            ALCP_CRYPT_GET_TIME(0, "Encrypt time")
#else
            ALCP_CRYPT_GET_TIME(1, "Encrypt time")
#endif
            ALCP_PRINT_TEXT(cipherText, inputLen, "cipherTxt")

#if SPEED_CHECK
            if (totalTimeElapsed > .5) {
                printf("\t :  %6.3lf GB Encrypted per second with block size "
                       "(%5d bytes) ",
                       (double)(((k / 1000.0) * inputLen)
                                / (totalTimeElapsed * 1000000.0)),
                       inputLen);
                break;
            }
        }
#endif

#if SPEED_CHECK
        totalTimeElapsed = 0.0;
        for (int k = 0; k < 100000000; k++) {
#endif
            ALCP_CRYPT_TIMER_START
            if (m != ALC_AES_MODE_GCM) {
                aclp_aes_decrypt_demo(
                    cipherText, // pointer to the PLAINTEXT
                    inputLen,   // text length in bytes
                    outputText, // pointer to the CIPHERTEXT buffer
                    iv);
            } else {
                aclp_aes_gcm_decrypt_demo(cipherText,
                                          inputLen,
                                          outputText,
                                          iv,
                                          ivLen,
                                          ad,
                                          adLen,
                                          tag,
                                          tagLen);
                ALCP_PRINT_TEXT(tag, tagLen, "tagDec   ")
            }

#if SPEED_CHECK
            ALCP_CRYPT_GET_TIME(0, "Decrypt time")
#else
            ALCP_CRYPT_GET_TIME(1, "Decrypt time")
#endif
            ALCP_PRINT_TEXT(outputText, inputLen, "outputTxt")

#if SPEED_CHECK
            if (totalTimeElapsed > .5) {
                printf("\t :  %6.3lf GB Decrypted per second with block size "
                       "(%5d bytes) ",
                       (double)(((k / 1000.0) * inputLen)
                                / (totalTimeElapsed * 1000000.0)),
                       inputLen);
                break;
            }
        }
#endif

        if (memcmp(inputText, outputText, (long unsigned int)inputLen) != 0) {
            printf("\n\t\t\t\t input->enc->dec->input FAILED \n");
        } else {
            // printf("\t input->encrypt&decrypt->input::Passed");
        }
        /*
         * Complete the transaction
         */
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
    }

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

int
main(void)
{
    uint8_t* inputText;
    uint8_t* cipherText;

    /*
     * Demo application validates complete encrypt and decrypt path
     * input feed to encrypt and output from encrypt are compared and validated.
     */

    printf("\n AOCL-CRYPTO: AES Demo application ");

    for (alc_aes_mode_t m = ALC_AES_MODE_ECB; m < ALC_AES_MODE_MAX; m++) {

        if (m == ALC_AES_MODE_ECB) {
            printf("\n\nAES-ECB not implemented");
            continue;
        } else if (m == ALC_AES_MODE_CBC) {
            printf("\n\nAES-CBC");
        } else if (m == ALC_AES_MODE_OFB) {
            printf("\n\nAES-OFB");
        } else if (m == ALC_AES_MODE_CTR) {
            printf("\n\nAES-CTR");
        } else if (m == ALC_AES_MODE_CFB) {
            printf("\n\nAES-CFB");
        } else if (m == ALC_AES_MODE_XTR) {
            printf("\n\nAES-XTR not implemented\n");
            continue;
        } else if (m == ALC_AES_MODE_GCM) {
            printf("\n\nAES-GCM\n");
        } else {
            printf("\n Invalid AES mode");
            continue;
        }

        // keep length multiple of 128bit (16x8)
#if SPEED_CHECK
        int inputLen = 16;
#else
        int inputLen = 16384;
        printf(" :Encrypt and decrypt demo with input length %d bytes",
               inputLen);
#endif
        for (; inputLen <= 16384; inputLen = (inputLen * 4)) {

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
                m);

            // its time to free!
            if (inputText) {
                free(inputText);
            }
            if (cipherText) {
                free(cipherText);
            }
        }
    }

    return 0;
}
