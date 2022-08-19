#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* for malloc */
#include <string.h>

#include "alcp/alcp.h"

#ifdef DEBUG
#define ALC_PRINT(a, size)                                                     \
    for (int x = 0; x < size; x++) {                                           \
        if (x % 16 == 0)                                                       \
            printf("\n0x%x0 - ", (x / 16));                                    \
        printf(" %2x ", (a)[x]);                                               \
    }                                                                          \
    printf("\n");
#else
#define ALC_PRINT(a, size)
#endif

static alc_cipher_handle_t handle;

void
create_demo_session(const uint8_t* key,
                    const uint8_t* tweak_key,
                    const uint8_t* iv,
                    const uint32_t key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = tweak_key,
        .len  = key_len,
    };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
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
    printf("supported succeeded\n");
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
    printf("request succeeded\n");
}

void
encrypt_demo(const uint8_t* plaintxt,
             const uint32_t len, /*  for both 'plaintxt' and 'ciphertxt' */
             uint8_t*       ciphertxt,
             const int8_t*  iv)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    printf("encrypt succeeded\n");
}

void
decrypt_demo(const uint8_t* ciphertxt,
             const uint32_t len, /* for both 'plaintxt' and 'ciphertxt' */
             uint8_t*       plaintxt,
             const uint8_t* iv)
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

    printf("decrypt succeeded\n");
}

// static char* sample_plaintxt = "Hello World from AOCL Crypto !!!";
static char* sample_plaintxt =
    "A paragraph is a series of sentences that are organized and coherent, and "
    "are all related to a single topic. Almost every piece of writing you do "
    "that is longer than a few sentences should be organized into paragraphs.";

static const uint8_t sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

static const uint8_t sample_tweak_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf,
};

static const uint8_t sample_iv[] = {
    0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};

#if 0
/*
 * Encrypted text of "Hello World from AOCL Crypto !!!"
 * with key = {00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f};
 * with iv = {00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f};
 */

static uint8_t cipher = {68,cc,95,fe,db,6c,0c,87,76,73,98,fc,0a,dc,f6,07,9e,33,17,75,ad,0a,eb,27,66,29,f3,9e,b6,8d,1f,05};
#else
static uint8_t sample_ciphertxt[1000] = {
    0,
};
#endif

#define BITS_PER_BYTE 8

int
alloc_and_test()
{
    void *    plaintxt, *ciphertxt, *output;
    const int keylen = 256, keylen_bytes = keylen / 8,
              keylen_words = keylen / sizeof(uint32_t) * BITS_PER_BYTE;

    uint8_t  key[keylen_bytes];
    uint32_t iv[] = {
        0x1,
        0x2,
        0x3,
        0x4,
    };

    assert(keylen_words == sizeof(iv));

    /* TODO: get this through command line */
    int buf_len = 1024 * 1024; /* Length of 1 buffer */
    int num_buf = 1;           /* number of buffers of length 'buf_len' */

    plaintxt = calloc(buf_len, num_buf);
    if (!plaintxt)
        goto out;

    ciphertxt = calloc(buf_len, num_buf);
    if (!ciphertxt)
        goto free_plaintxt_out;

    output = calloc(buf_len, num_buf);
    if (!output)
        goto free_ciphertxt_out;

free_ciphertxt_out:
    free(ciphertxt);

free_plaintxt_out:
    free(plaintxt);

out:
    return 0;
}

int
main(void)
{
    uint8_t sample_output[1000] = { 0 };

    int pt_size = strlen(sample_plaintxt);
    assert(sizeof(sample_plaintxt) < sizeof(sample_output));

    create_demo_session(
        sample_key, sample_tweak_key, sample_iv, sizeof(sample_key) * 8);

#ifdef DEBUG
    printf("plain text : \n");
    ALC_PRINT(((uint8_t*)sample_plaintxt), pt_size);
#endif
    encrypt_demo(sample_plaintxt,
                 pt_size, /* len of 'plaintxt' and 'ciphertxt' */
                 sample_ciphertxt,
                 sample_iv);
#ifdef DEBUG
    printf("cipher text : \n");
    ALC_PRINT(((uint8_t*)&sample_ciphertxt), pt_size);
#endif
    decrypt_demo(sample_ciphertxt, pt_size, sample_output, sample_iv);
#ifdef DEBUG
    printf("out text : \n");
    ALC_PRINT(((uint8_t*)&sample_output), pt_size);
#endif
    printf("sample_output: %s\n", sample_output);
    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    return 0;
}

/*  LocalWords:  decrypt Crypto AOCL
 */
