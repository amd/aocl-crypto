#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* for malloc */

#include "alcp/alcp.h"

void
decrypt_demo(const uint8_t* ciphertxt,
             const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
             uint8_t*       plaintxt,
             uint8_t*       key,
             uint8_t*       iv,
             const uint32_t key_len)
{
    alc_error_t         err;
    alc_cipher_handle_t handle;
    const int           err_size = 256;
    uint8_t             err_buf[err_size];

    alc_aes_info_t aes_data = {
        .mode = ALC_AES_MODE_CFB,
        .iv   = iv,
    };

    /*
    const alc_key_info_t kinfo = {
        .type    = ALC_KEY_TYPE_SYMMETRIC,
        .fmt     = ALC_KEY_FMT_RAW,
        .key     = key,
        .len     = key_len,
    };
    */
    alc_cipher_info_t cinfo = {
        .cipher_type = ALC_CIPHER_TYPE_AES,
        .mode_data   = {
            .aes = aes_data,
        },
        /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .key_info     = {
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
    // ctx = malloc(alcp_cipher_context_size(&cinfo));
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
    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, key, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    printf("decrypt succeeded\n");
    /*
     * Complete the transaction
     */
    alcp_cipher_finish(&handle);

    // free(ctx);
}

char*   sample_plaintxt = "Hello world from AOCL Crypto";
uint8_t sample_key[]    = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

uint8_t sample_iv[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

uint8_t sample_ciphertxt[] = { 0x18, 0xbd, 0x68, 0x25, 0x31, 0x11, 0x07,
                               0x1e, 0x90, 0x40, 0x32, 0xe6, 0x1f, 0x48,
                               0x16, 0x12, 0xa3, 0x85, 0xcd, 0xe6, 0x0e,
                               0x53, 0x63, 0x31, 0x7b, 0x68, 0x36, 0xee };

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
    uint8_t sample_output[512];

    decrypt_demo(
        sample_ciphertxt,
        sizeof(sample_ciphertxt), /* len of both 'plaintxt' and 'ciphertxt' */
        sample_output,
        sample_key,
        sample_iv,
        sizeof(sample_key));

    return 0;
}

/*  LocalWords:  decrypt Crypto AOCL
 */
