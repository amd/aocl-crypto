#include <stdint.h>
#include <stdlib.h> /* for malloc */

#include "alcp/alcp.h"

void
encrypt_demo(const uint8_t* plaintxt,
             const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
             uint8_t*       ciphertxt,
             uint8_t*       key,
             uint8_t*       iv,
             const uint32_t key_len)
{
    alc_error_t       err;
    alc_cipher_ctx_t* ctx;
    const int         err_size = 256;
    uint8_t           err_buf[err_size];

    alc_aes_mode_data_t aes_data = {
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
    const alc_cipher_info_t cinfo = {
        .type        = ALC_CIPHER_TYPE_AES,
        .data   = {
            .aes = aes_data,
        },
        //.pad     = ALC_CIPHER_PADDING_NONE,  /* No padding , Not Implemented yet*/
        .keyinfo     = {
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
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    /*
     * Application is expected to allocate for context
     */
    ctx = malloc(alcp_cipher_ctx_size(&cinfo));
    if (!ctx)
        return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, ctx);
    if (alcp_is_error(err)) {
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    err = alcp_cipher_encrypt(ctx, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    /*
     * Complete the transaction
     */
    alcp_cipher_finish(ctx);

    free(ctx);
}

int
main(void)
{
    return 0;
}

