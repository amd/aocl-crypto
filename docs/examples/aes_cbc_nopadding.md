# AES Encryption
## CBC Mode

Following code demonstrate an usage of AOCL Crypto APIs to perform AES
Encryption using CBC Mode and no-padding.

```c
void
encrypt_demo(const uint8_t *plaintxt,
             const uint32_t len,  /* Describes both 'plaintxt' and 'ciphertxt' */
             uint8_t       *ciphertxt,
             const uint8_t *key,
             const uint32_t key_len)
{
    alc_error_t     err;
    alc_context_t   ctx = ALC_CIPHER_INIT_CONTEXT();

    const alc_key_info_t kinfo = {
        .type    = ALC_KEY_TYPE_SYMMETRIC,
        .fmt     = ALC_KEY_FMT_RAW,
        .key     = key,
        .len     = (key_len == 128)? ALC_KEY_LEN_128 : ALC_KEY_LEN_256,
    };

    const alc_cipher_info_t cinfo = {
        .algo    = ALC_CIPHER_AES,
        .mode    = ALC_CIPHER_MODE_CBC,
        .pad     = ALC_PADDING_NONE,
        .keyinfo = kinfo,
    };

    /*
    * Check if the current cipher is supported,
    * optional call, alcp_cipher_request() will anyway return
    * ALC_ERR_NOSUPPORT error.
    *
    * This query call is provided to support fallback mode for applications
    */
    err = alcp_cipher_supported(&cinfo);
    if (alc_is_error(err)) {
        alc_error_str(err);
        return;
    }

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &kinfo, &ctx);
    if (alc_is_error(err)) {
        alc_error_str(err);
        return;
    }

    /* Cipher mode specific data */
    alc_cipher_mode_data_t data = {
        .mode = ALC_CIPHER_MODE_CBC,
        .cbc = {.iv = IV,},
    };

    err = alcp_cipher_encrypt(&ctx, plaintxt, len, ciphertxt, &data);
    if (alc_is_error(err)) {
        alc_error_str(err);
        return;
    }

    /*
    * Complete the transaction
    */
    alcp_cipher_finish(&ctx);

}
```
