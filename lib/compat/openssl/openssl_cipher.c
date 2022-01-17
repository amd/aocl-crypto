
#include <stdio.h>
#include <malloc.h>
#include <stdint.h>
#include <alcp/alcp.h>
#include <openssl/obj_mac.h>
// #undef DEBUG

typedef struct evp_cipher_st {
    int nid;
} EVP_CIPHER ;

typedef struct wrapper_contxt {
    int                 enc;
    alc_cipher_handle_t handle;
    alc_cipher_info_t   cinfo;
    EVP_CIPHER        * cipher;
    uint8_t           * iv;
    uint8_t           * key;
} EVP_CIPHER_CTX, *wrapper_contxt_p, wrapper_contxt_t;

alc_aes_mode_t get_cipher_mode(int nid)
{
    switch(nid)
    {
        case NID_aes_128_cfb8:
        case NID_aes_128_cfb1:
        case NID_aes_128_cfb128:
        case NID_aes_192_cfb8:
        case NID_aes_192_cfb1:
        case NID_aes_192_cfb128:
        case NID_aes_256_cfb8:
        case NID_aes_256_cfb1:
        case NID_aes_256_cfb128:
            return ALC_AES_MODE_CFB;
        case NID_aes_128_ctr:
        case NID_aes_192_ctr:
        case NID_aes_256_ctr:
            return ALC_AES_MODE_CTR;
        case NID_aes_128_ocb:
        case NID_aes_192_ocb:
        case NID_aes_256_ocb:
            return 0; // Unsupported
            //return ALC_AES_MODE_OCB;
        case NID_aes_128_ofb128:
        case NID_aes_192_ofb128:
        case NID_aes_256_ofb128:
            return 0; // Unsupported
            //return ALC_AES_MODE_OFB;
        case NID_aes_128_cbc:
        case NID_aes_192_cbc:
        case NID_aes_256_cbc:
            return ALC_AES_MODE_CBC;
        case NID_aes_128_ecb:
        case NID_aes_192_ecb:
        case NID_aes_256_ecb:
            return ALC_AES_MODE_ECB;
    }
    return 0; // Unsupported
}

int get_key_len(int nid)
{
    switch(nid)
    {
        case NID_aes_128_cfb8:
        case NID_aes_128_cfb1:
        case NID_aes_128_cfb128:
        case NID_aes_128_ctr:
        case NID_aes_128_ocb:
        case NID_aes_128_cbc:
        case NID_aes_128_ecb:
            return 128;
        case NID_aes_192_cfb8:
        case NID_aes_192_cfb1:
        case NID_aes_192_cfb128:
        case NID_aes_192_ctr:
        case NID_aes_192_ocb:
        case NID_aes_192_cbc:
        case NID_aes_192_ecb:
            return 192;
        case NID_aes_256_cfb8:
        case NID_aes_256_cfb1:
        case NID_aes_256_cfb128:
        case NID_aes_256_ctr:
        case NID_aes_256_ocb:
        case NID_aes_256_cbc:
        case NID_aes_256_ecb:
            return 256;
    }
    return 0; // Unsupported
}

typedef void ENGINE; // No need for engine as of now.

int alcp_create_handle_aes(wrapper_contxt_p wrapper){
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];
    uint8_t    *iv = wrapper->iv;
    uint8_t    *key = wrapper->key;
    int key_len = 0;

    key_len = get_key_len(wrapper->cipher->nid);

    alc_aes_info_t aes_data = {
        .mode = get_cipher_mode(wrapper->cipher->nid),
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
        printf("Wrapper: Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return 0; // Error
    }
    #ifdef DEBUG
    printf("Wrapper: supported succeeded\n");
    #endif
    /*
     * Application is expected to allocate for context
     */
    wrapper->handle.context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &(wrapper->handle));
    if (alcp_is_error(err)) {
        printf("Wrapper: Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return 0; // Error
    }
    wrapper->cinfo=cinfo;
    #ifdef DEBUG
    printf("Wrapper: request succeeded\n");
    #endif
    return 1; // No Error
}

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void){
    // Memory will be allocated which user (application programmer) has to keep.
    return malloc(sizeof(EVP_CIPHER_CTX));
}

/* CFB Cipher Generation wrapper functions */
const EVP_CIPHER *EVP_aes_128_cfb128(void){
    EVP_CIPHER *evp = malloc(sizeof(EVP_CIPHER));
    evp->nid=NID_aes_128_cfb128;
    return evp;
}

const EVP_CIPHER *EVP_aes_192_cfb128(void){
    EVP_CIPHER *evp = malloc(sizeof(EVP_CIPHER));
    evp->nid=NID_aes_192_cfb128;
    return evp;
}

const EVP_CIPHER *EVP_aes_256_cfb128(void){
    EVP_CIPHER *evp = malloc(sizeof(EVP_CIPHER));
    evp->nid=NID_aes_256_cfb128;
    return evp;
}

/* CBC Cipher Generation wrapper functions */
const EVP_CIPHER *EVP_aes_128_cbc(void){
    EVP_CIPHER *evp = malloc(sizeof(EVP_CIPHER));
    evp->nid=NID_aes_128_cbc;
    return evp;
}

const EVP_CIPHER *EVP_aes_192_cbc(void){
    EVP_CIPHER *evp = malloc(sizeof(EVP_CIPHER));
    evp->nid=NID_aes_192_cbc;
    return evp;
}

const EVP_CIPHER *EVP_aes_256_cbc(void){
    EVP_CIPHER *evp = malloc(sizeof(EVP_CIPHER));
    evp->nid=NID_aes_256_cbc;
    return evp;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    return 1;
}


int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    if(cipher==NULL){
        #ifdef DEBUG
        printf("Wrapper: Warning Cipher is NULL! Still giving green flag!!!!\n");
        #endif
        //getchar();
        return 1;
    }
    ctx->enc    = enc;
    ctx->cipher = (EVP_CIPHER *) cipher;
    ctx->key    = (unsigned char *) key;
    ctx->iv     = (unsigned char *) iv;
    switch(cipher->nid){
        case NID_aes_128_cfb128:
        case NID_aes_192_cfb128:
        case NID_aes_256_cfb128:
            alcp_create_handle_aes(ctx);
            break;
        default:
            // Error may be set to CBC
            break;
    }
    return 1;
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                        const EVP_CIPHER *cipher, ENGINE *impl,
                        const unsigned char *key,
                        const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
}

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl){
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    if(!ctx->enc){
        // Using wrong mode, its in decrypt mode but trying to encrypt
        return 0; // Some error code of openssl has to replace this
    }

    err = alcp_cipher_encrypt(&(ctx->handle), in, out, inl, ctx->iv);
    if (alcp_is_error(err)) {
        printf("Wrapper: Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return 0; // Error
    }
    *outl = inl;
    #ifdef DEBUG
    printf("Wrapper: Encrypt Success\n");
    #endif
    return 1; // No Error
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      int *outl, const unsigned char *in, int inl){
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    err = alcp_cipher_decrypt(&(ctx->handle), in, out, inl, ctx->iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return 0; //Error
    }
    *outl = inl;
    #ifdef DEBUG
    printf("Wrapper: Decrypt Success\n");
    #endif
    return 1;
}


void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u)
{
    // Do northing for now..
    return;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl){
    // Northing to be done as of now...
    *outl=0;
    return 1;
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl){
    // Northing to be done as of now...
    *outl=0;
    return 1;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx){
    alcp_cipher_finish(&(ctx->handle));
    free((void *)(ctx->handle.context));
    free((void *)ctx);
}

int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx){
    #ifdef DEBUG
    printf("Wrapper: Keylength querry value:%d\n",ctx->cinfo.key_info.len);
    #endif
    //getchar();
    return ctx->cinfo.key_info.len;
}

int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)
{
    // Do northing for now
    #ifdef DEBUG
    printf("Wrapper: EVP_CIPHER_CTX_rand_key\n");
    #endif
    return 1;
}

