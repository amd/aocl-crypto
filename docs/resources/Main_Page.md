
# Welcome to AOCL-Crypto

<b>AOCL-Crypto</b> is a library consisting of basic cryptographic functions optimized  tuned and for AMD Zen™ based microarchitecture. This library provides a unified solution for Cryptographic Alogrithm and has multiple implementations of different AES cryptographic encryption / decryption and SHA2, SHA3 Digest routines and Message Authentication Code.

---

## Table of Content
    - [Introduction](#Introduction)
    - [Build and Installation](#Build)
    - [Examples](#Example)
    - [Contact Us](#Contact)


<a name = "Introduction"></a>

## Introduction

<b> AOCL Crypto </b> supports a dynamic dispatcher feature that executes the most optimal function variant implemented using Function Multi-versioning thereby offering a single optimized library portable across different x86 CPU architectures. 
AOCL Crypto framework is developed in C / C++ for Unix and Windows based systems. A test suite is provided for validation and performance benchmarking for the supported Ciphers, Digest and MAC APIs. The test suite also supports the benchmarking of IPP and Openssl different methods like AES cryptographic encryption / decryption, SHA2, SHA3 and other algorithms. Below are details of AOCL Crypto APIs and Supports

### Cipher   

```
 
AES 
    
    AES Encrypt / Decrypt routines which will support the following cipher schemes:
        -  CBC, CFB, OFB, CTR, GCM, XTS, CCM.
```
-   click to know about more about [AOCL - AES API](group__cipher.html)

### Digest

```

SHA2

    Digest routines for the following schemes:
        - SHA2_224, SHA2_256, SHA2_384, SHA2_512

SHA3

    Digest routines for the following schemes:
        - SHA3_224, SHA3_256, SHA3_384, SHA3_512    
```

- Click to know more about [AOCL DIGEST API](group__digest.html)


### Message Authentication Code

```

HMAC 

    MAC routines for the following schemes:
        - HMAC_SHA2_224, HMAC_SHA2_256, HMAC_SHA2_384, HMAC_SHA2_512
        - HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512
```

- Click to know more about [AOCL MAC API](group__mac.html)

<a name = "Build"></a>

## Build and Installation

To Build AOCL-Crypto for Different Platform Please refer to Document Related your Platform
    - [ Notes for Unix-related Platform  ](md_BUILD.html)
    - [ Notes for Windows Platform  ](md_BUILD_Windows.html)

<a name = "Example"></a>

## Example

Here is a Demo Code Example on how to use Cipher:

```c

void
encrypt_demo(const uint8_t *plaintxt,
             const uint32_t len,  /* Describes both 'plaintxt' and 'ciphertxt' */
             uint8_t       *ciphertxt,
             const uint8_t *key,
             const uint32_t key_len)
{
    alc_error_t             err;
    alc_cipher_context_t   *ctx;

    
    const alc_key_info_t kinfo = {
        .type    = ALC_KEY_TYPE_SYMMETRIC,
        .fmt     = ALC_KEY_FMT_RAW,
        .key     = key,
        .len     = (key_len == 128)? ALC_KEY_LEN_128 : ALC_KEY_LEN_256,
    };

    const alc_cipher_info_t cinfo = {
        .algo    = ALC_CIPHER_ALGO_AES,
        .mode    = ALC_CIPHER_MODE_CBC,
        .pad     = ALC_CIPHER_PADDING_NONE,  /* No padding */
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
    if (alcp_is_error(err)) {
        alcp_error_str(err);
        return;
    }

    /*
    * Application is expected to allocate for context
    */
    ctx = malloc(alcp_cipher_ctx_size(&cinfo));
    if (!ctx)
        return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &kinfo, ctx);
    if (alcp_is_error(err)) {
        alcp_error_str(err);
        return;
    }

    /* Cipher mode specific data */
    alc_cipher_mode_data_t data = {
        .mode = ALC_CIPHER_MODE_CBC,
        .cbc = {.iv = IV,},
    };

    err = alcp_cipher_encrypt(&ctx, plaintxt, len, ciphertxt, &data);
    if (alcp_is_error(err)) {
        alcp_error_str(err);
        return;
    }

    /*
    * Complete the transaction
    */
    alcp_cipher_finish(&ctx);

}

```

<a name = "Contact"></a>

## CONTACTS

AOCL Crypto is developed and maintained by AMD. You can contact us on the email-id aoclsupport@amd.com.