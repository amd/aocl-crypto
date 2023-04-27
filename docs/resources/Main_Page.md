
# Welcome to AOCL-Crypto

**AOCL-Crypto** is a library consisting of basic cryptographic functions optimized and tuned for AMD Zen™ based microarchitecture. This library provides a unified solution for Cryptographic routines such as AES Cipher ( CFB, CTR, CBC, CCM, GCM, OFB, SIV, XTS ), SHA Digest ( SHA2, SHA3, SHAKE ), Message Authentication Code ( CMAC, HMAC ), Elliptical Curve ( ecdhx25519 ), Rivest-Shamir-Adleman ( Public key Encrypt, private key decrypt ) etc ...

---

## Table of Content
    * [Introduction](#Introduction)
    * [Build and Installation](#Build)
    * [Examples](#Example)
    * [Contact Us](#Contact)


<div id="Introduction" name="Introduction"></div>

## Introduction

<b> AOCL Crypto </b> supports a dynamic dispatcher feature that executes the most optimal function variant implemented using Function Multi-versioning thereby offering a single optimized library portable across different x86 CPU architectures. 
AOCL Crypto framework is developed in C / C++ for Unix and Windows based systems. A test suite is provided for validation and performance benchmarking for the supported Ciphers, Digest and MAC APIs. The test suite also supports the benchmarking of IPP and Openssl different methods like AES cryptographic encryption / decryption, SHA2, SHA3 and other algorithms. Below are details of AOCL Crypto APIs and Supports

### Cipher   

```
 
AES 
    
    AES Encrypt / Decrypt routines which will support the following cipher schemes:
        -  CBC, CFB, OFB, CTR, GCM, XTS, CCM, SIV.
```
-   Click to know about more about [AOCL - AES API](group__cipher.html)

### Digest

```

SHA2

    Digest routines for the following schemes:
        - SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256

SHA3

    Digest routines for the following schemes:
        - SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE_128, SHAKE_256    
```

- Click to know more about [AOCL DIGEST API](group__digest.html)


### Elliptic curve

```

EC 

    EC routines for the following schemes:
        - SHORT_WEIERSTRASS , MONTGOMERY

```

- Click to know more about [AOCL EC API](group__ec.html)


### Message Authentication Code

```

HMAC 

    MAC routines for the following schemes:
        - HMAC_SHA2_224, HMAC_SHA2_256, HMAC_SHA2_384, HMAC_SHA2_512
        - HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512

CMAC 

    MAC routines for the following schemes:
        - CMAC - AES (for key size 128,192 and 256)
```

- Click to know more about [AOCL MAC API](group__mac.html)

### Rivest-Shamir-Adleman (RSA)

```

RSA

    - Encrypt text with public key
    - Decrypt text with private Key

```

- Click to know more about [AOCL RSA API](group__rsa.html)


<div id = "Build" name="Build"></div>

## Build and Installation

To Build AOCL-Crypto for Different Platform Please refer to Document Related your Platform
    - [ Linux ](md_Combine_build.html#md_BUILD)
    - [ Windows  ](md_Combine_build.html#md_BUILD_Windows)

<div id = "Example"></div>

## Example

Here is a Demo Code Example on how to use Cipher:

\include{lineno} cipher/aes-cfb.c 

<div id = "Contact"></div>

## CONTACTS

AOCL Crypto is developed and maintained by AMD. You can contact us on the email-id <b>[aoclsupport@amd.com](mailto:aoclsupport@amd.com)</b>