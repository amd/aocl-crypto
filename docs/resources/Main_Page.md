
# Welcome to AOCL-Crypto

**AOCL-Crypto** is a library consisting of basic cryptographic functions optimized and tuned for AMD Zen™ based microarchitecture. This library provides a unified solution for Cryptographic routines such as AES (Advanced Encryption Standard) encryption/decryption routines (CFB, CTR, CBC, CCM, GCM, OFB, SIV, XTS), SHA (Secure Hash Algorithms) routines (SHA2, SHA3, SHAKE), Message Authentication Code (CMAC, HMAC), ECDH (Elliptic-curve Diffie–Hellman) and RSA (Rivest, Shamir, and Adleman) key generation functions, etc.

-   For building, please refer to [BUILD.md](md_BUILD.html)

--- 

## Table of Content
    * [Introduction](#Introduction)
    * [Build and Installation](#Build)
    * [Examples](#Example)
    * [Contact Us](#Contact)


<div id="Introduction" name="Introduction"></div>

## Introduction

<b> AOCL Crypto </b> supports a dynamic dispatcher feature that executes the most optimal function variant implemented using Function Multi-versioning thereby offering a single optimized library portable across different x86 CPU architectures. 
AOCL Crypto framework is developed in C / C++ for Unix and Windows based systems. Below are details of AOCL Crypto APIs and Supports

### Cipher   

```
 
AES 
    
    AES Encrypt / Decrypt routines which will support the following cipher schemes:
        -  CBC, CFB, OFB, CTR, GCM, XTS, CCM, SIV.
```
-   Click to know about more about [AOCL Cipher API](group__cipher.html)

### Digest

```

SHA2

    Digest routines for the following schemes:
        - SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256

SHA3

    Digest routines for the following schemes:
        - SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE_128, SHAKE_256    
```

- Click to know more about [AOCL Digest API](group__digest.html)


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

### Random Number Generator (RNG)
```

RNG

    - Generate random number
    - Seed random number generator with random data

```

- Click to know more about [AOCL RNG API](group__rng.html)


<div id = "Build" name="Build"></div>

<div id = "Example"></div>

## Build and Installation

To Build AOCL-Crypto for Different Platforms Please refer to the document
    - [ BUILD ](md_BUILD.html#md_BUILD)

<div id = "Example"></div>

## Example

Here is a Demo Code Example on how to use Cipher:

\include{lineno} cipher/aes-cfb.c 

<div id = "Contact"></div>

## CONTACTS

AOCL Crypto is developed and maintained by AMD. For support of these libraries and the other tools of AMD Zen Software Studio, see https://www.amd.com/en/developer/aocc/compiler-technical-support.html</b>