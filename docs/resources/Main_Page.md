
# Welcome to AOCL-Cryptography

**AOCL-Cryptography** is a library consisting of basic cryptographic functions optimized and tuned for AMD Zen™ based microarchitecture. This library provides a unified solution for Cryptographic routines such as AES (Advanced Encryption Standard) encryption/decryption routines (CFB, CTR, CBC, CCM, GCM, OFB, SIV, XTS), Chacha20 Stream Cipher routines, SHA (Secure Hash Algorithms) routines (SHA2, SHA3, SHAKE), Message Authentication Code (CMAC, HMAC, Poly1305 MAC), ECDH (Elliptic-curve Diffie–Hellman), RSA (Rivest, Shamir, and Adleman) key generation functions, etc.

- For building, please refer to [Build.md](md_BUILD.html)

## Table of contents
    * [Introduction](#Introduction)
    * [Build and Installation](#Build)
    * [Examples](#Example)
    * [Contact Us](#Contact)


## Introduction {#Introduction}

<b> AOCL-Cryptography </b> supports a dynamic dispatcher feature that executes the most optimal function variant implemented using Function Multi-versioning thereby offering a single optimized library portable across different x86 CPU architectures. 
AOCL Crypto framework is developed in C / C++ for Unix and Windows based systems. A test suite is provided for validation and performance benchmarking for the supported Ciphers, Digest, MAC, EC, and RSA APIs. The test suite also supports the benchmarking of IPP and Openssl different methods like AES cryptographic encryption / decryption, SHA2, SHA3 and other algorithms. Below are details of AOCL Crypto APIs and supported features

### Cipher

```
 
AES - Block Cipher algorithms
    
    AES Encrypt / Decrypt routines which will support the following cipher schemes:
        -  CBC, CFB, OFB, CTR, GCM, XTS, CCM, SIV.

Chacha20 - Stream Cipher algorithms

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

Poly 1305 MAC routines

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


## Build and Installation {#Build}

To Build AOCL-Cryptography for different platform please refer to the document related to your platform
    - [ Linux ](md_Combine_build.html#md_BUILD)
    - [ Windows  ](md_Combine_build.html#md_BUILD_Windows)

## Examples {#Example}

To build and run the examples, please refer to the document
    - [Examples](md_examples_BUILD_Examples.html#md_examples_BUILD_Examples)

## CONTACTS {#Contact}

<b>AOCL Cryptography is developed and maintained by AMD. For support of these libraries and the other tools of AMD Zen Software Studio, see https://www.amd.com/en/developer/aocc/compiler-technical-support.html</b>