# Welcome to AOCL-Cryptography

**AOCL-Cryptography** is a library consisting of basic cryptographic functions optimized and tuned for AMD Zen™ based microarchitecture. This library provides a unified solution for Cryptographic routines such as AES (Advanced Encryption Standard) encryption/decryption routines (CFB, CTR, CBC, CCM, GCM, OFB, SIV, XTS), Chacha20 Stream Cipher routines, Chacha20-Poly1305, SHA (Secure Hash Algorithms) routines (SHA2, SHA3, SHAKE), Message Authentication Code (CMAC, HMAC, Poly1305 MAC), RNG, ECDH (Elliptic-curve Diffie–Hellman), RSA Encrypt/Decrypt and Sign/Verify Functions.

### Table of contents
- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Examples](#examples)
- [Compat Support](#compat-support)
- [Contact Us](#contacts)


## Introduction 

<b> AOCL-Cryptography </b> supports a dynamic dispatcher feature that executes the most optimal function variant offering a single optimized library portable across different x86 CPU architectures. 
AOCL Crypto framework is developed in C / C++ for Unix and Windows based systems. A test suite is provided for validation and performance benchmarking for the supported Ciphers, Digest, MAC, EC, and RSA APIs. The test suite also supports the benchmarking of IPP and Openssl different methods like AES cryptographic encryption / decryption, SHA2, SHA3 and other algorithms. Below are details of AOCL Crypto APIs and supported features


### Cipher

```
 
AES - Block Cipher algorithms
    
    AES Encrypt / Decrypt routines which will support the following cipher schemes:
        -  CBC, CFB, OFB, CTR, GCM, XTS, CCM, SIV.

Chacha20 - Stream Cipher algorithms

Chacha20-Poly1305 AEAD

```
-   Click to know about more about [AOCL Cipher API](group__cipher)

### Digest

```

SHA2

    Digest routines for the following schemes:
        - SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256

SHA3

    Digest routines for the following schemes:
        - SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE_128, SHAKE_256
```

- Click to know more about [AOCL Digest API](group__digest)


### Elliptic curve

```

EC 

    EC key generation routines for the following schemes:
        - x25519 and Nist-P256

```

- Click to know more about [AOCL EC API](group__ec)


### Message Authentication Code

```

HMAC 

    MAC routines for the following schemes:
        - HMAC_SHA2_224, HMAC_SHA2_256, HMAC_SHA2_384, HMAC_SHA2_512
        - HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512
        - HMAC_SHA2_512_224, HMAC_SHA2_512_256

CMAC 

    MAC routines for the following schemes:
        - CMAC - AES (for key size 128,192 and 256)

Poly 1305 MAC routines

```

- Click to know more about [AOCL MAC API](group__mac)

### RSA

```

RSA
    - Encrypt text with public key (Non Padded, OAEP, PKCS)
    - Decrypt text with private Key (Non Padded,OAEP, PKCS)
    - Sign with private key and verify with public key (PKCS,PSS)

```

- Click to know more about [AOCL RSA API](group__rsa)

### Random Number Generator (RNG)
```

RNG

    - Generate random number
    - Seed random number generator with random data

```

- Click to know more about [AOCL RNG API](group__rng)

----

## Getting Started

### Quick Starter  
* [AOCL-Cryptography Linux Quick Starter](Quick_Start)

### Building

To Build AOCL-Cryptography for different platform please refer to the document related to your platform
- [ Linux ](md_BUILD)
- [ Windows ](md_BUILD_Windows)
    
## Examples 

To build and run the examples, please refer to the document
    - [Examples](BUILD_Examples)

## Compat Support 

 For applications using ippcp or openssl, it is possible to use AOCL-Cryptography library without replacing existing APIs using our compat libraries. 
  - [ OpenSSL Provider ](openssl_README)
  - [ IPPCP Wrapper ](ipp_README)


----

## Contacts

<b>AOCL Cryptography is developed and maintained by AMD. For support of these libraries and the other tools of AMD Zen Software Studio, see https://www.amd.com/en/developer/aocc/toolchain-technical-support.html</b>
