---
title: AOCL Crypto IPP Plugin Documentation
subtitle: IPP Plugin Documentation
subject: "markdown"
keywords: [books,programming]
language: en-US
#cover-image: img/example-book-cover.png
lof: true
lof-own-page: true
toc-own-page: true
titlepage: true
#;titlepage-background: backgrounds/background10.pdf
#titlepage-text-color: "333333"
#titlepage-rule-color: "00737C"
papersize: a4
#prepend-titlepage: img/example-book-cover.pdf
colorlinks: true
---

# Key Terminologies

1) IPP-CP - Intel Performance Primitives - CP
2) Asymmetric Cryptography - Cryptography which uses single key
3) Symmetric Cryptography  - Cryptography which uses two keys, one private key and one public key for encryption and decryption.
4) Hashing - Creating a value which represents a data which is a trap door(cant be decoded/converted back to the original file), which is mainly used for checking the integrity.
5) RNG - Random Number Generator
6) BRNG - Base Random Number Generator
7) PRNG - Pseudo Random Number Generator
8) AES - Advanced Encryption Standard

# Introduction

## About IPPCP

IPP-CP is an opensource cryptographic primitives library. It is specifically optimized for Intel CPU. 

It supports Symmetric Cryptography, Hashing Primitives, Authentication Primitives, Public Key (Asymmetric) Cryptography. 

Key algorithms supported by IPP-CP are as follows.

- Symmetric Cryptography Primitive Functions:
  - AES (ECB, CBC, CTR, OFB, CFB, XTS, GCM, CCM, SIV)
  - SM4 (ECB, CBC, CTR, OFB, CFB, CCM)
  - TDES (ECB, CBC, CTR, OFB, CFB)
  - RC4
- One-Way Hash Primitives:
  - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
  - MD5
  - SM3
- Data Authentication Primitive Functions:
  - HMAC
  - AES-CMAC
- Public Key Cryptography Functions:
  - RSA, RSA-OAEP, RSA-PKCS_v15, RSA-PSS
  - DLP, DLP-DSA, DLP-DH
  - ECC (NIST curves), ECDSA, ECDH, EC-SM2
- Multi-buffer RSA, ECDSA, SM3, x25519
- Finite Field Arithmetic Functions
- Big Number Integer Arithmetic Functions
- PRNG/TRNG and Prime Numbers Generation

To read more about IPP-CP click [here](https://github.com/intel/ipp-crypto/blob/develop/README.md)

Currently used version of IPP-CP is `ipp-crypto_2021_8` when this document was written.

## Usage of IPP-Plugin - Brief

### Building examples 

To build examples, simply invoke ```make -j``` from the root of the package directory. 
Set LD_LIBRARY_PATH properly to lib directory in the package to avoid loader issues while executing. 
Executables for examples should be found in bin directory after make is successful.  

For more information please read [BUILD_Examples.md](../../examples/BUILD_Examples.md) 

### Preloading IPP-Compat Lib 

``` bash
export LD_LIBRARY_PATH=/path/to/libalcp.so:$LD_LIBRARY_PATH 
LD_PRELOAD=/path/to/libipp-compat.so ./program_to_run 
```

* Export Path should be a directory. 
* Preload Path should be the .so file itself.
* Any command can follow LD_PRELOAD.

For more details, please refer to [Preloading_IPP] (Preloading IPP-CP wrapper plugin)

