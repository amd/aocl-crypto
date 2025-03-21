AOCL-Cryptography 
=================

**AOCL-Cryptography** is a library consisting of basic cryptographic functions optimized and tuned for AMD Zen™ based microarchitecture. This library provides a unified solution for Cryptographic routines such as AES (Advanced Encryption Standard) encryption/decryption routines (CFB, CTR, CBC, CCM, GCM, OFB, SIV, XTS), Chacha20 Stream Cipher routines, Chacha20-Poly1305, SHA (Secure Hash Algorithms) routines (SHA2, SHA3, SHAKE), Message Authentication Code (CMAC, HMAC, Poly1305 MAC), RNG, ECDH (Elliptic-curve Diffie–Hellman), RSA (Encrypt/Decrypt and Sign/Verify Functions).

Introduction
------------

**AOCL-Cryptography** supports a dynamic dispatcher feature that executes the most optimal function variant offering a single optimized library portable across different x86 CPU architectures. 
AOCL Crypto framework is developed in C / C++ for Unix and Windows based systems. A test suite is provided for validation and performance benchmarking for the supported Ciphers, Digest, MAC, EC, and RSA APIs. The test suite also supports the benchmarking of IPP and Openssl different methods like AES cryptographic encryption / decryption, SHA2, SHA3 and other algorithms. Below are details of AOCL Crypto APIs and supported features

Cipher
~~~~~~
Encrypt/Decrypt routines for the following cipher schemes:

1. **AES**

- AEAD :  GCM, CCM, SIV
- Non AEAD :  CBC, CFB, OFB, XTS, CTR

2. **Chacha20 Stream Cipher Algorithm**

3. **Chacha20-Poly1305 AEAD**

Digest
~~~~~~

1. **SHA2**

- SHA2_224, SHA2_256, SHA2_384, SHA2_512
- SHA2_512_224, SHA2_512_256

2. **SHA3**

- SHA3_224, SHA3_256, SHA3_384, SHA3_512
- SHAKE_128, SHAKE_256

Message Authentication Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **HMAC**

- HMAC_SHA2_224, HMAC_SHA2_256, HMAC_SHA2_384, HMAC_SHA2_512
- HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512
- HMAC_SHA2_512_224, HMAC_SHA2_512_256

2. **CMAC**

- CMAC - AES (for key size 128, 192 and 256)

3. **Poly1305**

RSA
~~~

- Encrypt text with public key (Non Padded, OAEP, PKCS) 
- Decrypt text with private Key (Non Padded,OAEP, PKCS) 
- Sign with private key and verify with public key (PKCS,PSS) 

Elliptic Curve
~~~~~~~~~~~~~~

EC key generation routines for the following schemes:

1. **X25519**
2. **NIST-P256**

Random Number Generator (RNG)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Generate random number
- Seed random number generator with random data

.. toctree::
    :maxdepth: 1
    :hidden:

    Cipher APIs <group__cipher>
    Digest APIs <group__digest>
    MAC APIs <group__mac>
    RSA APIs <group__rsa>
    EC APIs <group__ec>
    RNG APIs <group__rng>
    Error Handling APIs <group__error>
