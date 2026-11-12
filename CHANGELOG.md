# Changelog

All notable changes to AOCL Cryptography will be documented in this file.

## About AOCL Cryptography

AOCL Cryptography is a library consisting of basic cryptographic functions optimized for AMD Zen microarchitecture. This library provides multiple implementations of different cryptographic algorithms:

- AES cryptographic encryption / decryption routines
- SHA2, SHA3 Digest routines
- MAC (Cipher and Hash based) routines
- ECDH x25519 Key exchange functions
- RSA Encrypt/Decrypt and Sign/Verify functions
- Chacha20 stream cipher functions
- Poly1305 MAC functions
- Chacha20Poly1305 routines

---

## [6.0.0] - 2026

### Added

- **OpenSSL Provider**: ChaCha20-Poly1305 support, enabled by default.
- **Build**: Independent `ALCP_BUILD_SHARED` and `ALCP_BUILD_STATIC` options to select shared, static, or both library targets.
- **MAC**: Poly1305 AVX2 implementation for supported architectures.
- **CPU support**: Added Zen 6 detection and compiler support with graceful fallback when `znver6` is unavailable.

### Changed

- **Performance**:
  - ChaCha20: Added a scalar single-block fast path and optimized ChaCha20-Poly1305 keystream batching.
  - RSA: Improved private-key decryption performance.
  - CBC: Removed redundant initialization in the Zen 4 encrypt path.
  - Digest: Avoided the SHA-256 multi-buffer throughput regression with GCC 15 and later.
- **Build**: CMake support was expanded for unified object-library builds, host Zen detection, and current GCC/Clang/AOCC toolchains.
- **Build**: Shared-library exports were narrowed to the documented `alcp_*` C ABI; internal C++ symbols are no longer exported. This is a breaking change for consumers linking against ALCP C++ internals.

### Fixed

- **Cipher**: Fixed CFB residual-data decryption on Zen 3, multi-buffer reinitialization state, ChaCha20 counter carry on Zen 4, ChaCha20-Poly1305 multi-update and IV reinitialization, in-place AEAD decryption, and truncated XTS key handling.
- **CMAC/MAC**: Validated output sizes and function pointers before use.
- **RSA**: Validated OAEP ciphertext, private-key component, caller buffer, public exponent, and PSS salt sizes.
- **Elliptic Curve**: Validated ECDH key buffers and lifecycle, null-checked C API dispatch pointers, and enforced RFC 7748 X25519 semantics.
- **RNG**: Retried RDRAND before reporting entropy failure and ensured hardware RNG requests fill every requested byte.
- **C API**: Prevented C++ exceptions from escaping Digest, MAC, RNG, EC, and RSA entry points.
- **RNG**: Exported `alcp_rng_init`, which was declared in `rng.h` but missing from the shared-library export table.
- **Build and compatibility**: Added C23 compatibility for GCC 15 and fixed static-only build regressions.

### Removed

- **RNG**: Removed the DRBG feature and its public `alcp_drbg_*` API and test paths. This is a breaking change for consumers using those entry points.
- **Examples**: Removed the C++ cipher samples; the examples directory is now C-only and builds against the public C API.

### Known Limitations

- AES ciphers, RSA, and EC algorithms are not supported on pre-AVX2 architectures.
- RSA provider dispatch requires the runtime OpenSSL version to match the version used to compile the compatibility binary.
- Consumers linking against ALCP C++ internals must migrate to the documented C ABI because those internal symbols are no longer exported.

---

## [5.3.0] - 2026

### Added

- **Digest**: SHA-256 multi-buffer support
- **MAC**: HMAC-SHA-256 multi-buffer support
- **Cipher**: Variable-length multi-buffer support for CBC and CFB
- **OpenSSL**: OpenSSL 3.5 is no longer experimental and is the default packaged OpenSSL version for 5.3
- **OpenSSL Provider**: AES-CBC enabled by default
- **RSA Provider**: Fallback support for verify/recover operations
- **Dispatch**: ISA-based per-algorithm kernel dispatch across the library

### Changed

- **Performance**:
  - ChaCha20: 8-block parallel AVX2 implementation for Zen 2 and Zen 3
  - AES-XTS: Tweak block computation redesigned from O(n) to O(log n)
  - AES-GCM: Reduced provider initialization overhead and optimized GHASH aggregated reduction / carry-less multiplication for Zen 4 and later
  - Poly1305: Optimized for Zen 4 and later with BMI2/ADX scalar x1 fast-path and r^16 combined loop improvements
- **Cipher**: CBC in-place buffer support is enabled by default; the same input/output buffer can be used without the `ALCP_ENABLE_CBC_INPLACE_BUFFER` flag
- **Cipher**: AESNI fallback added for cipher multi-buffer kernels

### Fixed

- **Cipher (AES-CFB)**: Heap buffer overflow for input length smaller than one cipher block
- **Cipher**: Segmentation fault on `nullptr` input/output in cipher operations
- **OpenSSL Provider (RSA)**: Corrected init ordering and PSS dispatch
- **OpenSSL Compat**: Buffer overrun in `memcpy` in cipher layer
- **RNG**: Replaced deprecated WinCrypt API (`CryptGenRandom`) with CNG `ProcessPrng`
- **RSA**: Corrected output size to use modulus size instead of input size
- **Build**: GCC 15 compatibility fixes

### Known Limitations

- AES Ciphers, RSA and EC algorithms are not supported in pre-AVX2 architectures
- RSA provider dispatch requires the runtime OpenSSL version to match the version used to compile the compat binary

---

## [5.2.0] - 2025

### Added

- **Cipher**: Multi-update pathways for generic ciphers
- **Cipher**: In-place support for CBC (encrypt/decrypt)
- **Multi-buffer**: New APIs added (flush / dequeue) for CBC & CFB
- **GCM**: Enabled Streaming + multi-update API changes + tag verification improvements
- **Build**: Clang 19 support and gating
- **OpenSSL**: Experimental support for OpenSSL 3.5.0
  - Tested OpenSSL versions: 3.1.3 through 3.5.0

### Changed

- **Performance (AES-CBC)**: Large-block gains for applications
  - AES-128: all sizes
  - AES-192/256: ≥8K via multi-buffer
- **GCM**: Lifecycle & hash-table (AVX512) performance improvements using `GCM_ALWAYS_COMPUTE` flag
- **Digest**: SHA3 enforced inlining
- **Digest**: SHA256 load/store tuning, branch reductions
- **Utils**: ZEN enforcement flags renamed from `ALCP_` to `AOCL_` with validation

### Fixed

- **Build**: GCC 14 compatibility fixes
- **Build**: RHEL 8.6 (glibc <2.34) pthread affinity linkage fix
- **Error Handling**: Improved validation, unified macros, reliability & cleanup fixes

### Known Limitations

- AES Ciphers, RSA and EC algorithms are not supported in pre-AVX2 architectures
- RSA provider dispatch only if runtime OpenSSL matches same as the version used to compile the compat binary

---

## [5.1.0] - 2025

### Added

- **OpenSSL Provider**: Support for SHA3 and SHAKE algorithms
- **Build**: CMake preset config files
- **Build**: Runtime forcing of CPUID / arch code path support using aocl-utils
- **Debug**: Debug logging support in CAPIs and Provider APIs
- **Testing**: Multi-init benchmark support for AEAD Ciphers

### Changed

- **Performance**: SHA3 performance improvements
- **Performance**: AES-GCM improvements for real-world benchmarks (WRK, ApacheBench, etc.)
  - Note: Performance drop with AES-GCM is expected in Micro-benchmarks such as OpenSSL Speed

### Fixed

- **OpenSSL Provider**: Bug fixes and improvements in dispatch for RSA and Ciphers
- **Code Quality**: Coverity high and majority of medium and low severity defects fixed
- **Testing**: Improvements and enhancements in tests and benchmarks

### Known Limitations

- AES Ciphers, RSA and EC algorithms are not supported in pre-AVX2 architectures
- OpenSSL Provider dispatch for RSA works only if runtime OpenSSL version is the same as the version used to compile the compat binary
  - Tested OpenSSL versions: 3.1.3 through 3.3.0
- Performance drop with AES-GCM is expected in Micro-benchmarks such as OpenSSL Speed

---

## [5.0.0] - 2024

### Added

- **OpenSSL Provider**:
  - Support for CMAC, Poly1305, Cipher, RSA Algorithms
- **Cipher**:
  - Chacha20-Poly1305 Cipher Algorithm
  - Multi-update support for all non-AEAD, GCM and CCM cipher algorithms
  - Cipher API homogenization and C++ Interface
  - Padding support in CBC, CTR, OFB, CFB modes
- **RSA**:
  - PKCS Encrypt & Decrypt algorithms
  - Sign & Verify APIs for PSS and PKCS Padding schemes
- **Digest**:
  - SHA3 Shake Squeeze and Digest Context Copy support
- **Testing**:
  - Misaligned pointer tests in all integration test modules
  - Fuzz Testing support for all algorithms
  - Lifecycle Tests support for all algorithms
  - Test framework support for PKCS Encrypt/Decrypt, PKCS Sign Verify
- **Build**:
  - Make test covering all unit tests, KAT and cross tests
  - Make test supporting valgrind runs
  - CMake preset files for configure and build
  - Coverage build support for AOCC/clang
  - Ninja build support
  - Checks for dependencies (git-lfs, valgrind, lcov, etc.)
  - Windows build system updates
- **Utilities**:
  - Secure memcopy utility function

### Changed

- **Performance**:
  - Chacha20: Performance improvements
  - GCM: Performance improvements
  - CFB, CBC Decrypt: Performance improvements for vaes512 kernel
  - RSA: Performance improvements in OAEP Encrypt/Decrypt
  - MAC: Performance improvements in HMAC, CMAC and Poly1305
  - Digest: Performance improvements in SHA2, SHA3 algorithms
- **Testing**:
  - Tests refactored to align with OpenSSL Bench's lifecycle
  - HMAC: Support for Digest Truncated variants
  - Digest: SHA3 Shake Squeeze and Context copy support in integration tests
  - RSA: Test and bench support for Signature generation and verification

### Fixed

- **OpenSSL Provider**: Various bug fixes in provider path
- **Cipher**:
  - Chacha20: Bug fixes
  - GCM: Bug fixes
- **RSA**:
  - Bug fixes in Encrypt & Decrypt algorithms
  - Bug fix in PKCS Sign API
- **Digest**:
  - Bug fixes in reference algorithm in Squeeze API
  - Memory alignment fixes in SHA2
  - Bug fixes in Unit tests
- **MAC**: Bug fixes in HMAC, CMAC and Poly1305
- **Testing**: Crash fixes, cleanup, and improvements
- **Build**: Compilation issues fixed in all example sources
- **Code Quality**:
  - Coverity generated errors and warnings fixed across example sources
  - High severity defects from Coverity static analysis fixed
  - Memory errors fixed across various algorithms
  - Code cleanup
- **Dispatcher**: Bug fixes in dynamic dispatcher

### Removed

- **Cipher**: Removed C APIs `alcp_cipher_aead_encrypt` and `alcp_cipher_aead_decrypt`
- **Cipher**: C APIs `encryptUpdate/decryptUpdate` modified to `encrypt/decrypt`

### Build System

- **Toolchain Support**: AOCC 5.0, GCC 14.1.0 compilation support
- **Packaging**: Fixed compilation issues in all example sources
- **Documentation**: Updates related to Doxygen and Sphinx

### Known Limitations

- IPP Compat library is in experimental state in 5.0 release
- AES Ciphers, RSA and EC algorithms are not supported in pre-AVX2 architectures

---

## Copyright

(C) 2026 Advanced Micro Devices, Inc. All Rights Reserved.
