---
title: AOCL Cryptography
subtitle: Software Design Document
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

# Introduction
## Preface
AOCL Cryptography library described in this document is a part of AOCL Library that
provides a portable interface to cryptographic operations. The interface is
designed to be user friendly, while still providing low-level primitives. This
document includes:
  - System Architecture
  - High-level functional overview
  - Design considerations
  - Detailed definition of API's provided by the library

AOCL Cryptography library here in after referred to as 'the library' or crypto or
cryptolib for short.

This document provides details of APIs in the following categories.

  - Key Management
  - Digests (One-way Hash Functions)
  - Symmetric Ciphers
  - Public Key Algorithms
  - Message Authentication Codes (MAC)
  - Key Derivation Functions (KDF)
  - Random Number Generator (RNG)
  - Digest Signing and Verification
  - Padding

AOCL Cryptography also provides compatibility layer which translates libcrypto and
IPP-CP APIs to its own.

# System Overview
AOCL Cryptography is designed to be future compatible and extendable. AOCL-Cryptography
library has following components.

  1. Algorithm - Describes any algorithm that deals with one cryptographic function.
     For example, AES CBC Encode is an algorithm, supporting one mode.

  2. Module - Module is a collection of algorithms grouped together (logically).
     For example, AES and DES will be under module "Symmetric Key"

  3. Plugin - Is a loadable module, contains one or more algorithms, which
     registers itself with the library to extend its functionality.

  4. Compatibility layer - Compatibility layer allows any application compiled and
     linked against other libraries to work with AOCL Cryptography without
     modifications. AOCL Cryptography provides compatibility layer for IPP-CP and
     libcrypto(from OpenSSL).

Dynamic dispatcher in the library optimally dispatches to the best possible function
for a given architecture, this decision is made once in the lifetime of the
process and would not add any overhead due to decision making process.
Each algorithm would exist in at least 2 forms

  1. A Reference Implementation
  2. An Optimized Implementation.
        - AVX  SIMD
        - AVX2 SIMD
        - AVX512 SIMD
        - AESNI accelerated instructions
        - Hardware off-load processing

Any x86_64 machine that doesn't support AVX, the reference implementation (very
very slow) will be available, but we dont commit to support any machine before
full implementation of AVX.

Each of them are dynamically dispatched to at runtime based on CPUID features.

## Design Consideration

AOCL Cryptography is expected to cater new as well as existing customers. Current
customers may already be using other solutions like IPP-CP, OpenSSL-crypto,
BoringSSL-crypto, MbedTLS etc, and may not want to recompile their entire
software stack with AOCL Cryptography. A solution must be provided to experiment with
AOCL Cryptography and to enable existing software stacks to easily migrate.

All are version checked, and time to time libraries are updated and upgraded so
that all versions need not be maintained.

## Assumptions and Dependencies (TODO: TBD)
AOCL Cryptography assumes following libraries/tools available on system where it is
built or running.

  - Required Dependancies
    - CMake (3.26 or later)
    - GCC (11.0 or later)
    - Git (2.30.2 or later)
    - OpenSSL ( 3.0.8 or later )
    - LSB Release
    - Make ( 4.0 or later )
    - 7zip ( 15.0 or later )
  - Optional Dependancies
    - Pandoc ( + LaTeX for generating pdf docs)
    - Doxygen
    - Sphinx

## General Constraints (TODO: TBD)
The library will contain all the listed algorithms eventually.

OpenSSL compatibility library needs to be co-developed along with AOCL Cryptography,
as the requirement for drop-in replacement is crucial for AOCL Cryptography to
succeed.

# Architectural Strategies (TODO: TBD)
## Programming Details
The AOCL Cryptography library provides C99 like API described in detail in
[API](#api-design). Though the internal structures are implemented using C++
with no advanced features. This decision is taken to avoid writing primitive
library functions like stacks/queues or heaps to [<0;199;17M]manage the module/algorithms.
Also the C++ STL provides enough gears to achieve the needed functionality with
least efforts.

AOCL Cryptography makes use of AMD's CPUID identification library and RNG (random
number generator) library to provide additional functionality like dynamic
dispatcher. The RNG library also provides needed seeds for the algorithms
in need.

## Apps for testing

  - Nginx(pronounced Engine-X)
  - gRPC
  - QATv2


## System Architecture

To simplify the object access types, we introduce following notion

  1. Types - Each category (module) will have many types of schemes, this needs
     to be highlighted using one of the `type` mechanisms.

  2. Attributes - All the above mentioned components have attributes, an
     attribute defines properties for a given object or a context, may it be an
     algorithm or a module.

  2. Operations - The operations that can be performed using that object or on
     that object. For example an cipher algorithm provides encrypt()/decrypt()
     kind of operations, where as an hash algorithm provides hash() or digest()
     kind of operation. Modules provides load()/unload()/search()/init() and
     other operations and so on.

  3. Parameters - Parameters are passed to Operations to perform the same
     operation slightly differently. Some cases the distinction between
     attributes and parameters vanishes, as the attribute itself defines the
     parameter. However it is maintained throughout to provide uniform interface.

### Plugins
The future of cryptography cannot be easily foreseen. New types of
communication/certificate mechanisms may emerge, new types of messages may be
introduced. Plugins are provide flexible way to integrate both while
experimenting and deploying. Design of the plugins and its interfaces are
discussed in detail in later sections of this document.

## Policies and Tactics
For this library, GCC is the choice of compiler with LLVM/Clang also in support,
Designers and developers are made sure that no compiler-specific features are
used, as it looses big on portability.
On Windows VC compiler (latest version as of writing VS2019) is used.

Code will honor multiple operating systems, including Linux and Windows to start
with.

Library will be provided as a static archive (libalcrypto.a on Linux and
alcrypto.lib on Windows) as well as a dynamic version (libalcrypto.so on
Linux and alcrypto.dll on Windows)

For build system we have opted for industry standard CMake (version >=3.18.4),
and for testing 'Gtest' (Google Test) framework is used.

This library depends on libaoclutils (A CPU Identification Library), version >= 1.0
used by the dynamic dispatcher to select appropriate function.

Documentation is maintained in 'markdown' format, 'pandoc' (version >= 2.9.2.1 )
command is used to generate pdfs.

## Library Conventions
AOCL Cryptography is designed to be compliant with C99 API, hence uses all standard
datatypes like `uint8_t` , `uint16_t`, however we avoid using `size_t` kind of
datatypes as there is no clear mention of its size w.r.t ILP64 and LP64.

Library Defines following types
  - User Data types
  - Operation types
  - Attribute types

All types have prefix of `alc_` followed by type/module and end with `_t` , for example
  - Error type : `alc_error_t` and `alc_key_t` `alc_algorithm_t`
  - Operation type: `alc_cipher_ops_t` and `alc_hashing_ops_t`
  - Attributes: `alc_key_info_t` `alc_module_info_t`

### Directory Structure
This section details the very initial directory structure layout, though heavily
subjected to change, overall structure would be comparable to following

  - _docs/_ : Contains various documentation both for application developers and
    library developers.
      - _docs/internal_ : AMD's internal documentation such as design /
        architecture etc.

  - _examples/_ : sub-divided into its own directories to contain examples
    pertaining to a logical group of algorithms
      - _examples/symmetric/_ : symmetric key algorithm examples
      - _examples/digest/_    : One way hash function examples
      - etc...
  - _include/_ : Contains all the headers
      - _include/external_ : API header, C99 based
      - _include/alcp_     : Internal headers for library
  - _lib/_ : The library itself
      - _lib/compat_ : Compatibility layers
          - _lib/compat/openssl_ : OpenSSL Compatibility layer
          - _lib/compat/ippcp_   : Intel IPP CP compatibility layer


# Detailed System Design

## Error Reporting
### Design

### API
Error in AOCL Cryptography library is handled using an `uint64_t` value. It has
few possible values which is defined in `alcp/error.h`. Errors are defined in
an enum `alc_error_generic_t`. 

```c
typedef uint64_t alc_error_t;

```

```c
typedef enum _alc_error_generic
{
    /*
     * All is well
     */
    ALC_ERROR_NONE = 0UL,

    /*
     * An Error,
     *    but cant be categorized correctly
     */
    ALC_ERROR_GENERIC,

    /*
     * Not Supported,
     *  Any of Feature, configuration,  Algorithm or  Keysize not supported
     */
    ALC_ERROR_NOT_SUPPORTED,

    /*
     * Not Permitted,
     *  Operation supported but not permitted by this module/user etc.
     *  Kind of permission Denied situation, could be from the OS
     */
    ALC_ERROR_NOT_PERMITTED,

    /*
     * Exists,
     *  Something that is already exists is requested to register or replace
     */
    ALC_ERROR_EXISTS,

    /*
     * Does not Exist,
     *   Requested configuration/algorithm/module/feature  does not exists
     */
    ALC_ERROR_NOT_EXISTS,

    /*
     * Invalid argument
     */
    ALC_ERROR_INVALID_ARG,

    /*
     * Bad Internal State,
     *   Algorithm/context is in bad state due to internal Error
     */
    ALC_ERROR_BAD_STATE,

    /*
     * No Memory,
     *  Not enough free space available, Unable to allocate memory
     */
    ALC_ERROR_NO_MEMORY,

    /*
     * Data validation failure,
     *   Invalid pointer / Sent data is invalid
     */
    ALC_ERROR_INVALID_DATA,

    /*
     * Size Error,
     *   Data/Key size is invalid
     */
    ALC_ERROR_INVALID_SIZE,

    /*
     * Hardware Error,
     *   not in sane state, or failed during operation
     */
    ALC_ERROR_HARDWARE_FAILURE,

    /* There is not enough entropy for RNG
        retry needed with more entropy */
    ALC_ERROR_NO_ENTROPY,

    /*
     *The Tweak key and Encryption is same
     *for AES-XTS mode
     */
    ALC_ERROR_DUPLICATE_KEY,

    /*
     * Mismatch is tag observed in Decrypt
     */
    ALC_ERROR_TAG_MISMATCH,

} alc_error_generic_t;
```

## Dispatcher
The dynamic dispatcher will populate each kind of algorithm with best suitable
implementation for the architecture(on which it is currently running). During
the initialization phase of the library, it scans through available
implementation and selects the best possible option.

Once the best algorithm is selected, its initialization is called, which then
registers itself with the module manager. Once the registration is done, any
request for a given algorithm will be returned with the already selected algorithm.

The dynamic dispatcher will allow debug mode to override the selection of the
function.

If a plugin is loaded, its implementation will overwrite all the algorithms that
are currently selected by the dynamic dispatcher. Hence plugins to be loaded
with caution.

Since plugins are dynamic, there is no way to know/distinguish loaded plugin
with existing algorithm. Also it will become difficult if plugins are
distinguishable by the Application developer.

In cases when the plugin registers an algorithm that is not currently part of
the library, it will be treated as an extension and applications can request for
the algorithms supported by the newly loaded plugin.


<!--
Detailed Subsystem Design
        #include design/02-subsystem-design.md
-->

<!--
Device offloading
        #include design/devices.md
-->

