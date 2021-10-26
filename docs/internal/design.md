---
title: AOCL Crypto 
subtitle: Software Design Document
author: Prem Mallappa <pmallapp@amd.com>
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
AOCL Crypto library described in this document is a part of AOCL Library that
provides a portable interface to cryptographic operations. The interface is
designed to be user friendly, while still providing low-level primitives. This
document includes:
  - System Architecture
  - High-level functional overview
  - Design considerations
  - Detailed definition of API's provided by the library

AOCL Crypto library here in after referred to as 'the library' or crypto or
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

AOCL Crypto also provides compatibility layer which translates libcrypto and
IPP-CP APIs to its own.

# System Overview
AOCL Crypto is designed to be future compatible and extendable. AOCL-Crypto
library has following components.

  1. Algorithm - Describes any algorithm that deals with one cryptographic function.
     For example : AES Encode is an algorithm, supporting multiple modes.
     
  2. Module - Module is a collection of algorithms grouped together (logically).
     For example: AES and DES will be under module "Symmetric Key"
  
  3. Plugin - Is a loadable module, contains one or more algorithms, which
     registers itself with the library to extend its functionality.
  
  4. Compatibility layer - Compatibility layer allows any application compiled
     linked against other libraries to work with AOCL Crypto without
     modifications. AOCL Crypto provides compatibility layer for IPP-CP and
     libcrypto(from OpenSSL).

Dynamic dispatcher in the library optimally dispatches to best possible function
for a given architecture, this decision is made once in the lifetime of the
process and would not add any overhead due to decision making process.
Each algorithm would exist in at least 2 forms,
  1. A Reference Implementation
  2. An Optimized Implementation.
    - An Architectural optimization
    - Instruction Set optimized (Supporting AES-NI)

Offloading Support: Accelerators are the new trend in high-end computing to take
the load of computing and are becoming de-facto standard in the industry. The
library supports device plugins which extends the functionality to work with a
device for offloading. For ex: Hash computation SHA256, greatly useful in
Cryptocurrency mining need not waste CPU time, could generate millions of hashes
per second using offloading.

## Design Consideration

AOCL Crypto is expected to cater new customers as well as current ones. Current
customers may already be using other solutions like IPP-CP or OpenSSL-crypto or
BoringSSL-crypto or MbedTLS etc, and may not want to recompile their entire
software stack with AOCL Crypto. A solution must be provided to experiment with
AOCL Crypto and to enable existing software stacks to easily migrate.

A module is a subsystem of AOCL crypto like Symmetric Cipher or a Digest. Each
module has various algorithms listed under them for easier management.

A plugin is a loadable module which extends a module or adds new modules. This
enables AMD to deliver new algorithms as an extension to the existing software
early and safely.

All are version checked, and time to time libraries are updated and upgraded so
that all versions need not be maintained.

## Assumptions and Dependencies (TODO: TBD)

## General Constraints (TODO: TBD)

## Goals and Guidelines
AOCL Crypto aims at achieving FIPS certification. Source code is expected to be
highly secure and tamper resistant.
All developers are requested to adhere to coding standard and guidelines
provided. Recommended Readings:
  - Writing Secure Code (Microsoft Press)
  - Secure Coding Cookbook

# Architectural Strategies (TODO: TBD)
## Programming Details
The AOCL Crypto library provides C99 like API described in detail in
[API](#api-design). Though the internal structures are implemented using C++
with no advanced features. This decision is taken to avoid writing primitive
library functions like stacks/queues or heaps to manage the module/algorithms.
Also the C++ STL provides enough gears to achieve the needed functionality with
least efforts.

AOCL Crypto makes use of AMD's CPUID identification library and RNG (random
number generator) library to provide additional functionality like dynamic
dispatcher. The RNG library also provides needed seeds for the algorithms
in need.

Plugins feature enables useful and necessary functionality to extend the
library's capability itself. By providing new algorithms and new modes to
existing algorithm it allows to extend current library without need for upgrade.

Later versions of the library also supports offloading of some of the
computation using various device plugins. These computations may be partial or
fully supported by additional accelerators in the system/platform.

Crypto library's errors are cleverly designed to report all possible error from
modules and algorithms. With support to extend the current error reporting
mechanism to add new errors.

Concurrency is in the heart of the design where no locks are needed allow the
functionality itself. However locks are used when adding/removing
modules/plugins to/from the library.

## Apps for testing

  - Nginx(Engine X)
  - gRPC
  - QATv2

## System Architecture

To simplify the object access types, we introduce following notion

  1. Attributes - All the above mentioned components have attributes, an
     attribute defines properties for a given object, may it be an algorithm or
     a module.
     
  2. Operations - The operations that can be performed using that object or on
     that object. For example an cipher algorithm provides encrypt()/decrypt()
     kind of operations, where as an hash algorithm provides hash() or digest()
     kind of operation. Modules provides load()/unload()/search()/init() and
     other operations and so on.

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

This library depends on libcpuid(A CPU Identification Library), version >= 1.0
used by the dynamic dispatcher to select appropriate function.

Documentation is maintained in 'markdown' format, 'pandoc' (version >= 2.9.2.1 )
command is used to generate pdfs.

## Library Conventions
AOCL Crypto is designed to be compliant with C99 API, hence uses all standard
datatypes like `uint8_t` , `uint16_t`, however we avoid using `size_t` kind of
datatypes as there is no clear mention of its size w.r.t ILP64 and LP64.

Library Defines following types
  - User Data types
  - Operation types
  - Attribute types

All types have prefix of `alc_` followed by type/module and end with `_t` , for example
  - Error type : `alc_error_t` and `alc_key_t` `alc_algorithm_t`
  - Operation type: `alc_cipher_ops_t` and `alc_hashing_ops_t`
  - Attributes: `alc_key_info_t` `alc_module_info_t`, `alc_cipher_info_t` 
  
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
  - 


# Detailed System Design
## AOCL Crypto Error codes
This section needs to be populated from Detailed Subsystem design, and each
subsystem needs to either make use of existing error codes or define new ones
that may be relevant only to that subsystem.

If any subsystem requires a specific error code, such system should fill in the
error code in specified `alc_error_t` with their name as one of the prefixes.
For example, Key management subsystem would add `ALC_E_KEY_INVALID` instead of
using existing `ALC_E_INVALID`.


TODO: This structure needs to go to proper section

The `alc_error_t` is designed to contain all the information in a single 64-bit
value. All modules in AOCL Crypto library has an assigned ID which is internal
to the library. However detailed error message can be printed using the function
`alc_error_str()`. 

```c
static inline uint64_t
__alc_extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0U >> (64 - length));
}

#define ALC_ERR_DETAIL_SHIFT   0
#define ALC_ERR_DETAIL_LEN     16
#define ALC_ERR_GENERAL_SHIFT  (ALC_ERR_DETAIL_SHIFT + ALC_ERR_DETAIL_LEN)
#define ALC_ERR_GENERAL_LEN    16
#define ALC_ERR_MODULE_SHIFT   (ALC_ERR_GENERAL_SHIFT + ALC_ERR_GENERAL_LEN)
#define ALC_ERR_MODULE_LEN     16
#define ALC_ERR_RESERVED_LEN   (64 - (ALC_ERROR_MODULE_LEN +          \
                                        ALC_ERROR_GENERAL_LEN +       \
                                        ALC_ERROR_DETAIL_LEN          \
                                        ))

#define ALC_ERROR_DETAIL(x)     __alc_extract64(x.e_val,                \
                                                ALC_ERR_DETAIL_SHIFT,   \
                                                ALC_ERR_DETAIL_LEN)
#define ALC_ERROR_GENERAL(x)    __alc_extract64(x.e_val,               \
                                                ALC_ERR_GENERAL_SHIFT, \
                                                ALC_ERR_GENERAL_LEN)
#define ALC_ERROR_MODULE(x)     __alc_extract64(x.e_val,              \
                                                ALC_ERR_MODULE_SHIFT, \
                                                ALC_ERR_MODULE_LEN)

typedef union {
    uint64_t e_value;

    struct {
        uint64_t ef_detail  :ALC_ERR_DETAIL_LEN;   /* Low level error code */
        uint64_t ef_general :ALC_ERR_GENERAL_LEN;  /* High level error code */
        uint64_t ef_module  :ALC_ERR_MODULE_LEN;   /* Module ID */
        uint64_t ef_reserved:ALC_ERR_RESERVED_LEN; /* Unused, for now */
    } e_fields;

} alc_error_t;
```

## Error types

Following enumeration defines the error types.

```c
typedef enum {
    ALC_ERR_NONE,      /* All is Well */ 
    ALC_ERR_INVALID,   /* Invalid Parameters */
    ALC_ERR_NOENTRY,   /* Entry not found - used for plugins */
    ALC_ERR_NOSUPPORT, /* Not supported */
    ALC_ERR_NOMEM,

} alc_error_type_t;

```

The function `alc_error_str()` will decode a given error message to string, both
the buffer and length of the buffer needs to be passed by the user to know the
error.

```c
/**
* \brief        Converts AOCL Crypto errors to human readable form
* \notes        This is internal usage only, prints Filename and line number
*
* \param err    Actual Error
* \param buf    Buffer to write the Error message to
* \param size   Size of the buffer @buf
* \param file   Name of the file where error occured
* \param line   Line number in @file where error occured
*/

void
alc_error_str_internal(alc_error_t err,
                       al_u8* buf,
                       size_t size,
                       const char *file,
                       size_t line
                       )
{
    assert(buf != NULL);
    assert(size != 0);
}

/**
* \brief        Converts AOCL Crypto errors to human readable form
*/
void
alcp_error_str(alc_error_t err,
              al_u8* buf,
              size_t size)
{
    assert(buf != NULL);
    assert(size != 0);

    /* Write to Buffer */
}

```

The `alc_error_new()` is provided to create a new error out of given parameters.
It builds a returnable 64-bit value.

```c
alc_error_t
alcp_error_new(alc_error_high_t high,  /* High level error code */
               alc_error_low_t low,    /* Low level error code */
               alc_module_t mod,       /* Module ID */
               uint16_t reserved)
{
    alc_error_t err = {0,};

    if (high)
        err.e_fields.ef_general = high;

    if (low)
        err.e_fields.ef_detail = low;

    if (mod)
        err.e_fields.ef_module = mod;

    return err;
}
```


# Detailed Subsystem Design

## Key Management
Key management is decoupled from algorithms, allowing any algorithm to use any
key. However each algorithm checker will ensure that only supported keys are
passed down to the actual implementation. 

Key types supported are

### Key Types
```c
typedef enum {
    ALC_KEY_TYPE_NONE      = 0,
    ALC_KEY_TYPE_SYMMETRIC = 0x10,
    ALC_KEY_TYPE_PRIVATE   = 0x20,
    ALC_KEY_TYPE_PUBLIC    = 0x40,
    ALC_KEY_TYPE_CUSTOM    = 0x100,
} alc_key_type_t;
```

Key management module returns following errors,

`ALC_KEY_ERROR_INVALID` : When an Invalid key type or pattern is sent to the API
`ALC_KEY_ERROR_BAD_LEN` : When key length is not matching with keytype
`ALC_KEY_ERROR_NOSUPPORT` : When key type is not supported.

## Digests

## Symmetric Ciphers
Symmetric ciphers have single key for both encryption and decryption, The key
types are described in [Key Types](#key-types).

The library supports Symmetric ciphers with GCM, CFB, CTR and XTS modes.
Supported ciphers can be checked programatically using `alcp_cipher_supported()`
function.

Each Algorithm registers itself with algorithm-manager, which keeps a list of
currently supported algorithm. The `alcp_cipher_supported()` in turn calls the
internal function `alc_algo_mode_supported()` function to check if the provided
mode / keylength is supported by the algorithm.

### AES (Advanced Encryption Standard)
The library supports AES(Advanced Encryption Standard), 

#### CFB (Cipher FeedBack)


## Message Authentication Codes (MAC)

## Key Derivation Functions (KDF)

## Random Number Generator (RNG)

## Digest Signing and Verification

## Padding


# Plugin System design

## Plugin APIs

This section describes the API design for 'C', the same can be used by many
other languages using their respective FFI(Foreign Function Interface).

## Digests

## Symmetric Ciphers

## Message Authentication Codes (MAC)

## Key Derivation Functions (KDF)

## Random Number Generator (RNG)

## Digest Signing and Verification

## Padding
   
   ```c
   /* \fn alcrypt_padding_pad Pads the given input to the size specified
    * @param ctx AlCrypto Context
    */
   alc_status_t
   alcrypt_padding_pad(alc_context_t *ctx, alc_u8 *in, size_t size);
   ```

  ```c
  size_t alcrypt_padding_size(alc_context_t *ctx);
  ```

  ```c
  alc_status_t alcrypt_padding_unpad(alc_context_t *ctx);
  ```



# Device Offloading
## Device APIs
