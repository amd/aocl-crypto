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
     For example, AES CBC Encode is an algorithm, supporting one mode.
     
  2. Module - Module is a collection of algorithms grouped together (logically).
     For example, AES and DES will be under module "Symmetric Key"
  
  3. Plugin - Is a loadable module, contains one or more algorithms, which
     registers itself with the library to extend its functionality.
  
  4. Compatibility layer - Compatibility layer allows any application compiled
     linked against other libraries to work with AOCL Crypto without
     modifications. AOCL Crypto provides compatibility layer for IPP-CP and
     libcrypto(from OpenSSL).

Dynamic dispatcher in the library optimally dispatches to best possible function
for a given architecture, this decision is made once in the lifetime of the
process and would not add any overhead due to decision making process.
Each algorithm would exist in at least 2 forms

  1. A Reference Implementation
  2. An Optimized Implementation.
        - AVX  SIMD 
        - AVX2 SIMD 
        - AESNI accelerated instructions
        - Hardware off-load processing

Any x86_64 machine that doesn't support AVX, the reference implementation (very
very slow) will be available, but we dont commit to support any machine before
full implementation of AVX.

Each of them are dynamically dispatched to at runtime based on CPUID features.

Offloading Support: Accelerators are the new trend in high-end computing to take
the load of computing and are becoming de-facto standard in the industry. The
library supports device plugins which extends the functionality to work with a
device for offloading. For ex: Hash computation SHA256, greatly useful in
Cryptocurrency mining need not waste CPU time, could generate millions of hashes
per second using offloading.

## Design Consideration

AOCL Crypto is expected to cater new as well as existing customers. Current
customers may already be using other solutions like IPP-CP, OpenSSL-crypto,
BoringSSL-crypto, MbedTLS etc, and may not want to recompile their entire
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
AOCL Crypto assumes following libraries/tools available on system where it is
built or running.

  - CMake (3.18.4 or later)
  - GCC (11.0 or later)
  - Git (2.30.2 or later)
  - OpenSSL ( 1.1.1k or later)
  - Pandoc ( + LaTeX for generating pdf docs)

## General Constraints (TODO: TBD)
The library will contain all the listed algorithms eventually. At the library
completeness level the priority is only for implementing one over other for a
given release than choosing one over the other algorithm to include in library.

OpenSSL compatibility library needs to be co-developed along with AOCL Crypto,
as the requirement for drop-in replacement is crucial for AOCL Crypto to
succeed.

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
library\'s capability itself. By providing new algorithms and new modes to
existing algorithm it allows to extend current library without need for upgrade.

Later versions of the library also supports offloading of some of the
computation using various device plugins. These computations may be partial or
fully supported by additional accelerators in the system/platform.

Crypto library\'s errors are cleverly designed to report all possible error from
modules and algorithms. With support to extend the current error reporting
mechanism to add new errors.

Concurrency is in the heart of the design where no locks are needed allow the
functionality itself. However locks are used when adding/removing
modules/plugins to/from the library.

## Apps for testing

  - Nginx(pronounced Engine-X)
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
  - _lib/_ : The library itself
      - _lib/compat_ : Compatibility layers
          - _lib/compat/openssl_ : OpenSSL Compatibility layer
          - _lib/compat/ippcp_   : Intel IPP CP compatibility layer

# Detailed System Design
## Error Reporting
### AOCL Crypto Error codes
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

The function `alc_error_str()` will decode a given error to message string, both
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
                       uint8_t    *buf,
                       uint64_t    size,
                       const char *file,
                       uint64_t      line
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


## Module Manager
Refer to section [The Module Manager](#the-module-manager)

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

# Detailed Subsystem Design

## Key Management (TODO: WIP)
Key management is decoupled from algorithms, allowing any algorithm to use any
key. However each algorithm checker will ensure that only supported keys are
passed down to the actual implementation. 

The Key types enumeration `alc_key_type_t` suggest what keys are in possession,
and `alc_key_alg_t` determines the algorithm to be used for key derivation (if
any). The `alc_key_fmt_t` suggests if the keys are encoded in some format, and
needed to be converted in order to use. The `alc_key_attr_t` suggest type of key
in each of `alc_key_type_t`. For ex: 

### Key Types
```c
typedef enum {
    ALC_KEY_TYPE_UNKNOWN   = 0,

    ALC_KEY_TYPE_SYMMETRIC = 0x10,  /* Will cover all AES,DES,CHACHA20 etc */
    ALC_KEY_TYPE_PRIVATE   = 0x20,
    ALC_KEY_TYPE_PUBLIC    = 0x40,
    ALC_KEY_TYPE_DER       = 0x80,
    ALC_KEY_TYPE_PEM       = 0x100,
    ALC_KEY_TYPE_CUSTOM    = 0x200,

    ALC_KEY_TYPE_MAX,
} alc_key_type_t;
```

Key management module returns following errors,

  - `ALC_KEY_ERROR_INVALID` : When an Invalid key type or pattern is sent to the API
  - `ALC_KEY_ERROR_BAD_LEN` : When key length is not matching with keytype
  - `ALC_KEY_ERROR_NOSUPPORT` : When key type is not supported.

### Key Algorithm
```c
typedef enum {
    ALC_KEY_ALG_WILDCARD,
    ALC_KEY_ALG_DERIVATION,
    ALC_KEY_ALG_AGREEMENT,
    ALC_KEY_ALG_SYMMETRIC,
    ALC_KEY_ALG_SIGN,
    ALC_KEY_ALG_AEAD,
    ALC_KEY_ALG_MAC,
    ALC_KEY_ALG_HASH,
    
    ALC_KEY_ALG_MAX,
} alc_key_alg_t;
```

### The Key format
Key format specifies if the key represented by the buffer is encoded in some
form or its just a series of bytes

```c
typedef enum {
    ALC_KEY_FMT_RAW,    /* Default should be fine */
    ALC_KEY_FMT_BASE64, /* Base64 encoding*/
} alc_key_fmt_t ;
```

### The `alc_key_info_t` structure
The structure `alc_key_info_t` holds the metadata for the key, it is used by
other parts of the library. APIs needed to manage the key is may not directly be
part of this module.

```c
alc_key_algo_t
alcp_key_get_algo(alc_key_info_t *kinfo);
```

```c
alc_key_type_t
alcp_key_get_type(alc_key_info_t *kinfo);
```

```c
#define ALC_KEY_LEN_DEFAULT  128
#define BITS_TO_BYTES(x) (x >> 8)

typedef struct {
    alc_key_type_t    k_type;
    alc_key_algo_t    k_algo;
    uint32_t          k_len;    /* Key length in bits */
    uint8_t           k_key[0]; /* Key follows the rest of the structure */
} alc_key_info_t;
```


## Digests (TODO: WIP)
The preliminary APIs are similar to ciphers, the function
`alcp_digest_supported()` returns if a given digest is available(and usable) in
the module manager. Digests are also referred to as 'Hash' in various
texts/Internet. Rest of the document we refer to as Digest to stay in line with
industry standard acronym.

```c
alc_error_t 
alcp_digest_supported(alc_digest_type_t dt,  /* The digest type */
                      );
```

The actual call to `aclp_digest_request()` provides a context (a session handle)
to work with.

```c
alc_error_t
alcp_digest_request(alc_digest_type_t dt,    /* Requesting Digest type */
                    uint64_t          flags, /* reserved for future */
                    alc_context_t     *t,    /* a context to call future calls */
                    );
```

Once a `alc_context_t` handle is available, digest can be generated calling
`alcp_digest_update()`

```c
alc_error_t
alcp_digest_update(alc_context_t  *ctx,    /* Previously got context */
                   const uint8_t  *data,   /* pointer to actual data */
                   uint64_t        size,   /* size of data */
                   uint8_t        *digest, /* pointer to put the hash/digest */
                   uint64_t        dsize,  /* size of the hash/digest buffer */
                   );
```
An application can query the library to understand the final digest length to
allocate memory for the digest.
```c
uint64_t
alcp_digest_length(alc_context_t *ctx);
```

## Ciphers

### Symmetric Ciphers ###

Symmetric ciphers uses the same key for both encryption and decryption, The key
types are described in [Key Types](#key-types).

The library supports Symmetric ciphers with GCM, CFB, CTR and XTS modes.
Supported ciphers can be checked programatically using `alcp_cipher_available()`
function.

Each Algorithm registers itself with algorithm-manager, which keeps a list of
currently supported algorithm. The `alcp_cipher_available()` in turn calls the
internal function `alcp_algo_available()` function to check if the provided
mode / keylength is supported by the algorithm.

Crypto library uses "Factory" design pattern to create and manage the Cipher
module. All ciphers are requested using `alcp_cipher_request()` API, which
accepts various parameters to determine cipher and exact mode to operate.

```c
alc_error_t
alcp_cipher_request(alc_cipher_info_t *cinfo,
                    alc_key_info_t    *kinfo,
                    alc_context_t     *ctx
                    );
```

In the above api, `alc_cipher_info_t` is described as in
[`alc_cipher_info_t`](#the-alc-cipher-info-t-structure), which describes the
cipher action with specific key information indicated by
[`alc_key_info_t`](#the-alc-key-info-t-structure) and A context for the session
is described by [`alc_context_t`](#the-alc-context-t-structure). The Context
describes everything needed for the algorithm to start and finish the operation.
The key type is as described in the
[`alc_key_info_t`](#the-alc-key-info-t-structure).

#### The `alc_cipher_ctx_t` structure ####

The Cipher's context is very specific to a given cipher algorithm. This
structure or its contents are purely internal to the library, hence it will be
sent as a handle with opaque type.

```c
typedef struct {
    void *private;
} alc_cipher_ctx_t;
```

#### The `alc_cipher_ops_t` structure ####

This is a structure intended to be handled by the "Module Manager". Each cipher
algorithm will present following functions to the module manager. 

```c

```

#### The `alc_cipher_info_t` structure ####

Cipher metadata is contained in the `alc_cipher_info_t`, describes the Cipher
algorithm and Cipher mode along with additional padding needed.

```c
typedef struct {
    alc_cipher_algo_t    c_algo;
    alc_cipher_mode_t    c_mode;
    alc_cipher_padding_t c_pad;
    alc_key_info_t       c_keyinfo;
} alc_cipher_info_t;
```

#### The `alc_cipher_algo_t` type ####

Any new algo needs to be added towards the end of the enumeration but before the
`ALC_CIPHER_ALGO_MAX`. 

```c
typedef enum {
    ALC_CIPHER_ALGO_NONE = 0, /* INVALID: Catch the default case */
    
    ALC_CIPHER_ALGO_DES,
    ALC_CIPHER_ALGO_3DES,
    ALC_CIPHER_ALGO_BLOWFISH,
    ALC_CIPHER_ALGO_CAST_128,
    ALC_CIPHER_ALGO_IDEA,
    ALC_CIPHER_ALGO_RC2,
    ALC_CIPHER_ALGO_RC4,
    ALC_CIPHER_ALGO_RC5,
    ALC_CIPHER_ALGO_AES,

    ALC_CIPHER_ALGO_MAX
} alc_cipher_algo_t ;
```

#### The `alc_cipher_mode_t` type ####

Cipher modes are expressed in one of the following enumerations
```c
typedef enum {
    ALC_CIPHER_MODE_NONE = 0, /* INVALID: Catch the default case */
    
    ALC_CIPHER_MODE_ECB,
    ALC_CIPHER_MODE_CBC,
    ALC_CIPHER_MODE_CFB,
    ALC_CIPHER_MODE_OFB,
    ALC_CIPHER_MODE_CTR,

    ALC_CIPHER_MODE_CCM,
    ALC_CIPHER_MODE_GCM,
} alc_cipher_mode_t;
```


#### The `alc_cipher_padding_t` type ####

```c
typedef enum {
    ALC_CIPHER_PADDING_NONE = 0,
    ALC_CIPHER_PADDING_ISO7816,
    ALC_CIPHER_PADDING_PKCS7,
} alc_cipher_padding_t;

```

#### The `alc_key_info_t` structure ####



### AES (Advanced Encryption Standard) ###

The library supports AES(Advanced Encryption Standard), as part of the Symmetric
Cipher module.

##### CFB (Cipher FeedBack) #####

CFB Mode is cipher feedback, a stream-based mode. Encryption occurs by XOR'ing
the key-stream bytes with plaintext bytes. 
The key-stream is generated one block at a time, and it is dependent on the
previous key-stream block. CFB does this by using a buffered block, which
initially was supplied as IV (Initialization Vector).



### Message Authentication Codes (MAC) (TODO: WIP) ###

### AEAD Ciphers (TODO: WIP) ###

### Key Derivation Functions (KDF) (TODO: WIP) ###


#### Padding ####

Padding will take care of aligning the data to given length and filling the
newly aligned area with provided pattern.

```c
/* \fn alcrypt_padding_pad Pads the given input to the size specified
 * @param ctx AlCrypto Context
 */
alc_status_t
alcp_padding_pad(alc_context_t *ctx, alc_u8 *in, size_t size);
```

```c
size_t alcp_padding_size(alc_context_t *ctx);
```

```c
alc_status_t alcrypt_padding_unpad(alc_context_t *ctx);
```



### Random Number Generator ###

The AOCL Crypto library supports both PRNG and TRNG algorithms. AMD Zen series
of processors provide 'RDRAND' instruction as well as 'RDSEED', however there
are speculations on its security. Also it is prone to side-channel attacks.

PRNG's usually requires a seed, and not considered cryptographically secure.
The OS-level PRNG(/dev/random) are not desired as well for high-security
randomness, as they are known to never produce data more than 160-bits (many
have 128-bit ceiling).

However there are cryptographically secure PRNGs (or in other words CRNG) which
output high-entropy data. 

On Unix like modern operating systems provide blocking `/dev/random` and a
non-blocking `/dev/urandom` which returns immediately, providing
cryptographical randomness. In theory `/dev/random` should produce
data that is statistically close to pure entropy, 

Also the traditional `rand()` and `random()` standard library calls does not
output high-entropy data.

RNG module will support two modes 'accurate' and 'fast', along with multiple
distribution formats. The library also supports 'Descrete' and 'Continuous'
distribution formats. 
RNG type specified
  - i : Integer based
  - s : Single Precision
  - d : Double Precision

Continuous Distribution formats: 

| Distribution | Datatype             | RNG  | Description                                           |
| :--          | :--:                 | :--: | :--                                                   |
| Beta         | s,d                  |      | Beta distribution                                     |
| Cauchy       | s,d                  |      | Cauchy distribution                                   |
| ChiSquare    | s,d                  |      | Chi-Square distribution                               |
| Dirichlet    | alpha[, size])       |      | Dirichlet distribution.                               |
| Exponential  | s,d                  |      | Exponential Distribution                              |
| Gamma        | s,d                  |      | Gamma distribution                                    |
| Gaussian     | s,d                  |      | Normal (Gaussian) distribution                        |
| Gumbel       | s,d                  |      | Gumbel (extreme value) distribution                   |
| Laplace      | s,d                  |      | Laplace distribution (double exponent)                |
| Logistic     | [loc, scale, size])  |      | logistic distribution.                                |
| Lognormal    | s,d                  |      | Lognormal distribution                                |
| Pareto       | a[, size])           |      | Pareto II or Lomax distribution with specified shape. |
| Rayleigh     | s,d                  |      | Rayleigh distribution                                 |
| Uniform      | s,d                  |      | Uniform continuous distribution on [a,b)              |
| Vonmises     | mu, kappa[, size])   |      | von Mises distribution.                               |
| Weibull      | s,d                  |      | Weibull distribution                                  |
| Wald         | mean, scale[, size]) |      | Wald, or inverse Gaussian, distribution.              |
| Zipf         | a[, size])           |      | Zipf distribution.                                    |

Descrete Distribution formats:

| Type of Distribution | Data Types | RNG  | Description                                             |
| :--                  | :--:       | :--: | :--                                                     |
| Bernoulli            | i          | s    | Bernoulli distribution                                  |
| Binomial             | i          | d    | Binomial distribution                                   |
| Geometric            | i          | s    | Geometric distribution                                  |
| Hypergeometric       | i          | d    | Hypergeometric distribution                             |
| Multinomial          | i          | d    | Multinomial distribution                                |
| Negbinomial          | i          | d    | Negative binomial distribution, or Pascal distribution  |
| Poisson_V            | i          | s    | Poisson distribution with varying mean                  |
| Uniform_Bits         | i          | i    | Uniformly distributed bits in 32-bit chunks             |
| Uniform              | i          | d    | Uniform discrete distribution on the interval [a,b)     |
|                      | i          | i    | Uniformly distributed bits in 64-bit chunks             |


##### Design #####

Each RNG is represented by the `alc_rng_info_t` structure. The library provides
interface to query if a RNG configuration is available using
`alcp_rng_supported()`, this provides the option for the application to fall
back to different algorithm/configuration when not supported.

As usual with other modules, all the RNG api's return `alc_error_t` and use of
`alcp_is_error(ret)` will provide sufficient information to fallback or to abort
for the application.

All available RNG algorithms will register with Module Manager with type
`ALC_MODULE_TYPE_RNG`, Types of Generator are described by 

An RNG generator can be requested using `alcp_rng_request()`, which accepts an
`alc_rng_info_t` structure, which has following layout.

```c
typedef struct {
    alc_rng_type_t        r_type;
    alc_rng_source_t      r_source;
    alc_rng_distrib_t     r_distrib;
    alc_rng_algo_flags_t  r_flags;
} alc_rng_info_t;
```

```c
typedef enum {
    ALC_RNG_TYPE_INVALID = 0,
    ALC_RNG_TYPE_SIMPLE,
    ALC_RNG_TYPE_CONTINUOUS,
    ALC_RNG_TYPE_DESCRETE,

    ALC_RNG_TYPE_MAX,
} alc_rng_type_t ;

```

Random Number source can be selected using following enumeration. The request
function 
```c
typedef enum {
    ALC_RNG_SOURCE_ALGO = 0,  /* Default: select software CRNG/PRNG */
    ALC_RNG_SOURCE_OS,        /* Use the operating system based support */
    ALC_RNG_SOURCE_DEV,       /* Device based off-loading support */

    ALC_RNG_SOURCE_MAX,
} alc_rng_source_t;
```

Random Generation algorithms and their distribution are described by enumeration
`alc_rng_distribution_t`.

```c
typedef enum {
    ALC_RNG_DISTRIB_UNKNOWN = 0,

    ALC_RNG_DISTRIB_BETA,
    ALC_RNG_DISTRIB_CAUCHY,
    ALC_RNG_DISTRIB_CHISQUARE,
    ALC_RNG_DISTRIB_DIRICHLET,
    ALC_RNG_DISTRIB_EXPONENTIAL,
    ALC_RNG_DISTRIB_GAMMA,
    ALC_RNG_DISTRIB_GAUSSIAN,
    ALC_RNG_DISTRIB_GUMBEL,
    ALC_RNG_DISTRIB_LAPLACE,
    ALC_RNG_DISTRIB_LOGISTIC,
    ALC_RNG_DISTRIB_LOGNORMAL,
    ALC_RNG_DISTRIB_PARETO,
    ALC_RNG_DISTRIB_RAYLEIGH,
    ALC_RNG_DISTRIB_UNIFORM,
    ALC_RNG_DISTRIB_VONMISES,
    ALC_RNG_DISTRIB_WEIBULL,
    ALC_RNG_DISTRIB_WALD,
    ALC_RNG_DISTRIB_ZIPF,

    ALC_RNG_DISTRIB_BERNOULLI,
    ALC_RNG_DISTRIB_BINOMIAL,
    ALC_RNG_DISTRIB_GEOMETRIC,
    ALC_RNG_DISTRIB_HYPERGEOMETRIC,
    ALC_RNG_DISTRIB_MULTINOMIAL,
    ALC_RNG_DISTRIB_NEGBINOMIAL,
    ALC_RNG_DISTRIB_POISSON,
    ALC_RNG_DISTRIB_UNIFORM_BITS,
    ALC_RNG_DISTRIB_UNIFORM,

    ALC_RNG_DISTRIB_MAX,
} alc_rng_distrib_t;

```

Each algorithm have some flags to further extend/restrict. This may or may not
have valid information. For example `ALC_RNG_DISTRIB_POISON` could be selected
in multiple format
  1. Normal Poison distribution
  2. With Varying mean

```c
typedef enum {

} alc_rng_algo_flags_t;
```

##### APIs #####

To support the fallback for applications in cases where the expected RNG support
is not available, `alcp_rng_supported()`, returns error not supported. No errors
if the given RNG and its Distribution support is available.

```c
alc_error_t
alcp_rng_supported(const alc_rng_info_t *tt);

```

An RNG handle can be requested using `alc_rng_request()`, the context(handle) can
only be used if the check `if (!alc_is_error(ret))` passes for the call.

```c
alc_error_t
alcp_rng_request(const alc_rng_info_t *tt, alc_context_t *);
```

The `alcp_rng_gen_random()` generates random numbers and fills the buffer
pointed by `buf` for length specified by `size` in bytes.

```c
alc_error_t
alcp_rng_gen_random(alc_context_t *tt,
                    uint8_t       *buf,  /* RNG output buffer */
                    uint64_t       size  /* output buffer size */
                    );
```






### Utilities ###


#### Base-64 encoding and decoding ####

Encoding to Base-64 helps to print the long data into textual format. It uses
6-bits of input to encode into one of the following characters.
First 26 letters of uppercase alphabets, and next 26 letters are using lowercase
alphabets, rest of them use the digits 0-9 and ' + ', ' / '.

```c
static char base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+/";
```

APIs include `alcp_base64_encode()` and `alcp_base64_decode()` 

```c
alc_error_t
alcp_base64_encode(unsigned char *in,
                   uint64_t       in_size,
                   unsigned char *out,
                   uint64_t       out_len
                   );
```


```c
alc_error_t
alcp_base64_decode(unsigned char *in,
                   uint64_t       in_len,
                   unsigned char *out,
                   uint64_t       out_len
                   );

```






# Extensions to the Library


<!--
Plugin system design
        #include design/plugins.md
-->


<!--
Device offloading 
        #include design/devices.md
-->

