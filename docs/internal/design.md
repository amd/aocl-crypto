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

AOCL Cryptography is expected to cater new as well as existing customers. Current
customers may already be using other solutions like IPP-CP, OpenSSL-crypto,
BoringSSL-crypto, MbedTLS etc, and may not want to recompile their entire
software stack with AOCL Cryptography. A solution must be provided to experiment with
AOCL Cryptography and to enable existing software stacks to easily migrate.

A module is a subsystem of AOCL Cryptography like Symmetric Cipher or a Digest. Each
module has various algorithms listed under them for easier management.

A plugin is a loadable module which extends a module or adds new modules. This
enables AMD to deliver new algorithms as an extension to the existing software
early and safely.

All are version checked, and time to time libraries are updated and upgraded so
that all versions need not be maintained.

## Assumptions and Dependencies (TODO: TBD)
AOCL Cryptography assumes following libraries/tools available on system where it is
built or running.

  - CMake (3.18.4 or later)
  - GCC (11.0 or later)
  - Git (2.30.2 or later)
  - OpenSSL ( 3.1 or later)
  - Pandoc ( + LaTeX for generating pdf docs)

## General Constraints (TODO: TBD)
The library will contain all the listed algorithms eventually. At the library
completeness level the priority is only for implementing one over other for a
given release than choosing one over the other algorithm to include in library.

OpenSSL compatibility library needs to be co-developed along with AOCL Cryptography,
as the requirement for drop-in replacement is crucial for AOCL Cryptography to
succeed.

## Goals and Guidelines
AOCL Cryptography aims at achieving FIPS certification. Source code is expected to be
highly secure and tamper resistant.
All developers are requested to adhere to coding standard and guidelines
provided. Recommended Readings:
  - Writing Secure Code (Microsoft Press)
  - Secure Coding Cookbook

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
This section needs to be populated from Detailed Subsystem design, and each
subsystem needs to either make use of existing error codes or define new ones
that may be relevant only to that subsystem.

If any subsystem requires a specific error code, such system should fill in the
error code in specified `alc_error_t` with their name as one of the prefixes.
For example, Key management subsystem would add `ALC_E_KEY_INVALID` instead of
using existing `ALC_E_INVALID`.

TODO: This structure needs to go to proper section

The `alc_error_t` is designed to contain all the information in a single 64-bit
value. For external API user, its just an opaque type defined to be a pointer.

```c
typedef uint64_t alc_error_t;

```

All modules in AOCL Cryptography library has an assigned ID which is internal
to the library. However detailed error message can be printed using the function
`alc_error_str()`.

The function `alc_error_str_internal()` will perform the same action as
`alc_error_str()`. Just that it prints the filename and line number where the
error function was called. This is used only internally in the library.

```c
/**
* \brief        Converts AOCL Cryptography errors to human readable form
* \notes        This is internal usage only, prints Filename and line number
*
* \param err    Actual Error
* \param buf    Buffer to write the Error message to
* \param size   Size of the buffer @buf
* \param file   Name of the file where error occurred
* \param line   Line number in @file where error occurred
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
```

The function `alc_error_str()` will decode a given error to message string, both
the buffer and length of the buffer needs to be passed by the user to know the
error.

```c
/**
* \brief        Converts AOCL Cryptography errors to human readable form
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



### Implementation
Internally errors are represented as `class Error`




## Module Manager

The AOCL Cryptography library has internal module management for easy house keeping. A
module is a collection of algorithms, and each algorithm will register itself
with the Module Manager; each algorithm registers itself using the following
APIs.

  - `alcp_module_register()`
  - `alcp_module_deregister()`
  - `alcp_module_available()`

Some of the modules internally recognized at the time of writing are:
  - Digests   (`ALC_MODULE_DIGEST`)
  - Symmetric Ciphers (`ALC_MODULE_CIPHER`)
  - Message Authentication Codes (MAC) (`ALC_MODULE_MAC`)
  - Key Derivation Functions (KDF) (`ALC_MODULE_KEY`)
  - Random Number Generator (RNG) (`ALC_MODULE_RNG`)
  - Digest Signing and Verification (`ALC_MODULE_SIGN`)
  - Padding (`ALC_MODULE_PAD`)

Each module supports its own operation. For example, a Symmetric key module
supports
  - `alcp_cipher_encrypt()`
  - `alcp_cipher_decrypt()`
  - `alcp_cipher_available()`

The module also supports downward API's to register and manage algorithms. An
algorithm is a unit, an indivisible entity, that allows operations that are
specific to each type of module.

### Design
Each module is identified by the `alc_module_info_t` structure. It describes the
module type and supported operations.

The Module Manager is constructed as 'Singleton' pattern, a single instance
exists per process.

```c
typedef enum {
    ALC_MODULE_TYPE_INVALID = 0,

    ALC_MODULE_TYPE_DIGEST,
    ALC_MODULE_TYPE_MAC,
    ALC_MODULE_TYPE_EC,
    ALC_MODULE_TYPE_CIPHER,
    ALC_MODULE_TYPE_KDF,
    ALC_MODULE_TYPE_RNG,
    ALC_MODULE_TYPE_PADDING,

    ACL_MODULE_TYPE_MAX,
} alc_module_type_t;

```

The `alc_module_info_t` describes the module. The simple signature is checked to see if
the module belongs to aocl stack.

```c
typedef struct {
    const char         *name;
    alc_signature_t     signature;
    alc_module_type_t   type;
    void               *ops;
} alc_module_info_t;
```

Each module will have its own operations structure, for example: A Symmetric
Cipher algorithm will provide its own 'ops' structure as described in [Symmetric
Cipher Ops](#the-alc-cipher-ops-t-structure)

### APIs

The API `alcp_module_register()` tries to register the module with the module
manager, the registration process returns appropriate error codes to identify
the registration process's outcome.
Like other parts of AOCL Cryptography, use the `alcp_is_error()` API to detect success
or error. For more description see [ALC Error Types](#error-types)

```c
if (alcp_is_error(err)) {

}
```


```c
alc_error_t
alcp_module_register(alc_module_info_t *info);
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
Plugin system design
        #include design/plugins.md
-->


<!--
Device offloading
        #include design/devices.md
-->

