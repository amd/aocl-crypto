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

## Assumptions and Dependencies
AOCL Cryptography assumes following libraries/tools available on system where it is
built or running.

  - Required Dependancies
    - CMake (3.26 or later)
    - GCC (11.0 or later)
    - Git (2.30.2 or later)
    - OpenSSL ( 3.1.3 through 3.5.x )
    - Make ( 4.0 or later )
  - Optional Dependancies
    - Pandoc ( + LaTeX for generating pdf docs)
    - Doxygen
    - Sphinx

## General Constraints
The library will contain all the listed algorithms eventually.

OpenSSL compatibility library needs to be co-developed along with AOCL Cryptography,
as the requirement for drop-in replacement is crucial for AOCL Cryptography to
succeed.

# Architectural Strategies
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

Library will be provided as a static archive (libalcp.a on Linux and
alcp.lib on Windows) as well as a dynamic version (libalcp.so on
Linux and alcp.dll on Windows)

### Shared-library symbol visibility

#### Decision

Prior Linux builds rely on the compiler and linker defaults. Consequently,
the dynamic symbol tables of `libalcp.so`, `libipp-compat.so`, and
`libopenssl-compat.so` include public entry points and implementation symbols.
There is no machine-checked definition of the intended export surface.

This design makes hidden visibility the Linux default through
`ALCP_HIDDEN_VISIBILITY=ON`. It changes symbol publication, not cryptographic
behavior. A production Linux build exports the public C interface from
`libalcp.so`, the IPP compatibility interface from `libipp-compat.so`, and the
OpenSSL provider entry point from `libopenssl-compat.so`. Development builds
may additionally export a bounded, temporary C++ surface needed by bundled
consumers. The temporary surface is an implementation accommodation, not a
supported AOCL Cryptography interface.

The current public-header-derived C manifest contains 95 `alcp_*` functions.
That count was verified for this change and records the reviewed baseline; the
authoritative definition remains the annotated public headers, so an approved
API addition or removal may change the count. The IPP compatibility contract is
an exact, reviewed list of 73 functions. The OpenSSL compatibility contract is
exactly `OSSL_provider_init`.

#### Goals

  - Make accidental ELF exports fail automated checks.
  - Keep every documented public C API loadable from `libalcp.so`.
  - Preserve the existing default developer build and bundled tests, examples,
    and benchmarks while they still link to internal C++ APIs.
  - Provide C-only production builds when bundled consumers are disabled.
  - Give the IPP and OpenSSL compatibility DSOs explicit entry-point contracts.
  - Keep Linux and Windows export mechanisms explicit and independently
    maintainable.
  - Preserve source and runtime behavior, except for the intentional
    export-surface reduction and the compatibility fixes listed below.

#### Non-goals

  - No public C++ API or ABI is created. Mangled names, class layouts, RTTI,
    vtables, templates, and exception details may change without notice.
  - No external consumer may depend on the temporary C++ exceptions.
  - Hidden visibility does not replace API versioning or an ABI compatibility
    policy for the public C interface.
  - This feature does not alter algorithm selection, cryptographic operations,
    outputs, test vectors, or performance dispatch.
  - Static archives are not filtered; visibility controls dynamic symbol
    publication by shared libraries.
  - macOS is not supported by this feature. Darwin behavior is neither an export
    contract nor a tested approximation of the Linux policy.

#### Invariants

  1. Every public C declaration intended for dynamic use carries
     `ALCP_API_EXPORT`.
  2. With Linux hidden visibility enabled, an unannotated definition is not a
     public dynamic symbol.
  3. A production build, defined as `ALCP_ENABLE_TESTS=OFF`,
     `ALCP_ENABLE_EXAMPLES=OFF`, and `ALCP_ENABLE_BENCH=OFF`, exports no C++ API
     from `libalcp.so`.
  4. A bundled-consumer build may export only C++ names represented by
     `tests/export/alcp_export_cpp_exceptions.txt`.
  5. Temporary C++ exports exist solely to preserve in-tree consumers. They have
     no API or ABI guarantee and must not be advertised in installed/public API
     documentation or consumed as public interfaces.
  6. Hidden Linux `libipp-compat.so` exports exactly the 73 names in
     `lib/compat/ipp/ipp_compat_symbols.txt`.
  7. Hidden Linux `libopenssl-compat.so` exports exactly
     `OSSL_provider_init`.
  8. Disabling hidden visibility restores broad dynamic publication for all
     built DSOs. In that mode, checks require contracted symbols to exist but do
     not reject additional symbols.
  9. Windows exports remain explicit and do not depend on
     `ALCP_HIDDEN_VISIBILITY`.
  10. A change to an export contract and its declaration, definition, manifest,
      and tests is one atomic change.

#### Configuration matrix

Linux, `ALCP_HIDDEN_VISIBILITY=ON`, with any of tests, examples, or benchmarks
enabled:

  - `libalcp.so` exports the public C manifest plus required temporary C++
    exceptions.
  - The normal development default is in this category because
    `ALCP_ENABLE_EXAMPLES=ON` by default.
  - `ALCP_ENABLE_TESTS` and `ALCP_ENABLE_BENCH` default to `OFF`, but enabling
    either also enables the temporary C++ export accommodation.
  - Compatibility DSOs, when selected, retain their exact contracts: 73 IPP
    functions and `OSSL_provider_init`.

Linux, `ALCP_HIDDEN_VISIBILITY=ON`, with tests, examples, and benchmarks all
disabled:

  - This is the production configuration.
  - `libalcp.so` exports only the public C interface.
  - No temporary C++ exception is enabled or accepted.
  - The ELF version script provides a final allowlist of `alcp_*`; compiler
    annotations still determine which of those names are visible.

Linux, `ALCP_HIDDEN_VISIBILITY=OFF`:

  - Compiler-default broad visibility is retained for `libalcp.so` and all
    selected compatibility DSOs, matching the prior publication style.
  - Contracted symbols are still required. Extra symbols are allowed.
  - This setting is an escape hatch for migration and diagnosis, not the release
    configuration.

Static-only Linux builds:

  - Dynamic-export policy does not apply.
  - Tests use the static archive and do not require temporary shared-library C++
    exports.
  - Shared-export tests are not registered.

Windows:

  - `ALCP_HIDDEN_VISIBILITY` has no defined effect; it is a Linux-only option.
  - `ALCP_API_EXPORT` maps public C and enabled temporary C++ declarations to
    `__declspec(dllexport)`.
  - The OpenSSL provider uses its explicit OpenSSL export annotation; automatic
    `WINDOWS_EXPORT_ALL_SYMBOLS` is rejected.
  - IPP headers cannot safely be redeclared with `dllexport` under clang-cl, so
    CMake generates an exact `.def` file from the 73-name IPP manifest.
  - Windows therefore uses explicit declaration exports or an exact `.def`
    allowlist, never ELF visibility flags or the Linux version script.

macOS:

  - Unsupported by this feature.
  - No claim is made about Mach-O export completeness, strictness, or checker
    behavior. Support requires a separate design and platform-specific tests.

#### Manifests as policy

The public C manifest is generated from top-level `include/alcp/*.h` declarations
where `ALCP_API_EXPORT` is followed by an `alcp_*` function name. This makes
public declarations the source of truth and detects a declaration that lacks a
loadable definition. The extractor intentionally does not infer exports from
object files or accept arbitrary prefixes.

`tests/export/alcp_export_cpp_exceptions.txt` is the temporary C++ policy. A
`required` entry must match at least one demangled export. An `allow` entry
permits compiler-generated support such as RTTI, vtables, or selected standard
library template artifacts but does not require it. Entries are exact demangled
names unless terminated by `*`, which means an anchored fully qualified prefix.
Free substring matching is not accepted.

`lib/compat/ipp/ipp_compat_symbols.txt` is hand-reviewed and authoritative for
the IPP compatibility DSO. The same 73-name file drives Linux validation and
Windows `.def` generation, preventing platform lists from drifting.

The OpenSSL provider has one externally loadable function,
`OSSL_provider_init`. Its singleton contract is kept directly in the annotated
definition and export test rather than in a one-line manifest.

#### Compiler and linker defense in depth

On supported Linux builds with hidden visibility enabled, CMake selects hidden
C and C++ visibility and hides inline definitions. `ALCP_API_EXPORT`,
`IPP_COMPAT_EXPORT`, and the provider annotation selectively restore default
visibility. `ALCP_INTERNAL_CPP_EXPORT` and explicit-template annotations restore
visibility only when bundled consumers require the temporary C++ surface.

Production `libalcp.so` also links with `lib/alcp_exports.map`. The map publishes
`alcp_*` and localizes everything else. This second boundary protects against a
missed hidden compile flag or an accidentally default-visible internal symbol.
The map is not used while temporary C++ exports are enabled because it would
discard those required names. In both configurations, annotations remain the
first and most precise boundary.

This is intentionally redundant: annotations express ownership at declarations,
compiler defaults suppress accidental publication, the production linker map
provides a final C-only boundary, and binary checks validate the result.

#### Checker flow

Linux export checks are registered for shared builds with tests enabled. They
use target file paths for the built DSOs rather than guessing names or examining
the static archive. Windows uses `LoadLibrary` and `GetProcAddress` checks for
the explicit public manifests; ELF `nm`, `dlopen`, and `dlsym` checks are Linux
specific.

For `libalcp.so`, the checker:

  1. Regenerates the public C manifest from the source headers.
  2. Reads the C++ exception manifest.
  3. obtains defined dynamic symbols with `nm -D --defined-only`.
  4. Demangles C++ names with `c++filt`, including supported AddressSanitizer
     symbol wrappers.
  5. Reports every missing public C symbol.
  6. In bundled-consumer mode, reports a missing required C++ pattern and every
     export outside the C and C++ policies.
  7. In production mode, disables all C++ exceptions and reports every non-C
     export.
  8. With hidden visibility disabled, permits unlisted names and performs only
     required-symbol checks.

The GTest layer independently opens the DSO with `dlopen` and resolves each
required public C name with `dlsym`. Compatibility tests resolve all 73 IPP
names and `OSSL_provider_init`; hidden builds reject every unexpected defined
dynamic symbol, including weak functions and exported data. CTest labels separate
`export-alcp` and `export-compat` checks while retaining the common `unit` label.

Enabling the parent test suite itself enables temporary C++ exports, so it
cannot prove the production contract using its own `libalcp.so`. Production
validation therefore configures a separate child build with tests, examples,
and benchmarks disabled, builds only the shared library, regenerates the C
manifest, and runs the checker with all C++ exports disabled.

Failure is closed, not silent: an empty or missing manifest, unreadable DSO,
missing tool, `dlopen` failure, missing required symbol, unexpected strict-mode
symbol, malformed C++ pattern, or failed subprocess causes a nonzero test.

#### Concurrency and superproject use

Generated CMake manifests live in the current ALCP binary subtree. The shell
checker creates a uniquely named temporary C manifest with `mktemp` and removes
only that file on exit, so concurrent checks do not overwrite a shared
fixed-name manifest. Parallel configurations must still use separate CMake
binary directories, as required for normal CMake operation.

`config.h` is also generated under `ALCP_BINARY_DIR/include`, never into the
source checkout. Targets prefer that binary include directory. Therefore one
configuration cannot overwrite another configuration's library path, compiler,
or feature macros.

CMake passes the checker explicit source root, manifest directory, target file
paths, compatibility enablement, hidden-visibility state, and temporary-C++
state. The checker does not inspect a process-wide current directory, search
for a convenient DSO, or infer policy from a possibly stale cache. This makes a
failure identify the artifact and configuration that CMake actually built.

For superproject and `add_subdirectory` use, `ALCP_ROOT` identifies this source
checkout while `ALCP_BINARY_DIR` and target file generator expressions
identify this ALCP build. Export-manifest dependencies cover all public headers,
and generated files remain inside the corresponding binary subtree. A
configure probe verifies that the export-test graph can be created with AOCL
Cryptography below an enclosing project. Two configurations must not share one
binary directory; separate sub-builds may execute their checkers concurrently.

#### Maintenance procedure

Adding or removing a public C function requires updating its public declaration
with `ALCP_API_EXPORT`, its definition, API review material, and tests. The
generated manifest changes automatically. Reviewers must inspect the generated
delta and treat an unexpected count change as a policy change, not as snapshot
churn.

Adding an IPP compatibility function requires its implementation,
`IPP_COMPAT_EXPORT` on Linux, an entry in the 73-name manifest, and compatibility
tests. Because 73 is the exact approved contract, changing that count requires
explicit compatibility review.

No new C++ exception should be added merely to make a link succeed. First
migrate the consumer to the public C API or link an internal-only test to the
static archive. If neither is currently practical, add the narrowest exact
`required` pattern, annotate only the necessary declaration or instantiation,
document the bundled consumer, and add a removal path. Wildcards over a class or
namespace require specific justification.

`alcp::utils::CpuId` is a documented temporary exception because bundled tests,
benchmarks, and the cpuid example query selected methods through `libalcp.so`.
Only named methods are annotated; `CpuId::Impl`, `pImpl`, and unused methods
remain hidden. New consumers must use documented algorithm-support checks
instead of expanding this exception.

An export failure is fixed at its source. Missing public C symbols require a
declaration/definition correction. Unexpected symbols require removing or
narrowing an annotation, changing consumer linkage, or updating an explicitly
approved contract. Disabling the checker, broadening a wildcard, or turning
hidden visibility off is not a production fix.

#### Compatibility and migration

Existing Linux binaries that use the documented C API continue to resolve the
same entry points. Existing binaries or source builds that directly use
previously leaked C++ or internal C symbols were relying on unsupported
behavior; they must migrate to the public C API. `ALCP_HIDDEN_VISIBILITY=OFF`
provides a temporary broad-visibility migration mode, but does not convert those
symbols into supported interfaces.

Bundled tests, examples, and benchmarks retain existing linkage behavior while
temporary C++ exports are enabled. The intended migration is to public C APIs or
static internal linkage, followed by removal of the relevant exception.
Production builds opt out immediately by disabling all three bundled-consumer
options.

Windows consumers continue to use explicitly exported declarations. The IPP
`.def` list and removal of OpenSSL automatic export-all behavior make accidental
Windows publication a build-policy violation rather than an implicit contract.

#### Required supporting behavior changes

The visibility work contains three reviewed non-algorithmic source changes:

  - `alcp_rng_init` already existed in the public header but had no implementation.
    It is now a validated compatibility no-op: null handle or null context is
    rejected; a valid requested RNG context returns `ALC_ERROR_NONE` without
    changing state.
  - Digest examples now format hexadecimal output with bounded `snprintf` calls
    and explicit destination sizes instead of advancing an unbounded `sprintf`
    pointer.
  - Supporting declaration/include and linkage corrections make the stricter
    builds compile and link.

There are zero cryptographic algorithm changes. Cipher, digest, MAC, RNG, DRBG,
RSA, and elliptic-curve computation semantics remain unchanged.

#### Decisions and rejected alternatives

Selected: hidden-by-default Linux builds, declaration annotations, a production
linker map, explicit manifests, and binary validation. This gives local
ownership plus an independently checked final artifact.

Rejected: relying only on compiler hidden visibility. One missed flag or
default-visible annotation could leak a symbol without detection.

Rejected: relying only on an `alcp_*` linker wildcard. It cannot prove that each
documented function is present, and it does not define compatibility or
temporary C++ surfaces.

Rejected: maintaining a second hand-written list of the public C API. It would
duplicate public headers and drift. The generated 95-name baseline is reviewed,
but annotations remain authoritative.

Rejected: exporting all C++ internals for developer convenience. That would
preserve accidental dependencies and imply an ABI that the project cannot
guarantee.

Rejected: linking every bundled consumer statically in this change. It would
stop tests and examples from exercising `libalcp.so` and would hide
dynamic-link regressions.

Rejected: applying the production version script while temporary C++ consumers
are enabled. Its C-only wildcard would make those consumers fail to link.

Rejected: automatic Windows export-all. It publishes implementation details and
makes the ABI depend on compiler object discovery. Explicit `dllexport` and the
IPP `.def` contract are deterministic.

Rejected: claiming macOS support from generic Unix CMake conditions. Mach-O
needs its own export-list mechanism, artifact inspection, and CI evidence.

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

    /*
     * Algorithm is implimented for specific hardware only
     * and no fallback implementaion is available
     */
    ALC_ERROR_NO_FALLBACK,

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
