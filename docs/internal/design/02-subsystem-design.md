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
\#define ALC_KEY_LEN_DEFAULT  128
\#define BITS_TO_BYTES(x) (x >> 8)

typedef struct {
    alc_key_type_t    k_type;
    alc_key_algo_t    k_algo;
    uint32_t          k_len;    /* Key length in bits */
    uint8_t           k_key[0]; /* Key follows the rest of the structure */
} alc_key_info_t;
```


## Digests

### Design
The datatype `alc_digest_type_t` describes the digest that is being requested or
operated on.

```c
typedef enum _alc_digest_type 
{

    ALC_DIGEST_TYPE_MD2,
    ALC_DIGEST_TYPE_MD4,

    ALC_DIGEST_TYPE_MD5,
    ALC_DIGEST_TYPE_SHA1,
    ALC_DIGEST_TYPE_SHA2,
    ALC_DIGEST_TYPE_SHA3,
} alc_digest_type_t;
```

```c
typedef enum _alc_digest_attr {
    ALC_DIGEST_ATTR_SINGLE,     /* Block */
    ALC_DIGEST_ATTR_MULTIPART,  /* Stream */
} alc_digest_attr_t;
```

```c
typedef struct _alc_digest_info_t {
    alc_digest_type_t type;
    alc_digest_attr_t attr;
} alc_digest_info_t;


#ifndef __cplusplus
typedef void*  alc_digest_ctx_t;
#endif

```

### The _Digest_ class
This is the C++ interface to the Digests, all digest algorithms will be
inherited by this class.

```c++
class DigestInterface {
  public:
    virtual alc_error_t update(const Uint8* pBuf, Uint64 size)   = 0;
    virtual alc_error_t finalize(const Uint8* pBuf, Uint64 size) = 0;
    virtual void        finish()                                 = 0;
    virtual alc_error_t copyHash(Uint8* pBuf, Uint64 size) const = 0;
  protected:
    //static cpuid_variant cpu;
};
```
All algorithms are expected to implement the `DigestInterface` abstract base class.



 
```c++
class Sha2 : public DigestInterface {
  public:
    Sha2(alc_sha2_mode_t mode)
            :m_mode{mode}
    {
        if (cpuid::isCpu(ALC_CPU_ZEN3)) {
            m_finit{sha256}
        }
    }
    virtual bool init(args) {m_finit(args);}
    virtual bool update(args) {f_fupdate(args);}
    virtual bool finalize(args) {m_ffinalize(args);}

    // stream digest
    virtual bool compute(args) {m_fcompute(args);}
  private:
    Sha2() {}

    alc_sha2_mode_t m_mode;
    alc_sha2_attr_t m_attr;
    alc_sha2_param_t m_param;

    std::function m_fupdate, m_ffinalize, m_fcompute;
};

```

### API
Digests are computed like the other subsystem, All APIs are prefixed with
`alcp_digest`, `alcp` being project prefix and `digest` being subsystem prefix.
Following are the C99 APIs.

 1. Query: One needs to query the library and see if a required algorithm is
    supported. Only upon making sure the algorithm and its parameterized
    customization is supported by library, application writer must proceed to
    next steps.
    ```c
    alc_error_t
    alcp_digest_supported(const alc_digest_info_t *);
    ```

 2. Context size determination: The context size needs to be queried form the
    library, this helps the Application designer to allocate and free the memory
    needed for the 'Handle'.
    ```c
    Uint64
    alcp_digest_context_size(const alc_digest_info_t *);
    ```

 3. Request : The application needs to request the 'Handle', and supposed to
    send required configuration via the input of type `alc_digest_info_t`.
    ```c
    alc_error_t
    alcp_digest_request(const alc_digest_info_t* p_digest_info,
                        alc_digest_handle_t*     p_digest_handle);
    ```

 4. Update : Both block and stream digests are treated alike, however the
    update() method allows application to build on previously processed blocks.

    ```c
    alc_error_t
    alcp_digest_update(const alc_digest_handle_t* p_digest_handle,
                       const Uint8*               buf,
                       Uint64                     size);
    ```
 5. Finalize: This is the marker for last block, or end of sequence. Once this
    is called, its not possible to call update() again.

    ```c
    alc_error_t
    alcp_digest_finalize(const alc_digest_handle_t* p_digest_handle,
                         const Uint8*              p_msg_buf,
                         Uint64                    size);
    ```

 6. Finish : This is a cleanup phase, once finish is called the session ends,
    and the handle is no longer valid. Hence the digest needs to be copied by
    the application before this step.
    ```c
    void
    alcp_digest_finish(const alc_digest_handle_t* p_digest_handle);
    ```

 7. Copy : The digest that is computed is held as part of internal
    representation, that needs to be requested by application to be copied to a
    buffer before calling `alcp_digest_finish()`.
    ```c
    alc_error_t
    alcp_digest_copy(const alc_digest_handle_t* p_digest_handle,
                     Uint8*                    buf,
                     Uint64                    size);
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
    ALC_RNG_TYPE_DISCRETE,

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

## Random Number Generator (RNG)

### PRNG

### TRNG

## Message Authentication Codes (MAC)
