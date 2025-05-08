# Detailed Subsystem Design

## Digests
### Design
The datatype `alc_digest_mode_t` describes the digest that is being requested or
operated on.

```c
typedef enum _alc_digest_mode
{
    ALC_MD5,
    ALC_SHA1,
    ALC_MD5_SHA1,
    ALC_SHA2_224,
    ALC_SHA2_256,
    ALC_SHA2_384,
    ALC_SHA2_512,
    ALC_SHA2_512_224,
    ALC_SHA2_512_256,
    ALC_SHA3_224,
    ALC_SHA3_256,
    ALC_SHA3_384,
    ALC_SHA3_512,
    ALC_SHAKE_128,
    ALC_SHAKE_256,
} alc_digest_mode_t,
```

### The _Digest_ class
This is the C++ interface to the Digests. All digest algorithms will 
inherit this class.

```c++
class IDigest
{
  public:
    IDigest() = default;

  public:
    virtual void        init(void)                             = 0;
    virtual alc_error_t update(const Uint8* pBuf, Uint64 size) = 0;
    virtual alc_error_t finalize(Uint8* pBuf, Uint64 size)     = 0;
    /**
     * @return The input block size to the hash function in bytes
     */
    Uint64 getInputBlockSize() { return m_block_len; }

    /**
     * @return The digest size in bytes
     */
    Uint64 getHashSize() { return m_digest_len; }

    virtual ~IDigest() {}

  protected:
    Uint64 m_digest_len = 0; /* digest len in bytes */
    Uint64 m_block_len  = 0;
    bool   m_finished   = false;
    Uint64 m_msg_len    = 0;
    /* index to m_buffer of previously unprocessed bytes */
    Uint32            m_idx = 0;
    alc_digest_mode_t m_mode;
};
```
All algorithms are expected to implement the `IDigest` abstract base class.

```c++
template<alc_digest_len_t digest_len>
class Sha2 final : public IDigest
{
    static_assert(ALC_DIGEST_LEN_224 == digest_len
                  || ALC_DIGEST_LEN_256 == digest_len);

  public:
    static constexpr Uint64 /* define word size */
        cWordSizeBits   = 32,
        cNumRounds      = 64,                 /* num rounds in sha256 */
        cChunkSizeBits  = 512,                /* chunk size in bits */
        cChunkSize      = cChunkSizeBits / 8, /* chunks to process */
        cChunkSizeMask  = cChunkSize - 1,
        cChunkSizeWords = cChunkSizeBits / cWordSizeBits, /* same in words */
        cHashSizeBits   = ALC_DIGEST_LEN_256,             /* same in bits */
        cHashSize       = cHashSizeBits / 8, /* Hash size in bytes */
        cHashSizeWords  = cHashSizeBits / cWordSizeBits;

  public:
    ALCP_API_EXPORT Sha2();
    ALCP_API_EXPORT Sha2(const Sha2& src);
    virtual ALCP_API_EXPORT ~Sha2() = default;

  public:
    ALCP_API_EXPORT void init(void) override;

    ALCP_API_EXPORT alc_error_t update(const Uint8* pMsgBuf,
                                       Uint64       size) override;

    ALCP_API_EXPORT alc_error_t finalize(Uint8* pBuf, Uint64 size) override;

  private:
    alc_error_t processChunk(const Uint8* pSrc, Uint64 len);
    /* Any unprocessed bytes from last call to update() */
    alignas(64) Uint8 m_buffer[2 * cChunkSize]{};
    alignas(64) Uint32 m_hash[cHashSizeWords]{};
};

```

### API
Digests are computed like the other subsystem, All APIs are prefixed with
`alcp_digest`, `alcp` being project prefix and `digest` being subsystem prefix.
Following are the C99 APIs.

 1. Context size determination: The context size needs to be queried from the
    library, this helps the Application designer to allocate and free the memory
    needed for the 'Handle'.
    ```c
    Uint64
    alcp_digest_context_size();
    ```

 2. Request : The application needs to request the 'Handle', and supposed to
    send required configuration via the input of type `alc_digest_mode_t`.
    ```c
    alc_error_t
    alcp_digest_request(alc_digest_mode_t mode,
                        alc_digest_handle_t*     p_digest_handle);
    ```

 3. Init : Initializes the digest object. This is called to start a new sequence
    of digest creation.
    ```c
    alc_error_t
    alcp_digest_init(alc_digest_handle_p p_digest_handle);
    ```

 4. Update : Both block and stream digests are treated alike, however the
    update() method allows application to build on previously processed blocks.
    ```c
    alc_error_t
    alcp_digest_update(const alc_digest_handle_t* p_digest_handle,
                       const Uint8*               buf,
                       Uint64                     size);
    ```
    
 5. Duplicate : Duplicates the digest handle from 'pSrcHandle' to 'pDestHandle'.
    The independent duplicated handled can then be used to proceed with the remaining steps in lifecycle
    ```c
    alc_error_t
    alcp_digest_context_copy(const alc_digest_handle_p pSrcHandle,
                             const alc_digest_handle_p pDestHandle);
    ```

 6. Squeeze : Valid only for Shake(SHA3) algorithm for squeezing the digest out.
    This can be called multiple times to squeeze the digest out in steps.
    This API cannot be called together with 'alcp_digest_finalize'.
     ```c
    alc_error_t
    alcp_digest_shake_squeeze(const alc_digest_handle_p pDigestHandle,
                              Uint8*                    pBuff,
                              Uint64                    size);
    ```

 7. Finalize: This is the marker for end of sequence and also copies the digest that is computed. Once this
    is called, its not possible to call update() again.
    ```c
    alc_error_t
    alcp_digest_finalize(const alc_digest_handle_t* p_digest_handle,
                         Uint8*                     digest,
                         Uint64                     digest_size);
    ```

 8. Finish : This is a cleanup phase, once finish is called the session ends,
    and the handle is no longer valid. Hence the digest needs to be copied by
    the application before this step.
    ```c
    void
    alcp_digest_finish(const alc_digest_handle_t* p_digest_handle);
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
alcp_cipher_request(const alc_cipher_mode_t cipherMode,
                    const Uint64            keyLen,
                    alc_cipher_handle_p     pCipherHandle);
```

In the above api, `alc_cipher_mode_t` is described as in
[`alc_cipher_mode_t`](#the-alc_cipher_mode_t-type), which describes the
cipher type and mode of operation

```c

```

#### The `alc_cipher_context_t` structure ####

The Cipher's context is very specific to a given cipher algorithm. This
type is an opaque pointer which is purely internal to the library.

```c
typedef void alc_cipher_context_t;
```

#### The `alc_cipher_mode_t` type ####

Cipher modes are expressed in one of the following enumerations
```c
typedef enum _alc_cipher_mode
{
    ALC_AES_MODE_NONE = 0,

    // aes ciphers
    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTS,
    // non-aes ciphers
    ALC_CHACHA20,
    // aes aead ciphers
    ALC_AES_MODE_GCM,
    ALC_AES_MODE_CCM,
    ALC_AES_MODE_SIV,
    // non-aes aead ciphers
    ALC_CHACHA20_POLY1305,

    ALC_AES_MODE_MAX,

} alc_cipher_mode_t;
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

Descrete Distribution formats:

| Type of Distribution | Data Types | RNG  | Description                                             |
| :--                  | :--:       | :--: | :--                                                     |
| Uniform              | i          | i    | Uniform discrete distribution on the interval [a,b)     |
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

Random Generation algorithms and their distribution are described by 
enumeration `alc_rng_distribution_t`.

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

## Random Number Generator (RNG)

### PRNG

### TRNG

## Message Authentication Codes (MAC)
