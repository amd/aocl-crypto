# Module Manager
## The Module Manager
### Introduction
The AOCL Crypto library has internal module management for easy house keeping. A
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
Like other parts of AOCL Crypto, use the `alcp_is_error()` API to detect success
or error. For more description see [ALC Error Types](#error-types)

```c
if (alcp_is_error(err)) {

}
```


```c
alc_error_t
alcp_module_register(alc_module_info_t *info);
```
