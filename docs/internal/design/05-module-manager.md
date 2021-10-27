# Module Manager
The AOCL Crypto library has internal module management for easy house keeping. A
module has a collection of algorithms, and each algorithm will register itself
with the module. The Module Manager; each algorithm attaches itself to a module
and the module itself has following operations.

  - `module_register()`
  - `module_deregister()`
  - `module_available()`

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
specific to modules
