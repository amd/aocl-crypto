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

