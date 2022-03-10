#ifndef COMMON_HH_
#define COMMON_HH_

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* for malloc */
#include <string.h>
#include <time.h>
#include "types.hh"

#include <benchmark/benchmark.h>

#include <immintrin.h>
#include <wmmintrin.h>

int
cipher_test(
    benchmark::State&     state,
    alc_aes_mode_t        mode,
    _alc_cipher_test_type t_type);

void
GenerateRandomInput(
    uint8_t* output,
    int      inputLen,
    int      seed);

void
create_aes_session(
    uint8_t*             key,
    uint8_t*             iv,
    const uint32_t       key_len,
    const alc_aes_mode_t mode);

void
aclp_aes_encrypt(
    benchmark::State& state,
    _alc_cipher_test_type t_type,
    const uint8_t *       plaintxt,
    const uint32_t        len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*              ciphertxt,
    uint8_t*              iv);

void
aclp_aes_decrypt(
    benchmark::State&     state,
    _alc_cipher_test_type t_type,
    const uint8_t *       ciphertxt,
    const uint32_t        len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*              plaintxt,
    uint8_t*              iv);

int
encrypt_decrypt_test(
    benchmark::State&     state,
    _alc_cipher_test_type t_type,
    uint8_t*              inputText,  // plaintext
    uint32_t              inputLen,   // input length
    uint8_t*              cipherText, // ciphertext output
    alc_aes_mode_t        mode);

int
cipher_test(
    alc_aes_mode_t        mode,
    _alc_cipher_test_type t_type);

#endif


