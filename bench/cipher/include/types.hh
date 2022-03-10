#ifndef TYPES_HH_
#define TYPES_HH_

#include "alcp/digest.h"

/* conformance test vector */
typedef struct _alc_cipher_kat_vector {
    const uint8_t * input;
    const uint8_t * key;
    const uint8_t * expected;
} _alc_cipher_kat_vector;

/* test type */
typedef enum _alc_cipher_test_type {
    ALC_TEST_CIPHER_PERF,
    ALC_TEST_CIPHER_CONF,
} _alc_cipher_test_type_t;

/*test data*/
typedef struct _alc_cipher_test_data {
    const uint8_t * plaintext;
    const uint8_t * key;
    uint8_t * ciphertext;
} _alc_cipher_test_data;

#endif  // TYPES_HH_
