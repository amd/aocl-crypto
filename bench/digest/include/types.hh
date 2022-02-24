#ifndef TYPES_HH_
#define TYPES_HH_

#include "alcp/digest.h"

/* test types */
struct string_vector {
    const char* input;
    const char* output;
};

typedef enum _alc_test_type
{
    ALC_TEST_HASH_PERF,
    ALC_TEST_HASH_CONF,
} _alc_test_type_t;

/*test data*/
typedef struct _alc_hash_test_data
{
    const char * input_data;
    uint8_t * output_data;
} _alc_hash_test_data;

#endif  // TYPES_HH_
