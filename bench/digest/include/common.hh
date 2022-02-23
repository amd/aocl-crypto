#ifndef COMMON_HH_
#define COMMON_HH_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alcp/digest.h"

/* test types */
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

/* functions for test hash*/
alc_error_t
create_hash_session(alc_digest_handle_t * s_dg_handle,
		    _alc_digest_type digest_type,
                    _alc_digest_len  digest_len,
                    _alc_sha2_mode   digest_mode);

alc_error_t
hash_function(alc_digest_handle_t * s_dg_handle,
	       const char * src,
               uint64_t  src_size,
               uint8_t * output,
               uint64_t  out_size);

void
hash_to_string(char string[65], const uint8_t hash[32]);

int
CheckHashResult(const char * sample_input,
                    uint8_t * output,
                    const char * expected_output);

int
test_hash(_alc_sha2_mode digest_mode,
		_alc_hash_test_data * test_data);

int
RunHashConformanceTest(_alc_sha2_mode digest_mode);

#endif //COMMON_HH_
