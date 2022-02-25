#ifndef UTILS_HH_
#define UTILS_HH_

#include "alcp/digest.h"
#include "types.hh"

/*function to accept one test data, one digest algo, at a time, calculate hash of it */
int
test_hash(_alc_sha2_mode digest_mode, _alc_hash_test_data * test_data);

/* just check input output */
int
CheckHashResult(const char * sample_input, 
		    uint8_t * sample_output,
		    const char * expected_output);

#endif