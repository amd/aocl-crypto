#ifndef UTILS_HH_
#define UTILS_HH_

#include "alcp/digest.h"
#include "types.hh"
#include "digest_data.hh"

/*function to accept one test data, for one digest algo,
 * calculate hash of it */
int
test_hash(_alc_sha2_mode digest_mode,
          _alc_hash_test_data * test_data);

/* check output and expected */
int
CheckHashResult(const char * sample_input, 
		        uint8_t * sample_output,
		        const char * expected_output,
	            int sha_len);

/* Hash value to string */
void
hash_to_string(char * string,
               const uint8_t * hash,
               int sha_len);

#endif
