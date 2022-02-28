#ifndef COMMON_HH_
#define COMMON_HH_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "alcp/digest.h"
#include "types.hh"

/* functions for test hash*/
/* create session, as per scheme provided,save the session in the handle,
   which will be passed on to the hash function */
alc_error_t
create_hash_session(alc_digest_handle_t * s_dg_handle,
		            _alc_digest_type digest_type,
                    _alc_digest_len  digest_len,
                    _alc_sha2_mode   digest_mode);

/*Actual function which does digest operation on the input data */
alc_error_t
hash_function(alc_digest_handle_t * s_dg_handle,
	          const char * src,
              uint64_t  src_size,
              uint8_t * output,
              uint64_t  out_size);

/* hash to string */
void
hash_to_string(char string[65],
               const uint8_t hash[32],
               int sha_len);

#endif //COMMON_HH_
