#ifndef CONF_HH_
#define CONF_HH_

#include "alcp/digest.h"
#include <vector>
#include "types.hh"
#include "digest_data.hh"

int
RunHashConformanceTest(_alc_sha2_mode digest_mode);

/* run conformance with the test data provided */
int RunConformance(_alc_sha2_mode digest_mode,
               _alc_hash_test_data * test_data,
               std::vector <string_vector> test_vector);

#endif