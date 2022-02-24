#ifndef PERF_HH_
#define PERF_HH_

#include "alcp/digest.h"
#include "types.hh"
#include <vector>

#define PERF_TEST_LOOP 1000

/*perf*/
int
RunHashPerformance(_alc_sha2_mode digest_mode,
               _alc_hash_test_data * test_data,
               std::vector <string_vector> test_vector);

int
RunHashPerformanceTest(_alc_sha2_mode digest_mode);

#endif // PERF_HH_