#include "perf.hh"
#include "digest_data.hh"
#include "common.hh"
#include "utils.hh"

int RunHashPerformanceTest(_alc_sha2_mode digest_mode)
{
    _alc_hash_test_data test_data;
    /* Add more SHA digest cases here */
    switch (digest_mode)
    {
    case ALC_SHA2_224:
        RunHashPerformance(digest_mode, &test_data, STRING_VECTORS_SHA224);
        break;
    case ALC_SHA2_256:
        RunHashPerformance(digest_mode, &test_data, STRING_VECTORS_SHA256);
        break;
    default:
        break;
    }
    return 0;
}

/* run perf */
int RunHashPerformance(_alc_sha2_mode digest_mode,
               _alc_hash_test_data * test_data,
               std::vector <string_vector> test_vector)
{
        /* run with random data? */
        /* do we need a loop here?*/
	    test_data->input_data = test_vector[5].input;
	    test_hash(digest_mode, test_data);
    return 0;
}