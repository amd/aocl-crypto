#include "conf.hh"
#include "digest_data.hh"
#include "common.hh"
#include "utils.hh"

int RunHashConformanceTest(_alc_sha2_mode digest_mode)
{
    _alc_hash_test_data test_data;
    /* Add more SHA digest cases here */
    switch (digest_mode)
    {
    case ALC_SHA2_224:
        RunConformance(digest_mode, &test_data, STRING_VECTORS_SHA224);
        break;
    case ALC_SHA2_256:
        RunConformance(digest_mode, &test_data, STRING_VECTORS_SHA256);
        break;
    default:
        break;
    }

    return 0;
}

/* run conformance with the test data provided */
int RunConformance(_alc_sha2_mode digest_mode,
               _alc_hash_test_data * test_data,
               std::vector <string_vector> test_vector)
{
    const char * sample_input;
    const char * expected_output;
    uint8_t * sample_output;
    long unsigned int test_data_len = test_vector.size();
    printf ("Data len: %ld\n", test_data_len);

    for (long unsigned int i = 0; i < test_data_len; i++) {
        sample_input    = test_vector[i].input;
        expected_output = test_vector[i].output;
	    test_data->input_data = sample_input;
	    test_hash(digest_mode, test_data);
	    sample_output = test_data->output_data;

	    CheckHashResult(sample_input, sample_output, expected_output);
    } 

    return 0;
}