#include "conf.hh"
#include "digest_data.hh"
#include "common.hh"
#include "utils.hh"

int
RunHashConformanceTest(_alc_sha2_mode digest_mode)
{
    _alc_hash_test_data test_data;
    int fail = 0, sha_len;
    /* Add more SHA digest cases here */
    switch (digest_mode)
    {
    case ALC_SHA2_224:
        sha_len = 224;
        fail = RunConformance(digest_mode, &test_data, STRING_VECTORS_SHA224, sha_len);
        printf ("%d Conformance Tests failures for SHA224\n", fail);
        break;
    case ALC_SHA2_256:
        sha_len = 256;
        fail = RunConformance(digest_mode, &test_data, STRING_VECTORS_SHA256, sha_len);
        printf ("%d Conformance Test failures for SHA256\n", fail);
        break;
    case ALC_SHA2_384:
        sha_len = 384;
        fail = RunConformance(digest_mode, &test_data, STRING_VECTORS_SHA384, sha_len);
        printf ("%d Conformance Test failures for SHA384\n", fail);
        break;
    case ALC_SHA2_512:
        sha_len = 512;
        fail = RunConformance(digest_mode, &test_data, STRING_VECTORS_SHA512, sha_len);
        printf ("%d Conformance Test failures for SHA512\n", fail);
        break;
    default:
        break;
    }

    return 0;
}

/* run conformance with the test data provided */
int
RunConformance(_alc_sha2_mode digest_mode,
                   _alc_hash_test_data * test_data,
                   std::vector <_alc_hash_kat_vector> test_vector,
                   int sha_len)
{
    const char * sample_input;
    const char * expected_output;
    uint8_t * sample_output;
    long unsigned int test_data_len = test_vector.size();
    printf ("Data len: %ld\n", test_data_len);
    int fail = 0;

    for (long unsigned int i = 0; i < test_data_len; i++) {
        sample_input    = test_vector[i].input;
        expected_output = test_vector[i].output;
        test_data->input_data = sample_input;
        /* this is the actual hash function */
        test_hash(digest_mode, test_data);
        sample_output = test_data->output_data;
        /*check results if o/p and expected match */
        if (CheckHashResult(sample_input, sample_output, expected_output, sha_len)) {
            fail++;
        }
    } 
    return fail;
}
