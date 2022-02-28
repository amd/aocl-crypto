#include "common.hh"
#include "digest_data.hh"
#include "utils.hh"

/*function to accept one test data, one digest algo, at a time, calculate hash of it */
int
test_hash(_alc_sha2_mode digest_mode, _alc_hash_test_data * test_data)
{
    const char* sample_input = test_data->input_data;
    static uint8_t sample_output[512] = { 0 };

    test_data->output_data = sample_output;

    alc_digest_handle_t s_dg_handle;
    _alc_digest_type digest_type;
    _alc_digest_len digest_len;

    /* Add more SHA digest cases here */
    switch (digest_mode) {
        case ALC_SHA2_224:
	digest_type = ALC_DIGEST_TYPE_SHA2;
	digest_len  = ALC_DIGEST_LEN_224;
	break;
    
        case ALC_SHA2_256:
        digest_type = ALC_DIGEST_TYPE_SHA2;
        digest_len = ALC_DIGEST_LEN_256;
        break;

        case ALC_SHA2_384:
        digest_type = ALC_DIGEST_TYPE_SHA2;
        digest_len = ALC_DIGEST_LEN_384;
        break;

        case ALC_SHA2_512:
        digest_type = ALC_DIGEST_TYPE_SHA2;
        digest_len = ALC_DIGEST_LEN_512;
        break;

	default:
	digest_type = ALC_DIGEST_TYPE_SHA2;
        digest_len  = ALC_DIGEST_LEN_224;
	break;
    }

    alc_error_t err = create_hash_session(&s_dg_handle,
		                                  digest_type,
					                      digest_len,
					                      digest_mode);

    if (alcp_is_error(err))
        alcp_digest_finish(&s_dg_handle);

    if (!alcp_is_error(err)) {
        err = hash_function(&s_dg_handle,
                            sample_input,
                            strlen(sample_input),
                            test_data->output_data,
                            sizeof(sample_output));
    }

    return 0;
}

/* Verify output and expected */
int
CheckHashResult(const char * sample_input, 
		        uint8_t * sample_output,
		        const char * expected_output,
                int sha_len)
{
    int result = 1;
    char * output_string = (char*)malloc((sha_len/8)*2 + 1);

    printf("Input len: %ld\n", strlen(sample_input));

    hash_to_string(output_string, sample_output, sha_len);

    if (strcmp(expected_output, output_string)) {
        /* later print these data based on a verbose option */
        printf("=== FAILED ==== \n");
        printf("Input : %s\nExpected: %s\nActualOutput: %s\n",
               sample_input, expected_output, output_string);
    } else {
        printf("=== PASSED ===\n");
	    result = 0;
    }
    free(output_string);

    return result;
}

/* Hash value to string */
void
hash_to_string(char * output_string,
               const uint8_t * hash,
               int sha_len)
{
    for (int i = 0; i < sha_len/8; i++) {
        output_string += sprintf(output_string, "%02x", hash[i]);
    }
    output_string[(sha_len/8)*2 + 1] = '\0';
}
