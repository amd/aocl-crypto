#include "common.hh"
#include "digest_data.hh"

/*function to accept one test data, one digest algo, at a time, calculate hash of it */
int
test_hash(_alc_sha2_mode digest_mode, _alc_hash_test_data * test_data)
{
    const char* sample_input = test_data->input_data;
    uint8_t     sample_output[512] = { 0 };

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

	default:
		digest_type = ALC_DIGEST_TYPE_SHA2;
        digest_len  = ALC_DIGEST_LEN_224;
		break;
    }

    alc_error_t err = create_hash_session(&s_dg_handle, digest_type, digest_len, digest_mode);

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

/* just check input output */
int CheckHashResult(const char * sample_input, 
		    uint8_t * sample_output,
		    const char * expected_output)
{
    int result = 1;
    char output_string[65];

    printf("Input len: %ld\n", strlen(sample_input));

    hash_to_string(output_string, sample_output);

    printf("Input : %s\n", sample_input);
    printf("Expected: %s\n", expected_output);
    printf("output : %s\n", output_string);
    if (strcmp(expected_output, output_string)) {
        printf("=== FAILED ==== \n");
        printf("Expected output : %s\n", expected_output);
    } else {
        printf("=== Passed ===\n");
	result = 0;
    }
    return result;
}
