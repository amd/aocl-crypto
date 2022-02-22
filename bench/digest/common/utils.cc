#include "common.hh"
#include "digest_data.hh"

int test_hash(void) {
    const char * sample_input;
    const char * expected_output;
    uint8_t sample_output[512] = { 0 };
    char output_string[65];
    alc_digest_handle_t s_dg_handle;

    /* later pass this as a param */
    _alc_digest_type digest_type = ALC_DIGEST_TYPE_SHA2;
    _alc_digest_len digest_len = ALC_DIGEST_LEN_224;
    _alc_sha2_mode digest_mode = ALC_SHA2_224;

    for (long unsigned int i = 0;
         i < (sizeof STRING_VECTORS_SHA224 / sizeof(struct string_vector));
         i++) {
        sample_input = STRING_VECTORS_SHA224[i].input;
        expected_output = STRING_VECTORS_SHA224[i].output;
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
                                sample_output,
                                sizeof(sample_output));
        }

	/*move this to a diff check later on*/
        // check if the outputs are matching
        hash_to_string(output_string, sample_output);
        printf("Input : %s\n", sample_input);
        printf("output : %s\n", output_string);
        if (strcmp(expected_output, output_string)) {
            printf("=== FAILED ==== \n");
            printf("Expected output : %s\n", expected_output);
        } else {
            printf("=== Passed ===\n");
        }
    }
    return 0;
}
