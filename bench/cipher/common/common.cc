#include "alcp/alcp.h"
#include "common.hh"

static alc_cipher_handle_t handle;

// to do: these macro is better to be moved to common header.
long   seconds;
long   microseconds;
double elapsed;
double totalTimeElapsed;

void
GenerateRandomInput(uint8_t* output, int inputLen, int seed)
{
    // generate same random input based on seed value.
    srand(seed);
    for (int i = 0; i < inputLen; i++) {
        *output = (uint8_t)rand();
        output++;
    }
}

void
create_aes_session(uint8_t*             key,
                   uint8_t*             iv,
                   const uint32_t       key_len,
                   const alc_aes_mode_t mode)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    alc_aes_info_t aes_data = {
        .ai_mode = mode,
        .ai_iv   = iv,
    };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .len     = key_len,
            .key     = key,
        },
        .ci_mode_data   = {
            .cm_aes = aes_data,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

void
aclp_aes_encrypt(
    benchmark::State& state,
    _alc_cipher_test_type t_type,
    const uint8_t* plaintxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       ciphertxt,
    uint8_t*       iv)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    /* profile this call if test type is perf*/
    if (t_type == ALC_TEST_CIPHER_PERF) {
        for (auto _ : state) {
            err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
        }
        state.counters["Encryption Speed (Bits/Sec)"] = benchmark::Counter(state.iterations() * len * 8,
                                                    benchmark::Counter::kIsRate);
    }
    else
        err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: Encrypt failed \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

void
aclp_aes_decrypt(
    benchmark::State& state,
    _alc_cipher_test_type t_type,
    const uint8_t* ciphertxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       plaintxt,
    uint8_t*       iv)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    /* profile this call if test type is perf */
    if (t_type == ALC_TEST_CIPHER_PERF) {
        for (auto _ : state) {
            err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, iv);
        }
        state.counters["Decryption Speed (Bits/Sec)"] = benchmark::Counter(state.iterations() * len * 8,
                                                    benchmark::Counter::kIsRate);
    }
    else
        err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, iv);

    if (alcp_is_error(err)) {
        printf("Error: Decrypt failed \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
}

/*
    Demo application for complete path:
    input->encrypt->cipher->decrypt->output.
    input and output is matched for comparison.
*/
int
encrypt_decrypt_test(
                     benchmark::State& state,
                     _alc_cipher_test_type t_type,
                     uint8_t*       inputText,  // plaintext
                     uint32_t       inputLen,   // input length
                     uint8_t*       cipherText, // ciphertext output
                     alc_aes_mode_t m)
{
    unsigned int keybits;
    uint8_t      key[32];

    memset(key, 0, 32);

    uint8_t* outputText;
    outputText = (uint8_t * )malloc(inputLen);

    uint8_t* iv;
    iv = (uint8_t * )malloc(16 * 4);
    memset(iv, 0, 16 * 4);

    uint8_t* ref;
    ref = (uint8_t * )malloc(inputLen);

    for (int i = 0; i < 1; i++) { // limit the test to 128bit.
        int u   = i;
        keybits = 128 + u * 64;
        printf("\n keybits %d ", keybits);
        memset(key, ((i * 10) + m), 32);

        memset(inputText, i, inputLen);

        /*  Generate random input text based on seed.
            seed is kept constant(1) for simplicity, it can be
            modified for testing. */
        int seed = 1;
        GenerateRandomInput(inputText, inputLen, seed);

        memset(cipherText, 0, inputLen);
        memset(ref, 0, inputLen);
        memset(outputText, 0, inputLen);

        create_aes_session(key, iv, keybits, m);

        /* measure encrypt performance here */
        aclp_aes_encrypt(
                state,
                t_type,
                inputText,
                inputLen,
                cipherText,
                iv);

        aclp_aes_decrypt(
                state,
                t_type,
                cipherText, // pointer to the PLAINTEXT
                inputLen,   // text length in bytes
                outputText, // pointer to the CIPHERTEXT buffer
                iv);

        /* if test type is conformance, only then check this */
        if (t_type == ALC_TEST_CIPHER_CONF) {
            if (memcmp(inputText, outputText, (long unsigned int)inputLen) != 0) {
                printf("FAILED \n");
            }
            else {
                printf("Passed");
            }
        }
        /*
         * Complete the transaction
         */
        alcp_cipher_finish(&handle);
        free(handle.ch_context);
    }

    if (outputText) {
        free(outputText);
    }
    if (iv) {
        free(iv);
    }
    if (ref) {
        free(ref);
    }

    return 0;
}

int
cipher_test(benchmark::State& state,
            alc_aes_mode_t mode,
            _alc_cipher_test_type t_type)
{
    uint8_t* inputText;
    uint8_t* cipherText;

    /*
     * Demo application validates complete encrypt and decrypt path
     * input feed to encrypt and output from encrypt are compared and validated.
     */

    printf("\n AOCL-CRYPTO: AES Demo application ");
 
    switch (mode)
    {
    /*case ALC_AES_MODE_ECB:
         ALC_AES_MODE_CTR:
         ALC_AES_MODE_XTR:
         printf("Not implemented\n");
         return -1;
         break;
    */
    case ALC_AES_MODE_CBC:
        printf ("CBC\n");
        break;
    case ALC_AES_MODE_OFB:
        printf ("OFB\n");
        break;
    case ALC_AES_MODE_CFB:
        printf ("CFB\n");
        break;
    default:
        printf("Invalid AES Mode\n"); 
        break;
    }

    // keep length multiple of 128bit (16x8)
    int inputLen = 16384;
    printf(" :Encrypt and decrypt demo with input length %d bytes", inputLen);
    for (; inputLen <= 16384; inputLen = (inputLen * 4)) {
        // allocate inputText and cipherText memory
        inputText = (uint8_t * )malloc(inputLen);
        if (inputText == NULL) {
            return -1;
        }
        cipherText = (uint8_t * )malloc(inputLen);
        if (cipherText == NULL) {
            if (inputText) {
                free(inputText);
            }
            return -1;
        }

        encrypt_decrypt_test(
            state,
            t_type,
            inputText,
            inputLen, /* len of both 'plaintxt' and 'ciphertxt' */
            cipherText,
            mode);

        // its time to free!
        if (inputText) {
            free(inputText);
        }
        if (cipherText) {
            free(cipherText);
        }
    }

    return 0;
}
