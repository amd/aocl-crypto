/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Fuzz/alcp_fuzz_test.hh"

int
ALCP_Fuzz_Rsa_SignVerify(int PaddingMode, const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    /* Fuzz this for a negative test case , 48 is the valid case!*/
    size_t             size_input = 48;
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);
    size_t             size_salt  = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_salt  = stream.ConsumeBytes<Uint8>(size_salt);

    /* key component sizes */
    size_t size_modulus = 256, size_pvt_key_exp = 256, size_p_modulus = 64,
           size_q_modulus = 64, size_dp_exp = 64, size_dq_exp = 64,
           size_q_mod_inv = 64;

    Uint64 PublicKeyExponent = 0x10001;

    /* fuzzed buffers */
    std::vector<Uint8> fuzz_modulus = stream.ConsumeBytes<Uint8>(size_modulus);
    std::vector<Uint8> fuzz_pvt_key_exp =
        stream.ConsumeBytes<Uint8>(size_pvt_key_exp);
    std::vector<Uint8> fuzz_p_modulus =
        stream.ConsumeBytes<Uint8>(size_p_modulus);
    std::vector<Uint8> fuzz_q_modulus =
        stream.ConsumeBytes<Uint8>(size_q_modulus);
    std::vector<Uint8> fuzz_dp_exp = stream.ConsumeBytes<Uint8>(size_dp_exp);
    std::vector<Uint8> fuzz_dq_exp = stream.ConsumeBytes<Uint8>(size_dq_exp);
    std::vector<Uint8> fuzz_q_mod_inv =
        stream.ConsumeBytes<Uint8>(size_q_mod_inv);

    /* signature output */
    std::vector<Uint8> signature_output(size_modulus, 0);

    alc_rsa_handle_t handle;

    Uint64 size    = alcp_rsa_context_size();
    handle.context = malloc(size);

    err = alcp_rsa_request(&handle);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_request\n");
        goto dealloc;
    }

    err = alcp_rsa_set_publickey(
        &handle, PublicKeyExponent, &fuzz_modulus[0], size_modulus);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_set_publickey\n");
        goto dealloc;
    }

    err = alcp_rsa_set_privatekey(&handle,
                                  &fuzz_dp_exp[0],
                                  &fuzz_dq_exp[0],
                                  &fuzz_p_modulus[0],
                                  &fuzz_q_modulus[0],
                                  &fuzz_q_mod_inv[0],
                                  &fuzz_modulus[0],
                                  size_p_modulus);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_set_privatekey\n");
        goto dealloc;
    }

    err = alcp_rsa_add_digest(&handle, ALC_SHA2_256);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_add_digest\n");
        goto dealloc;
    }
    err = alcp_rsa_add_mgf(&handle, ALC_SHA2_256);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_add_mgf\n");
        goto dealloc;
    }

    if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS) {
        err = alcp_rsa_privatekey_sign_pss(&handle,
                                           true,
                                           &fuzz_input[0],
                                           size_input,
                                           &fuzz_salt[0],
                                           size_salt,
                                           &signature_output[0]);
        if (alcp_is_error(err)) {
            printf("Error: alcp_rsa_privatekey_sign_pss\n");
            goto dealloc;
        }

        err = alcp_rsa_publickey_verify_pss(
            &handle, &fuzz_input[0], size_input, &signature_output[0]);
        if (alcp_is_error(err)) {
            printf("Error: alcp_rsa_publickey_verify_pss\n");
            goto dealloc;
        }
    } else if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS) {
        err = alcp_rsa_privatekey_sign_pkcs1v15(
            &handle, true, &fuzz_input[0], size_input, &signature_output[0]);
        if (alcp_is_error(err)) {
            printf("Error: alcp_rsa_privatekey_sign_pkcs1v15\n");
            goto dealloc;
        }
        err = alcp_rsa_publickey_verify_pkcs1v15(
            &handle, &fuzz_input[0], size_input, &signature_output[0]);
        if (alcp_is_error(err)) {
            printf("Error: alcp_rsa_publickey_verify_pkcs1v15\n");
            goto dealloc;
        }
    } else {
        std::cout
            << "Error: Invalid/Unsupported padding scheme for RSA Sign/Verify"
            << std::endl;
        goto dealloc;
    }
    goto exit;

dealloc:
    alcp_rsa_finish(&handle);
    free(handle.context);
    return -1;

exit:
    alcp_rsa_finish(&handle);
    free(handle.context);
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Rsa_SignVerify(ALCP_TEST_RSA_PADDING_PKCS, Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Rsa_SignVerify PKCS test failed" << std::endl;
        return retval;
    }
    if (ALCP_Fuzz_Rsa_SignVerify(ALCP_TEST_RSA_PADDING_PSS, Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Rsa_SignVerify PSS test failed" << std::endl;
        return retval;
    }
    return retval;
}