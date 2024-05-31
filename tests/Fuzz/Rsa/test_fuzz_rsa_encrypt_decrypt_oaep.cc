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
ALCP_Fuzz_Rsa_OAEP(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             decrypted_output_size;
    size_t             size_encrypted_data = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_input =
        stream.ConsumeBytes<Uint8>(size_encrypted_data);

    /* key component sizes */
    size_t size_modulus = 256, size_pvt_key_exp = 256, size_p_modulus = 64,
           size_q_modulus = 64, size_dp_exp = 64, size_dq_exp = 64,
           size_q_mod_inv = 64;
    size_t size_label     = stream.ConsumeIntegral<Uint16>();

    Uint64             PublicKeyExponent = 0x10001;
    Uint64             hash_len          = dinfo.dt_custom_len / 8;
    std::vector<Uint8> fuzz_seed         = stream.ConsumeBytes<Uint8>(hash_len);

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
    std::vector<Uint8> fuzz_label = stream.ConsumeBytes<Uint8>(size_label);

    std::vector<Uint8> encrypted_text(size_encrypted_data, 0);
    std::vector<Uint8> decrypted_text(size_encrypted_data, 0);

    std::cout << "Running Rsa OAEP for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_t handle;

    Uint64 size    = alcp_rsa_context_size(KEY_SIZE_2048);
    handle.context = malloc(size);
    err            = alcp_rsa_request(KEY_SIZE_2048, &handle);
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
    err = alcp_rsa_add_digest(&handle, &dinfo);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_add_digest\n");
        goto dealloc;
    }
    err = alcp_rsa_add_mgf(&handle, &mgf_info);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_add_mgf\n");
        goto dealloc;
    }

    /* input buffer */
    fuzz_input.resize(size - 2 * hash_len - 2);
    encrypted_text.resize(size_modulus);
    decrypted_text.resize(size_modulus);

    /* encrypt and decrypt */
    err = alcp_rsa_publickey_encrypt_oaep(&handle,
                                          &fuzz_input[0],
                                          fuzz_input.size(),
                                          &fuzz_label[0],
                                          fuzz_label.size(),
                                          &fuzz_seed[0],
                                          &encrypted_text[0]);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_publickey_encrypt_oaep\n");
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
    err = alcp_rsa_privatekey_decrypt_oaep(&handle,
                                           &encrypted_text[0],
                                           size_modulus,
                                           &fuzz_label[0],
                                           fuzz_label.size(),
                                           &decrypted_text[0],
                                           &decrypted_output_size);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_privatekey_decrypt_oaep\n");
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
    std::cout << "Completed Rsa OAEP for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Rsa_OAEP(Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Rsa_OAEP test failed" << std::endl;
        return retval;
    }
    return retval;
}