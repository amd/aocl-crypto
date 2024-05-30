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
ALCP_Fuzz_Rsa_EncryptPubKey(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             size_key;

    size_t             size_input   = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_input   = stream.ConsumeBytes<Uint8>(size_input);
    size_t             size_modulus = 256;
    std::vector<Uint8> fuzz_modulus = stream.ConsumeBytes<Uint8>(size_modulus);

    std::vector<Uint8> input(size_input, 0);
    std::vector<Uint8> encrypted_text(size_input, 0);

    Uint64 PublicKeyExponent = 0x10001;

    std::cout << "Running for Input size: " << size_input
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_t handle_encrypt;

    Uint64 size            = alcp_rsa_context_size(KEY_SIZE_2048);
    handle_encrypt.context = malloc(size);
    err                    = alcp_rsa_request(KEY_SIZE_2048, &handle_encrypt);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_request\n");
        goto out_enc;
    }
    err = alcp_rsa_set_publickey(
        &handle_encrypt, PublicKeyExponent, &fuzz_modulus[0], size_modulus);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_set_publickey\n");
        goto free_enc;
    }
    size_key = alcp_rsa_get_key_size(&handle_encrypt);
    if (size_key == 0) {
        printf("\nkey size fetch failed");
        goto free_enc;
    }
    /* input buffer */
    input.resize(size_key);
    err = alcp_rsa_get_publickey(
        &handle_encrypt, &PublicKeyExponent, &fuzz_modulus[0], size_key);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_get_publickey\n");
        goto free_enc;
    }
    /* encrypted output */
    encrypted_text.resize(size_key);
    err = alcp_rsa_publickey_encrypt(&handle_encrypt,
                                     ALCP_RSA_PADDING_NONE,
                                     &input[0],
                                     size_key,
                                     &encrypted_text[0]);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_publickey_encrypt\n");
        goto free_enc;
    }
    goto out_enc;

free_enc:
    alcp_rsa_finish(&handle_encrypt);
    free(handle_encrypt.context);

out_enc:
    return 0;
}

int
ALCP_Fuzz_Rsa_DecryptPvtKey(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             size_key;
    size_t             size_encrypted_data = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_input =
        stream.ConsumeBytes<Uint8>(size_encrypted_data);

    /* key component sizes */
    size_t size_modulus = 256, size_pvt_key_exp = 256, size_p_modulus = 64,
           size_q_modulus = 64, size_dp_exp = 64, size_dq_exp = 64,
           size_q_mod_inv = 64;
    size_t size_label     = stream.ConsumeIntegral<Uint16>();

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

    std::cout << "Running decrypt for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_t handle_decrypt;

    Uint64 size            = alcp_rsa_context_size(KEY_SIZE_2048);
    handle_decrypt.context = malloc(size);
    err                    = alcp_rsa_request(KEY_SIZE_2048, &handle_decrypt);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_request\n");
        goto free_decrypt;
    }

    err = alcp_rsa_set_privatekey(&handle_decrypt,
                                  &fuzz_dp_exp[0],
                                  &fuzz_dq_exp[0],
                                  &fuzz_p_modulus[0],
                                  &fuzz_q_modulus[0],
                                  &fuzz_q_mod_inv[0],
                                  &fuzz_modulus[0],
                                  sizeof(size_p_modulus));

    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_set_privatekey\n");
        goto free_decrypt;
    }
    size_key = alcp_rsa_get_key_size(&handle_decrypt);
    if (size_key == 0) {
        printf("Error: alcp_rsa_get_key_size returned key size 0\n");
        goto free_decrypt;
    }
    /* encrypted text len is size of key */
    encrypted_text.resize(size_key);
    decrypted_text.resize(size_key);

    err = alcp_rsa_privatekey_decrypt(&handle_decrypt,
                                      ALCP_RSA_PADDING_NONE,
                                      &encrypted_text[0],
                                      size_key,
                                      &decrypted_text[0]);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_privatekey_decrypt\n");
        goto free_decrypt;
    }

    goto out_dec;

free_decrypt:
    alcp_rsa_finish(&handle_decrypt);
    free(handle_decrypt.context);

out_dec:
    std::cout << "Completed decrypt for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Rsa_EncryptPubKey(Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Rsa_EncryptPubKey test failed" << std::endl;
        return retval;
    }
    if (ALCP_Fuzz_Rsa_DecryptPvtKey(Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Rsa_DecryptPvtKey test failed" << std::endl;
        return retval;
    }
    return retval;
}