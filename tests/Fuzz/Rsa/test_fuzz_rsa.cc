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
ALCP_Fuzz_Rsa_Encrypt_2048(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t             size_input   = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_input   = stream.ConsumeBytes<Uint8>(size_input);
    size_t             size_modulus = 256;
    std::vector<Uint8> fuzz_modulus = stream.ConsumeBytes<Uint8>(size_modulus);

    std::vector<Uint8> encrypted_text(size_input, 0);
    std::vector<Uint8> decrypted_text(size_input, 0);

    std::cout << "Running for Input size: " << size_input
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_t handle;

    Uint64 size    = alcp_rsa_context_size(KEY_SIZE_2048);
    handle.context = malloc(size);
    err            = alcp_rsa_request(KEY_SIZE_2048, &handle);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_request\n");
        goto free;
    }
    err = alcp_rsa_set_publickey(
        &handle, PublicKeyExponent, &fuzz_modulus[0], size_modulus);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_set_publickey\n");
        goto free;
    }
    err = alcp_rsa_publickey_encrypt(&handle,
                                     ALCP_RSA_PADDING_NONE,
                                     &fuzz_input[0],
                                     size_input,
                                     &encrypted_text[0]);
    if (alcp_is_error(err)) {
        printf("Error: alcp_rsa_publickey_encrypt\n");
        goto free;
    }
    goto out;

free:
    alcp_rsa_finish(&handle);
    free(handle.context);

out:
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Rsa_Encrypt_2048(Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Rsa test failed" << std::endl;
        return retval;
    }
    return retval;
}