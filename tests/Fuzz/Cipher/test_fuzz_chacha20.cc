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
ALCP_Fuzz_Chacha20(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key   = stream.ConsumeIntegral<Uint16>(); // key
    size_t size_input = stream.ConsumeIntegral<Uint16>(); // plaintext
    size_t size_iv    = stream.ConsumeIntegral<Uint16>(); // IV

    std::vector<Uint8> fuzz_key   = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);
    std::vector<Uint8> fuzz_iv    = stream.ConsumeBytes<Uint8>(size_iv);

    std::vector<Uint8> CipherText((Uint32)size_input, 0);

    alc_cipher_info_t cinfo = { .ci_type   = ALC_CIPHER_TYPE_CHACHA20,
                                .ci_mode   = ALC_CHACHA20,
                                .ci_keyLen = fuzz_key.size(),
                                .ci_key    = &fuzz_key[0],
                                .ci_iv     = &fuzz_iv[0],
                                .ci_ivLen  = fuzz_iv.size() };

    alc_cipher_handle_p handle;
    handle->ch_context = malloc(alcp_cipher_context_size());

    if (handle->ch_context == nullptr) {
        printf("Error: Memory Allocation Failed!\n");
        return -1;
    }

    std::cout << "Running for Input size: " << size_input << " and Key size "
              << size_key << std::endl;

    err = alcp_cipher_request(cinfo.ci_mode, cinfo.ci_keyLen, handle);
    if (alcp_is_error(err)) {
        free(handle->ch_context);
        printf("Error: Unable to Request \n");
        return -1;
    }
    err = alcp_cipher_init(
        handle, &fuzz_key[0], fuzz_key.size(), &fuzz_iv[0], fuzz_iv.size());
    if (alcp_is_error(err)) {
        free(handle->ch_context);
        printf("Error: Unable to Initalize \n");
        return -1;
    }
    err = alcp_cipher_encrypt(
        handle, &fuzz_input[0], &CipherText[0], fuzz_input.size());
    if (alcp_is_error(err)) {
        printf("Error: Unable to Encrypt \n");
        return -1;
    }
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Chacha20(Data, Size) != 0) {
        std::cout << "Cipher Chacha20 fuzz test failed for Mode" << std::endl;
        return retval;
    }

    return retval;
}