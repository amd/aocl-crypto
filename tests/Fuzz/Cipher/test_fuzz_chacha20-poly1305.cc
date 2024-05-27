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
ALCP_Fuzz_Chacha20_Poly1305(const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key   = stream.ConsumeIntegral<Uint16>();
    size_t size_input = stream.ConsumeIntegral<Uint16>();
    size_t size_ad    = stream.ConsumeIntegral<Uint16>();

    /* keeping these sizes constant for now */
    size_t size_iv  = 16;
    size_t size_tag = 16;

    std::vector<Uint8> fuzz_key   = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_input = stream.ConsumeBytes<Uint8>(size_input);
    std::vector<Uint8> fuzz_iv    = stream.ConsumeBytes<Uint8>(size_iv);
    std::vector<Uint8> fuzz_ad    = stream.ConsumeBytes<Uint8>(size_ad);

    std::vector<Uint8> tag(size_tag, 0);

    const Uint8* key        = fuzz_key.data();
    Uint32       keySize    = fuzz_key.size();
    const Uint8* input      = fuzz_input.data();
    Uint32       input_size = fuzz_input.size();
    const Uint8* iv         = fuzz_iv.data();
    Uint32       ivl        = fuzz_iv.size();
    Uint32       tagl       = tag.size();
    Uint32       adl        = fuzz_ad.size();
    const Uint8* ad         = fuzz_ad.data();

    std::vector<Uint8> ciphertext(input_size, 0);

    std::cout << "Running for Input size: " << input_size << " and Key size "
              << keySize << " and IV Len " << ivl << std::endl;

    alc_cipher_aead_info_t cinfo = { .ci_type =
                                         ALC_CIPHER_TYPE_CHACHA20_POLY1305,
                                     .ci_mode   = ALC_CHACHA20_POLY1305,
                                     .ci_keyLen = keySize,
                                     .ci_key    = key,
                                     .ci_iv     = iv,
                                     .ci_ivLen  = ivl };

    alc_cipher_handle_t handle;
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    if (!handle.ch_context) {
        std::cout << "Error in allocating context" << std::endl;
        return -1;
    }
    err = alcp_cipher_aead_request(cinfo.ci_mode, cinfo.ci_keyLen, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: alcp_cipher_aead_request \n");
        return -1;
    }
    err = alcp_cipher_aead_init(&handle, key, keySize, iv, ivl);
    if (alcp_is_error(err)) {
        printf("Error: alcp_cipher_aead_init failed \n");
        return -1;
    }
    err = alcp_cipher_aead_set_tag_length(&handle, tagl);
    if (alcp_is_error(err)) {
        printf("Error: alcp_cipher_aead_set_tag_length failed \n");
        return -1;
    }

    err = alcp_cipher_aead_set_aad(&handle, ad, adl);
    if (alcp_is_error(err)) {
        printf("Error: alcp_cipher_aead_set_aad failed \n");
        return -1;
    }

    err = alcp_cipher_aead_encrypt(&handle, input, &ciphertext[0], input_size);
    if (alcp_is_error(err)) {
        printf("Error: alcp_cipher_aead_encrypt failed\n");
        return -1;
    }

    err = alcp_cipher_aead_get_tag(&handle, &tag[0], tagl);
    if (alcp_is_error(err)) {
        printf("Error:alcp_cipher_aead_get_tag failed \n");
        return -1;
    }

    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    if (ALCP_Fuzz_Chacha20_Poly1305(Data, Size) != 0) {
        std::cout << "ALCP_Fuzz_Chacha20_Poly1305 fuzz test failed"
                  << std::endl;
        return retval;
    }
    return retval;
}
