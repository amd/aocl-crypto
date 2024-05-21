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

/* For all Non AEAD Ciphers */
int
ALCP_Fuzz_Cipher_Encrypt(alc_cipher_mode_t Mode, const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    Uint32 size1 = stream.ConsumeIntegral<Uint16>();
    size_t size2 = stream.ConsumeIntegral<Uint16>();

    /* Splitting the fuzzed input into 3 parts   */
    std::vector<Uint8> fuzz_in1 = stream.ConsumeBytes<Uint8>(size1);
    std::vector<Uint8> fuzz_in2 = stream.ConsumeBytes<Uint8>(size2);
    std::vector<Uint8> fuzz_in3 = stream.ConsumeBytes<Uint8>(size2);
    std::vector<Uint8> fuzz_in4 = std::vector<Uint8>{ 16, 0 };
    fuzz_in4.reserve(16);

    /* Initializing the fuzz seeds  */
    const Uint8* key       = fuzz_in1.data();
    Uint32       keySize   = size1;
    const Uint8* plaintxt  = fuzz_in2.data();
    Uint8*       ciphertxt = fuzz_in3.data();
    const Uint32 PT_len    = size2;
    const Uint8* iv        = fuzz_in4.data();

    std::unique_ptr<Uint8[]> CT = std::make_unique<Uint8[]>(PT_len);

    alc_cipher_info_t cinfo = { .ci_type   = ALC_CIPHER_TYPE_AES,
                                .ci_mode   = Mode,
                                .ci_keyLen = keySize,
                                .ci_key    = key,
                                .ci_iv     = iv };

    alc_cipher_handle_p handle_encrypt = new alc_cipher_handle_t;

    if (handle_encrypt == nullptr) {
        std::cout << "handle_encrypt is null" << std::endl;
        return -1;
    }
    handle_encrypt->ch_context = malloc(alcp_cipher_context_size());
    if (handle_encrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }
    err = alcp_cipher_request(cinfo.ci_mode, cinfo.ci_keyLen, handle_encrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_request failed for encrypt for keylen "
                  << cinfo.ci_keyLen << std::endl;
        goto DEALLOC;
    }
    err = alcp_cipher_init(
        handle_encrypt, cinfo.ci_key, cinfo.ci_keyLen, cinfo.ci_iv, 16);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_init failed for keylen " << cinfo.ci_keyLen
                  << std::endl;
        goto DEALLOC;
    }
    err = alcp_cipher_encrypt(handle_encrypt, plaintxt, ciphertxt, len);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_encrypt failed for keylen " << cinfo.ci_keyLen
                  << std::endl;
        goto DEALLOC;
    }
    goto DEALLOC;

DEALLOC:
    if (handle_encrypt != nullptr) {
        alcp_cipher_finish(handle_encrypt);
        if (handle_encrypt->ch_context != nullptr) {
            free(handle_encrypt->ch_context);
        }
        delete handle_encrypt;
    }

    return 0;
}

int
ALCP_Fuzz_Cipher_Decrypt(alc_cipher_mode_t Mode, const Uint8* buf, size_t len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    Uint32 size1 = stream.ConsumeIntegral<Uint16>(); // Key
    size_t size2 = stream.ConsumeIntegral<Uint16>(); // PT and CT

    /* Splitting the fuzzed input into 3 parts   */
    std::vector<Uint8> fuzz_in1 = stream.ConsumeBytes<Uint8>(size1); // Key
    std::vector<Uint8> fuzz_in2 =
        stream.ConsumeBytes<Uint8>(size2); // Plain_Text
    std::vector<Uint8> fuzz_in3 =
        stream.ConsumeBytes<Uint8>(size2);                     // Cipher_Text
    std::vector<Uint8> fuzz_in4 = std::vector<Uint8>{ 16, 0 }; // IV
    fuzz_in4.reserve(16);

    /* Initializing the fuzz seeds  */
    const Uint8*       key       = fuzz_in1.data();
    Uint32             keySize   = size1;
    const Uint8*       plaintxt  = fuzz_in2.data();
    Uint8*             ciphertxt = fuzz_in3.data();
    const Uint32       PT_len    = size2;
    const Uint8*       iv        = fuzz_in4.data();
    std::vector<Uint8> decrypted_output(size2);

    alc_cipher_info_t cinfo = { .ci_type   = ALC_CIPHER_TYPE_AES,
                                .ci_mode   = Mode,
                                .ci_keyLen = keySize,
                                .ci_key    = key,
                                .ci_iv     = iv };

    alc_cipher_handle_p handle_decrypt = new alc_cipher_handle_t;

    /* for decrypt */
    if (handle_decrypt == nullptr) {
        std::cout << "handle_decrypt is null" << std::endl;
        return -1;
    }
    handle_decrypt->ch_context = malloc(alcp_cipher_context_size());

    if (handle_decrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }
    err = alcp_cipher_request(cinfo.ci_mode, cinfo.ci_keyLen, handle_decrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_request failed for decrypt for keylen "
                  << cinfo.ci_keyLen << std::endl;
        goto DEALLOC;
    }
    err = alcp_cipher_init(
        handle_decrypt, cinfo.ci_key, cinfo.ci_keyLen, cinfo.ci_iv, 16);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_init failed for decrypt for keylen "
                  << cinfo.ci_keyLen << std::endl;
        goto DEALLOC;
    }
    err = alcp_cipher_decrypt(
        handle_decrypt, ciphertxt, &decrypted_output[0], len);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_decrypt failed for decrypt for keylen "
                  << cinfo.ci_keyLen << std::endl;
        goto DEALLOC;
    }
    std::cout << "PASSED for decrypt for keylen " << cinfo.ci_keyLen
              << std::endl;
    goto DEALLOC;

DEALLOC:
    if (handle_decrypt != nullptr) {
        // alcp_cipher_finish(handle_decrypt);
        if (handle_decrypt->ch_context != nullptr) {
            free(handle_decrypt->ch_context);
        }
        delete handle_decrypt;
    }

    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    int retval = 0;
    /* for AEAD Ciphers, we will have another fuzz target altogether */
    for (const alc_cipher_mode_t& Mode : AES_Modes) {
        if (ALCP_Fuzz_Cipher_Encrypt(Mode, Data, Size) != 0) {
            std::cout << "Cipher AES Encrypt fuzz test failed for Mode"
                      << aes_mode_string_map[Mode] << std::endl;
            return retval;
        }
        // if (ALCP_Fuzz_Cipher_Decrypt(Mode, Data, Size) != 0) {
        //     std::cout << "Cipher AES Decrypt fuzz test failed for Mode"
        //               << aes_mode_string_map[Mode] << std::endl;
        //     return retval;
        // }
    }
    return retval;
}