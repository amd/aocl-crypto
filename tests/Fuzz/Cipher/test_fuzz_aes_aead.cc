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
ALCP_Fuzz_AEAD_Cipher_Encrypt(alc_cipher_mode_t Mode,
                              const Uint8*      buf,
                              size_t            len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key = stream.ConsumeIntegralInRange<Uint16>(128, 256);
    size_t size_pt  = stream.ConsumeIntegralInRange<Uint16>(1, 1024);
    size_t size_ad  = stream.ConsumeIntegralInRange<Uint16>(128, 256);

    size_t size_iv  = stream.ConsumeIntegral<Uint16>();
    size_t size_tag = 16;

    std::vector<Uint8> fuzz_key = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_pt  = stream.ConsumeBytes<Uint8>(size_pt);
    std::vector<Uint8> fuzz_iv  = stream.ConsumeBytes<Uint8>(size_iv);
    std::vector<Uint8> fuzz_ad  = stream.ConsumeBytes<Uint8>(size_ad);

    std::vector<Uint8> tag(size_tag, 0);
    std::vector<Uint8> ciphertxt(size_pt, 0);

    /* Initializing the fuzz seeds  */
    const Uint8* key      = fuzz_key.data();
    const Uint32 keySize  = fuzz_key.size();
    const Uint8* plaintxt = fuzz_pt.data();
    const Uint32 pt_len   = fuzz_pt.size();

    const Uint8* iv   = fuzz_iv.data();
    Uint32       ivl  = fuzz_iv.size();
    const Uint8* ad   = fuzz_ad.data();
    Uint32       adl  = fuzz_ad.size();
    Uint32       tagl = tag.size();

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
    handle_encrypt->ch_context = malloc(alcp_cipher_aead_context_size());
    if (handle_encrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }

    std::cout << "Running for Input size: " << pt_len << " and Key size "
              << keySize << " and IV Len " << ivl << " And ADL: " << adl
              << std::endl;

    err = alcp_cipher_aead_request(
        cinfo.ci_mode, cinfo.ci_keyLen, handle_encrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_request failed for encrypt "
                  << std::endl;
        goto DEALLOC_ENC;
    }
    err = alcp_cipher_aead_init(
        handle_encrypt, cinfo.ci_key, cinfo.ci_keyLen, cinfo.ci_iv, 16);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_init failed" << std::endl;
        goto DEALLOC_ENC;
    }
    err = alcp_cipher_aead_set_aad(handle_encrypt, ad, adl);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_set_aad failed" << std::endl;
        goto DEALLOC_ENC;
    }
    err =
        alcp_cipher_aead_encrypt(handle_encrypt, plaintxt, &ciphertxt[0], len);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_encrypt failed" << std::endl;
        goto DEALLOC_ENC;
    }
    err = alcp_cipher_aead_get_tag(handle_encrypt, &tag[0], tagl);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_get_tag failed" << std::endl;
        goto DEALLOC_ENC;
    }
    goto DEALLOC_ENC;

DEALLOC_ENC:
    if (handle_encrypt != nullptr) {
        if (handle_encrypt->ch_context != nullptr) {
            free(handle_encrypt->ch_context);
        }
        delete handle_encrypt;
    }
    return 0;
}

int
ALCP_Fuzz_AEAD_Cipher_Decrypt(alc_cipher_mode_t Mode,
                              const Uint8*      buf,
                              size_t            len)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key = stream.ConsumeIntegralInRange<Uint16>(128, 256);
    size_t size_ct  = stream.ConsumeIntegralInRange<Uint16>(1, 1024);
    size_t size_iv  = stream.ConsumeIntegral<Uint16>();
    size_t size_ad  = stream.ConsumeIntegral<Uint16>();
    size_t size_tag = 16;

    std::vector<Uint8> fuzz_ct  = stream.ConsumeBytes<Uint8>(size_ct);
    std::vector<Uint8> fuzz_key = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_iv  = stream.ConsumeBytes<Uint8>(size_iv);
    std::vector<Uint8> fuzz_ad  = stream.ConsumeBytes<Uint8>(size_ad);

    std::vector<Uint8> decrypted_tag(size_tag, 0);
    std::vector<Uint8> plaintxt(size_ct, 0);

    /* Initializing the fuzz seeds  */
    const Uint8* key       = fuzz_key.data();
    const Uint32 keySize   = fuzz_key.size();
    Uint8*       ciphertxt = fuzz_ct.data();
    const Uint32 ct_len    = fuzz_ct.size();
    const Uint8* iv        = fuzz_iv.data();
    const Uint8* ad        = fuzz_ad.data();
    const Uint32 adl       = fuzz_ad.size();

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
    handle_decrypt->ch_context = malloc(alcp_cipher_aead_context_size());

    if (handle_decrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }

    std::cout << "Running for Input size:" << ct_len << ",Key size:" << keySize
              << ",IV Len:" << fuzz_iv.size() << ",ADL:" << adl << std::endl;

    err = alcp_cipher_aead_request(
        cinfo.ci_mode, cinfo.ci_keyLen, handle_decrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_request failed for decrypt" << std::endl;
        goto DEALLOC_DEC;
    }
    err = alcp_cipher_aead_init(
        handle_decrypt, cinfo.ci_key, cinfo.ci_keyLen, cinfo.ci_iv, 16);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_init failed for decrypt" << std::endl;
        goto DEALLOC_DEC;
    }
    err = alcp_cipher_aead_set_aad(handle_decrypt, &ad[0], adl);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_set_aad failed for decrypt" << std::endl;
        goto DEALLOC_DEC;
    }
    err = alcp_cipher_aead_decrypt(
        handle_decrypt, ciphertxt, &plaintxt[0], ct_len);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_decrypt failed" << std::endl;
        goto DEALLOC_DEC;
    }
    err = alcp_cipher_aead_get_tag(handle_decrypt, &decrypted_tag[0], size_tag);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_get_tag failed for decrypt" << std::endl;
        goto DEALLOC_DEC;
    }
    std::cout << "Operation passed for decrypt for keylen " << cinfo.ci_keyLen
              << std::endl;
    goto DEALLOC_DEC;

DEALLOC_DEC:
    if (handle_decrypt != nullptr) {
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
    for (const alc_cipher_mode_t& Mode : AES_AEAD_Modes) {
        if (ALCP_Fuzz_AEAD_Cipher_Encrypt(Mode, Data, Size) != 0) {
            std::cout << "Cipher AES AEAD Encrypt fuzz test failed for Mode"
                      << aes_aead_mode_string_map[Mode] << std::endl;
            return retval;
        }
        if (ALCP_Fuzz_AEAD_Cipher_Decrypt(Mode, Data, Size) != 0) {
            std::cout << "Cipher AES AEAD decrypt fuzz test failed for Mode"
                      << aes_aead_mode_string_map[Mode] << std::endl;
            return retval;
        }
    }
    return retval;
}